/**
 * Strict Inbox Filter & RFC 5322 MIME Packet Parser (`DCP/1.0`)
 *
 * Core requirement:
 *   "Then the format email needs to be read from the app, ignoring anything that is a regular email."
 *
 * This module inspects raw incoming emails (either from Gmail/Outlook API queries or raw MIME streams)
 * and enforces a strict 3-gate protocol validation:
 *   Gate 1: Header Check (`X-DontCall-Protocol: DCP/1.0`)
 *   Gate 2: Subject / MIME Part Check (`application/vnd.dontcall.packet+pgp` & PGP ASCII Armor)
 *   Gate 3: Cryptographic Decryption & Signature Verification via `openpgp.js`
 *
 * Any newsletter, receipt, work email, or personal email lacking the exact `DCP/1.0` headers
 * and encrypted packet is immediately rejected and never touches the app state.
 */

import {
  DCP_MIME_PACKET_TYPE,
  DCP_PROTOCOL_VERSION,
  DcpPacket,
  DcpPacketType,
  EncryptionMode,
  FilterInspectionResult,
  RawTransportEmail,
} from './types';
import { decryptDcpPayload } from '../crypto/openpgpService';
import { verifyComplianceAttestation } from '../crypto/complianceAndShredding';

/**
 * Extracts headers and PGP blocks directly from a raw RFC 5322 MIME string if not pre-parsed
 */
export function parseRawMimeStructure(rawMime: string): {
  headers: Record<string, string>;
  encryptedPacketArmored?: string;
  attachedPublicKeyArmored?: string;
} {
  const headers: Record<string, string> = {};
  const lines = rawMime.split(/\r?\n/);

  for (const line of lines) {
    if (line.trim() === '') break;
    const colonIdx = line.indexOf(':');
    if (colonIdx > 0) {
      const key = line.slice(0, colonIdx).trim();
      const val = line.slice(colonIdx + 1).trim();
      headers[key] = val;
    }
  }

  let encryptedPacketArmored: string | undefined;
  const pgpMsgMatch = rawMime.match(
    /-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/
  );
  if (pgpMsgMatch) {
    encryptedPacketArmored = pgpMsgMatch[0];
  }

  let attachedPublicKeyArmored: string | undefined;
  const pgpKeyMatch = rawMime.match(
    /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----/
  );
  if (pgpKeyMatch) {
    attachedPublicKeyArmored = pgpKeyMatch[0];
  }

  return {
    headers,
    encryptedPacketArmored,
    attachedPublicKeyArmored,
  };
}

/**
 * Fast synchronous check to determine if an email is a valid `DCP/1.0` messaging packet
 * vs. a regular email that must be ignored.
 */
export function isDontCallFormattedEmail(email: RawTransportEmail): {
  valid: boolean;
  reason: string;
  detectedHeaders: Record<string, string>;
} {
  const parsed = parseRawMimeStructure(email.rawMime);
  const mergedHeaders: Record<string, string> = {
    ...parsed.headers,
    ...email.headers,
  };

  // Case-insensitive lookup for X-DontCall-* headers
  const dcpHeaders: Record<string, string> = {};
  for (const [key, val] of Object.entries(mergedHeaders)) {
    if (key.toLowerCase().startsWith('x-dontcall-')) {
      dcpHeaders[key] = val;
    }
  }

  const protocolHeader =
    mergedHeaders['X-DontCall-Protocol'] ||
    mergedHeaders['x-dontcall-protocol'];

  if (protocolHeader !== DCP_PROTOCOL_VERSION) {
    return {
      valid: false,
      reason: `Ignored Regular Email: Missing 'X-DontCall-Protocol: ${DCP_PROTOCOL_VERSION}' header`,
      detectedHeaders: dcpHeaders,
    };
  }

  const hasMimeType = email.rawMime.includes(DCP_MIME_PACKET_TYPE);
  const hasPgpBlock = Boolean(
    email.encryptedPacketArmored || parsed.encryptedPacketArmored
  );

  if (!hasMimeType || !hasPgpBlock) {
    return {
      valid: false,
      reason: `Rejected Malformed Packet: Missing '${DCP_MIME_PACKET_TYPE}' or OpenPGP ciphertext block`,
      detectedHeaders: dcpHeaders,
    };
  }

  return {
    valid: true,
    reason: `Accepted DCP/1.0 Encrypted Messaging Packet (${
      mergedHeaders['X-DontCall-Packet-Type'] || 'chat.message'
    })`,
    detectedHeaders: dcpHeaders,
  };
}

/**
 * Runs the complete Strict Filter + OpenPGP Decryption pipeline on an incoming email
 */
export async function inspectAndDecryptEmail(params: {
  email: RawTransportEmail;
  recipientPrivateKeyArmored?: string;
  inviteSecret?: string;
}): Promise<FilterInspectionResult> {
  const { email, recipientPrivateKeyArmored, inviteSecret } = params;
  const startTime = performance.now();

  const gateCheck = isDontCallFormattedEmail(email);

  if (!gateCheck.valid) {
    return {
      emailId: email.id,
      subject: email.subject,
      from: email.from,
      receivedAt: email.date,
      accepted: false,
      reason: gateCheck.reason,
      detectedHeaders: gateCheck.detectedHeaders,
    };
  }

  const parsedMime = parseRawMimeStructure(email.rawMime);
  const encryptedArmored =
    email.encryptedPacketArmored || parsedMime.encryptedPacketArmored;
  const senderPublicKeyArmored =
    email.attachedPublicKeyArmored || parsedMime.attachedPublicKeyArmored;

  const packetType = (gateCheck.detectedHeaders['X-DontCall-Packet-Type'] ||
    'chat.message') as DcpPacketType;
  const encryptionMode = (gateCheck.detectedHeaders['X-DontCall-Encryption'] ||
    'openpgp-asymmetric') as EncryptionMode;

  if (!encryptedArmored) {
    return {
      emailId: email.id,
      subject: email.subject,
      from: email.from,
      receivedAt: email.date,
      accepted: false,
      reason: 'Missing OpenPGP armored payload',
      detectedHeaders: gateCheck.detectedHeaders,
    };
  }

  try {
    const { cleartextJson, signatureVerified } = await decryptDcpPayload({
      encryptedArmored,
      recipientPrivateKeyArmored,
      inviteSecret: inviteSecret || email.inviteKeyFragment,
      senderPublicKeyArmored,
    });

    const decryptedPacket = JSON.parse(cleartextJson) as DcpPacket;
    const elapsedMs = Math.round((performance.now() - startTime) * 10) / 10;

    let compliantBuildVerified = Boolean(signatureVerified);
    if (decryptedPacket.complianceAttestation) {
      const check = await verifyComplianceAttestation({
        senderEmail: decryptedPacket.sender.email,
        senderPgpFingerprint: decryptedPacket.sender.pgpFingerprint,
        attestation: decryptedPacket.complianceAttestation,
      });
      compliantBuildVerified = check.verified && Boolean(signatureVerified);
    }

    return {
      emailId: email.id,
      subject: email.subject,
      from: email.from,
      receivedAt: email.date,
      accepted: true,
      reason: gateCheck.reason,
      detectedHeaders: gateCheck.detectedHeaders,
      packetType,
      encryptionMode,
      decryptedPacket,
      signatureVerified,
      compliantBuildVerified,
      decryptionTimeMs: elapsedMs,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      emailId: email.id,
      subject: email.subject,
      from: email.from,
      receivedAt: email.date,
      accepted: true,
      reason: `DCP/1.0 Packet recognized, awaiting recipient PGP key or invite secret (${message})`,
      detectedHeaders: gateCheck.detectedHeaders,
      packetType,
      encryptionMode,
    };
  }
}
