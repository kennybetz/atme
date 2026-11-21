/**
 * Strict Inbox Filter & RFC 5322 MIME Packet Parser (`ATME/1.0`)
 *
 * Core requirement:
 *   Ignores 100% of regular personal/work emails while parsing ONLY valid `ATME/1.0`
 *   (or legacy `DCP/1.0`) messaging packets.
 *
 * Dual-Mode Interoperability:
 *   - Fast Path (`cleartext-json`): Directly parses `application/vnd.atme.packet+json`
 *     parts in `<0.1ms` with zero crypto overhead on the simple starter branch.
 *   - Encrypted Interop Path (`openpgp-*`): Automatically decrypts and verifies
 *     `application/vnd.atme.packet+pgp` packets sent by peers on encrypted `@me` branches.
 */

import {
  ACCEPTED_ATME_MIME_TYPES,
  ACCEPTED_ATME_PROTOCOL_VERSIONS,
  ATME_JSON_PACKET_TYPE,
  ATME_MIME_PACKET_TYPE,
  ATME_PROTOCOL_VERSION,
  DcpPacket,
  DcpPacketType,
  EncryptionMode,
  FilterInspectionResult,
  RawTransportEmail,
} from './types';
import { decryptDcpPayload } from '../crypto/openpgpService';

/**
 * Extracts headers, cleartext JSON packet blocks, and OpenPGP armor blocks
 * directly from a raw RFC 5322 MIME string.
 */
export function parseRawMimeStructure(rawMime: string): {
  headers: Record<string, string>;
  encryptedPacketArmored?: string;
  cleartextPacketJson?: string;
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

  let cleartextPacketJson: string | undefined;
  const jsonPartIdx = rawMime.toLowerCase().indexOf(ATME_JSON_PACKET_TYPE);
  if (jsonPartIdx !== -1) {
    const afterType = rawMime.slice(jsonPartIdx);
    const blankMatch = afterType.match(/\r?\n\r?\n/);
    if (blankMatch && blankMatch.index !== undefined) {
      const bodyStart = blankMatch.index + blankMatch[0].length;
      let bodySlice = afterType.slice(bodyStart);
      const boundaryMatch = rawMime.match(/boundary="?([^"\r\n;]+)"?/i);
      if (boundaryMatch?.[1]) {
        const endMarkerIdx = bodySlice.indexOf(`--${boundaryMatch[1]}`);
        if (endMarkerIdx !== -1) {
          bodySlice = bodySlice.slice(0, endMarkerIdx);
        }
      }
      const trimmed = bodySlice.trim();
      if (trimmed.startsWith('{')) {
        cleartextPacketJson = trimmed;
      }
    }
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
    cleartextPacketJson,
    attachedPublicKeyArmored,
  };
}

/**
 * Fast synchronous check to determine if an email is a valid `ATME/1.0` messaging packet
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

  // Case-insensitive lookup for X-ATME-* and legacy X-DontCall-* headers
  const dcpHeaders: Record<string, string> = {};
  for (const [key, val] of Object.entries(mergedHeaders)) {
    const lower = key.toLowerCase();
    if (lower.startsWith('x-atme-') || lower.startsWith('x-dontcall-')) {
      dcpHeaders[key] = val;
    }
  }

  const protocolHeader =
    mergedHeaders['X-ATME-Protocol'] ||
    mergedHeaders['x-atme-protocol'] ||
    mergedHeaders['X-DontCall-Protocol'] ||
    mergedHeaders['x-dontcall-protocol'];

  if (
    !protocolHeader ||
    !(ACCEPTED_ATME_PROTOCOL_VERSIONS as readonly string[]).includes(
      protocolHeader
    )
  ) {
    return {
      valid: false,
      reason: `Ignored Regular Email: Missing 'X-ATME-Protocol: ${ATME_PROTOCOL_VERSION}' header`,
      detectedHeaders: dcpHeaders,
    };
  }

  const hasMimeType = ACCEPTED_ATME_MIME_TYPES.some((mime) =>
    email.rawMime.includes(mime)
  );
  const hasJsonBlock = Boolean(
    email.cleartextPacketJson || parsed.cleartextPacketJson
  );
  const hasPgpBlock = Boolean(
    email.encryptedPacketArmored || parsed.encryptedPacketArmored
  );

  if (!hasMimeType || (!hasJsonBlock && !hasPgpBlock)) {
    return {
      valid: false,
      reason: `Rejected Malformed Packet: Missing '${ATME_JSON_PACKET_TYPE}' / '${ATME_MIME_PACKET_TYPE}' payload`,
      detectedHeaders: dcpHeaders,
    };
  }

  const detectedPacketType =
    mergedHeaders['X-ATME-Packet-Type'] ||
    mergedHeaders['X-DontCall-Packet-Type'] ||
    'chat.message';

  return {
    valid: true,
    reason: hasJsonBlock
      ? `Accepted ATME/1.0 JSON Messaging Packet (${detectedPacketType})`
      : `Accepted ATME/1.0 Encrypted Messaging Packet (${detectedPacketType})`,
    detectedHeaders: dcpHeaders,
  };
}

/**
 * Runs the Strict Filter + Fast Cleartext JSON / OpenPGP Interop Parser on an incoming email
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
  const cleartextJsonPayload =
    email.cleartextPacketJson || parsedMime.cleartextPacketJson;
  const encryptedArmored =
    email.encryptedPacketArmored || parsedMime.encryptedPacketArmored;
  const senderPublicKeyArmored =
    email.attachedPublicKeyArmored || parsedMime.attachedPublicKeyArmored;

  const packetType = (gateCheck.detectedHeaders['X-ATME-Packet-Type'] ||
    gateCheck.detectedHeaders['X-DontCall-Packet-Type'] ||
    'chat.message') as DcpPacketType;
  const encryptionMode = (gateCheck.detectedHeaders['X-ATME-Encryption'] ||
    gateCheck.detectedHeaders['X-DontCall-Encryption'] ||
    (cleartextJsonPayload ? 'cleartext-json' : 'openpgp-asymmetric')) as EncryptionMode;

  // Fast Path: Cleartext JSON packet (`ATME/1.0` simple scaffold mode)
  if (cleartextJsonPayload && !encryptedArmored) {
    try {
      const parsedPacket = JSON.parse(cleartextJsonPayload) as DcpPacket;
      const elapsedMs = Math.round((performance.now() - startTime) * 10) / 10;
      return {
        emailId: email.id,
        subject: email.subject,
        from: email.from,
        receivedAt: email.date,
        accepted: true,
        reason: gateCheck.reason,
        detectedHeaders: gateCheck.detectedHeaders,
        packetType,
        encryptionMode: 'cleartext-json',
        decryptedPacket: parsedPacket,
        signatureVerified: false,
        compliantBuildVerified: true,
        decryptionTimeMs: elapsedMs,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        emailId: email.id,
        subject: email.subject,
        from: email.from,
        receivedAt: email.date,
        accepted: false,
        reason: `Rejected Malformed JSON Packet (${message})`,
        detectedHeaders: gateCheck.detectedHeaders,
      };
    }
  }

  if (!encryptedArmored) {
    return {
      emailId: email.id,
      subject: email.subject,
      from: email.from,
      receivedAt: email.date,
      accepted: false,
      reason: 'Missing ATME/1.0 JSON or OpenPGP armored payload',
      detectedHeaders: gateCheck.detectedHeaders,
    };
  }

  // Interop Path: Decrypt incoming OpenPGP-encrypted packets from encrypted ATME/1.0 peers
  try {
    const { cleartextJson, signatureVerified } = await decryptDcpPayload({
      encryptedArmored,
      recipientPrivateKeyArmored,
      inviteSecret: inviteSecret || email.inviteKeyFragment,
      senderPublicKeyArmored,
    });

    const decryptedPacket = JSON.parse(cleartextJson) as DcpPacket;
    const elapsedMs = Math.round((performance.now() - startTime) * 10) / 10;

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
      compliantBuildVerified: Boolean(signatureVerified),
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
      reason: `ATME/1.0 Packet recognized, awaiting recipient PGP key or invite secret (${message})`,
      detectedHeaders: gateCheck.detectedHeaders,
      packetType,
      encryptionMode,
    };
  }
}
