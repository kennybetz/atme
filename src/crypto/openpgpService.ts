/**
 * On-Device OpenPGP Encryption Engine (`openpgp.js`)
 *
 * - Generates Curve25519 / Ed25519 PGP keypairs directly on the user's device.
 * - Encrypts and cryptographically signs DCP/1.0 JSON packets so Google, Microsoft,
 *   or Yahoo servers only ever transport an opaque PGP ASCII-armored block.
 * - Natively interoperable with Proton Mail's OpenPGP implementation.
 * - Supports Ephemeral Invite Keys (`openpgp-invite-key`) when messaging a recipient
 *   who has not installed the app or published a PGP key yet.
 */

import * as openpgp from 'openpgp';

export interface GeneratedKeyPair {
  publicKeyArmored: string;
  privateKeyArmored: string;
  fingerprint: string;
  createdAt: string;
}

/**
 * Generates an ECC Curve25519 OpenPGP keypair on-device
 */
export async function generateDeviceKeyPair(
  displayName: string,
  email: string
): Promise<GeneratedKeyPair> {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519Legacy',
    userIDs: [{ name: displayName, email }],
    format: 'armored',
  });

  const parsedPub = await openpgp.readKey({ armoredKey: publicKey });
  const fingerprint = parsedPub.getFingerprint().toUpperCase();

  return {
    publicKeyArmored: publicKey,
    privateKeyArmored: privateKey,
    fingerprint,
    createdAt: new Date().toISOString(),
  };
}

/**
 * Encrypts & signs a JSON string using the recipient's PGP public key(s) and sender's private key
 */
export async function encryptDcpPayloadAsymmetric(params: {
  cleartextJson: string;
  recipientPublicKeysArmored: string[];
  senderPublicKeyArmored: string;
  senderPrivateKeyArmored: string;
}): Promise<string> {
  const {
    cleartextJson,
    recipientPublicKeysArmored,
    senderPublicKeyArmored,
    senderPrivateKeyArmored,
  } = params;

  // Include sender's own public key so sender can also decrypt their own sent messages on other devices
  const allPubKeyStrings = Array.from(
    new Set([...recipientPublicKeysArmored, senderPublicKeyArmored])
  );

  const encryptionKeys = await Promise.all(
    allPubKeyStrings.map((armoredKey) => openpgp.readKey({ armoredKey }))
  );

  const signingKey = await openpgp.readPrivateKey({
    armoredKey: senderPrivateKeyArmored,
  });

  const message = await openpgp.createMessage({ text: cleartextJson });

  const encrypted = await openpgp.encrypt({
    message,
    encryptionKeys,
    signingKeys: signingKey,
    format: 'armored',
  });

  return String(encrypted);
}

/**
 * Encrypts & signs a JSON string using a generated ephemeral invite secret
 * (Used when sending the first message to someone who does not have the app yet)
 */
export async function encryptDcpPayloadWithInviteKey(params: {
  cleartextJson: string;
  inviteSecret: string;
  senderPublicKeyArmored: string;
  senderPrivateKeyArmored: string;
}): Promise<string> {
  const {
    cleartextJson,
    inviteSecret,
    senderPublicKeyArmored,
    senderPrivateKeyArmored,
  } = params;

  const senderPubKey = await openpgp.readKey({
    armoredKey: senderPublicKeyArmored,
  });
  const signingKey = await openpgp.readPrivateKey({
    armoredKey: senderPrivateKeyArmored,
  });

  const message = await openpgp.createMessage({ text: cleartextJson });

  const encrypted = await openpgp.encrypt({
    message,
    encryptionKeys: [senderPubKey],
    passwords: [inviteSecret],
    signingKeys: signingKey,
    format: 'armored',
  });

  return String(encrypted);
}

/**
 * Decrypts and verifies a PGP-armored DCP packet on the recipient's device
 */
export async function decryptDcpPayload(params: {
  encryptedArmored: string;
  recipientPrivateKeyArmored?: string;
  inviteSecret?: string;
  senderPublicKeyArmored?: string;
}): Promise<{
  cleartextJson: string;
  signatureVerified: boolean;
}> {
  const {
    encryptedArmored,
    recipientPrivateKeyArmored,
    inviteSecret,
    senderPublicKeyArmored,
  } = params;

  const message = await openpgp.readMessage({
    armoredMessage: encryptedArmored,
  });

  const decryptOptions: openpgp.DecryptOptions = {
    message,
    format: 'utf8',
  };

  if (recipientPrivateKeyArmored) {
    decryptOptions.decryptionKeys = await openpgp.readPrivateKey({
      armoredKey: recipientPrivateKeyArmored,
    });
  }

  if (inviteSecret) {
    decryptOptions.passwords = [inviteSecret];
  }

  if (senderPublicKeyArmored) {
    decryptOptions.verificationKeys = await openpgp.readKey({
      armoredKey: senderPublicKeyArmored,
    });
  }

  const { data, signatures } = await openpgp.decrypt(decryptOptions);

  let signatureVerified = false;
  if (signatures && signatures.length > 0 && senderPublicKeyArmored) {
    try {
      await signatures[0].verified;
      signatureVerified = true;
    } catch {
      signatureVerified = false;
    }
  }

  return {
    cleartextJson: String(data),
    signatureVerified,
  };
}

/**
 * Generates a URL-safe random ephemeral invite token for first-contact deep links
 */
export function generateInviteSecret(): string {
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Formats a 40-char PGP fingerprint into readable 4-char blocks
 */
export function formatFingerprint(fp: string): string {
  const clean = fp.replace(/\s+/g, '').toUpperCase();
  return clean.match(/.{1,4}/g)?.join(' ') || clean;
}
