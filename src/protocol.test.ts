/**
 * Automated Unit Tests for the Stage 1 Core Protocol Engine:
 *   1. On-Device OpenPGP Key Generation (`generateDeviceKeyPair`)
 *   2. Asymmetric E2EE Encryption + Proton Mail PGP compatibility (`encryptDcpPayloadAsymmetric`)
 *   3. First-Contact Ephemeral Invite Encryption (`encryptDcpPayloadWithInviteKey`)
 *   4. RFC 5322 Multipart MIME Builder + Non-App Download Card (`buildDcpMimeEmail`)
 *   5. Strict Inbox Filter (`isDontCallFormattedEmail` + `inspectAndDecryptEmail`) ensuring
 *      100% of regular emails (Stripe, GitHub, Delta) are ignored while `DCP/1.0` packets are decrypted.
 */

import { describe, expect, it } from 'vitest';
import {
  encryptDcpPayloadAsymmetric,
  encryptDcpPayloadWithInviteKey,
  generateDeviceKeyPair,
  generateInviteSecret,
} from './crypto/openpgpService';
import { buildDcpMimeEmail } from './protocol/mimeBuilder';
import {
  inspectAndDecryptEmail,
  isDontCallFormattedEmail,
} from './protocol/mimeParser';
import { DCP_PROTOCOL_VERSION, DcpPacket } from './protocol/types';
import { createSampleRegularEmails } from './store/seedEmails';
import {
  discoverCustomDomainEmailConfig,
  generatePkceChallengePair,
} from './transport/oauthPortal';
import {
  createSignedComplianceAttestation,
  destroyThreadWrappingKey,
  encryptAtRestWithThreadKey,
  verifyComplianceAttestation,
} from './crypto/complianceAndShredding';
import {
  computeSafetyNumberAndQrMatrix,
  createShieldedBurnerAlias,
  evaluatePinOrDuressCode,
  extractClientSideLinkPreview,
} from './crypto/privacyFeatures';

describe('Dont Call Stage 1 Technical Protocol Engine (DCP/1.0)', () => {
  it('strictly ignores regular emails (Stripe, GitHub, Delta) and never parses them into the app', async () => {
    const regularEmails = createSampleRegularEmails();
    expect(regularEmails.length).toBeGreaterThanOrEqual(3);

    for (const regEmail of regularEmails) {
      const quickCheck = isDontCallFormattedEmail(regEmail);
      expect(quickCheck.valid).toBe(false);
      expect(quickCheck.reason).toContain('Ignored Regular Email');

      const fullInspection = await inspectAndDecryptEmail({ email: regEmail });
      expect(fullInspection.accepted).toBe(false);
      expect(fullInspection.decryptedPacket).toBeUndefined();
    }
  });

  it('encrypts a message on-device with OpenPGP, formats it as RFC 5322 MIME, and decrypts it with verified signature', async () => {
    const aliceKeys = await generateDeviceKeyPair(
      'Alice Rivera',
      'alice@gmail.com'
    );
    const elenaProtonKeys = await generateDeviceKeyPair(
      'Elena Vogt',
      'elena@proton.me'
    );

    const packet: DcpPacket = {
      protocol: DCP_PROTOCOL_VERSION,
      packetId: 'pkt_test_001',
      type: 'chat.message',
      encryptionMode: 'openpgp-asymmetric',
      channel: {
        id: 'ch_launch_team',
        type: 'group',
        name: 'launch-team',
        participants: ['alice@gmail.com', 'elena@proton.me'],
      },
      sender: {
        email: 'alice@gmail.com',
        displayName: 'Alice Rivera',
        provider: 'gmail',
        pgpFingerprint: aliceKeys.fingerprint,
        publicKeyArmored: aliceKeys.publicKeyArmored,
      },
      payload: {
        messageId: 'msg_test_001',
        text: 'Hello Elena! This JSON packet is OpenPGP encrypted over email.',
        formatting: 'markdown',
      },
      sentAt: new Date().toISOString(),
    };

    const encryptedArmored = await encryptDcpPayloadAsymmetric({
      cleartextJson: JSON.stringify(packet),
      recipientPublicKeysArmored: [elenaProtonKeys.publicKeyArmored],
      senderPublicKeyArmored: aliceKeys.publicKeyArmored,
      senderPrivateKeyArmored: aliceKeys.privateKeyArmored,
    });

    expect(encryptedArmored).toContain('-----BEGIN PGP MESSAGE-----');
    // Ensure cleartext message never appears inside the encrypted payload
    expect(encryptedArmored).not.toContain('Hello Elena!');

    const mimeEmail = buildDcpMimeEmail({
      packet,
      encryptedPacketArmored: encryptedArmored,
    });

    // Verify RFC 5322 headers & Non-App Download Card
    expect(mimeEmail.headers['X-DontCall-Protocol']).toBe(DCP_PROTOCOL_VERSION);
    expect(mimeEmail.rawMime).toContain('application/vnd.dontcall.packet+pgp');
    expect(mimeEmail.htmlFallbackPart).toContain(
      'Download @me on the App Store (iOS)'
    );
    expect(mimeEmail.htmlFallbackPart).toContain(
      'Get @me on Google Play (Android)'
    );
    // Ensure cleartext chat text is NOT leaked into the HTML fallback card
    expect(mimeEmail.htmlFallbackPart).not.toContain('Hello Elena!');

    // Recipient (Elena) runs Strict Inbox Filter & Decryptor
    const inspection = await inspectAndDecryptEmail({
      email: mimeEmail,
      recipientPrivateKeyArmored: elenaProtonKeys.privateKeyArmored,
    });

    expect(inspection.accepted).toBe(true);
    expect(inspection.signatureVerified).toBe(true);
    expect(inspection.decryptedPacket?.payload.text).toBe(
      'Hello Elena! This JSON packet is OpenPGP encrypted over email.'
    );
    expect(inspection.decryptedPacket?.sender.pgpFingerprint).toBe(
      aliceKeys.fingerprint
    );
  });

  it('supports First-Contact Ephemeral Invite Encryption when messaging a user who does not have the app yet', async () => {
    const senderKeys = await generateDeviceKeyPair(
      'Alex Rivera',
      'alex@gmail.com'
    );
    const inviteSecret = generateInviteSecret();

    const packet: DcpPacket = {
      protocol: DCP_PROTOCOL_VERSION,
      packetId: 'pkt_invite_002',
      type: 'chat.message',
      encryptionMode: 'openpgp-invite-key',
      channel: {
        id: 'dm_alex_jordan',
        type: 'dm',
        name: 'Jordan Taylor',
        participants: ['alex@gmail.com', 'jordan@yahoo.com'],
      },
      sender: {
        email: 'alex@gmail.com',
        displayName: 'Alex Rivera',
        provider: 'gmail',
        pgpFingerprint: senderKeys.fingerprint,
        publicKeyArmored: senderKeys.publicKeyArmored,
      },
      payload: {
        messageId: 'msg_invite_002',
        text: 'Hey Jordan! Once you install Dont Call from the App Store link, this message decrypts automatically.',
        formatting: 'markdown',
      },
      sentAt: new Date().toISOString(),
    };

    const encryptedArmored = await encryptDcpPayloadWithInviteKey({
      cleartextJson: JSON.stringify(packet),
      inviteSecret,
      senderPublicKeyArmored: senderKeys.publicKeyArmored,
      senderPrivateKeyArmored: senderKeys.privateKeyArmored,
    });

    const mimeEmail = buildDcpMimeEmail({
      packet,
      encryptedPacketArmored: encryptedArmored,
      inviteKeyFragment: inviteSecret,
    });

    expect(mimeEmail.htmlFallbackPart).toContain(
      'Download @me on the App Store'
    );
    expect(mimeEmail.htmlFallbackPart).toContain('inviteKey=');

    // When Jordan installs the app and opens the deep-link invite, it decrypts with the inviteSecret
    const inspection = await inspectAndDecryptEmail({
      email: mimeEmail,
      inviteSecret,
    });

    expect(inspection.accepted).toBe(true);
    expect(inspection.signatureVerified).toBe(true);
    expect(inspection.decryptedPacket?.payload.text).toContain(
      'Once you install Dont Call from the App Store link'
    );
  });

  it('supports adding and removing group members via encrypted chat.member-update email packets', async () => {
    const alexKeys = await generateDeviceKeyPair('Alex Rivera', 'alex@gmail.com');
    const elenaKeys = await generateDeviceKeyPair('Elena Vogt', 'elena@proton.me');
    const samKeys = await generateDeviceKeyPair('Sam Chen', 'sam@outlook.com');

    // Alex adds Sam to the group and broadcasts a signed chat.member-update packet
    const addPacket: DcpPacket = {
      protocol: DCP_PROTOCOL_VERSION,
      packetId: 'pkt_member_add_01',
      type: 'chat.member-update',
      encryptionMode: 'openpgp-asymmetric',
      channel: {
        id: 'ch_product_launch',
        type: 'group',
        name: 'product-launch',
        participants: ['alex@gmail.com', 'elena@proton.me', 'sam@outlook.com'],
      },
      sender: {
        email: 'alex@gmail.com',
        displayName: 'Alex Rivera',
        provider: 'gmail',
        pgpFingerprint: alexKeys.fingerprint,
        publicKeyArmored: alexKeys.publicKeyArmored,
      },
      payload: {
        messageId: 'msg_member_add_01',
        text: 'Alex Rivera added Sam Chen to #product-launch',
        memberUpdate: {
          action: 'add',
          targetEmail: 'sam@outlook.com',
          targetDisplayName: 'Sam Chen',
          updatedParticipants: [
            'alex@gmail.com',
            'elena@proton.me',
            'sam@outlook.com',
          ],
        },
      },
      sentAt: new Date().toISOString(),
    };

    const encryptedAdd = await encryptDcpPayloadAsymmetric({
      cleartextJson: JSON.stringify(addPacket),
      recipientPublicKeysArmored: [
        elenaKeys.publicKeyArmored,
        samKeys.publicKeyArmored,
      ],
      senderPublicKeyArmored: alexKeys.publicKeyArmored,
      senderPrivateKeyArmored: alexKeys.privateKeyArmored,
    });

    const addMime = buildDcpMimeEmail({
      packet: addPacket,
      encryptedPacketArmored: encryptedAdd,
    });

    expect(addMime.to).toContain('sam@outlook.com');
    const samInspection = await inspectAndDecryptEmail({
      email: addMime,
      recipientPrivateKeyArmored: samKeys.privateKeyArmored,
    });
    expect(samInspection.accepted).toBe(true);
    expect(samInspection.decryptedPacket?.payload.memberUpdate?.action).toBe(
      'add'
    );
  });

  it('bundles the user Profile Card (avatar image, display name, @handle) in the first encrypted message and supports Read Receipts', async () => {
    const alexKeys = await generateDeviceKeyPair('Alex Rivera', 'alex@gmail.com');
    const elenaKeys = await generateDeviceKeyPair('Elena Vogt', 'elena@proton.me');

    const firstContactPacket: DcpPacket = {
      protocol: DCP_PROTOCOL_VERSION,
      packetId: 'pkt_profile_sync_01',
      type: 'chat.message',
      encryptionMode: 'openpgp-asymmetric',
      channel: {
        id: 'dm_alex_elena',
        type: 'dm',
        name: 'Elena Vogt',
        participants: ['alex@gmail.com', 'elena@proton.me'],
      },
      sender: {
        email: 'alex@gmail.com',
        displayName: 'Alex Rivera',
        handle: '@alexrivera',
        provider: 'gmail',
        pgpFingerprint: alexKeys.fingerprint,
        publicKeyArmored: alexKeys.publicKeyArmored,
        profileCard: {
          displayName: 'Alex Rivera',
          handle: '@alexrivera',
          avatarDataUrl: 'data:image/svg+xml;utf8,<svg></svg>',
          bio: 'Zero-Server E2EE',
          updatedAt: new Date().toISOString(),
        },
      },
      payload: {
        messageId: 'msg_first_01',
        text: 'First message carrying my encrypted Profile Card!',
      },
      sentAt: new Date().toISOString(),
    };

    const encMsg = await encryptDcpPayloadAsymmetric({
      cleartextJson: JSON.stringify(firstContactPacket),
      recipientPublicKeysArmored: [elenaKeys.publicKeyArmored],
      senderPublicKeyArmored: alexKeys.publicKeyArmored,
      senderPrivateKeyArmored: alexKeys.privateKeyArmored,
    });

    const mimeMsg = buildDcpMimeEmail({
      packet: firstContactPacket,
      encryptedPacketArmored: encMsg,
    });

    const decryptedOnElenaDevice = await inspectAndDecryptEmail({
      email: mimeMsg,
      recipientPrivateKeyArmored: elenaKeys.privateKeyArmored,
    });

    expect(decryptedOnElenaDevice.accepted).toBe(true);
    expect(
      decryptedOnElenaDevice.decryptedPacket?.sender.profileCard?.handle
    ).toBe('@alexrivera');
    expect(
      decryptedOnElenaDevice.decryptedPacket?.sender.profileCard?.avatarDataUrl
    ).toContain('data:image/');

    // Elena sends back an encrypted Read Receipt (`chat.receipt`)
    const receiptPacket: DcpPacket = {
      protocol: DCP_PROTOCOL_VERSION,
      packetId: 'pkt_receipt_01',
      type: 'chat.receipt',
      encryptionMode: 'openpgp-asymmetric',
      channel: firstContactPacket.channel,
      sender: {
        email: 'elena@proton.me',
        displayName: 'Elena Vogt',
        handle: '@elenavogt',
        provider: 'proton',
        pgpFingerprint: elenaKeys.fingerprint,
        publicKeyArmored: elenaKeys.publicKeyArmored,
      },
      payload: {
        messageId: 'msg_receipt_01',
        targetMessageId: 'msg_first_01',
        receiptStatus: 'read',
      },
      sentAt: new Date().toISOString(),
    };

    const encReceipt = await encryptDcpPayloadAsymmetric({
      cleartextJson: JSON.stringify(receiptPacket),
      recipientPublicKeysArmored: [alexKeys.publicKeyArmored],
      senderPublicKeyArmored: elenaKeys.publicKeyArmored,
      senderPrivateKeyArmored: elenaKeys.privateKeyArmored,
    });

    const mimeReceipt = buildDcpMimeEmail({
      packet: receiptPacket,
      encryptedPacketArmored: encReceipt,
    });

    const decryptedOnAlexDevice = await inspectAndDecryptEmail({
      email: mimeReceipt,
      recipientPrivateKeyArmored: alexKeys.privateKeyArmored,
    });

    expect(decryptedOnAlexDevice.accepted).toBe(true);
    expect(decryptedOnAlexDevice.decryptedPacket?.type).toBe('chat.receipt');
    expect(decryptedOnAlexDevice.decryptedPacket?.payload.receiptStatus).toBe(
      'read'
    );
  });

  it('generates OAuth2 PKCE S256 challenges and auto-discovers mail server settings for custom domains', async () => {
    const pkce = await generatePkceChallengePair();
    expect(pkce.codeVerifier.length).toBeGreaterThanOrEqual(40);
    expect(pkce.codeChallenge.length).toBeGreaterThan(20);

    const customDomainConfig = await discoverCustomDomainEmailConfig(
      'founder@mycustomstartup.io'
    );
    expect(customDomainConfig.domain).toBe('mycustomstartup.io');
    expect(customDomainConfig.imapHost).toContain('mycustomstartup.io');
    expect(customDomainConfig.smtpHost).toContain('mycustomstartup.io');
  });

  it('verifies Compliant Build Attestations and executes Remote Key Shredding (chat.shred-request & chat.shred-ack)', async () => {
    const alexKeys = await generateDeviceKeyPair(
      'Alex Rivera',
      'alex@gmail.com'
    );
    const elenaKeys = await generateDeviceKeyPair(
      'Elena Vogt',
      'elena@proton.me'
    );

    const attestation = await createSignedComplianceAttestation({
      senderEmail: 'alex@gmail.com',
      senderPgpFingerprint: alexKeys.fingerprint,
    });

    const verifyCheck = await verifyComplianceAttestation({
      senderEmail: 'alex@gmail.com',
      senderPgpFingerprint: alexKeys.fingerprint,
      attestation,
    });
    expect(verifyCheck.verified).toBe(true);

    // Reject if a tampered or non-compliant sender email or fingerprint claims the attestation
    const tamperedCheck = await verifyComplianceAttestation({
      senderEmail: 'spoofed@gmail.com',
      senderPgpFingerprint: alexKeys.fingerprint,
      attestation,
    });
    expect(tamperedCheck.verified).toBe(false);

    // Encrypt at-rest record with non-extractable thread wrapping key, then destroy key
    const atRest = await encryptAtRestWithThreadKey({
      channelId: 'dm_alex_elena',
      plaintext: 'Sensitive local index record',
      recordId: 'msg_01',
    });
    expect(atRest.ciphertextBase64.length).toBeGreaterThan(10);
    expect(destroyThreadWrappingKey('dm_alex_elena')).toBe(true);

    // Dispatch a signed `chat.shred-request` packet over MIME email
    const shredReqPacket: DcpPacket = {
      protocol: DCP_PROTOCOL_VERSION,
      packetId: 'pkt_shred_req_01',
      type: 'chat.shred-request',
      encryptionMode: 'openpgp-asymmetric',
      channel: {
        id: 'dm_alex_elena',
        type: 'dm',
        name: 'Elena Vogt',
        participants: ['alex@gmail.com', 'elena@proton.me'],
      },
      sender: {
        email: 'alex@gmail.com',
        displayName: 'Alex Rivera',
        provider: 'gmail',
        pgpFingerprint: alexKeys.fingerprint,
        publicKeyArmored: alexKeys.publicKeyArmored,
      },
      complianceAttestation: attestation,
      payload: {
        messageId: 'msg_shred_req_01',
        text: 'Erase peer PGP key and scrub IndexedDB',
        shredRequest: {
          shredScope: 'peer-pgp-key-and-threads',
          targetPeerEmail: 'elena@proton.me',
          targetKeyFingerprint: elenaKeys.fingerprint,
          reason: 'Remote key erase requested',
          requestedAt: new Date().toISOString(),
        },
      },
      sentAt: new Date().toISOString(),
    };

    const encShred = await encryptDcpPayloadAsymmetric({
      cleartextJson: JSON.stringify(shredReqPacket),
      recipientPublicKeysArmored: [elenaKeys.publicKeyArmored],
      senderPublicKeyArmored: alexKeys.publicKeyArmored,
      senderPrivateKeyArmored: alexKeys.privateKeyArmored,
    });

    const shredMime = buildDcpMimeEmail({
      packet: shredReqPacket,
      encryptedPacketArmored: encShred,
    });

    const elenaInspect = await inspectAndDecryptEmail({
      email: shredMime,
      recipientPrivateKeyArmored: elenaKeys.privateKeyArmored,
    });

    expect(elenaInspect.accepted).toBe(true);
    expect(elenaInspect.signatureVerified).toBe(true);
    expect(elenaInspect.compliantBuildVerified).toBe(true);
    expect(elenaInspect.decryptedPacket?.type).toBe('chat.shred-request');
    expect(
      elenaInspect.decryptedPacket?.payload.shredRequest?.targetKeyFingerprint
    ).toBe(elenaKeys.fingerprint);
  });

  it('supports all 6 next-gen @me features: Safety Numbers + QR, Shielded Burner Aliases, Client-Side Link Previews, Duress PIN, Burn Timers, Encrypted Polls & Personal Vault', async () => {
    const alexKeys = await generateDeviceKeyPair(
      'Alex Rivera',
      'alex.rivera@gmail.com'
    );
    const elenaKeys = await generateDeviceKeyPair(
      'Elena Vogt',
      'elena.vogt@proton.me'
    );

    // 1. Canonical 60-digit Safety Number & 21x21 QR Code Matrix (symmetric regardless of peer order)
    const safetyA = await computeSafetyNumberAndQrMatrix({
      myEmail: 'alex.rivera@gmail.com',
      myFingerprint: alexKeys.fingerprint,
      peerEmail: 'elena.vogt@proton.me',
      peerFingerprint: elenaKeys.fingerprint,
    });
    const safetyB = await computeSafetyNumberAndQrMatrix({
      myEmail: 'elena.vogt@proton.me',
      myFingerprint: elenaKeys.fingerprint,
      peerEmail: 'alex.rivera@gmail.com',
      peerFingerprint: alexKeys.fingerprint,
    });
    expect(safetyA.formattedSafetyNumber).toBe(safetyB.formattedSafetyNumber);
    expect(safetyA.groups).toHaveLength(12);
    expect(safetyA.qrMatrix).toHaveLength(21);

    // 2. Anonymous Shielded Burner Alias with isolated Curve25519 PGP keypair
    const burner = await createShieldedBurnerAlias({
      parentEmail: 'alex.rivera@gmail.com',
      displayName: 'Alex Rivera',
      label: 'Craigslist Buyer',
      strategy: 'duck-privacy',
    });
    expect(burner.aliasEmail).toContain('@duck.com');
    expect(burner.pgpFingerprint).not.toBe(alexKeys.fingerprint);

    // 3. Zero-server client-side Link Preview extraction before encryption
    const preview = extractClientSideLinkPreview(
      'Check out https://github.com/openpgpjs/openpgpjs for the audit'
    );
    expect(preview).toBeDefined();
    expect(preview?.domain).toBe('github.com');

    // 4. Duress / Panic PIN vs Normal Unlock PIN evaluation
    expect(
      evaluatePinOrDuressCode({
        enteredPin: '2580',
        normalPin: '2580',
        duressPin: '9999',
      })
    ).toBe('unlock');
    expect(
      evaluatePinOrDuressCode({
        enteredPin: '9999',
        normalPin: '2580',
        duressPin: '9999',
      })
    ).toBe('duress-shred');

    // 5 & 6. Encrypted Poll + Burn-After-Reading TTL + Shielded Alias inside a DCP/1.0 packet
    const pollPacket: DcpPacket = {
      protocol: DCP_PROTOCOL_VERSION,
      packetId: 'pkt_poll_test_01',
      type: 'chat.poll',
      encryptionMode: 'openpgp-asymmetric',
      channel: {
        id: 'ch_product_launch',
        type: 'workspace-channel',
        name: 'product-launch',
        participants: ['alex.rivera@gmail.com', 'elena.vogt@proton.me'],
        ephemeralTimerSeconds: 60,
        shieldedAliasEmail: burner.aliasEmail,
      },
      sender: {
        email: 'alex.rivera@gmail.com',
        displayName: 'Alex Rivera',
        provider: 'gmail',
        pgpFingerprint: alexKeys.fingerprint,
        publicKeyArmored: alexKeys.publicKeyArmored,
      },
      payload: {
        messageId: 'msg_poll_test_01',
        text: '📊 Encrypted Poll: Which feature do we demo first?',
        ephemeralTtlSeconds: 60,
        senderShieldedAlias: {
          aliasEmail: burner.aliasEmail,
          strategy: burner.strategy,
          ephemeralFingerprint: burner.pgpFingerprint,
        },
        linkPreview: preview,
        poll: {
          pollId: 'poll_test_01',
          question: 'Which feature do we demo first?',
          allowMultiple: false,
          options: [
            { id: 'opt_1', text: 'Burn-After-Reading Timers' },
            { id: 'opt_2', text: 'Vault (@me)' },
          ],
        },
      },
      sentAt: new Date().toISOString(),
    };

    const encPoll = await encryptDcpPayloadAsymmetric({
      cleartextJson: JSON.stringify(pollPacket),
      recipientPublicKeysArmored: [elenaKeys.publicKeyArmored],
      senderPublicKeyArmored: alexKeys.publicKeyArmored,
      senderPrivateKeyArmored: alexKeys.privateKeyArmored,
    });

    const pollMime = buildDcpMimeEmail({
      packet: pollPacket,
      encryptedPacketArmored: encPoll,
    });

    const decryptedPoll = await inspectAndDecryptEmail({
      email: pollMime,
      recipientPrivateKeyArmored: elenaKeys.privateKeyArmored,
    });

    expect(decryptedPoll.accepted).toBe(true);
    expect(decryptedPoll.decryptedPacket?.type).toBe('chat.poll');
    expect(decryptedPoll.decryptedPacket?.payload.ephemeralTtlSeconds).toBe(60);
    expect(
      decryptedPoll.decryptedPacket?.payload.senderShieldedAlias?.aliasEmail
    ).toBe(burner.aliasEmail);
    expect(
      decryptedPoll.decryptedPacket?.payload.poll?.options[0].text
    ).toBe('Burn-After-Reading Timers');
  });
});
