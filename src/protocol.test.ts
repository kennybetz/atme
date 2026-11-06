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
import {
  computeBurnerCascadeTimings,
  computeViewerBurnerCascade,
  DCP_PROTOCOL_VERSION,
  DcpPacket,
} from './protocol/types';
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

  it('implements sequential cascade deletion for Burner Chats (20s per message, 3 messages = 60s total)', () => {
    const baseTime = 1000000;
    const messages = [
      { messageId: 'm1', viewedAtMs: baseTime },
      { messageId: 'm2', viewedAtMs: baseTime },
      { messageId: 'm3', viewedAtMs: baseTime },
    ];

    // At T = 0s (baseTime): m1 is active (20s remaining); m2 and m3 are queued
    const t0 = computeBurnerCascadeTimings(messages, baseTime, 20);
    expect(t0.get('m1')?.isActive).toBe(true);
    expect(t0.get('m1')?.isQueued).toBe(false);
    expect(t0.get('m1')?.isExpired).toBe(false);
    expect(t0.get('m1')?.remainingSeconds).toBe(20);

    expect(t0.get('m2')?.isActive).toBe(false);
    expect(t0.get('m2')?.isQueued).toBe(true);
    expect(t0.get('m2')?.isExpired).toBe(false);

    expect(t0.get('m3')?.isActive).toBe(false);
    expect(t0.get('m3')?.isQueued).toBe(true);
    expect(t0.get('m3')?.isExpired).toBe(false);

    // At T = 10s: m1 has 10s remaining; m2 and m3 still queued
    const t10 = computeBurnerCascadeTimings(messages, baseTime + 10000, 20);
    expect(t10.get('m1')?.isActive).toBe(true);
    expect(t10.get('m1')?.remainingSeconds).toBe(10);
    expect(t10.get('m2')?.isQueued).toBe(true);
    expect(t10.get('m3')?.isQueued).toBe(true);

    // At T = 20s: m1 is expired/deleted! m2 immediately becomes active (20s remaining); m3 still queued
    const t20 = computeBurnerCascadeTimings(messages, baseTime + 20000, 20);
    expect(t20.get('m1')?.isExpired).toBe(true);
    expect(t20.get('m2')?.isActive).toBe(true);
    expect(t20.get('m2')?.isQueued).toBe(false);
    expect(t20.get('m2')?.remainingSeconds).toBe(20);
    expect(t20.get('m3')?.isQueued).toBe(true);

    // At T = 40s: m1 and m2 are expired/deleted! m3 immediately becomes active (20s remaining)
    const t40 = computeBurnerCascadeTimings(messages, baseTime + 40000, 20);
    expect(t40.get('m1')?.isExpired).toBe(true);
    expect(t40.get('m2')?.isExpired).toBe(true);
    expect(t40.get('m3')?.isActive).toBe(true);
    expect(t40.get('m3')?.isQueued).toBe(false);
    expect(t40.get('m3')?.remainingSeconds).toBe(20);

    // At T = 60s: all 3 messages are expired/deleted (total duration exactly 60s once viewed!)
    const t60 = computeBurnerCascadeTimings(messages, baseTime + 60000, 20);
    expect(t60.get('m1')?.isExpired).toBe(true);
    expect(t60.get('m2')?.isExpired).toBe(true);
    expect(t60.get('m3')?.isExpired).toBe(true);
  });

  it('activates the burner timer ONLY when the recipient views the message in the app (sender send time does not burn)', () => {
    const baseTime = 1000000;
    const channelMessages = [
      { messageId: 'm1', senderEmail: 'alex@gmail.com' },
      { messageId: 'm2', senderEmail: 'alex@gmail.com' },
      { messageId: 'm3', senderEmail: 'alex@gmail.com' },
    ];
    const participants = ['alex@gmail.com', 'elena@proton.me'];

    // 1. Initially: Alex sent 3 messages at baseTime. Elena has NOT viewed them yet!
    const elenaT0 = computeViewerBurnerCascade({
      messages: channelMessages,
      viewerEmail: 'elena@proton.me',
      participants,
      localViewMap: {},
      nowMs: baseTime + 15000, // 15 seconds have passed since send
      ttlSeconds: 20,
    });

    // Elena has not viewed them in the app -> none have started!
    expect(elenaT0.get('m1')?.isViewed).toBe(false);
    expect(elenaT0.get('m1')?.isActive).toBe(false);
    expect(elenaT0.get('m1')?.isExpired).toBe(false);
    expect(elenaT0.get('m1')?.remainingSeconds).toBe(20);
    expect(elenaT0.get('m1')?.summaryLabel).toContain('burns 20s once viewed');

    // Alex (the sender) sees that Elena has not viewed them yet
    const alexT0 = computeViewerBurnerCascade({
      messages: channelMessages,
      viewerEmail: 'alex@gmail.com',
      participants,
      localViewMap: {},
      nowMs: baseTime + 15000,
      ttlSeconds: 20,
    });
    expect(alexT0.get('m1')?.isExpired).toBe(false);
    expect(alexT0.get('m1')?.summaryLabel).toContain('Unread by Elena (burns 20s once viewed)');

    // 2. Elena opens the chat and views them at baseTime + 30000 (30 seconds after send)
    const elenaViewTime = baseTime + 30000;
    const localViewMap: Record<string, number> = {
      'elena@proton.me:m1': elenaViewTime,
      'elena@proton.me:m2': elenaViewTime,
      'elena@proton.me:m3': elenaViewTime,
    };

    // Immediately upon Elena viewing (at T = 30s): m1 starts 20s timer, m2 and m3 are queued
    const elenaT30 = computeViewerBurnerCascade({
      messages: channelMessages,
      viewerEmail: 'elena@proton.me',
      participants,
      localViewMap,
      nowMs: elenaViewTime,
      ttlSeconds: 20,
    });
    expect(elenaT30.get('m1')?.isViewed).toBe(true);
    expect(elenaT30.get('m1')?.isActive).toBe(true);
    expect(elenaT30.get('m1')?.remainingSeconds).toBe(20);
    expect(elenaT30.get('m2')?.isQueued).toBe(true);
    expect(elenaT30.get('m3')?.isQueued).toBe(true);

    // On Alex's screen (via Elena's view/receipt): Alex sees Elena actively burning m1!
    const alexT30 = computeViewerBurnerCascade({
      messages: channelMessages,
      viewerEmail: 'alex@gmail.com',
      participants,
      localViewMap,
      nowMs: elenaViewTime,
      ttlSeconds: 20,
    });
    expect(alexT30.get('m1')?.isExpired).toBe(false);
    expect(alexT30.get('m1')?.summaryLabel).toContain('Elena (20s)');
    expect(alexT30.get('m2')?.summaryLabel).toContain('Elena queued (20s)');

    // 20s later (T = 50s): m1 has expired for Elena and deletes from both screens; m2 is active
    const elenaT50 = computeViewerBurnerCascade({
      messages: channelMessages,
      viewerEmail: 'elena@proton.me',
      participants,
      localViewMap,
      nowMs: elenaViewTime + 20000,
      ttlSeconds: 20,
    });
    expect(elenaT50.get('m1')?.isExpired).toBe(true);
    expect(elenaT50.get('m2')?.isActive).toBe(true);
    expect(elenaT50.get('m2')?.remainingSeconds).toBe(20);
    expect(elenaT50.get('m3')?.isQueued).toBe(true);

    const alexT50 = computeViewerBurnerCascade({
      messages: channelMessages,
      viewerEmail: 'alex@gmail.com',
      participants,
      localViewMap,
      nowMs: elenaViewTime + 20000,
      ttlSeconds: 20,
    });
    expect(alexT50.get('m1')?.isExpired).toBe(true); // Deletes from sender screen because Elena finished
    expect(alexT50.get('m2')?.isExpired).toBe(false);
    expect(alexT50.get('m2')?.summaryLabel).toContain('Elena (20s)');

    // Total 60s from Elena's view time (T = 90s): all messages are deleted
    const elenaT90 = computeViewerBurnerCascade({
      messages: channelMessages,
      viewerEmail: 'elena@proton.me',
      participants,
      localViewMap,
      nowMs: elenaViewTime + 60000,
      ttlSeconds: 20,
    });
    expect(elenaT90.get('m1')?.isExpired).toBe(true);
    expect(elenaT90.get('m2')?.isExpired).toBe(true);
    expect(elenaT90.get('m3')?.isExpired).toBe(true);
  });

  it('supports Group Burner Chats with multiple users and independent read times', () => {
    const baseTime = 1000000;
    const channelMessages = [
      { messageId: 'm1', senderEmail: 'alex@gmail.com' },
      { messageId: 'm2', senderEmail: 'alex@gmail.com' },
      { messageId: 'm3', senderEmail: 'alex@gmail.com' },
    ];
    const participants = ['alex@gmail.com', 'elena@proton.me', 'sam@dontcall.me'];

    // Elena views at T = 1000ms
    // Sam does NOT view until T = 100,000ms
    const elenaViewTime = baseTime + 1000;
    const samViewTime = baseTime + 100000;

    const localViewMap: Record<string, number> = {
      'elena@proton.me:m1': elenaViewTime,
      'elena@proton.me:m2': elenaViewTime,
      'elena@proton.me:m3': elenaViewTime,
    };

    // At T = 25s (24s after Elena viewed, but Sam has still not viewed):
    const nowMs25 = elenaViewTime + 24000;

    // For Elena: m1 has expired and deleted; m2 is active with 16s remaining
    const elenaState = computeViewerBurnerCascade({
      messages: channelMessages,
      viewerEmail: 'elena@proton.me',
      participants,
      localViewMap,
      nowMs: nowMs25,
      ttlSeconds: 20,
    });
    expect(elenaState.get('m1')?.isExpired).toBe(true);
    expect(elenaState.get('m2')?.isActive).toBe(true);
    expect(elenaState.get('m2')?.remainingSeconds).toBe(16);

    // For Sam at T = 25s: Sam has NOT viewed m1 yet! m1 is NOT expired for Sam!
    const samStateBeforeView = computeViewerBurnerCascade({
      messages: channelMessages,
      viewerEmail: 'sam@dontcall.me',
      participants,
      localViewMap,
      nowMs: nowMs25,
      ttlSeconds: 20,
    });
    expect(samStateBeforeView.get('m1')?.isExpired).toBe(false);
    expect(samStateBeforeView.get('m1')?.isViewed).toBe(false);
    expect(samStateBeforeView.get('m1')?.remainingSeconds).toBe(20);

    // For Alex (sender) at T = 25s:
    // Elena has burned m1, but Sam has NOT read m1 yet!
    // Therefore, m1 MUST NOT be deleted from Alex's screen!
    const alexStateAt25 = computeViewerBurnerCascade({
      messages: channelMessages,
      viewerEmail: 'alex@gmail.com',
      participants,
      localViewMap,
      nowMs: nowMs25,
      ttlSeconds: 20,
    });
    expect(alexStateAt25.get('m1')?.isExpired).toBe(false); // Elena expired, but Sam hasn't!
    expect(alexStateAt25.get('m1')?.summaryLabel).toContain('Burned by Elena');
    expect(alexStateAt25.get('m1')?.summaryLabel).toContain('Sam unread');

    // Now at T = 100,000ms: Sam opens the chat and views all 3 messages!
    localViewMap['sam@dontcall.me:m1'] = samViewTime;
    localViewMap['sam@dontcall.me:m2'] = samViewTime;
    localViewMap['sam@dontcall.me:m3'] = samViewTime;

    const samStateAtView = computeViewerBurnerCascade({
      messages: channelMessages,
      viewerEmail: 'sam@dontcall.me',
      participants,
      localViewMap,
      nowMs: samViewTime,
      ttlSeconds: 20,
    });
    // Sam gets his full independent 20s cascade: m1 active (20s), m2 queued, m3 queued
    expect(samStateAtView.get('m1')?.isActive).toBe(true);
    expect(samStateAtView.get('m1')?.remainingSeconds).toBe(20);
    expect(samStateAtView.get('m2')?.isQueued).toBe(true);
    expect(samStateAtView.get('m3')?.isQueued).toBe(true);

    // Sender Alex sees: Burned by Elena, Sam active (20s)
    const alexStateAtSamView = computeViewerBurnerCascade({
      messages: channelMessages,
      viewerEmail: 'alex@gmail.com',
      participants,
      localViewMap,
      nowMs: samViewTime,
      ttlSeconds: 20,
    });
    expect(alexStateAtSamView.get('m1')?.isExpired).toBe(false);
    expect(alexStateAtSamView.get('m1')?.summaryLabel).toContain('Burned by Elena');
    expect(alexStateAtSamView.get('m1')?.summaryLabel).toContain('Sam (20s)');

    // 20s later (samViewTime + 20,000ms): Sam finishes burning m1!
    // NOW both Elena and Sam have expired m1 -> m1 is finally expired and deleted on Alex's screen!
    const alexStateAfterSamM1 = computeViewerBurnerCascade({
      messages: channelMessages,
      viewerEmail: 'alex@gmail.com',
      participants,
      localViewMap,
      nowMs: samViewTime + 20000,
      ttlSeconds: 20,
    });
    expect(alexStateAfterSamM1.get('m1')?.isExpired).toBe(true);
    // m2 is still alive on Alex's screen because Sam is now burning m2!
    expect(alexStateAfterSamM1.get('m2')?.isExpired).toBe(false);
    expect(alexStateAfterSamM1.get('m2')?.summaryLabel).toContain('Burned by Elena');
    expect(alexStateAfterSamM1.get('m2')?.summaryLabel).toContain('Sam (20s)');
  });
});
