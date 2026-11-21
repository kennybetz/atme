/**
 * Automated Unit Tests for `@me/simple` (`ATME/1.0` Protocol Engine & OAuth Helpers):
 *   1. Strict Inbox Filter (`isDontCallFormattedEmail` + `inspectAndDecryptEmail`) ignores 100% of regular emails
 *   2. Fast-path Cleartext JSON (`application/vnd.atme.packet+json`, `atme-packet.json`) MIME building & parsing
 *   3. Bidirectional `ATME/1.0` Interoperability with Encrypted OpenPGP peers (`application/vnd.atme.packet+pgp`)
 *   4. First-Contact Ephemeral Invite Interoperability (`encryptDcpPayloadWithInviteKey`)
 *   5. Group Membership (`chat.member-update`), Profile Cards & Client-Side Link Previews
 *   6. Google OAuth Client ID Sanitization & Validation + PKCE + Custom Domain Discovery
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
  ATME_JSON_PACKET_TYPE,
  DCP_PROTOCOL_VERSION,
  DcpPacket,
  RawTransportEmail,
} from './protocol/types';
import { createSampleRegularEmails } from './store/seedEmails';
import { reconcileLocalEmailsWithRemoteMailbox } from './transport/emailConnectors';
import {
  discoverCustomDomainEmailConfig,
  generatePkceChallengePair,
  sanitizeGoogleClientId,
  validateGoogleClientId,
} from './transport/oauthPortal';
import { extractClientSideLinkPreview } from './utils/linkPreview';

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
    expect(mimeEmail.headers['X-ATME-Protocol']).toBe(DCP_PROTOCOL_VERSION);
    expect(mimeEmail.headers['X-DontCall-Protocol']).toBe(DCP_PROTOCOL_VERSION);
    expect(mimeEmail.rawMime).toContain('application/vnd.atme.packet+pgp');
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

  it('bundles the user Profile Card (avatar image, display name, @handle) in the first encrypted message', async () => {
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

  it('builds and parses cleartext-json ATME/1.0 MIME packets in <5ms without blocking on OpenPGP', async () => {
    const simplePacket: DcpPacket = {
      protocol: DCP_PROTOCOL_VERSION,
      packetId: 'pkt_simple_json_01',
      type: 'chat.message',
      encryptionMode: 'cleartext-json',
      channel: {
        id: 'ch_simple_squad',
        type: 'workspace-channel',
        name: 'simple-squad',
        participants: ['alex@gmail.com', 'sam@outlook.com'],
      },
      sender: {
        email: 'alex@gmail.com',
        displayName: 'Alex Rivera',
        handle: '@alex',
        provider: 'gmail',
      },
      payload: {
        messageId: 'msg_simple_01',
        text: 'Checkout https://github.com/openpgpjs/openpgpjs on our clean scaffold!',
        linkPreview: extractClientSideLinkPreview(
          'Checkout https://github.com/openpgpjs/openpgpjs on our clean scaffold!'
        ),
      },
      sentAt: new Date().toISOString(),
    };

    const mimeEmail = buildDcpMimeEmail({ packet: simplePacket });

    expect(mimeEmail.headers['X-ATME-Protocol']).toBe(DCP_PROTOCOL_VERSION);
    expect(mimeEmail.rawMime).toContain(ATME_JSON_PACKET_TYPE);
    expect(mimeEmail.rawMime).toContain('atme-packet.json');
    expect(mimeEmail.rawMime).not.toContain('-----BEGIN PGP MESSAGE-----');
    expect(isDontCallFormattedEmail(mimeEmail).valid).toBe(true);

    const inspected = await inspectAndDecryptEmail({ email: mimeEmail });

    expect(inspected.accepted).toBe(true);
    expect(inspected.encryptionMode).toBe('cleartext-json');
    expect(inspected.signatureVerified).toBe(false);
    expect(inspected.decryptionTimeMs).toBeLessThan(50);
    expect(inspected.decryptedPacket?.payload.text).toContain('clean scaffold!');
    expect(inspected.decryptedPacket?.payload.linkPreview?.domain).toBe(
      'github.com'
    );
  });

  it('maintains bidirectional interoperability between @me/simple (cleartext-json) and full OpenPGP @me peers', async () => {
    const elenaKeys = await generateDeviceKeyPair('Elena Vogt', 'elena@proton.me');

    // 1. @me/simple user sends cleartext-json packet
    const outboundSimple: DcpPacket = {
      protocol: DCP_PROTOCOL_VERSION,
      packetId: 'pkt_interop_out',
      type: 'chat.message',
      encryptionMode: 'cleartext-json',
      channel: {
        id: 'dm_interop',
        type: 'dm',
        name: 'Elena Vogt',
        participants: ['sam@outlook.com', 'elena@proton.me'],
      },
      sender: {
        email: 'sam@outlook.com',
        displayName: 'Sam Chen',
        provider: 'outlook',
      },
      payload: {
        messageId: 'msg_interop_out',
        text: 'Hey Elena from @me/simple!',
      },
      sentAt: new Date().toISOString(),
    };
    const outboundMime = buildDcpMimeEmail({ packet: outboundSimple });
    const parsedOutbound = await inspectAndDecryptEmail({ email: outboundMime });
    expect(parsedOutbound.accepted).toBe(true);
    expect(parsedOutbound.decryptedPacket?.payload.text).toBe(
      'Hey Elena from @me/simple!'
    );

    // 2. Encrypted @me peer replies with OpenPGP asymmetric MIME (and @me/simple background keys decrypt it)
    const samKeys = await generateDeviceKeyPair('Sam Chen', 'sam@outlook.com');
    const inboundEncrypted: DcpPacket = {
      protocol: DCP_PROTOCOL_VERSION,
      packetId: 'pkt_interop_in',
      type: 'chat.message',
      encryptionMode: 'openpgp-asymmetric',
      channel: outboundSimple.channel,
      sender: {
        email: 'elena@proton.me',
        displayName: 'Elena Vogt',
        provider: 'proton',
        pgpFingerprint: elenaKeys.fingerprint,
        publicKeyArmored: elenaKeys.publicKeyArmored,
      },
      payload: {
        messageId: 'msg_interop_in',
        text: 'Received loud and clear — encrypted reply from main branch!',
      },
      sentAt: new Date().toISOString(),
    };
    const encryptedArmored = await encryptDcpPayloadAsymmetric({
      cleartextJson: JSON.stringify(inboundEncrypted),
      recipientPublicKeysArmored: [samKeys.publicKeyArmored],
      senderPublicKeyArmored: elenaKeys.publicKeyArmored,
      senderPrivateKeyArmored: elenaKeys.privateKeyArmored,
    });
    const inboundMime = buildDcpMimeEmail({
      packet: inboundEncrypted,
      encryptedPacketArmored: encryptedArmored,
    });

    const parsedInbound = await inspectAndDecryptEmail({
      email: inboundMime,
      recipientPrivateKeyArmored: samKeys.privateKeyArmored,
    });
    expect(parsedInbound.accepted).toBe(true);
    expect(parsedInbound.encryptionMode).toBe('openpgp-asymmetric');
    expect(parsedInbound.signatureVerified).toBe(true);
    expect(parsedInbound.decryptedPacket?.payload.text).toContain(
      'encrypted reply from main branch!'
    );
  });

  it('sanitizes and validates Google Cloud Web Client IDs to prevent Error 401: invalid_client', () => {
    expect(
      sanitizeGoogleClientId(' "https://123456-abc.apps.googleusercontent.com/" ')
    ).toBe('123456-abc.apps.googleusercontent.com');

    expect(
      validateGoogleClientId('1234567890-abcdef123.apps.googleusercontent.com')
    ).toEqual({
      valid: true,
      sanitized: '1234567890-abcdef123.apps.googleusercontent.com',
    });

    // Reject client secret pasted by mistake
    const secretCheck = validateGoogleClientId('GOCSPX-mySecretValue123');
    expect(secretCheck.valid).toBe(false);
    expect(secretCheck.reason).toContain('Client Secret');

    // Reject email / invalid string without apps.googleusercontent.com suffix
    const badSuffix = validateGoogleClientId('KennyBetz@gmail.com');
    expect(badSuffix.valid).toBe(false);
    expect(badSuffix.reason).toContain('.apps.googleusercontent.com');

    // Reject documentation placeholder IDs
    const placeholder = validateGoogleClientId(
      '1234567890-abcdefg.apps.googleusercontent.com'
    );
    expect(placeholder.valid).toBe(false);
  });

  it('supports cross-branch interoperability via ATME/1.0 branchMod payloads', async () => {
    const alexKeys = await generateDeviceKeyPair('Alex', 'alex@gmail.com');
    const elenaKeys = await generateDeviceKeyPair('Elena', 'elena@proton.me');

    const modPacket: DcpPacket = {
      protocol: 'ATME/1.0',
      packetId: 'pkt_mod_arcade_01',
      type: 'chat.branch-mod',
      encryptionMode: 'openpgp-asymmetric',
      channel: {
        id: 'ch_arcade_squad',
        type: 'group',
        name: 'arcade-squad',
        participants: ['alex@gmail.com', 'elena@proton.me'],
      },
      sender: {
        email: 'alex@gmail.com',
        displayName: 'Alex',
        provider: 'gmail',
        pgpFingerprint: alexKeys.fingerprint,
        publicKeyArmored: alexKeys.publicKeyArmored,
      },
      payload: {
        messageId: 'msg_mod_arcade_01',
        text: '🕹️ Sent a Pixel Duel challenge!',
        branchMod: {
          branchId: '@me/arcade-squad',
          modId: 'pixel-duel',
          title: 'Pixel Duel 1v1',
          fallbackBody: '🕹️ Alex challenged you to Pixel Duel (Open in @me/arcade-squad)',
          data: { game: 'rps', wagerIou: 1, moveHash: 'a94f2c' },
        },
      },
      sentAt: new Date().toISOString(),
    };

    const encrypted = await encryptDcpPayloadAsymmetric({
      cleartextJson: JSON.stringify(modPacket),
      recipientPublicKeysArmored: [elenaKeys.publicKeyArmored],
      senderPublicKeyArmored: alexKeys.publicKeyArmored,
      senderPrivateKeyArmored: alexKeys.privateKeyArmored,
    });

    const mime = buildDcpMimeEmail({
      packet: modPacket,
      encryptedPacketArmored: encrypted,
    });

    expect(mime.headers['X-ATME-Protocol']).toBe('ATME/1.0');
    expect(mime.headers['X-ATME-Branch']).toBe('@me/arcade-squad');

    const decrypted = await inspectAndDecryptEmail({
      email: mime,
      recipientPrivateKeyArmored: elenaKeys.privateKeyArmored,
    });

    expect(decrypted.accepted).toBe(true);
    expect(decrypted.decryptedPacket?.payload.branchMod?.branchId).toBe(
      '@me/arcade-squad'
    );
    expect(decrypted.decryptedPacket?.payload.branchMod?.modId).toBe(
      'pixel-duel'
    );
  });

  it('pulls all remote ATME/1.0 emails on a new device and reconciles drifted/deleted records on existing devices', () => {
    const accountEmail = 'kenny@gmail.com';
    const makeSamplePacketMime = (packetId: string, text: string, idOverride?: string) => {
      const pkt: DcpPacket = {
        protocol: DCP_PROTOCOL_VERSION,
        packetId,
        type: 'chat.message',
        encryptionMode: 'cleartext-json',
        channel: {
          id: 'dm_kenny_sam',
          type: 'dm',
          name: 'Sam',
          participants: [accountEmail, 'sam@outlook.com'],
        },
        sender: {
          email: accountEmail,
          displayName: 'Kenny',
          provider: 'gmail',
        },
        payload: { messageId: `msg_${packetId}`, text },
        sentAt: '2026-11-21T03:00:00.000Z',
      };
      const built = buildDcpMimeEmail({ packet: pkt });
      return idOverride ? { ...built, id: idOverride } : built;
    };

    const remote1 = makeSamplePacketMime('pkt_sync_1', 'First cloud message', 'gmail_1');
    const remote2 = makeSamplePacketMime('pkt_sync_2', 'Second cloud message', 'gmail_2');
    const remote3 = makeSamplePacketMime('pkt_sync_3', 'New incoming message', 'gmail_3');

    // 1. Brand-new device with empty local storage pulls all 3 remote emails
    const newDeviceSync = reconcileLocalEmailsWithRemoteMailbox({
      localEmails: [],
      remoteEmails: [remote1, remote2, remote3],
      accountEmail,
    });
    expect(newDeviceSync.addedCount).toBe(3);
    expect(newDeviceSync.updatedCount).toBe(0);
    expect(newDeviceSync.removedCount).toBe(0);
    expect(newDeviceSync.reconciledEmails.map((e) => e.id)).toEqual([
      'gmail_1',
      'gmail_2',
      'gmail_3',
    ]);

    // 2. Existing device:
    // - seed_demo stays untouched
    // - remote1 matches identically
    // - pkt_sync_2 was saved with temporary optimistic local ID 'eml_pkt_sync_2' -> reconciles to 'gmail_2'
    // - gmail_stale_99 was deleted from Gmail -> pruned from local storage
    // - remote3 is brand-new -> added
    const seedOnly: RawTransportEmail = {
      ...makeSamplePacketMime('pkt_seed_only', 'Demo seed', 'seed_demo_1'),
      from: 'alex.rivera@gmail.com',
      to: ['sam.chen@outlook.com'],
    };
    const localDrifted2 = makeSamplePacketMime('pkt_sync_2', 'Second cloud message', 'eml_pkt_sync_2');
    const localDeletedStale = makeSamplePacketMime('pkt_deleted_99', 'Removed in Gmail', 'gmail_stale_99');

    const existingDeviceSync = reconcileLocalEmailsWithRemoteMailbox({
      localEmails: [seedOnly, remote1, localDrifted2, localDeletedStale],
      remoteEmails: [remote1, remote2, remote3],
      accountEmail,
    });

    expect(existingDeviceSync.verifiedMatchCount).toBe(1);
    expect(existingDeviceSync.updatedCount).toBe(1);
    expect(existingDeviceSync.removedCount).toBe(1);
    expect(existingDeviceSync.addedCount).toBe(1);

    const reconciledIds = existingDeviceSync.reconciledEmails.map((e) => e.id);
    expect(reconciledIds).toContain('seed_demo_1');
    expect(reconciledIds).toContain('gmail_1');
    expect(reconciledIds).toContain('gmail_2');
    expect(reconciledIds).toContain('gmail_3');
    expect(reconciledIds).not.toContain('eml_pkt_sync_2');
    expect(reconciledIds).not.toContain('gmail_stale_99');
  });
});
