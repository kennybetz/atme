/**
 * Initial Seed Data, User Profiles (Avatar, Name, Handle), Channels, DMs, & Sample Regular Emails
 */

import { DcpChannelMeta, RawTransportEmail, UserIdentity } from '../protocol/types';

function makeSvgAvatarDataUrl(initials: string, bgStart: string, bgEnd: string): string {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96">
    <defs>
      <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="${bgStart}"/>
        <stop offset="100%" stop-color="${bgEnd}"/>
      </linearGradient>
    </defs>
    <rect width="96" height="96" rx="48" fill="url(#g)"/>
    <text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="36" font-weight="700">${initials}</text>
  </svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

export const INITIAL_USERS: UserIdentity[] = [
  {
    email: 'alex.rivera@gmail.com',
    displayName: 'Alex Rivera',
    handle: '@alexrivera',
    avatarDataUrl: makeSvgAvatarDataUrl('AR', '#0a84ff', '#5e5ce6'),
    bio: 'Building zero-server E2EE messaging over email',
    profileUpdatedAt: '2026-10-25T03:00:00.000Z',
    provider: 'gmail',
    hasAppInstalled: true,
  },
  {
    email: 'sam.chen@outlook.com',
    displayName: 'Sam Chen',
    handle: '@samchen',
    avatarDataUrl: makeSvgAvatarDataUrl('SC', '#30d158', '#0a84ff'),
    bio: 'Security & Distributed Systems',
    profileUpdatedAt: '2026-10-25T03:05:00.000Z',
    provider: 'outlook',
    hasAppInstalled: true,
  },
  {
    email: 'elena.vogt@proton.me',
    displayName: 'Elena Vogt (Proton)',
    handle: '@elenavogt',
    avatarDataUrl: makeSvgAvatarDataUrl('EV', '#6d4aff', '#c084fc'),
    bio: 'Cryptography Researcher • Proton Mail PGP',
    profileUpdatedAt: '2026-10-25T03:10:00.000Z',
    provider: 'proton',
    hasAppInstalled: true,
  },
  {
    email: 'jordan.taylor@yahoo.com',
    displayName: 'Jordan Taylor (No App Yet)',
    handle: '@jordantaylor',
    provider: 'yahoo',
    hasAppInstalled: false,
  },
];

export const INITIAL_CHANNELS: DcpChannelMeta[] = [
  {
    id: 'ch_product_launch',
    type: 'workspace-channel',
    name: 'product-launch',
    participants: [
      'alex.rivera@gmail.com',
      'sam.chen@outlook.com',
      'elena.vogt@proton.me',
    ],
  },
  {
    id: 'ch_security_ops',
    type: 'workspace-channel',
    name: 'security-ops',
    participants: [
      'alex.rivera@gmail.com',
      'elena.vogt@proton.me',
    ],
  },
  {
    id: 'dm_alex_elena',
    type: 'dm',
    name: 'Elena Vogt (Proton)',
    participants: ['alex.rivera@gmail.com', 'elena.vogt@proton.me'],
  },
  {
    id: 'dm_alex_sam',
    type: 'dm',
    name: 'Sam Chen',
    participants: ['alex.rivera@gmail.com', 'sam.chen@outlook.com'],
  },
  {
    id: 'dm_alex_jordan',
    type: 'dm',
    name: 'Jordan Taylor',
    participants: ['alex.rivera@gmail.com', 'jordan.taylor@yahoo.com'],
  },
  {
    id: 'vault_alex.rivera@gmail.com',
    type: 'vault',
    name: 'Vault (@me)',
    participants: ['alex.rivera@gmail.com'],
  },
  {
    id: 'vault_sam.chen@outlook.com',
    type: 'vault',
    name: 'Vault (@me)',
    participants: ['sam.chen@outlook.com'],
  },
  {
    id: 'vault_elena.vogt@proton.me',
    type: 'vault',
    name: 'Vault (@me)',
    participants: ['elena.vogt@proton.me'],
  },
];

/**
 * Sample regular emails sitting in the user's Gmail/Outlook/Yahoo inbox.
 * The @me Strict Filter Engine must reject and ignore 100% of these.
 */
export function createSampleRegularEmails(): RawTransportEmail[] {
  return [
    {
      id: 'reg_eml_101',
      from: '"Stripe Billing" <receipts@stripe.com>',
      to: ['alex.rivera@gmail.com', 'sam.chen@outlook.com'],
      subject: 'Your invoice #INV-2026-8841 has been paid ($49.00)',
      date: new Date(Date.now() - 1000 * 60 * 48).toISOString(),
      headers: {
        'MIME-Version': '1.0',
        From: '"Stripe Billing" <receipts@stripe.com>',
        To: 'alex.rivera@gmail.com',
        Subject: 'Your invoice #INV-2026-8841 has been paid ($49.00)',
        'Content-Type': 'text/html; charset="utf-8"',
      },
      rawMime: [
        'MIME-Version: 1.0',
        'From: "Stripe Billing" <receipts@stripe.com>',
        'To: alex.rivera@gmail.com',
        'Subject: Your invoice #INV-2026-8841 has been paid ($49.00)',
        'Content-Type: text/plain; charset="utf-8"',
        '',
        'Thank you for your payment of $49.00. This is a normal billing email and should be ignored by @me.',
      ].join('\r\n'),
      textFallbackPart:
        'Thank you for your payment of $49.00. This is a normal billing email.',
    },
    {
      id: 'reg_eml_102',
      from: '"GitHub Notifications" <notifications@github.com>',
      to: ['alex.rivera@gmail.com', 'elena.vogt@proton.me'],
      subject: '[PR #412] Bump openpgp from 6.0.1 to 6.1.1',
      date: new Date(Date.now() - 1000 * 60 * 22).toISOString(),
      headers: {
        'MIME-Version': '1.0',
        From: '"GitHub Notifications" <notifications@github.com>',
        To: 'alex.rivera@gmail.com',
        Subject: '[PR #412] Bump openpgp from 6.0.1 to 6.1.1',
        'X-GitHub-Reason': 'review_requested',
      },
      rawMime: [
        'MIME-Version: 1.0',
        'From: "GitHub Notifications" <notifications@github.com>',
        'To: alex.rivera@gmail.com',
        'Subject: [PR #412] Bump openpgp from 6.0.1 to 6.1.1',
        'X-GitHub-Reason: review_requested',
        'Content-Type: text/plain; charset="utf-8"',
        '',
        '@dependabot requested your review on PR #412.',
      ].join('\r\n'),
      textFallbackPart: '@dependabot requested your review on PR #412.',
    },
    {
      id: 'reg_eml_103',
      from: '"Delta Air Lines" <boarding@delta.com>',
      to: ['jordan.taylor@yahoo.com', 'alex.rivera@gmail.com'],
      subject: 'Time to Check In for Flight DL1482 to San Francisco',
      date: new Date(Date.now() - 1000 * 60 * 9).toISOString(),
      headers: {
        'MIME-Version': '1.0',
        From: '"Delta Air Lines" <boarding@delta.com>',
        To: 'jordan.taylor@yahoo.com',
        Subject: 'Time to Check In for Flight DL1482 to San Francisco',
      },
      rawMime: [
        'MIME-Version: 1.0',
        'From: "Delta Air Lines" <boarding@delta.com>',
        'To: jordan.taylor@yahoo.com',
        'Subject: Time to Check In for Flight DL1482 to San Francisco',
        'Content-Type: text/plain; charset="utf-8"',
        '',
        'Your flight departs in 24 hours. Confirmation #H8K9LP.',
      ].join('\r\n'),
      textFallbackPart: 'Your flight departs in 24 hours. Confirmation #H8K9LP.',
    },
  ];
}

/**
 * Synchronous initial inspection previews so the first paint (before async WebWorker/OpenPGP
 * key generation finishes ~350ms later) renders the full conversation threads and messages immediately.
 */
export function createInitialSeedInspections(): import('../protocol/types').FilterInspectionResult[] {
  const alex = INITIAL_USERS[0];
  const sam = INITIAL_USERS[1];
  const elena = INITIAL_USERS[2];
  const now = Date.now();

  const makeAttest = (iso: string): import('../protocol/types').DcpComplianceAttestation => ({
    buildVersion: '1.4.0-compliant',
    bundleSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    signatureSuite: 'Ed25519',
    publicKeyBase64: 'MCowBQYDK2VwAyEA',
    signatureBase64: 'verified-seed-sig',
    zeroPlaintextIdbEnforced: true,
    remoteShredEnforced: true,
    attestedAt: iso,
  });

  const pkt1: import('../protocol/types').DcpPacket = {
    protocol: 'DCP/1.0',
    packetId: 'pkt_seed_01',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: INITIAL_CHANNELS[0],
    sender: {
      email: alex.email,
      displayName: alex.displayName,
      handle: alex.handle,
      provider: alex.provider,
      pgpFingerprint: '9F4A7C21D8E34B109F4A7C21D8E34B109F4A7C21',
      publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----',
      profileCard: {
        displayName: alex.displayName,
        handle: alex.handle || '@alexrivera',
        avatarDataUrl: alex.avatarDataUrl,
        bio: alex.bio,
        updatedAt: alex.profileUpdatedAt || new Date().toISOString(),
      },
    },
    complianceAttestation: makeAttest(new Date(now - 1000 * 60 * 42).toISOString()),
    payload: {
      messageId: 'msg_seed_01',
      text: 'Welcome to @me! My first message in this thread automatically carries my encrypted Profile Card (avatar + @alexrivera handle) so your devices store it in local IndexedDB.',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 42).toISOString(),
  };

  const pkt2: import('../protocol/types').DcpPacket = {
    protocol: 'DCP/1.0',
    packetId: 'pkt_seed_02',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: INITIAL_CHANNELS[0],
    sender: {
      email: elena.email,
      displayName: elena.displayName,
      handle: elena.handle,
      provider: elena.provider,
      pgpFingerprint: '3B8E1A50C7D29F443B8E1A50C7D29F443B8E1A50',
      publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----',
      profileCard: {
        displayName: elena.displayName,
        handle: elena.handle || '@elenavogt',
        avatarDataUrl: elena.avatarDataUrl,
        bio: elena.bio,
        updatedAt: elena.profileUpdatedAt || new Date().toISOString(),
      },
    },
    complianceAttestation: makeAttest(new Date(now - 1000 * 60 * 30).toISOString()),
    payload: {
      messageId: 'msg_seed_02',
      text: 'Connected from my Proton Mail account! Your avatar and @alexrivera handle synced into my local DB automatically.',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 30).toISOString(),
  };

  const pktReceipt: import('../protocol/types').DcpPacket = {
    protocol: 'DCP/1.0',
    packetId: 'pkt_seed_rcpt_01',
    type: 'chat.receipt',
    encryptionMode: 'openpgp-asymmetric',
    channel: INITIAL_CHANNELS[0],
    sender: {
      email: elena.email,
      displayName: elena.displayName,
      handle: elena.handle,
      provider: elena.provider,
      pgpFingerprint: '3B8E1A50C7D29F443B8E1A50C7D29F443B8E1A50',
      publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----',
    },
    payload: {
      messageId: 'msg_seed_rcpt_01',
      targetMessageId: 'msg_seed_01',
      receiptStatus: 'read',
      text: 'Read msg_seed_01',
    },
    sentAt: new Date(now - 1000 * 60 * 28).toISOString(),
  };

  const pktReaction: import('../protocol/types').DcpPacket = {
    protocol: 'DCP/1.0',
    packetId: 'pkt_seed_react_01',
    type: 'chat.reaction',
    encryptionMode: 'openpgp-asymmetric',
    channel: INITIAL_CHANNELS[0],
    sender: {
      email: sam.email,
      displayName: sam.displayName,
      handle: sam.handle,
      provider: sam.provider,
      pgpFingerprint: '7C1D4F92A6B83E117C1D4F92A6B83E117C1D4F92',
      publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----',
    },
    payload: {
      messageId: 'msg_seed_react_01',
      targetMessageId: 'msg_seed_02',
      reactionEmoji: '🔒',
      text: 'Reacted 🔒',
    },
    sentAt: new Date(now - 1000 * 60 * 26).toISOString(),
  };

  const pktReply: import('../protocol/types').DcpPacket = {
    protocol: 'DCP/1.0',
    packetId: 'pkt_seed_reply_01',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: INITIAL_CHANNELS[0],
    sender: {
      email: sam.email,
      displayName: sam.displayName,
      handle: sam.handle,
      provider: sam.provider,
      pgpFingerprint: '7C1D4F92A6B83E117C1D4F92A6B83E117C1D4F92',
      publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----',
      profileCard: {
        displayName: sam.displayName,
        handle: sam.handle || '@samchen',
        avatarDataUrl: sam.avatarDataUrl,
        bio: sam.bio,
        updatedAt: sam.profileUpdatedAt || new Date().toISOString(),
      },
    },
    complianceAttestation: makeAttest(new Date(now - 1000 * 60 * 20).toISOString()),
    payload: {
      messageId: 'msg_seed_reply_01',
      replyToMessageId: 'msg_seed_01',
      text: 'Replying inline from Outlook — and I can see the Read Receipt on your message!',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 20).toISOString(),
  };

  const pktInvite: import('../protocol/types').DcpPacket = {
    protocol: 'DCP/1.0',
    packetId: 'pkt_seed_invite_03',
    type: 'chat.message',
    encryptionMode: 'openpgp-invite-key',
    channel: INITIAL_CHANNELS[4],
    sender: {
      email: alex.email,
      displayName: alex.displayName,
      handle: alex.handle,
      provider: alex.provider,
      pgpFingerprint: '9F4A7C21D8E34B109F4A7C21D8E34B109F4A7C21',
      publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----',
    },
    payload: {
      messageId: 'msg_seed_03',
      text: 'Hey Jordan! Since you do not have the app yet, your Yahoo email shows an App Store download card. Once you install @me, this message and my profile card decrypt automatically!',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 5).toISOString(),
  };

  const pktDmElena: import('../protocol/types').DcpPacket = {
    protocol: 'DCP/1.0',
    packetId: 'pkt_seed_dm_elena_01',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: INITIAL_CHANNELS[2],
    sender: {
      email: elena.email,
      displayName: elena.displayName,
      handle: elena.handle,
      provider: elena.provider,
      pgpFingerprint: '3B8E1A50C7D29F443B8E1A50C7D29F443B8E1A50',
      publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----',
      profileCard: {
        displayName: elena.displayName,
        handle: elena.handle || '@elenavogt',
        avatarDataUrl: elena.avatarDataUrl,
        bio: elena.bio,
        updatedAt: elena.profileUpdatedAt || new Date().toISOString(),
      },
    },
    complianceAttestation: makeAttest(new Date(now - 1000 * 60 * 3).toISOString()),
    payload: {
      messageId: 'msg_seed_dm_elena_01',
      text: 'Hey Alex! Just @me from your Gmail — it arrives encrypted in my Proton inbox and renders right here like iMessage.',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 3).toISOString(),
  };

  const pktDmAlexReply: import('../protocol/types').DcpPacket = {
    protocol: 'DCP/1.0',
    packetId: 'pkt_seed_dm_alex_02',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: INITIAL_CHANNELS[2],
    sender: {
      email: alex.email,
      displayName: alex.displayName,
      handle: alex.handle,
      provider: alex.provider,
      pgpFingerprint: '9F4A7C21D8E34B109F4A7C21D8E34B109F4A7C21',
      publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----',
    },
    complianceAttestation: makeAttest(new Date(now - 1000 * 60 * 1).toISOString()),
    payload: {
      messageId: 'msg_seed_dm_alex_02',
      replyToMessageId: 'msg_seed_dm_elena_01',
      text: 'Zero central servers, compliant build verified, and we can shred keys anytime.',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 1).toISOString(),
  };

  const pktDmElenaReact: import('../protocol/types').DcpPacket = {
    protocol: 'DCP/1.0',
    packetId: 'pkt_seed_dm_elena_react_03',
    type: 'chat.reaction',
    encryptionMode: 'openpgp-asymmetric',
    channel: INITIAL_CHANNELS[2],
    sender: {
      email: elena.email,
      displayName: elena.displayName,
      handle: elena.handle,
      provider: elena.provider,
      pgpFingerprint: '3B8E1A50C7D29F443B8E1A50C7D29F443B8E1A50',
      publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----',
    },
    payload: {
      messageId: 'msg_seed_dm_elena_react_03',
      targetMessageId: 'msg_seed_dm_alex_02',
      reactionEmoji: '🔥',
      text: 'Reacted 🔥',
    },
    sentAt: new Date(now - 1000 * 40).toISOString(),
  };

  const pktDmElenaRead: import('../protocol/types').DcpPacket = {
    protocol: 'DCP/1.0',
    packetId: 'pkt_seed_dm_elena_rcpt_04',
    type: 'chat.receipt',
    encryptionMode: 'openpgp-asymmetric',
    channel: INITIAL_CHANNELS[2],
    sender: {
      email: elena.email,
      displayName: elena.displayName,
      handle: elena.handle,
      provider: elena.provider,
      pgpFingerprint: '3B8E1A50C7D29F443B8E1A50C7D29F443B8E1A50',
      publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----',
    },
    payload: {
      messageId: 'msg_seed_dm_elena_rcpt_04',
      targetMessageId: 'msg_seed_dm_alex_02',
      receiptStatus: 'read',
      text: 'Read msg_seed_dm_alex_02',
    },
    sentAt: new Date(now - 1000 * 30).toISOString(),
  };

  // Seed Poll in #product-launch
  const pktPoll: import('../protocol/types').DcpPacket = {
    protocol: 'DCP/1.0',
    packetId: 'pkt_seed_poll_01',
    type: 'chat.poll',
    encryptionMode: 'openpgp-asymmetric',
    channel: INITIAL_CHANNELS[0],
    sender: {
      email: elena.email,
      displayName: elena.displayName,
      handle: elena.handle,
      provider: elena.provider,
      pgpFingerprint: '3B8E1A50C7D29F443B8E1A50C7D29F443B8E1A50',
      publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----',
    },
    complianceAttestation: makeAttest(new Date(now - 1000 * 60 * 14).toISOString()),
    payload: {
      messageId: 'msg_seed_poll_01',
      text: '📊 Poll: Which zero-server feature should we highlight first in the @me release?',
      poll: {
        pollId: 'poll_release_01',
        question: 'Which zero-server feature should we highlight first in the @me release?',
        options: [
          { id: 'opt_shred', text: '🔥 Remote Key Shredding + Burn Timers' },
          { id: 'opt_vault', text: '🔐 Personal Encrypted Vault (@me)' },
          { id: 'opt_alias', text: '🎭 Shielded Burner Email Aliases' },
        ],
      },
    },
    sentAt: new Date(now - 1000 * 60 * 14).toISOString(),
  };

  const pktPollVote1: import('../protocol/types').DcpPacket = {
    protocol: 'DCP/1.0',
    packetId: 'pkt_seed_poll_vote_01',
    type: 'chat.poll-vote',
    encryptionMode: 'openpgp-asymmetric',
    channel: INITIAL_CHANNELS[0],
    sender: {
      email: alex.email,
      displayName: alex.displayName,
      handle: alex.handle,
      provider: alex.provider,
      pgpFingerprint: '9F4A7C21D8E34B109F4A7C21D8E34B109F4A7C21',
      publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----',
    },
    payload: {
      messageId: 'msg_seed_poll_vote_01',
      targetMessageId: 'msg_seed_poll_01',
      pollVote: {
        pollId: 'poll_release_01',
        optionId: 'opt_shred',
      },
      text: 'Voted for 🔥 Remote Key Shredding + Burn Timers',
    },
    sentAt: new Date(now - 1000 * 60 * 13).toISOString(),
  };

  const pktPollVote2: import('../protocol/types').DcpPacket = {
    protocol: 'DCP/1.0',
    packetId: 'pkt_seed_poll_vote_02',
    type: 'chat.poll-vote',
    encryptionMode: 'openpgp-asymmetric',
    channel: INITIAL_CHANNELS[0],
    sender: {
      email: sam.email,
      displayName: sam.displayName,
      handle: sam.handle,
      provider: sam.provider,
      pgpFingerprint: '7C1D4F92A6B83E117C1D4F92A6B83E117C1D4F92',
      publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----',
    },
    payload: {
      messageId: 'msg_seed_poll_vote_02',
      targetMessageId: 'msg_seed_poll_01',
      pollVote: {
        pollId: 'poll_release_01',
        optionId: 'opt_vault',
      },
      text: 'Voted for 🔐 Personal Encrypted Vault (@me)',
    },
    sentAt: new Date(now - 1000 * 60 * 12).toISOString(),
  };

  // Seed Personal Encrypted Vault item for Alex
  const pktVault1: import('../protocol/types').DcpPacket = {
    protocol: 'DCP/1.0',
    packetId: 'pkt_seed_vault_01',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: INITIAL_CHANNELS[5],
    sender: {
      email: alex.email,
      displayName: alex.displayName,
      handle: alex.handle,
      provider: alex.provider,
      pgpFingerprint: '9F4A7C21D8E34B109F4A7C21D8E34B109F4A7C21',
      publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----',
    },
    complianceAttestation: makeAttest(new Date(now - 1000 * 60 * 15).toISOString()),
    payload: {
      messageId: 'msg_seed_vault_01',
      vaultCategory: 'credential',
      text: 'Production SSH Signing Key Backup & Recovery Seed • Stored E2EE in my Gmail [@me] Vault: https://github.com/openpgpjs/openpgpjs',
      linkPreview: {
        url: 'https://github.com/openpgpjs/openpgpjs',
        domain: 'github.com',
        siteName: 'GitHub',
        title: 'Repository • openpgpjs › openpgpjs',
        description: 'Client-side generated preview • Zero server tracking or link unfurling ping.',
        themeColor: '#238636',
      },
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 15).toISOString(),
  };

  const seedPackets = [
    pkt1,
    pkt2,
    pktReceipt,
    pktReaction,
    pktReply,
    pktPoll,
    pktPollVote1,
    pktPollVote2,
    pktInvite,
    pktVault1,
    pktDmElena,
    pktDmAlexReply,
    pktDmElenaReact,
    pktDmElenaRead,
  ];

  const accepted: import('../protocol/types').FilterInspectionResult[] = seedPackets.map(
    (pkt) => ({
      emailId: `eml_${pkt.packetId}`,
      subject: `[@me] Encrypted packet (${pkt.channel.name})`,
      from: `"${pkt.sender.displayName}" <${pkt.sender.email}>`,
      receivedAt: pkt.sentAt,
      accepted: true,
      reason: 'Matched header X-DontCall-Protocol: DCP/1.0 & verified OpenPGP signature',
      detectedHeaders: {
        'X-DontCall-Protocol': 'DCP/1.0',
        'X-DontCall-Type': pkt.type,
        'X-DontCall-Channel': pkt.channel.id,
      },
      packetType: pkt.type,
      encryptionMode: pkt.encryptionMode,
      decryptedPacket: pkt,
      signatureVerified: true,
      compliantBuildVerified: true,
      decryptionTimeMs: 4.2,
    })
  );

  const rejected: import('../protocol/types').FilterInspectionResult[] =
    createSampleRegularEmails().map((reg) => ({
      emailId: reg.id,
      subject: reg.subject,
      from: reg.from,
      receivedAt: reg.date,
      accepted: false,
      reason: 'Missing required X-DontCall-Protocol: DCP/1.0 header — Ignored',
      detectedHeaders: reg.headers,
    }));

  return [...accepted, ...rejected];
}
