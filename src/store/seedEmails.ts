/**
 * Initial Seed Data, Hand-Drawn Cartoon Sketch Avatars, First-Name Kid Profiles,
 * Group Chats, Burner Chats, Broadcast Channels (BCC), and IOU Ledger Packets
 */

import {
  encryptDcpPayloadAsymmetric,
  encryptDcpPayloadWithInviteKey,
  generateInviteSecret,
} from '../crypto/openpgpService';
import { createSignedComplianceAttestation } from '../crypto/complianceAndShredding';
import { buildDcpMimeEmail } from '../protocol/mimeBuilder';
import {
  DCP_PROTOCOL_VERSION,
  DcpChannelMeta,
  DcpComplianceAttestation,
  DcpPacket,
  FilterInspectionResult,
  RawTransportEmail,
  UserIdentity,
} from '../protocol/types';



function makeStoryIllustrationDataUrl(
  theme: 'skate' | 'pixel' | 'meme'
): string {
  if (theme === 'skate') {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="560" height="320" viewBox="0 0 560 320">
      <defs>
        <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stop-color="#0f172a"/>
          <stop offset="55%" stop-color="#1e1b4b"/>
          <stop offset="100%" stop-color="#0d9488"/>
        </linearGradient>
      </defs>
      <rect width="560" height="320" rx="20" fill="url(#bg)"/>
      <circle cx="450" cy="82" r="42" fill="#f59e0b" opacity="0.85"/>
      <path d="M0 250 Q180 210 340 245 T560 220 L560 320 L0 320 Z" fill="#090d16"/>
      <g transform="translate(185, 130) rotate(-14)">
        <rect x="0" y="30" width="170" height="16" rx="8" fill="#ff6b4a" stroke="#ffffff" stroke-width="2.5"/>
        <circle cx="34" cy="54" r="9" fill="#38bdf8" stroke="#ffffff" stroke-width="2"/>
        <circle cx="136" cy="54" r="9" fill="#38bdf8" stroke="#ffffff" stroke-width="2"/>
      </g>
      <text x="28" y="46" fill="#ffffff" font-family="-apple-system, sans-serif" font-size="18" font-weight="700">SKATE CLIPS DAILY • LIVE FEED</text>
      <text x="28" y="292" fill="#99f6e4" font-family="-apple-system, sans-serif" font-size="15" font-weight="600">Sunset 5-stair kickflip landed on 3rd try</text>
    </svg>`;
    return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
  }
  if (theme === 'pixel') {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="560" height="320" viewBox="0 0 560 320">
      <defs>
        <linearGradient id="bg2" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stop-color="#311042"/>
          <stop offset="100%" stop-color="#4f46e5"/>
        </linearGradient>
      </defs>
      <rect width="560" height="320" rx="20" fill="url(#bg2)"/>
      <rect x="190" y="70" width="180" height="130" rx="16" fill="#0f172a" stroke="#a855f7" stroke-width="3"/>
      <circle cx="245" cy="125" r="14" fill="#22d3ee"/>
      <circle cx="315" cy="125" r="14" fill="#22d3ee"/>
      <path d="M245 162 L315 162" stroke="#f472b6" stroke-width="6" stroke-linecap="round"/>
      <text x="28" y="46" fill="#ffffff" font-family="-apple-system, sans-serif" font-size="18" font-weight="700">PIXEL ART &amp; ARCADE DROPS</text>
      <text x="28" y="292" fill="#e9d5ff" font-family="-apple-system, sans-serif" font-size="15" font-weight="600">New boss sprite finished during study hall</text>
    </svg>`;
    return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
  }
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="560" height="320" viewBox="0 0 560 320">
    <defs>
      <linearGradient id="bg3" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="#0f172a"/>
        <stop offset="100%" stop-color="#1d4ed8"/>
      </linearGradient>
    </defs>
    <rect width="560" height="320" rx="20" fill="url(#bg3)"/>
    <rect x="130" y="68" width="300" height="150" rx="18" fill="#1e293b" stroke="#38bdf8" stroke-width="2.5"/>
    <text x="280" y="135" text-anchor="middle" fill="#ffffff" font-family="-apple-system, sans-serif" font-size="22" font-weight="800">CHROMEBOOK BATTERY: 2%</text>
    <text x="280" y="170" text-anchor="middle" fill="#38bdf8" font-family="-apple-system, sans-serif" font-size="16" font-weight="600">Right when Kahoot starts in 6th period</text>
    <text x="28" y="292" fill="#bae6fd" font-family="-apple-system, sans-serif" font-size="15" font-weight="600">Broadcast via BCC • Anonymous reactions</text>
  </svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

export const INITIAL_USERS: UserIdentity[] = [
  {
    email: 'alex.rivera@gmail.com',
    displayName: 'Alex',
    handle: '@alex',
    bio: 'Skateboarding & building @me 🛹',
    profileUpdatedAt: '2026-10-25T03:00:00.000Z',
    provider: 'gmail',
    hasAppInstalled: true,
  },
  {
    email: 'sam.chen@outlook.com',
    displayName: 'Sam',
    handle: '@sam',
    bio: 'Robotics club & drumline 🥁',
    profileUpdatedAt: '2026-10-25T03:05:00.000Z',
    provider: 'outlook',
    hasAppInstalled: true,
  },
  {
    email: 'elena.vogt@proton.me',
    displayName: 'Elena',
    handle: '@elena',
    bio: 'Pixel art & Mario Kart champ 🎮',
    profileUpdatedAt: '2026-10-25T03:10:00.000Z',
    provider: 'proton',
    hasAppInstalled: true,
  },
  {
    email: 'maya.lin@icloud.com',
    displayName: 'Maya',
    handle: '@maya',
    bio: 'Track team & late night Minecraft ⚡',
    profileUpdatedAt: '2026-10-25T03:12:00.000Z',
    provider: 'custom-domain',
    hasAppInstalled: true,
  },
  {
    email: 'jordan.taylor@yahoo.com',
    displayName: 'Jordan',
    handle: '@jordan',
    bio: 'BMX & arcade high scores 🕹️',
    provider: 'yahoo',
    hasAppInstalled: false,
  },
];

export const INITIAL_CHANNELS: DcpChannelMeta[] = [
  {
    id: 'ch_product_launch',
    type: 'workspace-channel',
    name: 'friday-hangout',
    participants: [
      'alex.rivera@gmail.com',
      'sam.chen@outlook.com',
      'elena.vogt@proton.me',
      'maya.lin@icloud.com',
    ],
  },
  {
    id: 'burner_ch_lunch_table',
    type: 'workspace-channel',
    name: 'lunch-table-secrets',
    isBurner: true,
    ephemeralTimerSeconds: 20,
    participants: [
      'alex.rivera@gmail.com',
      'sam.chen@outlook.com',
      'elena.vogt@proton.me',
      'maya.lin@icloud.com',
    ],
  },
  {
    id: 'ch_broadcast_skate_clips',
    type: 'broadcast-channel',
    name: 'skate-clips-daily',
    creatorEmail: 'elena.vogt@proton.me',
    description:
      'Daily skatepark clips & pixel art drops by Elena • Anonymous BCC broadcast',
    participants: [
      'elena.vogt@proton.me',
      'alex.rivera@gmail.com',
      'sam.chen@outlook.com',
      'maya.lin@icloud.com',
    ],
  },
  {
    id: 'ch_broadcast_meme_radar',
    type: 'broadcast-channel',
    name: 'school-meme-radar',
    creatorEmail: 'alex.rivera@gmail.com',
    description:
      'Live hallway stories & Chromebook memes by Alex • Subscribers hidden via BCC',
    participants: [
      'alex.rivera@gmail.com',
      'sam.chen@outlook.com',
      'elena.vogt@proton.me',
      'maya.lin@icloud.com',
    ],
  },
  {
    id: 'ch_security_ops',
    type: 'workspace-channel',
    name: 'minecraft-realm',
    participants: [
      'alex.rivera@gmail.com',
      'sam.chen@outlook.com',
      'elena.vogt@proton.me',
      'maya.lin@icloud.com',
    ],
  },
  {
    id: 'burner_dm_alex_sam',
    type: 'dm',
    name: 'Sam',
    isBurner: true,
    ephemeralTimerSeconds: 20,
    participants: ['alex.rivera@gmail.com', 'sam.chen@outlook.com'],
  },
  {
    id: 'dm_alex_elena',
    type: 'dm',
    name: 'Elena',
    participants: ['alex.rivera@gmail.com', 'elena.vogt@proton.me'],
  },
  {
    id: 'dm_alex_maya',
    type: 'dm',
    name: 'Maya',
    participants: ['alex.rivera@gmail.com', 'maya.lin@icloud.com'],
  },
  {
    id: 'dm_alex_jordan',
    type: 'dm',
    name: 'Jordan',
    participants: ['alex.rivera@gmail.com', 'jordan.taylor@yahoo.com'],
  },
  {
    id: 'vault_alex.rivera@gmail.com',
    type: 'vault',
    name: 'Notes (@me)',
    participants: ['alex.rivera@gmail.com'],
  },
  {
    id: 'vault_sam.chen@outlook.com',
    type: 'vault',
    name: 'Notes (@me)',
    participants: ['sam.chen@outlook.com'],
  },
  {
    id: 'vault_elena.vogt@proton.me',
    type: 'vault',
    name: 'Notes (@me)',
    participants: ['elena.vogt@proton.me'],
  },
  {
    id: 'vault_maya.lin@icloud.com',
    type: 'vault',
    name: 'Notes (@me)',
    participants: ['maya.lin@icloud.com'],
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
      textFallbackPart:
        'Your flight departs in 24 hours. Confirmation #H8K9LP.',
    },
  ];
}

/**
 * Builds the canonical list of demo DCP/1.0 packets using only first names, kid-centric topics,
 * zero inline replies, multi-user group chats, Group & 1-on-1 Burner Chats, Broadcast Channels, and IOUs.
 */
export function buildDemoSeedPackets(
  usersList: UserIdentity[],
  attestByEmail?: Record<string, DcpComplianceAttestation>
): DcpPacket[] {
  const alex = usersList[0] || INITIAL_USERS[0];
  const sam = usersList[1] || INITIAL_USERS[1];
  const elena = usersList[2] || INITIAL_USERS[2];
  const maya = usersList[3] || INITIAL_USERS[3];
  const now = Date.now();

  const chFridayHangout = INITIAL_CHANNELS[0]; // #friday-hangout
  const chBurnerLunch = INITIAL_CHANNELS[1]; // lunch-table-secrets (Group Burner)
  const chBroadcastSkate = INITIAL_CHANNELS[2]; // skate-clips-daily (Elena's Broadcast Channel)
  const chBroadcastMeme = INITIAL_CHANNELS[3]; // school-meme-radar (Alex's Broadcast Channel)
  const chMinecraft = INITIAL_CHANNELS[4]; // #minecraft-realm
  const dmBurnerSam = INITIAL_CHANNELS[5]; // Sam (1-on-1 Burner)
  const dmElena = INITIAL_CHANNELS[6]; // Elena (1-on-1 DM)
  const dmMaya = INITIAL_CHANNELS[7]; // Maya (1-on-1 DM)
  const dmJordanInvite = INITIAL_CHANNELS[8]; // Jordan (1-on-1 Invite DM)
  const vaultAlex = INITIAL_CHANNELS[9]; // Notes (@me)

  const fallbackAttest = (iso: string): DcpComplianceAttestation => ({
    buildVersion: '1.5.0-atme-compliant',
    bundleSha256:
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    signatureSuite: 'Ed25519',
    publicKeyBase64: 'MCowBQYDK2VwAyEA',
    signatureBase64: 'verified-seed-sig',
    zeroPlaintextIdbEnforced: true,
    remoteShredEnforced: true,
    attestedAt: iso,
  });

  const getAttest = (email: string, minutesAgo: number) =>
    attestByEmail?.[email] ||
    fallbackAttest(new Date(now - 1000 * 60 * minutesAgo).toISOString());

  const makeSender = (
    u: UserIdentity,
    fallbackFp: string,
    includeCard = false
  ): DcpPacket['sender'] => ({
    email: u.email,
    displayName: u.displayName,
    handle: u.handle,
    provider: u.provider,
    pgpFingerprint: u.pgpKeyPair?.fingerprint || fallbackFp,
    publicKeyArmored:
      u.pgpKeyPair?.publicKeyArmored ||
      '-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----',
    ...(includeCard
      ? {
          profileCard: {
            displayName: u.displayName,
            handle: u.handle || `@${u.displayName.toLowerCase()}`,
            avatarDataUrl: u.avatarDataUrl,
            bio: u.bio,
            updatedAt: u.profileUpdatedAt || new Date().toISOString(),
          },
        }
      : {}),
  });

  const fpAlex = '9F4A7C21D8E34B109F4A7C21D8E34B109F4A7C21';
  const fpSam = '7C1D4F92A6B83E117C1D4F92A6B83E117C1D4F92';
  const fpElena = '3B8E1A50C7D29F443B8E1A50C7D29F443B8E1A50';
  const fpMaya = '5E2C8B14F0A96D335E2C8B14F0A96D335E2C8B14';

  // =========================================================================
  // 1. MULTI-USER GROUP CHAT: #friday-hangout (Alex, Sam, Elena, Maya)
  // =========================================================================
  const pktFh1: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_01',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: chFridayHangout,
    sender: makeSender(alex, fpAlex, true),
    complianceAttestation: getAttest(alex.email, 45),
    payload: {
      messageId: 'msg_seed_01',
      text: 'Yo everyone! School Wi-Fi blocked every other app on our Chromebooks, so we are officially on @me now 🛹',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 45).toISOString(),
  };

  const pktFh2: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_02',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: chFridayHangout,
    sender: makeSender(elena, fpElena, true),
    complianceAttestation: getAttest(elena.email, 38),
    payload: {
      messageId: 'msg_seed_02',
      text: 'Wait this is so cool!! And no phone number needed so Maya can text from her iPad too 🎮',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 38).toISOString(),
  };

  const pktFhReceipt1: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_rcpt_01',
    type: 'chat.receipt',
    encryptionMode: 'openpgp-asymmetric',
    channel: chFridayHangout,
    sender: makeSender(elena, fpElena),
    payload: {
      messageId: 'msg_seed_fh_rcpt_01',
      targetMessageId: 'msg_seed_01',
      receiptStatus: 'read',
      text: 'Read msg_seed_01',
    },
    sentAt: new Date(now - 1000 * 60 * 37).toISOString(),
  };

  const pktFhReact1: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_react_01',
    type: 'chat.reaction',
    encryptionMode: 'openpgp-asymmetric',
    channel: chFridayHangout,
    sender: makeSender(sam, fpSam),
    payload: {
      messageId: 'msg_seed_fh_react_01',
      targetMessageId: 'msg_seed_02',
      reactionEmoji: '❤️',
      text: 'Reacted ❤️',
    },
    sentAt: new Date(now - 1000 * 60 * 35).toISOString(),
  };

  const pktFh3: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_03',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: chFridayHangout,
    sender: makeSender(sam, fpSam, true),
    complianceAttestation: getAttest(sam.email, 31),
    payload: {
      messageId: 'msg_seed_fh_03',
      text: 'Are we still hitting the skatepark right after 7th period on Friday? 🛹',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 31).toISOString(),
  };

  const pktFh4: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_04',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: chFridayHangout,
    sender: makeSender(maya, fpMaya, true),
    complianceAttestation: getAttest(maya.email, 26),
    payload: {
      messageId: 'msg_seed_fh_04',
      text: '100%! My mom said we can set up the basement projector for a Mario Kart tournament after 🏎️💨',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 26).toISOString(),
  };

  const pktFh5: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_05',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: chFridayHangout,
    sender: makeSender(alex, fpAlex),
    complianceAttestation: getAttest(alex.email, 22),
    payload: {
      messageId: 'msg_seed_fh_05',
      text: 'Dibs on Yoshi!! Nobody is beating my Rainbow Road shortcut this time 🏆',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 22).toISOString(),
  };

  const pktFhReceipt2: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_rcpt_05',
    type: 'chat.receipt',
    encryptionMode: 'openpgp-asymmetric',
    channel: chFridayHangout,
    sender: makeSender(sam, fpSam),
    payload: {
      messageId: 'msg_seed_fh_rcpt_05',
      targetMessageId: 'msg_seed_fh_05',
      receiptStatus: 'read',
      text: 'Read msg_seed_fh_05',
    },
    sentAt: new Date(now - 1000 * 60 * 21).toISOString(),
  };

  const pktPoll: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_poll_01',
    type: 'chat.poll',
    encryptionMode: 'openpgp-asymmetric',
    channel: chFridayHangout,
    sender: makeSender(elena, fpElena),
    complianceAttestation: getAttest(elena.email, 18),
    payload: {
      messageId: 'msg_seed_poll_01',
      text: '📊 What snacks are we getting for Friday night?',
      poll: {
        pollId: 'poll_release_01',
        question: 'What snacks are we getting for Friday night?',
        options: [
          { id: 'opt_shred', text: '🍕 Pepperoni Pizza' },
          { id: 'opt_vault', text: '🌮 Doritos Locos Tacos' },
          { id: 'opt_alias', text: '🧋 Brown Sugar Boba' },
        ],
      },
    },
    sentAt: new Date(now - 1000 * 60 * 18).toISOString(),
  };

  const pktPollVote1: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_poll_vote_01',
    type: 'chat.poll-vote',
    encryptionMode: 'openpgp-asymmetric',
    channel: chFridayHangout,
    sender: makeSender(alex, fpAlex),
    payload: {
      messageId: 'msg_seed_poll_vote_01',
      targetMessageId: 'msg_seed_poll_01',
      pollVote: {
        pollId: 'poll_release_01',
        optionId: 'opt_shred',
      },
      text: 'Voted for 🍕 Pepperoni Pizza',
    },
    sentAt: new Date(now - 1000 * 60 * 17).toISOString(),
  };

  const pktPollVote2: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_poll_vote_02',
    type: 'chat.poll-vote',
    encryptionMode: 'openpgp-asymmetric',
    channel: chFridayHangout,
    sender: makeSender(sam, fpSam),
    payload: {
      messageId: 'msg_seed_poll_vote_02',
      targetMessageId: 'msg_seed_poll_01',
      pollVote: {
        pollId: 'poll_release_01',
        optionId: 'opt_vault',
      },
      text: 'Voted for 🌮 Doritos Locos Tacos',
    },
    sentAt: new Date(now - 1000 * 60 * 16).toISOString(),
  };

  const pktPollVote3: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_poll_vote_03',
    type: 'chat.poll-vote',
    encryptionMode: 'openpgp-asymmetric',
    channel: chFridayHangout,
    sender: makeSender(maya, fpMaya),
    payload: {
      messageId: 'msg_seed_poll_vote_03',
      targetMessageId: 'msg_seed_poll_01',
      pollVote: {
        pollId: 'poll_release_01',
        optionId: 'opt_shred',
      },
      text: 'Voted for 🍕 Pepperoni Pizza',
    },
    sentAt: new Date(now - 1000 * 60 * 15).toISOString(),
  };

  const pktFhUnread1: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_unread_01',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: chFridayHangout,
    sender: makeSender(sam, fpSam),
    complianceAttestation: getAttest(sam.email, 4),
    payload: {
      messageId: 'msg_seed_fh_unread_01',
      text: 'Bring your extra Switch Joy-Cons if you have them, my blue one has stick drift 😭',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 4).toISOString(),
  };

  const pktFhUnread2: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_unread_02',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: chFridayHangout,
    sender: makeSender(maya, fpMaya),
    complianceAttestation: getAttest(maya.email, 2),
    payload: {
      messageId: 'msg_seed_fh_unread_02',
      text: 'I packed two extra controllers in my backpack already! Meet by the bike racks at 3:15 🚲',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 2).toISOString(),
  };

  // =========================================================================
  // 2. MULTI-USER GROUP BURNER CHAT: lunch-table-secrets (Alex, Sam, Elena, Maya)
  // =========================================================================
  const pktBurnerGroup1: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_bg_01',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: chBurnerLunch,
    sender: makeSender(elena, fpElena),
    complianceAttestation: getAttest(elena.email, 9),
    payload: {
      messageId: 'msg_seed_bg_01',
      ephemeralTtlSeconds: 20,
      text: 'Psst! Mr. Davis left the pop quiz topics on the whiteboard during 3rd period—it is all on photosynthesis 🌱',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 9).toISOString(),
  };

  const pktBurnerGroup2: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_bg_02',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: chBurnerLunch,
    sender: makeSender(sam, fpSam),
    complianceAttestation: getAttest(sam.email, 8),
    payload: {
      messageId: 'msg_seed_bg_02',
      ephemeralTtlSeconds: 20,
      text: 'You are a lifesaver!! Also I stashed two bags of Takis in the band room cubby for lunch 🌶️',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 8).toISOString(),
  };

  const pktBurnerGroup3: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_bg_03',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: chBurnerLunch,
    sender: makeSender(maya, fpMaya),
    complianceAttestation: getAttest(maya.email, 7),
    payload: {
      messageId: 'msg_seed_bg_03',
      ephemeralTtlSeconds: 20,
      text: 'Save me some!! New treehouse padlock code is 7-3-9-1 before this message self-destructs 🗝️',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 7).toISOString(),
  };

  // =========================================================================
  // 3. BROADCAST CHANNELS (BCC Newsletter / Story Live Feeds)
  //    - skate-clips-daily (Creator: Elena -> Subscribers: Alex, Sam, Maya via BCC)
  //    - school-meme-radar (Creator: Alex -> Subscribers: Sam, Elena, Maya via BCC)
  // =========================================================================
  const pktBroadcastSkate1: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_bcast_skate_01',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: chBroadcastSkate,
    sender: makeSender(elena, fpElena, true),
    complianceAttestation: getAttest(elena.email, 32),
    payload: {
      messageId: 'msg_seed_bcast_skate_01',
      text: 'Landed my first clean kickflip down the 5-stair behind the library!! Watch the clip frame 👇',
      formatting: 'markdown',
      storyCard: {
        imageDataUrl: makeStoryIllustrationDataUrl('skate'),
        caption: '5-Stair Kickflip • Behind Oakridge Library',
        badgeText: 'BCC STORY DROP #14',
      },
      channelReactionTotals: {
        msg_seed_bcast_skate_01: { '❤️': 29, '😂': 8, '⚡': 19 },
      },
    },
    sentAt: new Date(now - 1000 * 60 * 32).toISOString(),
  };

  const pktBroadcastSkate2: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_bcast_skate_02',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: chBroadcastSkate,
    sender: makeSender(elena, fpElena),
    complianceAttestation: getAttest(elena.email, 6),
    payload: {
      messageId: 'msg_seed_bcast_skate_02',
      text: 'Finished the final boss pixel sprite during 4th period study hall! React below to vote on the neon palette 🎨 (previous post reaction counts updated!)',
      formatting: 'markdown',
      storyCard: {
        imageDataUrl: makeStoryIllustrationDataUrl('pixel'),
        caption: 'Arcade Boss Sprite v2 • 64x64 Pixel Grid',
        badgeText: 'BCC STORY DROP #15',
      },
      channelReactionTotals: {
        msg_seed_bcast_skate_01: { '❤️': 34, '😂': 11, '⚡': 27 },
        msg_seed_bcast_skate_02: { '❤️': 16, '⚡': 14 },
      },
    },
    sentAt: new Date(now - 1000 * 60 * 6).toISOString(),
  };

  const pktBroadcastMeme1: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_bcast_meme_01',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: chBroadcastMeme,
    sender: makeSender(alex, fpAlex),
    complianceAttestation: getAttest(alex.email, 19),
    payload: {
      messageId: 'msg_seed_bcast_meme_01',
      text: 'Every single day in 6th period science when the teacher launches Kahoot and nobody brought a charger 😭🔌',
      formatting: 'markdown',
      storyCard: {
        imageDataUrl: makeStoryIllustrationDataUrl('meme'),
        caption: '6th Period Kahoot Survival Guide',
        badgeText: 'CREATOR CHANNEL • BCC',
      },
      channelReactionTotals: {
        msg_seed_bcast_meme_01: { '😂': 41, '😭': 23, '💀': 18 },
      },
    },
    sentAt: new Date(now - 1000 * 60 * 19).toISOString(),
  };

  // =========================================================================
  // 4. MULTI-USER GROUP CHAT: #minecraft-realm (Alex, Sam, Elena, Maya)
  // =========================================================================
  const pktMc1: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_mc_01',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: chMinecraft,
    sender: makeSender(sam, fpSam),
    complianceAttestation: getAttest(sam.email, 55),
    payload: {
      messageId: 'msg_seed_mc_01',
      text: 'Who lured a Creeper right next to our automatic cow farm?? Half the oak fence is gone 💀',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 55).toISOString(),
  };

  const pktMc2: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_mc_02',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: chMinecraft,
    sender: makeSender(alex, fpAlex),
    complianceAttestation: getAttest(alex.email, 50),
    payload: {
      messageId: 'msg_seed_mc_02',
      text: 'I rebuilt the bridge with obsidian and hid 32 diamonds in the barrel under the waterfall 💎',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 50).toISOString(),
  };

  const pktMc3: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_mc_03',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: chMinecraft,
    sender: makeSender(maya, fpMaya),
    complianceAttestation: getAttest(maya.email, 11),
    payload: {
      messageId: 'msg_seed_mc_03',
      text: 'Hopping on the server right after dinner so we can finally beat the Ender Dragon 🐉⚔️',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 11).toISOString(),
  };

  // =========================================================================
  // 5. 1-ON-1 BURNER CHAT: Sam (Alex -> Sam)
  // =========================================================================
  const pktBurnerSam1: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_bsam_01',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: dmBurnerSam,
    sender: makeSender(alex, fpAlex),
    complianceAttestation: getAttest(alex.email, 6),
    payload: {
      messageId: 'msg_seed_bsam_01',
      ephemeralTtlSeconds: 20,
      text: 'Secret Minecraft base coordinates: X: -420, Y: 64, Z: 1180 behind the lava waterfall 🌋',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 6).toISOString(),
  };

  const pktBurnerSam2: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_bsam_02',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: dmBurnerSam,
    sender: makeSender(alex, fpAlex),
    complianceAttestation: getAttest(alex.email, 5),
    payload: {
      messageId: 'msg_seed_bsam_02',
      ephemeralTtlSeconds: 20,
      text: 'Flip the hidden lever behind the bookshelf to open the Redstone vault door (lever #3)',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 5).toISOString(),
  };

  const pktBurnerSam3: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_bsam_03',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: dmBurnerSam,
    sender: makeSender(alex, fpAlex),
    complianceAttestation: getAttest(alex.email, 4),
    payload: {
      messageId: 'msg_seed_bsam_03',
      ephemeralTtlSeconds: 20,
      text: 'Do not tell Elena or Maya yet, we are surprising them with full Netherite armor tonight 🛡️',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 4).toISOString(),
  };

  // =========================================================================
  // 6. 1-ON-1 DM: Elena (Alex & Elena — NO replies, 2 unread at bottom)
  // =========================================================================
  const pktDmElena1: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_dm_elena_01',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: dmElena,
    sender: makeSender(elena, fpElena, true),
    complianceAttestation: getAttest(elena.email, 14),
    payload: {
      messageId: 'msg_seed_dm_elena_01',
      text: 'Hey Alex! Are we still walking to the skatepark after last bell? 🎧',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 14).toISOString(),
  };

  const pktDmAlex2: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_dm_alex_02',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: dmElena,
    sender: makeSender(alex, fpAlex),
    complianceAttestation: getAttest(alex.email, 12),
    payload: {
      messageId: 'msg_seed_dm_alex_02',
      text: 'Yep! Grabbing my board from my locker right at 3:10 🛹',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 12).toISOString(),
  };

  const pktDmElenaReact: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_dm_elena_react_03',
    type: 'chat.reaction',
    encryptionMode: 'openpgp-asymmetric',
    channel: dmElena,
    sender: makeSender(elena, fpElena),
    payload: {
      messageId: 'msg_seed_dm_elena_react_03',
      targetMessageId: 'msg_seed_dm_alex_02',
      reactionEmoji: '❤️',
      text: 'Reacted ❤️',
    },
    sentAt: new Date(now - 1000 * 60 * 11).toISOString(),
  };

  const pktDmElenaRead: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_dm_elena_rcpt_04',
    type: 'chat.receipt',
    encryptionMode: 'openpgp-asymmetric',
    channel: dmElena,
    sender: makeSender(elena, fpElena),
    payload: {
      messageId: 'msg_seed_dm_elena_rcpt_04',
      targetMessageId: 'msg_seed_dm_alex_02',
      receiptStatus: 'read',
      text: 'Read msg_seed_dm_alex_02',
    },
    sentAt: new Date(now - 1000 * 60 * 10).toISOString(),
  };

  const pktDmElenaUnread1: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_dm_elena_unread_01',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: dmElena,
    sender: makeSender(elena, fpElena),
    complianceAttestation: getAttest(elena.email, 1),
    payload: {
      messageId: 'msg_seed_dm_elena_unread_01',
      text: 'Can you bring your mini Bluetooth speaker too? 🔊',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 35).toISOString(),
  };

  const pktDmElenaUnread2: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_dm_elena_unread_02',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: dmElena,
    sender: makeSender(elena, fpElena),
    complianceAttestation: getAttest(elena.email, 0),
    payload: {
      messageId: 'msg_seed_dm_elena_unread_02',
      text: 'Also I brought that holographic Charizard card to trade you! ✨',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 12).toISOString(),
  };

  // =========================================================================
  // 7. 1-ON-1 DM: Maya (Alex & Maya)
  // =========================================================================
  const pktDmMayaUnread: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_dm_maya_01',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: dmMaya,
    sender: makeSender(maya, fpMaya, true),
    complianceAttestation: getAttest(maya.email, 3),
    payload: {
      messageId: 'msg_seed_dm_maya_01',
      text: 'Did Mrs. Parker assign page 42 or 45 for math homework? My Chromebook died before the bell 😅',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 3).toISOString(),
  };

  // =========================================================================
  // 8. PEER-TO-PEER CRYPTO-STYLE IOU LEDGER PACKETS (`chat.iou`)
  // =========================================================================
  const pktIouSam: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_iou_sam_01',
    type: 'chat.iou',
    encryptionMode: 'openpgp-asymmetric',
    channel: chFridayHangout,
    sender: makeSender(sam, fpSam),
    complianceAttestation: getAttest(sam.email, 29),
    payload: {
      messageId: 'msg_seed_iou_sam_01',
      text: 'Sent 12 IOU to Alex (Pizza slices + arcade tokens)',
      iou: {
        iouId: 'iou_seed_sam_01',
        action: 'send-iou',
        amount: 12,
        unit: 'IOU',
        note: 'Pizza slices + arcade tokens 🍕',
        debtorEmail: sam.email,
        creditorEmail: alex.email,
      },
    },
    sentAt: new Date(now - 1000 * 60 * 29).toISOString(),
  };

  const pktIouElena: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_iou_elena_01',
    type: 'chat.iou',
    encryptionMode: 'openpgp-asymmetric',
    channel: dmElena,
    sender: makeSender(elena, fpElena),
    complianceAttestation: getAttest(elena.email, 24),
    payload: {
      messageId: 'msg_seed_iou_elena_01',
      text: 'Sent 5 IOU to Alex (Brown sugar boba)',
      iou: {
        iouId: 'iou_seed_elena_01',
        action: 'send-iou',
        amount: 5,
        unit: 'IOU',
        note: 'Brown sugar boba 🧋',
        debtorEmail: elena.email,
        creditorEmail: alex.email,
      },
    },
    sentAt: new Date(now - 1000 * 60 * 24).toISOString(),
  };

  const pktIouMaya: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_iou_maya_01',
    type: 'chat.iou',
    encryptionMode: 'openpgp-asymmetric',
    channel: dmMaya,
    sender: makeSender(alex, fpAlex),
    complianceAttestation: getAttest(alex.email, 21),
    payload: {
      messageId: 'msg_seed_iou_maya_01',
      text: 'Sent 4 IOU to Maya (Cafeteria ice cream)',
      iou: {
        iouId: 'iou_seed_maya_01',
        action: 'send-iou',
        amount: 4,
        unit: 'IOU',
        note: 'Cafeteria ice cream 🍦',
        debtorEmail: alex.email,
        creditorEmail: maya.email,
      },
    },
    sentAt: new Date(now - 1000 * 60 * 21).toISOString(),
  };

  // =========================================================================
  // 9. FIRST-CONTACT INVITE DM: Jordan (No App Installed Yet)
  // =========================================================================
  const pktInviteJordan: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_invite_03',
    type: 'chat.message',
    encryptionMode: 'openpgp-invite-key',
    channel: dmJordanInvite,
    sender: makeSender(alex, fpAlex, true),
    payload: {
      messageId: 'msg_seed_03',
      text: 'Yo Jordan! Scan my @me QR pass at lunch so we can chat from our school Chromebooks 🛹',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 5).toISOString(),
  };

  // =========================================================================
  // 10. PERSONAL ENCRYPTED VAULT: Notes (@me)
  // =========================================================================
  const pktVault1: DcpPacket = {
    protocol: DCP_PROTOCOL_VERSION,
    packetId: 'pkt_seed_vault_01',
    type: 'chat.message',
    encryptionMode: 'openpgp-asymmetric',
    channel: vaultAlex,
    sender: makeSender(alex, fpAlex),
    complianceAttestation: getAttest(alex.email, 20),
    payload: {
      messageId: 'msg_seed_vault_01',
      vaultCategory: 'note',
      text: '📌 Hallway locker combo: 24-18-09 • Kickflip tip: flick off the nose corner!',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 20).toISOString(),
  };

  return [
    pktFh1,
    pktFh2,
    pktFhReceipt1,
    pktFhReact1,
    pktFh3,
    pktFh4,
    pktFh5,
    pktFhReceipt2,
    pktPoll,
    pktPollVote1,
    pktPollVote2,
    pktPollVote3,
    pktFhUnread1,
    pktFhUnread2,
    pktBurnerGroup1,
    pktBurnerGroup2,
    pktBurnerGroup3,
    pktBroadcastSkate1,
    pktBroadcastSkate2,
    pktBroadcastMeme1,
    pktMc1,
    pktMc2,
    pktMc3,
    pktBurnerSam1,
    pktBurnerSam2,
    pktBurnerSam3,
    pktDmElena1,
    pktDmAlex2,
    pktDmElenaReact,
    pktDmElenaRead,
    pktDmElenaUnread1,
    pktDmElenaUnread2,
    pktDmMayaUnread,
    pktIouSam,
    pktIouElena,
    pktIouMaya,
    pktInviteJordan,
    pktVault1,
  ];
}

/**
 * Encrypts the canonical demo seed packets with real OpenPGP keys for IndexedDB persistence.
 */
export async function createEncryptedSeedEmailsForUsers(
  hydratedUsers: UserIdentity[]
): Promise<RawTransportEmail[]> {
  const appUsers = hydratedUsers.filter((u) => u.pgpKeyPair);
  if (appUsers.length === 0) return [];

  const allAppKeys = appUsers.map((u) => u.pgpKeyPair!.publicKeyArmored);
  const attestByEmail: Record<string, DcpComplianceAttestation> = {};

  for (const u of appUsers) {
    attestByEmail[u.email] = await createSignedComplianceAttestation({
      senderEmail: u.email,
      senderPgpFingerprint: u.pgpKeyPair!.fingerprint,
    });
  }

  const packets = buildDemoSeedPackets(hydratedUsers, attestByEmail);
  const userByEmail = new Map(
    hydratedUsers.map((u) => [u.email.toLowerCase(), u])
  );
  const seedDcpEmails: RawTransportEmail[] = [];

  for (const pkt of packets) {
    const senderUser =
      userByEmail.get(pkt.sender.email.toLowerCase()) || appUsers[0];
    if (!senderUser?.pgpKeyPair) continue;

    if (pkt.encryptionMode === 'openpgp-invite-key') {
      const inviteSecret = generateInviteSecret();
      const encInvite = await encryptDcpPayloadWithInviteKey({
        cleartextJson: JSON.stringify(pkt),
        inviteSecret,
        senderPublicKeyArmored: senderUser.pgpKeyPair.publicKeyArmored,
        senderPrivateKeyArmored: senderUser.pgpKeyPair.privateKeyArmored,
      });
      seedDcpEmails.push(
        buildDcpMimeEmail({
          packet: pkt,
          encryptedPacketArmored: encInvite,
          inviteKeyFragment: inviteSecret,
        })
      );
    } else {
      const encAsym = await encryptDcpPayloadAsymmetric({
        cleartextJson: JSON.stringify(pkt),
        recipientPublicKeysArmored: allAppKeys,
        senderPublicKeyArmored: senderUser.pgpKeyPair.publicKeyArmored,
        senderPrivateKeyArmored: senderUser.pgpKeyPair.privateKeyArmored,
      });
      seedDcpEmails.push(
        buildDcpMimeEmail({
          packet: pkt,
          encryptedPacketArmored: encAsym,
        })
      );
    }
  }

  return seedDcpEmails;
}

/**
 * Synchronous initial inspection previews so the first paint (before async WebWorker/OpenPGP
 * key generation finishes ~350ms later) renders the full conversation threads and messages immediately.
 */
export function createInitialSeedInspections(): FilterInspectionResult[] {
  const seedPackets = buildDemoSeedPackets(INITIAL_USERS);

  const accepted: FilterInspectionResult[] = seedPackets.map((pkt) => ({
    emailId: `eml_${pkt.packetId}`,
    subject: `[@me] Encrypted packet (${pkt.channel.name})`,
    from: `"${pkt.sender.displayName}" <${pkt.sender.email}>`,
    receivedAt: pkt.sentAt,
    accepted: true,
    reason:
      'Matched header X-DontCall-Protocol: DCP/1.0 & verified OpenPGP signature',
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
  }));

  const rejected: FilterInspectionResult[] = createSampleRegularEmails().map(
    (reg) => ({
      emailId: reg.id,
      subject: reg.subject,
      from: reg.from,
      receivedAt: reg.date,
      accepted: false,
      reason:
        'Missing required X-DontCall-Protocol: DCP/1.0 header — Ignored',
      detectedHeaders: reg.headers,
    })
  );

  return [...accepted, ...rejected];
}
