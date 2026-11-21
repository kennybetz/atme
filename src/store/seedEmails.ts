/**
 * Clean Starter Seed Data for `@me/simple` (`ATME/1.0`)
 *
 * Provides clean starter friends, DMs, group chats,
 * and personal `Notes (@me)` threads using fast `cleartext-json` ATME/1.0 packets.
 */

import { buildDcpMimeEmail } from '../protocol/mimeBuilder';
import {
  ATME_PROTOCOL_VERSION,
  DcpChannelMeta,
  DcpPacket,
  FilterInspectionResult,
  RawTransportEmail,
  UserIdentity,
} from '../protocol/types';

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
    id: 'dm_alex_sam',
    type: 'dm',
    name: 'Sam',
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
 * The @me Strict Filter Engine rejects and ignores 100% of these.
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
      subject: '[PR #412] Bump boring-avatars from 1.11.2 to 2.0.0',
      date: new Date(Date.now() - 1000 * 60 * 22).toISOString(),
      headers: {
        'MIME-Version': '1.0',
        From: '"GitHub Notifications" <notifications@github.com>',
        To: 'alex.rivera@gmail.com',
        Subject: '[PR #412] Bump boring-avatars from 1.11.2 to 2.0.0',
        'X-GitHub-Reason': 'review_requested',
      },
      rawMime: [
        'MIME-Version: 1.0',
        'From: "GitHub Notifications" <notifications@github.com>',
        'To: alex.rivera@gmail.com',
        'Subject: [PR #412] Bump boring-avatars from 1.11.2 to 2.0.0',
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
 * Builds the clean starter ATME/1.0 demo packets (DMs, Groups, Notes).
 * Outbound packets on the `simple` branch default to fast `cleartext-json` mode.
 */
export function buildDemoSeedPackets(usersList: UserIdentity[]): DcpPacket[] {
  const alex = usersList[0] || INITIAL_USERS[0];
  const sam = usersList[1] || INITIAL_USERS[1];
  const elena = usersList[2] || INITIAL_USERS[2];
  const maya = usersList[3] || INITIAL_USERS[3];
  const now = Date.now();

  const chFridayHangout = INITIAL_CHANNELS[0];
  const chMinecraft = INITIAL_CHANNELS[1];
  const dmSam = INITIAL_CHANNELS[2];
  const dmElena = INITIAL_CHANNELS[3];
  const dmMaya = INITIAL_CHANNELS[4];
  const dmJordanInvite = INITIAL_CHANNELS[5];
  const vaultAlex = INITIAL_CHANNELS[6];

  const makeSender = (
    u: UserIdentity,
    includeCard = false
  ): DcpPacket['sender'] => ({
    email: u.email,
    displayName: u.displayName,
    handle: u.handle,
    provider: u.provider,
    pgpFingerprint: u.pgpKeyPair?.fingerprint || '',
    publicKeyArmored: u.pgpKeyPair?.publicKeyArmored || '',
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

  // 1. MULTI-USER GROUP CHAT: #friday-hangout
  const pktFh1: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_01',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: chFridayHangout,
    sender: makeSender(alex, true),
    payload: {
      messageId: 'msg_seed_01',
      text: 'Yo everyone! School Wi-Fi blocked every other app on our Chromebooks, so we are officially on @me now 🛹',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 45).toISOString(),
  };

  const pktFh2: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_02',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: chFridayHangout,
    sender: makeSender(elena, true),
    payload: {
      messageId: 'msg_seed_02',
      text: 'Wait this is so cool!! And no phone number needed so Maya can text from her iPad too 🎮',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 38).toISOString(),
  };

  const pktFhReact1: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_react_01',
    type: 'chat.reaction',
    encryptionMode: 'cleartext-json',
    channel: chFridayHangout,
    sender: makeSender(sam),
    payload: {
      messageId: 'msg_seed_fh_react_01',
      targetMessageId: 'msg_seed_02',
      reactionEmoji: '❤️',
      text: 'Reacted ❤️',
    },
    sentAt: new Date(now - 1000 * 60 * 35).toISOString(),
  };

  const pktFh3: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_03',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: chFridayHangout,
    sender: makeSender(sam, true),
    payload: {
      messageId: 'msg_seed_fh_03',
      text: 'Are we still hitting the skatepark right after 7th period on Friday? 🛹',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 31).toISOString(),
  };

  const pktFh4: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_04',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: chFridayHangout,
    sender: makeSender(maya, true),
    payload: {
      messageId: 'msg_seed_fh_04',
      text: '100%! My mom said we can set up the basement projector for a Mario Kart tournament after 🏎️💨',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 26).toISOString(),
  };

  const pktFh5: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_05',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: chFridayHangout,
    sender: makeSender(alex),
    payload: {
      messageId: 'msg_seed_fh_05',
      text: 'Dibs on Yoshi!! Nobody is beating my Rainbow Road shortcut this time 🏆',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 22).toISOString(),
  };

  const pktFhUnread1: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_unread_01',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: chFridayHangout,
    sender: makeSender(sam),
    payload: {
      messageId: 'msg_seed_fh_unread_01',
      text: 'Bring your extra Switch Joy-Cons if you have them, my blue one has stick drift 😭',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 4).toISOString(),
  };

  const pktFhUnread2: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_fh_unread_02',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: chFridayHangout,
    sender: makeSender(maya),
    payload: {
      messageId: 'msg_seed_fh_unread_02',
      text: 'I packed two extra controllers in my backpack already! Meet by the bike racks at 3:15 🚲',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 2).toISOString(),
  };

  // 2. MULTI-USER GROUP CHAT: #minecraft-realm
  const pktMc1: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_mc_01',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: chMinecraft,
    sender: makeSender(sam),
    payload: {
      messageId: 'msg_seed_mc_01',
      text: 'Who lured a Creeper right next to our automatic cow farm?? Half the oak fence is gone 💀',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 55).toISOString(),
  };

  const pktMc2: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_mc_02',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: chMinecraft,
    sender: makeSender(alex),
    payload: {
      messageId: 'msg_seed_mc_02',
      text: 'I rebuilt the bridge with obsidian and hid 32 diamonds in the barrel under the waterfall 💎',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 50).toISOString(),
  };

  const pktMc3: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_mc_03',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: chMinecraft,
    sender: makeSender(maya),
    payload: {
      messageId: 'msg_seed_mc_03',
      text: 'Hopping on the server right after dinner so we can finally beat the Ender Dragon 🐉⚔️',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 11).toISOString(),
  };

  // 4. 1-ON-1 DM: Sam
  const pktDmSam1: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_dm_sam_01',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: dmSam,
    sender: makeSender(sam, true),
    payload: {
      messageId: 'msg_seed_dm_sam_01',
      text: 'Yo Alex! Did you test out the new simple @me scaffold branch on your Chromebook yet? 🤖',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 10).toISOString(),
  };

  const pktDmSam2: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_dm_sam_02',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: dmSam,
    sender: makeSender(alex),
    payload: {
      messageId: 'msg_seed_dm_sam_02',
      text: 'Just forked it into my own branch! Super clean to build custom features with AI 🌿',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 8).toISOString(),
  };

  // 5. 1-ON-1 DM: Elena
  const pktDmElena1: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_dm_elena_01',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: dmElena,
    sender: makeSender(elena, true),
    payload: {
      messageId: 'msg_seed_dm_elena_01',
      text: 'Hey Alex! Are we still walking to the skatepark after last bell? 🎧',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 14).toISOString(),
  };

  const pktDmAlex2: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_dm_alex_02',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: dmElena,
    sender: makeSender(alex),
    payload: {
      messageId: 'msg_seed_dm_alex_02',
      text: 'Yep! Grabbing my board from my locker right at 3:10 🛹',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 12).toISOString(),
  };

  const pktDmElenaReact: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_dm_elena_react_03',
    type: 'chat.reaction',
    encryptionMode: 'cleartext-json',
    channel: dmElena,
    sender: makeSender(elena),
    payload: {
      messageId: 'msg_seed_dm_elena_react_03',
      targetMessageId: 'msg_seed_dm_alex_02',
      reactionEmoji: '❤️',
      text: 'Reacted ❤️',
    },
    sentAt: new Date(now - 1000 * 60 * 11).toISOString(),
  };

  const pktDmElenaUnread1: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_dm_elena_unread_01',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: dmElena,
    sender: makeSender(elena),
    payload: {
      messageId: 'msg_seed_dm_elena_unread_01',
      text: 'Can you bring your mini Bluetooth speaker too? 🔊',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 35).toISOString(),
  };

  const pktDmElenaUnread2: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_dm_elena_unread_02',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: dmElena,
    sender: makeSender(elena),
    payload: {
      messageId: 'msg_seed_dm_elena_unread_02',
      text: 'Also I brought that holographic Charizard card to trade you! ✨',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 12).toISOString(),
  };

  // 6. 1-ON-1 DM: Maya
  const pktDmMayaUnread: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_dm_maya_01',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: dmMaya,
    sender: makeSender(maya, true),
    payload: {
      messageId: 'msg_seed_dm_maya_01',
      text: 'Did Mrs. Parker assign page 42 or 45 for math homework? My Chromebook died before the bell 😅',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 3).toISOString(),
  };

  // 7. FIRST-CONTACT INVITE DM: Jordan (No App Installed Yet)
  const pktInviteJordan: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_invite_03',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: dmJordanInvite,
    sender: makeSender(alex, true),
    payload: {
      messageId: 'msg_seed_03',
      text: 'Yo Jordan! Scan my @me QR pass at lunch so we can chat from our school Chromebooks 🛹',
      formatting: 'markdown',
    },
    sentAt: new Date(now - 1000 * 60 * 5).toISOString(),
  };

  // 8. PERSONAL VAULT: Notes (@me)
  const pktVault1: DcpPacket = {
    protocol: ATME_PROTOCOL_VERSION,
    packetId: 'pkt_seed_vault_01',
    type: 'chat.message',
    encryptionMode: 'cleartext-json',
    channel: vaultAlex,
    sender: makeSender(alex),
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
    pktFhReact1,
    pktFh3,
    pktFh4,
    pktFh5,
    pktFhUnread1,
    pktFhUnread2,
    pktMc1,
    pktMc2,
    pktMc3,
    pktDmSam1,
    pktDmSam2,
    pktDmElena1,
    pktDmAlex2,
    pktDmElenaReact,
    pktDmElenaUnread1,
    pktDmElenaUnread2,
    pktDmMayaUnread,
    pktInviteJordan,
    pktVault1,
  ];
}

/**
 * Builds clean `RawTransportEmail[]` for the starter seed packets in `cleartext-json` mode
 * with zero blocking startup OpenPGP calls.
 */
export async function createEncryptedSeedEmailsForUsers(
  hydratedUsers: UserIdentity[]
): Promise<RawTransportEmail[]> {
  const packets = buildDemoSeedPackets(hydratedUsers);
  return packets.map((pkt) => buildDcpMimeEmail({ packet: pkt }));
}

/**
 * Synchronous initial inspection previews so the first paint renders conversations immediately.
 */
export function createInitialSeedInspections(): FilterInspectionResult[] {
  const seedPackets = buildDemoSeedPackets(INITIAL_USERS);

  const accepted: FilterInspectionResult[] = seedPackets.map((pkt) => ({
    emailId: `eml_${pkt.packetId}`,
    subject: `[@me] Message in #${pkt.channel.name}`,
    from: `"${pkt.sender.displayName}" <${pkt.sender.email}>`,
    receivedAt: pkt.sentAt,
    accepted: true,
    reason: `Accepted ${ATME_PROTOCOL_VERSION} JSON Messaging Packet (${pkt.type})`,
    detectedHeaders: {
      'X-ATME-Protocol': ATME_PROTOCOL_VERSION,
      'X-ATME-Packet-Type': pkt.type,
      'X-ATME-Channel-Id': pkt.channel.id,
      'X-ATME-Encryption': 'cleartext-json',
    },
    packetType: pkt.type,
    encryptionMode: 'cleartext-json',
    decryptedPacket: pkt,
    signatureVerified: false,
    compliantBuildVerified: true,
    decryptionTimeMs: 0.2,
  }));

  const rejected: FilterInspectionResult[] = createSampleRegularEmails().map(
    (reg) => ({
      emailId: reg.id,
      subject: reg.subject,
      from: reg.from,
      receivedAt: reg.date,
      accepted: false,
      reason: `Ignored Regular Email: Missing 'X-ATME-Protocol: ${ATME_PROTOCOL_VERSION}' header`,
      detectedHeaders: reg.headers,
    })
  );

  return [...accepted, ...rejected];
}
