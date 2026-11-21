/**
 * RFC 5322 Multipart MIME Builder & Non-App Invite Fallback Generator (`ATME/1.0`)
 *
 * Formats outbound `@me` chat actions into standards-compliant Multipart Email messages:
 *   1. Strict `X-ATME-*` headers (plus `X-DontCall-*` compatibility mirrors) so `@me`
 *      filters ONLY messaging packets and ignores 100% of regular personal/work emails.
 *   2. `text/html` & `text/plain` Fallback Card for recipients reading in regular email clients.
 *   3. Packet Attachment Part:
 *      - Simple mode (`cleartext-json`): `application/vnd.atme.packet+json` (`atme-packet.json`)
 *      - Encrypted interop (`openpgp-*`): `application/vnd.atme.packet+pgp` (`atme-packet.pgp`)
 *        plus optional `application/pgp-keys` (`sender-pubkey.asc`).
 */

import {
  ATME_JSON_PACKET_TYPE,
  ATME_MIME_PACKET_TYPE,
  ATME_PROTOCOL_VERSION,
  ATME_SUBJECT_PREFIX,
  MAX_CHANNEL_AND_GROUP_USERS,
  DcpPacket,
  RawTransportEmail,
} from './types';
import { ACTIVE_BRANCH_MANIFEST } from './branchManifest';
import { formatFingerprint } from '../crypto/openpgpService';

export interface BuildMimeEmailOptions {
  packet: DcpPacket;
  /** Optional armored OpenPGP ciphertext; omit when sending in simple `cleartext-json` mode */
  encryptedPacketArmored?: string;
  inviteKeyFragment?: string;
  appStoreUrl?: string;
  playStoreUrl?: string;
  webAppBaseUrl?: string;
}

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Generates the HTML fallback card shown when a recipient opens the email in a normal
 * email client (or does not have `@me` installed yet).
 */
export function buildNonAppInviteHtmlCard(options: {
  packet: DcpPacket;
  inviteKeyFragment?: string;
  appStoreUrl: string;
  playStoreUrl: string;
  webAppDeepLink: string;
}): string {
  const { packet, appStoreUrl, playStoreUrl, webAppDeepLink } = options;
  const senderName = escapeHtml(packet.sender.displayName);
  const senderEmail = escapeHtml(packet.sender.email);
  const channelName = escapeHtml(packet.channel.name);
  const isCleartext = packet.encryptionMode === 'cleartext-json';
  const rawFp = packet.sender.pgpFingerprint?.trim() || '';
  const fpFormatted = rawFp
    ? escapeHtml(formatFingerprint(rawFp).slice(0, 24) + '…')
    : '';

  const actionLabel =
    packet.type === 'chat.reaction'
      ? `reacted (${escapeHtml(packet.payload.reactionEmoji || '👍')}) to a message`
      : packet.type === 'chat.edit'
      ? 'edited a message'
      : packet.type === 'chat.receipt'
      ? `marked message as ${escapeHtml(packet.payload.receiptStatus || 'read')}`
      : packet.type === 'chat.member-update'
      ? `updated group members (${escapeHtml(
          packet.payload.memberUpdate?.action || 'update'
        )} ${escapeHtml(packet.payload.memberUpdate?.targetEmail || '')})`
      : isCleartext
      ? 'sent you a message on @me'
      : 'sent you an end-to-end encrypted message';

  const previewText =
    isCleartext && packet.payload.text
      ? escapeHtml(packet.payload.text)
      : `This message was packaged for @me on ${senderName}'s device. Open it in @me to read and reply instantly via messaging.`;

  const badgeText = isCleartext
    ? `@me MESSAGING PACKET (${ATME_PROTOCOL_VERSION})`
    : 'LOCKED END-TO-END ENCRYPTED MESSAGE (@me / OPENPGP)';

  const openCtaText = isCleartext ? 'Open in @me Web App' : 'Decrypt in @me Web App';

  return `<div class="dc-fallback-card">
  <div class="dc-fallback-badge">${badgeText}</div>
  <h2 class="dc-fallback-title">${senderName} ${actionLabel}</h2>
  <p class="dc-fallback-sub">From <strong>${senderEmail}</strong> in channel <strong>#${channelName}</strong></p>
  <div class="dc-fallback-cipherbox">
    <p class="dc-fallback-cipher-notice">${previewText}</p>
    ${fpFormatted ? `<p class="dc-fallback-fp">PGP Key Fingerprint: <code>${fpFormatted}</code></p>` : ''}
  </div>
  <div class="dc-fallback-actions">
    <a class="dc-btn-primary" href="${escapeHtml(appStoreUrl)}" target="_blank" rel="noopener noreferrer">Download @me on the App Store (iOS)</a>
    <a class="dc-btn-secondary" href="${escapeHtml(playStoreUrl)}" target="_blank" rel="noopener noreferrer">Get @me on Google Play (Android)</a>
    <a class="dc-btn-tertiary" href="${escapeHtml(webAppDeepLink)}" target="_blank" rel="noopener noreferrer">${openCtaText}</a>
  </div>
  <p class="dc-fallback-footer">
    Sent via @me over Recycled Email &bull; Protocol ${ATME_PROTOCOL_VERSION}
  </p>
</div>`;
}

/**
 * Builds the complete RFC 5322 Multipart MIME message and structured transport wrapper
 */
export function buildDcpMimeEmail(
  options: BuildMimeEmailOptions
): RawTransportEmail {
  const {
    packet,
    encryptedPacketArmored,
    inviteKeyFragment,
    appStoreUrl = 'https://apps.apple.com/app/atme-encrypted-chat/id0000000000',
    playStoreUrl = 'https://play.google.com/store/apps/details?id=app.atme.messenger',
    webAppBaseUrl = 'https://app.atme.chat',
  } = options;

  const isCleartextJson =
    packet.encryptionMode === 'cleartext-json' || !encryptedPacketArmored?.trim();

  const boundaryMixed = `----=_ATME_Mixed_${packet.packetId}`;
  const boundaryAlt = `----=_ATME_Alt_${packet.packetId}`;

  const isBroadcastChannel = packet.channel.type === 'broadcast-channel';
  const creatorEmail = (
    packet.channel.creatorEmail ||
    packet.channel.participants[0] ||
    packet.sender.email
  ).toLowerCase();
  const isSenderCreator =
    packet.sender.email.toLowerCase() === creatorEmail;

  const cappedParticipants = packet.channel.participants.slice(
    0,
    MAX_CHANNEL_AND_GROUP_USERS
  );
  const recipients =
    isBroadcastChannel && !isSenderCreator
      ? [creatorEmail]
      : cappedParticipants.filter(
          (email) => email.toLowerCase() !== packet.sender.email.toLowerCase()
        );

  const webAppDeepLink = inviteKeyFragment
    ? `${webAppBaseUrl}/#packet=${encodeURIComponent(packet.packetId)}&inviteKey=${encodeURIComponent(inviteKeyFragment)}`
    : `${webAppBaseUrl}/#packet=${encodeURIComponent(packet.packetId)}`;

  const subject = isCleartextJson
    ? `${ATME_SUBJECT_PREFIX} Message in #${packet.channel.name} [${packet.channel.id}]`
    : `${ATME_SUBJECT_PREFIX} Encrypted ${packet.type.replace('chat.', '')} (${packet.channel.name}) [${packet.channel.id}]`;

  const headers: Record<string, string> = {
    'MIME-Version': '1.0',
    From: `"${packet.sender.displayName}" <${packet.sender.email}>`,
    To:
      isBroadcastChannel && isSenderCreator
        ? `"Undisclosed Channel Subscribers" <${packet.sender.email}>`
        : recipients.join(', '),
    ...(isBroadcastChannel && isSenderCreator
      ? {
          Bcc: recipients.join(', '),
          'X-ATME-Broadcast-Bcc': 'anonymous-subscriber-shield',
          'X-DontCall-Broadcast-Bcc': 'anonymous-subscriber-shield',
        }
      : {}),
    Subject: subject,
    Date: new Date(packet.sentAt).toUTCString(),
    'Message-ID': `<${packet.payload.messageId}@atme.local>`,
    'X-ATME-Protocol': ATME_PROTOCOL_VERSION,
    'X-ATME-Branch': packet.payload.branchMod?.branchId || ACTIVE_BRANCH_MANIFEST.branchId,
    'X-ATME-Packet-Id': packet.packetId,
    'X-ATME-Packet-Type': packet.type,
    'X-ATME-Channel-Id': packet.channel.id,
    'X-ATME-Channel-Type': packet.channel.type,
    'X-ATME-Encryption': isCleartextJson ? 'cleartext-json' : packet.encryptionMode,
    ...(packet.sender.pgpFingerprint
      ? { 'X-ATME-Sender-FP': packet.sender.pgpFingerprint }
      : {}),
    'X-DontCall-Protocol': ATME_PROTOCOL_VERSION,
    'X-DontCall-Packet-Id': packet.packetId,
    'X-DontCall-Packet-Type': packet.type,
    'X-DontCall-Channel-Id': packet.channel.id,
    'X-DontCall-Channel-Type': packet.channel.type,
    'X-DontCall-Encryption': isCleartextJson ? 'cleartext-json' : packet.encryptionMode,
    ...(packet.sender.pgpFingerprint
      ? { 'X-DontCall-Sender-FP': packet.sender.pgpFingerprint }
      : {}),
    'Auto-Submitted': 'auto-generated',
  };

  if (packet.payload.replyToMessageId || packet.payload.targetMessageId) {
    const refId =
      packet.payload.replyToMessageId || packet.payload.targetMessageId;
    headers['In-Reply-To'] = `<${refId}@atme.local>`;
    headers['References'] = `<${packet.channel.id}@atme.local> <${refId}@atme.local>`;
  } else {
    headers['References'] = `<${packet.channel.id}@atme.local>`;
  }

  const textFallbackPart = isCleartextJson
    ? [
        `[@me MESSAGING PACKET — ${ATME_PROTOCOL_VERSION}]`,
        `From: ${packet.sender.displayName} <${packet.sender.email}>`,
        `Channel: #${packet.channel.name}`,
        packet.payload.text ? `Message: ${packet.payload.text}` : '',
        ``,
        `Sent via @me over Recycled Email:`,
        `- Open @me Web App: ${webAppDeepLink}`,
      ]
        .filter(Boolean)
        .join('\r\n')
    : [
        `[LOCKED END-TO-END ENCRYPTED MESSAGE — @me (${ATME_PROTOCOL_VERSION})]`,
        `From: ${packet.sender.displayName} <${packet.sender.email}>`,
        `Channel: #${packet.channel.name}`,
        packet.sender.pgpFingerprint
          ? `PGP Fingerprint: ${formatFingerprint(packet.sender.pgpFingerprint)}`
          : '',
        ``,
        `This message is encrypted on-device. Your regular email client cannot read the encrypted chat payload.`,
        `Download @me to read and respond via instant messaging:`,
        `- iOS App Store: ${appStoreUrl}`,
        `- Google Play Store: ${playStoreUrl}`,
        `- Open @me Web App: ${webAppDeepLink}`,
      ]
        .filter(Boolean)
        .join('\r\n');

  const htmlFallbackPart = buildNonAppInviteHtmlCard({
    packet,
    inviteKeyFragment,
    appStoreUrl,
    playStoreUrl,
    webAppDeepLink,
  });

  const headerLines = Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\r\n');

  const cleartextPacketJson = isCleartextJson
    ? JSON.stringify(packet, null, 2)
    : undefined;

  const mimeParts: string[] = [
    headerLines,
    `Content-Type: multipart/mixed; boundary="${boundaryMixed}"`,
    ``,
    `--${boundaryMixed}`,
    `Content-Type: multipart/alternative; boundary="${boundaryAlt}"`,
    ``,
    `--${boundaryAlt}`,
    `Content-Type: text/plain; charset="utf-8"`,
    `Content-Transfer-Encoding: 8bit`,
    ``,
    textFallbackPart,
    ``,
    `--${boundaryAlt}`,
    `Content-Type: text/html; charset="utf-8"`,
    `Content-Transfer-Encoding: 8bit`,
    ``,
    htmlFallbackPart,
    ``,
    `--${boundaryAlt}--`,
    ``,
  ];

  if (isCleartextJson && cleartextPacketJson) {
    mimeParts.push(
      `--${boundaryMixed}`,
      `Content-Type: ${ATME_JSON_PACKET_TYPE}; name="atme-packet.json"`,
      `Content-Disposition: attachment; filename="atme-packet.json"`,
      `Content-Description: @me Messaging Packet (ATME/1.0 JSON)`,
      ``,
      cleartextPacketJson,
      ``
    );
  } else if (encryptedPacketArmored) {
    mimeParts.push(
      `--${boundaryMixed}`,
      `Content-Type: ${ATME_MIME_PACKET_TYPE}; name="atme-packet.pgp"`,
      `Content-Disposition: attachment; filename="atme-packet.pgp"`,
      `Content-Description: @me Encrypted Messaging Packet (ATME/1.0)`,
      ``,
      encryptedPacketArmored.trim(),
      ``
    );
  }

  if (packet.sender.publicKeyArmored?.trim()) {
    mimeParts.push(
      `--${boundaryMixed}`,
      `Content-Type: application/pgp-keys; name="sender-pubkey.asc"`,
      `Content-Disposition: attachment; filename="sender-pubkey.asc"`,
      ``,
      packet.sender.publicKeyArmored.trim(),
      ``
    );
  }

  mimeParts.push(`--${boundaryMixed}--`);
  const rawMime = mimeParts.join('\r\n');

  return {
    id: `eml_${packet.packetId}`,
    threadId: packet.channel.id,
    from: packet.sender.email,
    to: recipients,
    bcc: isBroadcastChannel && isSenderCreator ? recipients : undefined,
    subject,
    date: packet.sentAt,
    headers,
    rawMime,
    htmlFallbackPart,
    textFallbackPart,
    encryptedPacketArmored: isCleartextJson ? undefined : encryptedPacketArmored,
    cleartextPacketJson,
    attachedPublicKeyArmored: packet.sender.publicKeyArmored?.trim()
      ? packet.sender.publicKeyArmored
      : undefined,
    inviteKeyFragment,
  };
}
