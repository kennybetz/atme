/**
 * @me Open Micro-Messaging Protocol (ATME/1.0)
 * Core technical types for Email-as-a-Backend E2EE Squad Messaging & AI Branching
 */

export const ATME_PROTOCOL_VERSION = 'ATME/1.0';
export const ATME_MIME_PACKET_TYPE = 'application/vnd.atme.packet+pgp';
export const ATME_JSON_PACKET_TYPE = 'application/vnd.atme.packet+json';
export const ATME_SUBJECT_PREFIX = '[@me]';

/** Legacy aliases retained so existing imports and tests continue to work seamlessly */
export const DCP_PROTOCOL_VERSION = ATME_PROTOCOL_VERSION;
export const DCP_MIME_PACKET_TYPE = ATME_MIME_PACKET_TYPE;
export const DCP_SUBJECT_PREFIX = ATME_SUBJECT_PREFIX;

/** Accepted protocol versions & MIME types during parsing (ATME/1.0 JSON + PGP + legacy DCP/1.0 fallback) */
export const ACCEPTED_ATME_PROTOCOL_VERSIONS = ['ATME/1.0', 'DCP/1.0'] as const;
export const ACCEPTED_ATME_MIME_TYPES = [
  'application/vnd.atme.packet+json',
  'application/vnd.atme.packet+pgp',
  'application/vnd.dontcall.packet+pgp',
] as const;

/** Hard cap on group and broadcast-channel participants to prevent personal email provider spam/rate blocks */
export const MAX_CHANNEL_AND_GROUP_USERS = 99;

/**
 * Official Compliant Build Manifest Constants
 * Used during messaging to verify the peer is running an unmodified compliant build
 * that honors Remote Key Shredding (`chat.shred-request`) and Zero-Plaintext IndexedDB rules.
 */
export const ATME_COMPLIANT_BUILD_VERSION = '1.5.0-atme-compliant';
export const ATME_COMPLIANT_BUNDLE_SHA256 =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
export const DCP_COMPLIANT_BUILD_VERSION = ATME_COMPLIANT_BUILD_VERSION;
export const DCP_COMPLIANT_BUNDLE_SHA256 = ATME_COMPLIANT_BUNDLE_SHA256;

export type EmailProviderType =
  | 'gmail'
  | 'outlook'
  | 'yahoo'
  | 'proton'
  | 'custom-domain';

export type DcpPacketType =
  | 'chat.message'
  | 'chat.reaction'
  | 'chat.edit'
  | 'chat.receipt'
  | 'chat.key-exchange'
  | 'chat.channel-invite'
  | 'chat.member-update'
  | 'chat.shred-request'
  | 'chat.shred-ack'
  | 'chat.ephemeral-policy'
  | 'chat.poll'
  | 'chat.poll-vote'
  | 'chat.pin'
  | 'chat.key-rotation'
  | 'chat.iou'
  | 'chat.branch-mod';

export type AtmePacketType = DcpPacketType;

/**
 * Plug-and-play payload slot for AI-coded squad branches (`@me/arcade-squad`, `@me/lunch-table`, etc.).
 * Any branch can attach custom interactive state in `data` while providing `fallbackBody` so peers on
 * other ATME/1.0 branches can still read the message cleanly.
 */
export interface AtmeBranchModPayload {
  branchId: string;
  modId: string;
  title: string;
  fallbackBody: string;
  data: Record<string, unknown>;
}

/**
 * Self-destructing / Burn-After-Reading timer policy (in seconds after read receipt or send).
 * 0 = Off (permanent until manually shredded)
 */
export type EphemeralTimerSeconds = 0 | 15 | 20 | 60 | 300 | 3600 | 86400;

export interface DcpPollOption {
  id: string;
  text: string;
}

export interface DcpPollPayload {
  pollId: string;
  question: string;
  options: DcpPollOption[];
  allowMultiple?: boolean;
}

export interface DcpPollVotePayload {
  pollId: string;
  optionId: string;
}

export interface DcpPinPayload {
  targetMessageId: string;
  action: 'pin' | 'unpin';
  pinnedPreviewText?: string;
}

export interface DcpIouPayload {
  iouId: string;
  /** 'send-iou' = sender owes recipient; 'request-iou' = recipient owes sender; 'collect' = recognize collection / settle */
  action: 'send-iou' | 'request-iou' | 'collect';
  amount: number;
  unit: string;
  note?: string;
  debtorEmail: string;
  creditorEmail: string;
  settledAt?: string;
}

export interface DcpLinkPreview {
  url: string;
  domain: string;
  title: string;
  description: string;
  siteName: string;
  themeColor?: string;
}

export interface ShieldedBurnerAlias {
  aliasEmail: string;
  parentEmail: string;
  label: string;
  strategy: 'plus-subaddress' | 'duck-privacy' | 'simplelogin-relay';
  pgpFingerprint: string;
  publicKeyArmored: string;
  privateKeyArmored: string;
  createdAt: string;
  shredded?: boolean;
}

export type EncryptionMode =
  | 'cleartext-json' // Simple scaffold default: readable ATME/1.0 JSON packet over email (zero PGP overhead)
  | 'openpgp-asymmetric' // Encrypted peer interop using recipient's PGP public key (also Proton Mail native)
  | 'openpgp-invite-key'; // First-contact E2EE using an ephemeral symmetric key embedded in deep-link hash

/**
 * Compact User Profile synced peer-to-peer inside the encrypted DCP/1.0 packet
 * on first contact (or whenever a user updates their avatar/handle) and cached
 * in the recipient's local IndexedDB.
 */
export interface DcpUserProfileCard {
  displayName: string;
  handle: string; // e.g. "@alexrivera"
  avatarDataUrl?: string; // Compressed 96x96 WebP/JPEG data URL
  bio?: string;
  updatedAt: string;
}

/**
 * Cryptographic Build Compliance Attestation included in every `DCP/1.0` packet.
 * Signed via WebCrypto (`ML-DSA-65` / `Ed25519` / `ECDSA`) with domain-separation context
 * and wrapped inside the OpenPGP signed envelope.
 */
export interface DcpComplianceAttestation {
  buildVersion: string;
  bundleSha256: string;
  signatureSuite: string; // e.g. 'ML-DSA-65' | 'Ed25519' | 'ECDSA-P256'
  publicKeyBase64: string;
  signatureBase64: string;
  /** Confirms non-extractable WebCrypto hardware/IndexedDB key storage & zero-plaintext-at-rest */
  zeroPlaintextIdbEnforced: boolean;
  /** Confirms automatic execution of incoming signed `chat.shred-request` packets */
  remoteShredEnforced: boolean;
  attestedAt: string;
}

export interface DcpShredRequestPayload {
  shredScope: 'thread-only' | 'peer-pgp-key-and-threads';
  targetPeerEmail: string;
  targetKeyFingerprint?: string;
  reason: string;
  requestedAt: string;
}

export interface DcpShredAckPayload {
  requestId: string;
  shreddedByEmail: string;
  purgedKeyFingerprint: string;
  scrubbedEmailIdsCount: number;
  idbCiphertextZeroed: boolean;
  attestedBuildHash: string;
  completedAt: string;
}

export interface UserIdentity {
  email: string;
  displayName: string;
  handle?: string;
  avatarDataUrl?: string;
  bio?: string;
  profileUpdatedAt?: string;
  provider: EmailProviderType;
  hasAppInstalled: boolean;
  /** Whether this user's PGP key has been remotely shredded / revoked */
  keyShreddedAt?: string;
  pgpKeyPair?: {
    publicKeyArmored: string;
    privateKeyArmored: string;
    fingerprint: string;
    createdAt: string;
  };
}

export interface DcpAttachment {
  id: string;
  filename: string;
  mimeType: string;
  sizeBytes: number;
  cid: string;
  /** Base64 / DataURL payload encrypted inside the OpenPGP DCP packet */
  encryptedData: string;
  durationSeconds?: number; // For voice notes
}

export interface DcpChannelMeta {
  id: string;
  type: 'dm' | 'group' | 'workspace-channel' | 'vault' | 'broadcast-channel';
  name: string;
  participants: string[];
  /** Email of the creator/broadcaster for a 'broadcast-channel' (subscribers receive via BCC) */
  creatorEmail?: string;
  /** Short channel description or bio for broadcast channels */
  description?: string;
  /** Optional channel-wide Burn-After-Reading timer in seconds */
  ephemeralTimerSeconds?: EphemeralTimerSeconds;
  /** Optional shielded burner alias used by the active user in this thread */
  shieldedAliasEmail?: string;
  /** Pinned message ID in this conversation */
  pinnedMessageId?: string;
  /** Whether this channel is a permanent Burner Chat (20s sequential cascade delete) */
  isBurner?: boolean;
  /** Optional creation timestamp ISO string so newly created empty chats sort to the top */
  createdAt?: string;
}

export interface DcpPacketPayload {
  messageId: string;
  replyToMessageId?: string;
  targetMessageId?: string; // For reactions, edits, receipts, shred-ack, pins, poll-votes
  text?: string;
  formatting?: 'markdown' | 'plain';
  reactionEmoji?: string;
  receiptStatus?: 'delivered' | 'read';
  attachments?: DcpAttachment[];
  /** Burn-after-reading TTL in seconds once read receipt is emitted */
  ephemeralTtlSeconds?: EphemeralTimerSeconds;
  /** Client-side generated encrypted link preview */
  linkPreview?: DcpLinkPreview;
  /** Encrypted Poll creation payload */
  poll?: DcpPollPayload;
  /** Encrypted Poll vote payload */
  pollVote?: DcpPollVotePayload;
  /** Encrypted Pin / Unpin payload */
  pinUpdate?: DcpPinPayload;
  /** Peer-to-peer IOU ledger packet */
  iou?: DcpIouPayload;
  /** Aggregated anonymous reaction counts pushed out by the creator in a broadcast-channel message */
  channelReactionTotals?: Record<string, Record<string, number>>;
  /** Story visual card metadata for broadcast-channel posts */
  storyCard?: {
    imageDataUrl?: string;
    caption?: string;
    badgeText?: string;
  };
  /** Optional shielded alias metadata when messaging via burner alias */
  senderShieldedAlias?: {
    aliasEmail: string;
    strategy: 'plus-subaddress' | 'duck-privacy' | 'simplelogin-relay';
    ephemeralFingerprint: string;
  };
  /** Optional Vault category tag for Note-to-@me */
  vaultCategory?: 'note' | 'credential' | 'file' | 'snippet';
  memberUpdate?: {
    action: 'add' | 'remove';
    targetEmail: string;
    targetDisplayName?: string;
    updatedParticipants: string[];
  };
  shredRequest?: DcpShredRequestPayload;
  shredAck?: DcpShredAckPayload;
  /** Optional custom AI-coded squad branch module payload */
  branchMod?: AtmeBranchModPayload;
}

export type AtmePacketPayload = DcpPacketPayload;

/**
 * The JSON structure carried inside `application/vnd.atme.packet+json` (`@me/simple`)
 * or encrypted inside `application/vnd.atme.packet+pgp` (full E2EE `@me` branches).
 */
export interface DcpPacket {
  protocol: 'ATME/1.0' | 'DCP/1.0';
  packetId: string;
  type: DcpPacketType;
  encryptionMode: EncryptionMode;
  channel: DcpChannelMeta;
  sender: {
    email: string;
    displayName: string;
    handle?: string;
    provider: EmailProviderType;
    pgpFingerprint?: string;
    publicKeyArmored?: string;
    /** Included on first message to a user/group or after profile edit so peers store it in local IndexedDB */
    profileCard?: DcpUserProfileCard;
  };
  /** Verifiable proof that the sender is running an unmodified compliant build */
  complianceAttestation?: DcpComplianceAttestation;
  payload: DcpPacketPayload;
  sentAt: string;
}

export type AtmePacket = DcpPacket;

/**
 * Raw RFC 5322 Email representation traveling across Gmail / Outlook / IMAP / Proton servers
 */
export interface RawTransportEmail {
  id: string;
  threadId?: string;
  from: string;
  to: string[];
  bcc?: string[];
  subject: string;
  date: string;
  headers: Record<string, string>;
  rawMime: string;
  /** Extracted HTML fallback part (what non-app email clients display) */
  htmlFallbackPart?: string;
  /** Extracted Plaintext fallback part */
  textFallbackPart?: string;
  /** Extracted encrypted DCP PGP block */
  encryptedPacketArmored?: string;
  /** Extracted cleartext ATME/1.0 JSON packet block (simple branch mode) */
  cleartextPacketJson?: string;
  /** Attached Sender Public Key block (`application/pgp-keys`) */
  attachedPublicKeyArmored?: string;
  /** Optional Ephemeral Invite Passphrase (only kept in client deep-link hash, never read by server) */
  inviteKeyFragment?: string;
}

/**
 * Result of running the Strict Inbox Filter & Parser on an incoming email
 */
export interface FilterInspectionResult {
  emailId: string;
  subject: string;
  from: string;
  receivedAt: string;
  accepted: boolean;
  reason: string;
  detectedHeaders: Record<string, string>;
  packetType?: DcpPacketType;
  encryptionMode?: EncryptionMode;
  decryptedPacket?: DcpPacket;
  signatureVerified?: boolean;
  compliantBuildVerified?: boolean;
  decryptionTimeMs?: number;
}

export * from './branchManifest';


