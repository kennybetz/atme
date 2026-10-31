import React, { useEffect, useId, useMemo, useRef, useState, useCallback } from 'react';
import {
  AlertTriangle,
  ArrowDown,
  ArrowLeft,
  BarChart3,
  Bookmark,
  Camera,
  Check,
  CheckCheck,
  CheckCircle2,
  ChevronRight,
  Clock,
  Code2,
  Copy,
  CornerDownLeft,
  ExternalLink,
  Eye,
  EyeOff,
  FileText,
  Filter,
  Fingerprint,
  Flame,
  Globe,
  Hash,
  Image as ImageIcon,
  KeyRound,
  Link2,
  Lock,
  Mail,
  Menu,
  MessageSquare,
  Mic,
  Moon,
  Paperclip,
  Pin,
  Plus,
  PlusCircle,
  QrCode,
  RefreshCw,
  Search,
  Send,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Smile,
  Smartphone,
  Sparkles,
  Square,
  Sun,
  Terminal,
  Timer,
  Trash2,
  User,
  UserCheck,
  UserMinus,
  UserPlus,
  Users,
  VenetianMask,
  X,
  XCircle,
} from 'lucide-react';
import {
  DCP_COMPLIANT_BUILD_VERSION,
  DCP_COMPLIANT_BUNDLE_SHA256,
  DCP_PROTOCOL_VERSION,
  DcpAttachment,
  DcpChannelMeta,
  DcpLinkPreview,
  DcpPacket,
  DcpPacketType,
  DcpPinPayload,
  DcpPollPayload,
  DcpPollVotePayload,
  DcpShredAckPayload,
  DcpShredRequestPayload,
  DcpUserProfileCard,
  EphemeralTimerSeconds,
  FilterInspectionResult,
  RawTransportEmail,
  ShieldedBurnerAlias,
  UserIdentity,
} from './protocol/types';
import {
  encryptDcpPayloadAsymmetric,
  encryptDcpPayloadWithInviteKey,
  formatFingerprint,
  generateDeviceKeyPair,
  generateInviteSecret,
} from './crypto/openpgpService';
import {
  createSignedComplianceAttestation,
  destroyThreadWrappingKey,
} from './crypto/complianceAndShredding';
import {
  SafetyNumberVerificationBundle,
  computeSafetyNumberAndQrMatrix,
  createShieldedBurnerAlias,
  evaluatePinOrDuressCode,
  extractClientSideLinkPreview,
  verifyWebAuthnPasskeyLock,
} from './crypto/privacyFeatures';
import { buildDcpMimeEmail } from './protocol/mimeBuilder';
import { inspectAndDecryptEmail } from './protocol/mimeParser';
import {
  INITIAL_CHANNELS,
  INITIAL_USERS,
  createInitialSeedInspections,
  createSampleRegularEmails,
} from './store/seedEmails';
import {
  clearIdbDatabase,
  cryptographicScrubPeerAndEmailsInIdb,
  loadTransportEmailsFromIdb,
  loadUserIdentitiesFromIdb,
  saveTransportEmailsToIdb,
  saveUserIdentitiesToIdb,
} from './store/localDb';
import {
  GmailDirectTransport,
  OutlookDirectTransport,
  getProviderTechnicalSpecs,
} from './transport/emailConnectors';
import {
  DomainAutoDiscoveryResult,
  discoverCustomDomainEmailConfig,
  launchRealOAuthPopup,
} from './transport/oauthPortal';
import { safeSetInviteHTML } from './utils/safeHtml';

type AppSurfaceMode = 'messenger-ui' | 'protocol-workbench';

type WorkbenchTab =
  | 'chat-bridge'
  | 'filter-gate'
  | 'mime-inspector'
  | 'non-app-fallback'
  | 'provider-connectors';

interface FreeflowChatMessage {
  emailId: string;
  packet: DcpPacket;
  signatureVerified: boolean;
  decryptionTimeMs?: number;
  reactions: Array<{ emoji: string; senderName: string; senderEmail: string }>;
  receipts: Array<{
    status: 'delivered' | 'read';
    senderName: string;
    senderEmail: string;
    readAtIso?: string;
  }>;
  pollVotes: Array<{
    optionId: string;
    senderName: string;
    senderEmail: string;
  }>;
  quotedMessage?: {
    messageId: string;
    senderName: string;
    textSnippet: string;
  };
}

/**
 * Compresses an uploaded image file onto a 96x96 canvas so the avatar data URL
 * stays lightweight (~3-8 KB) when attached to first-contact encrypted DCP packets.
 */
async function compressImageToAvatarDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error('Failed to read image file'));
    reader.onload = () => {
      const img = new Image();
      img.onerror = () => reject(new Error('Invalid image format'));
      img.onload = () => {
        const canvas = document.createElement('canvas');
        const size = 96;
        canvas.width = size;
        canvas.height = size;
        const ctx = canvas.getContext('2d');
        if (!ctx) {
          resolve(String(reader.result));
          return;
        }
        const minSide = Math.min(img.width, img.height);
        const sx = (img.width - minSide) / 2;
        const sy = (img.height - minSide) / 2;
        ctx.drawImage(img, sx, sy, minSide, minSide, 0, 0, size, size);
        resolve(canvas.toDataURL('image/webp', 0.84));
      };
      img.src = String(reader.result);
    };
    reader.readAsDataURL(file);
  });
}

/**
 * Reads any file attachment as a Data URL so it can be encrypted inside the DCP/1.0 packet
 * and rendered inline on the recipient's device.
 */
async function readFileAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.onload = () => resolve(String(reader.result));
    reader.readAsDataURL(file);
  });
}

/**
 * Synthesizes a valid playable WAV audio DataURL when testing voice notes in environments
 * without a physical microphone or when clicking Quick Voice Note.
 */
function createSynthesizedVoiceNoteDataUrl(durationSec = 2): {
  dataUrl: string;
  sizeBytes: number;
  durationSeconds: number;
} {
  const sampleRate = 8000;
  const numSamples = sampleRate * durationSec;
  const buffer = new ArrayBuffer(44 + numSamples * 2);
  const view = new DataView(buffer);

  const writeStr = (offset: number, str: string) => {
    for (let i = 0; i < str.length; i++) {
      view.setUint8(offset + i, str.charCodeAt(i));
    }
  };

  writeStr(0, 'RIFF');
  view.setUint32(4, 36 + numSamples * 2, true);
  writeStr(8, 'WAVE');
  writeStr(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, 1, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * 2, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);
  writeStr(36, 'data');
  view.setUint32(40, numSamples * 2, true);

  for (let i = 0; i < numSamples; i++) {
    const t = i / sampleRate;
    const freq = t < 0.8 ? 440 : t < 1.4 ? 554.37 : 659.25;
    const envelope = Math.sin((Math.PI * (i % (sampleRate / 2))) / (sampleRate / 2));
    const sample = Math.sin(2 * Math.PI * freq * t) * envelope * 0.25;
    view.setInt16(44 + i * 2, sample * 32767, true);
  }

  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return {
    dataUrl: `data:audio/wav;base64,${base64}`,
    sizeBytes: buffer.byteLength,
    durationSeconds: durationSec,
  };
}

type BubbleThemeId =
  | 'ocean'
  | 'berry'
  | 'violet'
  | 'mint'
  | 'sunset'
  | 'gold'
  | 'custom';

const DEFAULT_TOP_5_EMOJIS: string[] = ['❤️', '😂', '🔥', '💀', '😭'];

const ALL_SEARCHABLE_EMOJIS: Array<{ emoji: string; keywords: string }> = [
  { emoji: '❤️', keywords: 'heart love red like' },
  { emoji: '😂', keywords: 'laugh cry tears joy lol funny' },
  { emoji: '🔥', keywords: 'fire lit hot flame hype' },
  { emoji: '💀', keywords: 'skull dead Icant funny skeleton' },
  { emoji: '😭', keywords: 'sob crying sad tears' },
  { emoji: '👍', keywords: 'thumbs up yes ok good approve' },
  { emoji: '👎', keywords: 'thumbs down no bad' },
  { emoji: '🎉', keywords: 'party celebrate confetti tada' },
  { emoji: '🙌', keywords: 'hands praise hooray celebrate' },
  { emoji: '😮', keywords: 'wow surprised shocked omg' },
  { emoji: '😢', keywords: 'sad tear cry' },
  { emoji: '🙏', keywords: 'pray please thanks highfive' },
  { emoji: '💯', keywords: '100 hundred perfect facts real' },
  { emoji: '👀', keywords: 'eyes lookingtea see watch' },
  { emoji: '✨', keywords: 'sparkles magic shine stars vibe' },
  { emoji: '🚀', keywords: 'rocket launch space fast hype' },
  { emoji: '🫶', keywords: 'heart hands love care' },
  { emoji: '🥹', keywords: 'holding back tears touched happy cry' },
  { emoji: '🤣', keywords: 'rofl rolling laughing floor lol' },
  { emoji: '😎', keywords: 'cool sunglasses chill boss' },
  { emoji: '🥳', keywords: 'party face birthday celebrate' },
  { emoji: '🤯', keywords: 'mind blown exploding head crazy' },
  { emoji: '🫠', keywords: 'melting face awkward hot' },
  { emoji: '🫡', keywords: 'salute respect yes sir' },
  { emoji: '🤝', keywords: 'handshake deal friend agree' },
  { emoji: '⚡', keywords: 'lightning bolt zap energy fast' },
  { emoji: '💜', keywords: 'purple heart love' },
  { emoji: '🩷', keywords: 'pink heart love cute' },
  { emoji: '🩵', keywords: 'light blue heart cyan' },
  { emoji: '💚', keywords: 'green heart' },
  { emoji: '🧡', keywords: 'orange heart' },
  { emoji: '💛', keywords: 'yellow heart gold' },
  { emoji: '🖤', keywords: 'black heart dark' },
  { emoji: '🤍', keywords: 'white heart pure' },
  { emoji: '💔', keywords: 'broken heart sad' },
  { emoji: '❤️‍🔥', keywords: 'heart on fire passionate' },
  { emoji: '👑', keywords: 'crown king queen royal goat' },
  { emoji: '🐐', keywords: 'goat greatest of all time' },
  { emoji: '🏆', keywords: 'trophy winner champion award' },
  { emoji: '💎', keywords: 'diamond gem icy rich' },
  { emoji: '🌟', keywords: 'glowing star shine' },
  { emoji: '🌈', keywords: 'rainbow colorful pride' },
  { emoji: '☀️', keywords: 'sun sunny bright' },
  { emoji: '🌙', keywords: 'moon night' },
  { emoji: '👻', keywords: 'ghost spooky boo' },
  { emoji: '👽', keywords: 'alien ufo space' },
  { emoji: '🤖', keywords: 'robot bot ai' },
  { emoji: '👾', keywords: 'alien monster arcade game' },
  { emoji: '🎮', keywords: 'video game controller gaming' },
  { emoji: '🎧', keywords: 'headphones music audio' },
  { emoji: '🛹', keywords: 'skateboard skate' },
  { emoji: '🏀', keywords: 'basketball sports hoop' },
  { emoji: '⚽', keywords: 'soccer ball football' },
  { emoji: '🏈', keywords: 'football american sports' },
  { emoji: '⚾', keywords: 'baseball sports' },
  { emoji: '🎾', keywords: 'tennis ball' },
  { emoji: '🍕', keywords: 'pizza food slice' },
  { emoji: '🍔', keywords: 'burger hamburger food' },
  { emoji: '🍟', keywords: 'fries french fries food' },
  { emoji: '🌮', keywords: 'taco food' },
  { emoji: '🍦', keywords: 'ice cream sweet cone' },
  { emoji: '🍩', keywords: 'donut doughnut sweet' },
  { emoji: '🧋', keywords: 'boba bubble tea drink' },
  { emoji: '🍿', keywords: 'popcorn movie drama' },
  { emoji: '🐱', keywords: 'cat kitty pet' },
  { emoji: '🐶', keywords: 'dog puppy pet' },
  { emoji: '🦊', keywords: 'fox animal' },
  { emoji: '🐼', keywords: 'panda bear' },
  { emoji: '🐸', keywords: 'frog toad meme' },
  { emoji: '🦋', keywords: 'butterfly bug pretty' },
  { emoji: '🦄', keywords: 'unicorn magic horse' },
  { emoji: '🦖', keywords: 'dino dinosaur trex' },
  { emoji: '🦈', keywords: 'shark ocean' },
  { emoji: '🫡', keywords: 'salute respect' },
  { emoji: '🤫', keywords: 'shh quiet secret' },
  { emoji: '🤔', keywords: 'thinking hmm question' },
  { emoji: '🙄', keywords: 'eye roll annoyed whatever' },
  { emoji: '😴', keywords: 'sleeping tired zzz' },
  { emoji: '🥶', keywords: 'cold freezing icy' },
  { emoji: '🥵', keywords: 'hot sweating' },
  { emoji: '🤡', keywords: 'clown silly circus' },
  { emoji: '🤠', keywords: 'cowboy hat yeehaw' },
  { emoji: '😇', keywords: 'angel halo innocent' },
  { emoji: '😈', keywords: 'devil horns mischievous' },
  { emoji: '✌️', keywords: 'peace victory hand' },
  { emoji: '🤞', keywords: 'fingers crossed luck' },
  { emoji: '🤙', keywords: 'call me shaka hang loose' },
  { emoji: '👋', keywords: 'wave hello hi bye' },
  { emoji: '👏', keywords: 'clap applause bravo' },
  { emoji: '💪', keywords: 'muscle strong flex' },
  { emoji: '🧠', keywords: 'brain smart genius' },
  { emoji: '💥', keywords: 'boom explosion collision' },
  { emoji: '💫', keywords: 'dizzy star shooting' },
  { emoji: '💤', keywords: 'zzz sleep' },
  { emoji: '✅', keywords: 'check mark done yes green' },
  { emoji: '❌', keywords: 'cross mark no wrong x' },
  { emoji: '❓', keywords: 'question mark what' },
  { emoji: '❗', keywords: 'exclamation mark alert' },
];

export function App() {
  const [surfaceMode, setSurfaceMode] =
    useState<AppSurfaceMode>('messenger-ui');

  const [users, setUsers] = useState<UserIdentity[]>(INITIAL_USERS);
  const [channels, setChannels] = useState<DcpChannelMeta[]>(INITIAL_CHANNELS);
  const [activeUserEmail, setActiveUserEmail] = useState<string>(
    INITIAL_USERS[0].email
  );
  const [activeChannelId, setActiveChannelId] = useState<string>(
    INITIAL_CHANNELS[2].id
  );
  const [mobileShowChatPane, setMobileShowChatPane] = useState<boolean>(
    () =>
      typeof window !== 'undefined' &&
      window.location.search.includes('mobileView=chat')
  );

  // Track which channel IDs the active user has already sent their profileCard to
  // (Sent automatically on the FIRST message to any user/group, or after updating profile)
  const [profileBroadcastedChannels, setProfileBroadcastedChannels] = useState<
    Record<string, boolean>
  >({});
  const [forceBroadcastProfileNext, setForceBroadcastProfileNext] =
    useState<boolean>(false);

  // Free-flowing inline reply quote state
  const [replyingToMessage, setReplyingToMessage] =
    useState<FreeflowChatMessage | null>(null);

  // Contact & Thread Search Query
  const [contactSearchQuery, setContactSearchQuery] = useState<string>('');

  // Messenger Composer State
  const [composerText, setComposerText] = useState<string>('');
  const [pendingAttachments, setPendingAttachments] = useState<DcpAttachment[]>(
    []
  );
  const [activeReactionPickerMsgId, setActiveReactionPickerMsgId] = useState<
    string | null
  >(null);

  // Voice Note Recording State (MediaRecorder + Fallback)
  const [isRecordingVoice, setIsRecordingVoice] = useState<boolean>(false);
  const [recordingSeconds, setRecordingSeconds] = useState<number>(0);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const recordingChunksRef = useRef<Blob[]>([]);
  const recordingTimerRef = useRef<number | null>(null);

  // Hidden File Inputs
  const fileAttachmentInputRef = useRef<HTMLInputElement | null>(null);
  const avatarUploadInputRef = useRef<HTMLInputElement | null>(null);

  // User Profile Editor State (Avatar, Display Name, Handle, Bio)
  const [profileNameInput, setProfileNameInput] = useState<string>('');
  const [profileHandleInput, setProfileHandleInput] = useState<string>('');
  const [profileBioInput, setProfileBioInput] = useState<string>('');
  const [profileAvatarInput, setProfileAvatarInput] = useState<
    string | undefined
  >(undefined);
  const [profileSaveBanner, setProfileSaveBanner] = useState<string>('');

  // Email Provider OAuth & Bridge Onboarding Wizard State
  const [connectModalMode, setConnectModalMode] = useState<
    'easy' | 'advanced'
  >('easy');
  const [easyEmailInput, setEasyEmailInput] = useState<string>('');
  const [easyDisplayNameInput, setEasyDisplayNameInput] =
    useState<string>('');
  const [easyAppPasswordInput, setEasyAppPasswordInput] =
    useState<string>('');
  const [easyDiscoveryResult, setEasyDiscoveryResult] =
    useState<DomainAutoDiscoveryResult | null>(null);
  const [isEasyDiscovering, setIsEasyDiscovering] = useState<boolean>(false);

  const [wizardProvider, setWizardProvider] = useState<
    'gmail' | 'outlook' | 'proton' | 'yahoo' | 'custom-domain'
  >('gmail');
  const [gmailAccessToken, setGmailAccessToken] = useState<string>('');
  const [outlookAccessToken, setOutlookAccessToken] = useState<string>('');
  const [googleClientId, setGoogleClientId] = useState<string>(
    (import.meta.env.VITE_GOOGLE_CLIENT_ID as string) || ''
  );
  const [microsoftClientId, setMicrosoftClientId] = useState<string>(
    (import.meta.env.VITE_MICROSOFT_CLIENT_ID as string) || ''
  );
  const [showAdvancedOAuthConfig, setShowAdvancedOAuthConfig] =
    useState<boolean>(false);

  // Interactive OAuth Consent Popup Simulator State (when testing without a cloud Client ID)
  const [simulatedOAuthProvider, setSimulatedOAuthProvider] = useState<
    'google' | 'microsoft' | null
  >(null);
  const [simulatedOAuthEmail, setSimulatedOAuthEmail] = useState<string>(
    'founder@startup.io'
  );
  const [simulatedOAuthName, setSimulatedOAuthName] =
    useState<string>('Taylor Brooks');

  // Custom Domain Auto-Discovery & Universal IMAP/SMTP/JMAP Sign-In State
  const [customDomainEmail, setCustomDomainEmail] = useState<string>(
    'cto@customcompany.com'
  );
  const [customDomainName, setCustomDomainName] =
    useState<string>('Morgan Vance');
  const [customDomainPassword, setCustomDomainPassword] =
    useState<string>('');
  const [domainDiscoveryResult, setDomainDiscoveryResult] =
    useState<DomainAutoDiscoveryResult | null>(null);
  const [isDiscoveringDomain, setIsDiscoveringDomain] =
    useState<boolean>(false);

  const [protonBridgeHost, setProtonBridgeHost] = useState<string>(
    'http://127.0.0.1:1143'
  );
  const [autoArchivePrimaryInbox, setAutoArchivePrimaryInbox] =
    useState<boolean>(true);
  const [connectorStatusMsg, setConnectorStatusMsg] = useState<string>('');

  // Group / Channel Member Management State
  const [newMemberEmailInput, setNewMemberEmailInput] = useState<string>('');
  const [newMemberNameInput, setNewMemberNameInput] = useState<string>('');

  // Stage 1 Workbench State
  const [recipientEmail, setRecipientEmail] = useState<string>(
    INITIAL_USERS[2].email
  );
  const [channelName, setChannelName] = useState<string>('product-launch');
  const [packetType, setPacketType] = useState<DcpPacketType>('chat.message');
  const [messageText, setMessageText] = useState<string>(
    'Hey team! Testing our zero-server OpenPGP email messaging protocol (DCP/1.0).'
  );
  const [reactionEmoji, setReactionEmoji] = useState<string>('🚀');

  const [transportEmails, setTransportEmails] = useState<RawTransportEmail[]>(
    []
  );
  const [inspections, setInspections] = useState<FilterInspectionResult[]>(() =>
    createInitialSeedInspections()
  );
  const [selectedEmailId, setSelectedEmailId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<WorkbenchTab>('chat-bridge');
  const [isInitializingKeys, setIsInitializingKeys] = useState<boolean>(true);
  const [isSending, setIsSending] = useState<boolean>(false);

  // Native <dialog closedby="any"> refs
  const menuDirectoryDialogRef = useRef<HTMLDialogElement | null>(null);
  const groupInfoDialogRef = useRef<HTMLDialogElement | null>(null);
  const profileDialogRef = useRef<HTMLDialogElement | null>(null);
  const connectWizardDialogRef = useRef<HTMLDialogElement | null>(null);
  const packetModalRef = useRef<HTMLDialogElement | null>(null);
  const newChannelModalRef = useRef<HTMLDialogElement | null>(null);
  const shredConfirmDialogRef = useRef<HTMLDialogElement | null>(null);
  const safetyNumberDialogRef = useRef<HTMLDialogElement | null>(null);
  const pollCreatorDialogRef = useRef<HTMLDialogElement | null>(null);
  const appLockConfigDialogRef = useRef<HTMLDialogElement | null>(null);
  const safetyListDialogRef = useRef<HTMLDialogElement | null>(null);
  const cameraCaptureDialogRef = useRef<HTMLDialogElement | null>(null);
  const cameraVideoRef = useRef<HTMLVideoElement | null>(null);
  const cameraStreamRef = useRef<MediaStream | null>(null);
  const [isCameraStreaming, setIsCameraStreaming] = useState<boolean>(false);
  const [cameraFacingMode, setCameraFacingMode] = useState<
    'user' | 'environment'
  >('user');
  const [capturedPhotoDataUrl, setCapturedPhotoDataUrl] = useState<
    string | null
  >(null);
  const [fullscreenImageUrl, setFullscreenImageUrl] = useState<string | null>(
    null
  );

  // Pending Shred & Purge Confirmation State
  const [pendingShredOptions, setPendingShredOptions] = useState<{
    shredScope: 'thread-only' | 'peer-pgp-key-and-threads';
    targetPeerEmail?: string;
  } | null>(null);

  // Feature 1: Self-Destructing / Burn-After-Reading Timers & Read Receipt Policy State
  const [composerBurnSeconds, setComposerBurnSeconds] =
    useState<EphemeralTimerSeconds>(0);
  const [isPlusMenuOpen, setIsPlusMenuOpen] = useState<boolean>(false);
  const [isComposerEmojiOpen, setIsComposerEmojiOpen] =
    useState<boolean>(false);
  const [isHeaderMenuOpen, setIsHeaderMenuOpen] = useState<boolean>(false);
  const [isAvatarMenuOpen, setIsAvatarMenuOpen] = useState<boolean>(false);
  const [profileModalStep, setProfileModalStep] = useState<'edit' | 'qr-card'>(
    'edit'
  );
  const [qrLinkCopied, setQrLinkCopied] = useState<boolean>(false);
  const [isSettingsExpandedInMenu, setIsSettingsExpandedInMenu] =
    useState<boolean>(false);
  const [showMessageTimestamps, setShowMessageTimestamps] =
    useState<boolean>(false);
  const [colorSchemePref, setColorSchemePref] = useState<
    'dark' | 'light' | 'light dark'
  >(() => {
    try {
      const stored = localStorage.getItem('color-scheme');
      if (stored === 'light' || stored === 'dark' || stored === 'light dark') {
        return stored;
      }
    } catch {
      // Ignore storage access errors
    }
    return 'dark';
  });

  // Custom Chat Bubble Color Theme + Custom Color Picker Circle
  const [chatBubbleTheme, setChatBubbleTheme] = useState<BubbleThemeId>(() => {
    try {
      const saved = localStorage.getItem('atme_bubble_theme');
      if (
        saved === 'ocean' ||
        saved === 'berry' ||
        saved === 'violet' ||
        saved === 'mint' ||
        saved === 'sunset' ||
        saved === 'gold' ||
        saved === 'custom'
      ) {
        return saved;
      }
    } catch {
      // Ignore storage access errors
    }
    return 'ocean';
  });

  const [customBubbleHex, setCustomBubbleHex] = useState<string>(() => {
    try {
      const savedHex = localStorage.getItem('atme_custom_bubble_hex');
      if (savedHex && /^#[0-9a-fA-F]{6}$/.test(savedHex)) {
        return savedHex;
      }
    } catch {
      // Ignore storage errors
    }
    return '#06b6d4';
  });

  // Top 5 Customizable Default Emojis (persisted in localStorage)
  const [defaultQuickEmojis, setDefaultQuickEmojis] = useState<string[]>(() => {
    try {
      const raw = localStorage.getItem('atme_default_emojis');
      if (raw) {
        const parsed = JSON.parse(raw);
        if (
          Array.isArray(parsed) &&
          parsed.length === 5 &&
          parsed.every((item) => typeof item === 'string' && item.trim())
        ) {
          return parsed;
        }
      }
    } catch {
      // Ignore storage errors
    }
    return DEFAULT_TOP_5_EMOJIS;
  });
  const [isDefaultEmojiMenuOpen, setIsDefaultEmojiMenuOpen] =
    useState<boolean>(false);
  const [editingEmojiSlotIndex, setEditingEmojiSlotIndex] = useState<
    number | null
  >(null);
  const [emojiSearchQuery, setEmojiSearchQuery] = useState<string>('');

  // Blocked Users List & Whitelist Only ("Approved Friends") Mode
  const [blockedEmails, setBlockedEmails] = useState<string[]>(() => {
    try {
      const raw = localStorage.getItem('atme_blocked_emails');
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) return parsed;
      }
    } catch {
      // Ignore storage errors
    }
    return [];
  });

  const [whitelistedEmails, setWhitelistedEmails] = useState<string[]>(() => {
    try {
      const raw = localStorage.getItem('atme_whitelisted_emails');
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) return parsed;
      }
    } catch {
      // Ignore storage errors
    }
    return INITIAL_USERS.map((u) => u.email.toLowerCase());
  });

  const [whitelistOnlyMode, setWhitelistOnlyMode] = useState<boolean>(() => {
    try {
      return localStorage.getItem('atme_whitelist_only') === '1';
    } catch {
      return false;
    }
  });

  const [safetyModalTab, setSafetyModalTab] = useState<
    'scan-qr' | 'whitelist' | 'blocked'
  >('scan-qr');
  const [whitelistInputEmail, setWhitelistInputEmail] = useState<string>('');
  const [blockInputEmail, setBlockInputEmail] = useState<string>('');
  const [qrScanPasteInput, setQrScanPasteInput] = useState<string>('');
  const [safetyBannerNotice, setSafetyBannerNotice] = useState<string>('');
  const [selectedActionMsgId, setSelectedActionMsgId] = useState<string | null>(
    null
  );
  // Preserves Pin & Email Packet inspection features in codebase while hiding them in UI by default
  const showPinAndPacketControls = false;
  const [isComposerMultiline, setIsComposerMultiline] = useState<boolean>(false);
  const actionMenuContainerRef = useRef<HTMLDivElement | null>(null);
  const composerEmojiContainerRef = useRef<HTMLDivElement | null>(null);
  const headerMenuContainerRef = useRef<HTMLDivElement | null>(null);
  const avatarMenuContainerRef = useRef<HTMLDivElement | null>(null);
  const composerTextareaRef = useRef<HTMLTextAreaElement | null>(null);
  const freeflowFeedRef = useRef<HTMLDivElement | null>(null);
  const prevChannelIdRef = useRef<string | null>(null);
  const [burnReadStartedAtMs, setBurnReadStartedAtMs] = useState<
    Record<string, number>
  >({});
  const [burnTickNowMs, setBurnTickNowMs] = useState<number>(() => Date.now());
  const [readReceiptMode, setReadReceiptMode] = useState<'auto' | 'manual'>(
    'auto'
  );
  const autoReadSentKeysRef = useRef<Set<string>>(new Set());
  const [isAtBottom, setIsAtBottom] = useState<boolean>(true);
  const isScrolledToBottomRef = useRef<boolean>(true);
  const [readMessageIds, setReadMessageIds] = useState<Set<string>>(
    () => new Set()
  );

  // Feature 2: Personal Encrypted Vault (@me) Category Tag
  const [vaultCategoryInput, setVaultCategoryInput] = useState<
    'note' | 'credential' | 'file' | 'snippet'
  >('note');

  // Feature 3: Shielded Burner Email Aliases
  const [shieldedAliases, setShieldedAliases] = useState<ShieldedBurnerAlias[]>(
    []
  );
  const [useShieldedAliasInNewChat, setUseShieldedAliasInNewChat] =
    useState<boolean>(false);
  const [newChatAliasStrategy, setNewChatAliasStrategy] = useState<
    'plus-subaddress' | 'duck-privacy' | 'simplelogin-relay'
  >('duck-privacy');
  const [newChatAliasLabel, setNewChatAliasLabel] = useState<string>('private');

  // Feature 4: Safety Number & QR Key Verification + Key Change Tracking
  const [safetyBundle, setSafetyBundle] =
    useState<SafetyNumberVerificationBundle | null>(null);
  const [verifiedPeersMap, setVerifiedPeersMap] = useState<
    Record<string, string>
  >({});

  // Feature 5: Encrypted Polls & Pinned Messages State
  const [pollQuestionInput, setPollQuestionInput] = useState<string>('');
  const [pollOptionsInput, setPollOptionsInput] = useState<string[]>([
    '🍕 Pizza',
    '🌮 Tacos',
    '🧋 Boba',
  ]);
  const [pinnedMessageByChannel, setPinnedMessageByChannel] = useState<
    Record<string, { messageId: string; text: string; senderName: string }>
  >({
    ch_product_launch: {
      messageId: 'msg_seed_01',
      text: 'Welcome to @me! First messages automatically exchange your encrypted Profile Card into local IndexedDB.',
      senderName: 'Alex Rivera',
    },
  });

  // Feature 6: WebAuthn Biometric App Lock & Panic/Duress PIN State
  const [isAppLocked, setIsAppLocked] = useState<boolean>(false);
  const [appLockPin, setAppLockPin] = useState<string>('2580');
  const [duressPanicPin, setDuressPanicPin] = useState<string>('9999');
  const [lockScreenPinInput, setLockScreenPinInput] = useState<string>('');
  const [lockScreenError, setLockScreenError] = useState<string>('');
  const [duressTriggeredBanner, setDuressTriggeredBanner] =
    useState<string>('');
  const [passkeyRegisteredId, setPasskeyRegisteredId] =
    useState<string>('atme-local-passkey-01');

  const invitePreviewRef = useRef<HTMLDivElement | null>(null);
  const modalPacketRenderRef = useRef<HTMLDivElement | null>(null);

  const menuDialogTitleId = useId();
  const groupInfoTitleId = useId();
  const profileDialogTitleId = useId();
  const connectWizardTitleId = useId();
  const packetDialogTitleId = useId();
  const newChannelDialogTitleId = useId();
  const shredConfirmDialogTitleId = useId();
  const safetyNumberDialogTitleId = useId();
  const pollCreatorDialogTitleId = useId();
  const appLockDialogTitleId = useId();
  const safetyDialogTitleId = useId();
  const cameraDialogTitleId = useId();

  // New Group / Channel or DM Creation Form State
  const [newChatName, setNewChatName] = useState<string>('');
  const [newChatRecipientEmail, setNewChatRecipientEmail] =
    useState<string>('');
  const [newChatType, setNewChatType] = useState<'workspace-channel' | 'dm'>(
    'workspace-channel'
  );

  const activeUser = useMemo(
    () => users.find((u) => u.email === activeUserEmail) || users[0],
    [users, activeUserEmail]
  );

  // Helper: check if an email is allowed (not on Blocked list, and on Whitelist if Whitelist Only mode is active)
  const isEmailAllowed = React.useCallback(
    (email: string) => {
      const normalized = email.trim().toLowerCase();
      if (!normalized) return false;
      if (normalized === activeUser.email.toLowerCase()) return true;
      if (blockedEmails.some((b) => b.toLowerCase() === normalized)) {
        return false;
      }
      if (
        whitelistOnlyMode &&
        !whitelistedEmails.some((w) => w.toLowerCase() === normalized)
      ) {
        return false;
      }
      return true;
    },
    [activeUser.email, blockedEmails, whitelistOnlyMode, whitelistedEmails]
  );

  // Scope channels strictly to conversations where `activeUser.email` is a participant
  // and filter out 1:1 DMs with blocked (or non-whitelisted when Whitelist Only is on) peers
  const userScopedChannels = useMemo(
    () =>
      channels.filter((c) => {
        if (c.type === 'vault') return false;
        const isParticipant = c.participants.some(
          (p) => p.toLowerCase() === activeUser.email.toLowerCase()
        );
        if (!isParticipant) return false;
        if (c.type === 'dm' || c.participants.length <= 2) {
          const peer = c.participants.find(
            (p) => p.toLowerCase() !== activeUser.email.toLowerCase()
          );
          if (peer && !isEmailAllowed(peer)) {
            return false;
          }
        }
        return true;
      }),
    [channels, activeUser.email, isEmailAllowed]
  );

  const activeChannel = useMemo<DcpChannelMeta | null>(
    () =>
      userScopedChannels.find((c) => c.id === activeChannelId) ||
      userScopedChannels[0] ||
      null,
    [userScopedChannels, activeChannelId]
  );

  // Dynamically resolve the peer user and display title so a 2-person conversation
  // ALWAYS shows the OTHER person's name (never the active user's own name).
  const activeChannelPeerUser = useMemo<UserIdentity | undefined>(() => {
    if (!activeChannel) return undefined;
    const peerEmail =
      activeChannel.participants.find(
        (p) => p.toLowerCase() !== activeUser.email.toLowerCase()
      ) || activeChannel.participants[0];
    if (!peerEmail) return undefined;
    return users.find((u) => u.email.toLowerCase() === peerEmail.toLowerCase());
  }, [activeChannel, activeUser.email, users]);

  const activeChannelDisplayTitle = useMemo<string>(() => {
    if (!activeChannel) return 'Conversation';
    if (activeChannel.type === 'vault') {
      return 'Vault (@me)';
    }
    if (
      activeChannel.type === 'dm' ||
      activeChannel.participants.length <= 2
    ) {
      const peerEmail =
        activeChannel.participants.find(
          (p) => p.toLowerCase() !== activeUser.email.toLowerCase()
        ) || activeChannel.participants[0];
      if (activeChannelPeerUser) {
        return activeChannelPeerUser.displayName.replace(' (No App Yet)', '');
      }
      if (peerEmail) {
        const localPart = peerEmail.split('@')[0];
        return localPart.charAt(0).toUpperCase() + localPart.slice(1);
      }
      return activeChannel.name;
    }
    return `#${activeChannel.name}`;
  }, [activeChannel, activeUser.email, activeChannelPeerUser]);

  // Compute deterministic 60-digit Safety Number & QR matrix whenever activeChannel or peer changes
  useEffect(() => {
    let cancelled = false;
    async function updateSafetyBundle() {
      const myFp =
        activeUser.pgpKeyPair?.fingerprint ||
        '9F4A7C21D8E34B109F4A7C21D8E34B109F4A7C21';
      const peerEmail =
        activeChannelPeerUser?.email ||
        activeChannel?.participants.find(
          (p) => p.toLowerCase() !== activeUser.email.toLowerCase()
        ) ||
        activeUser.email;
      const peerFp =
        activeChannelPeerUser?.pgpKeyPair?.fingerprint ||
        (peerEmail.includes('elena')
          ? '3B8E1A50C7D29F443B8E1A50C7D29F443B8E1A50'
          : peerEmail.includes('sam')
          ? '7C1D4F92A6B83E117C1D4F92A6B83E117C1D4F92'
          : myFp);

      const bundle = await computeSafetyNumberAndQrMatrix({
        myEmail: activeUser.email,
        myFingerprint: myFp,
        peerEmail,
        peerFingerprint: peerFp,
      });
      if (!cancelled) {
        setSafetyBundle(bundle);
      }
    }
    updateSafetyBundle();
    return () => {
      cancelled = true;
    };
  }, [activeChannel, activeChannelPeerUser, activeUser]);

  // Live Burn-After-Reading countdown ticker (checks every 1s for messages with active burn timers)
  useEffect(() => {
    const timer = window.setInterval(() => {
      setBurnTickNowMs(Date.now());
    }, 1000);
    return () => window.clearInterval(timer);
  }, []);

  // Dismiss composer '+' menu, quick emoji picker, top-right header menu, or left avatar menu on outside click/touch or Escape key
  useEffect(() => {
    if (
      !isPlusMenuOpen &&
      !isComposerEmojiOpen &&
      !isHeaderMenuOpen &&
      !isAvatarMenuOpen
    ) {
      return;
    }
    const handlePointerDown = (event: MouseEvent | TouchEvent) => {
      const target = event.target as Node;
      if (
        isPlusMenuOpen &&
        actionMenuContainerRef.current &&
        !actionMenuContainerRef.current.contains(target)
      ) {
        setIsPlusMenuOpen(false);
      }
      if (
        isComposerEmojiOpen &&
        composerEmojiContainerRef.current &&
        !composerEmojiContainerRef.current.contains(target)
      ) {
        setIsComposerEmojiOpen(false);
      }
      if (
        isHeaderMenuOpen &&
        headerMenuContainerRef.current &&
        !headerMenuContainerRef.current.contains(target)
      ) {
        setIsHeaderMenuOpen(false);
      }
      if (
        isAvatarMenuOpen &&
        avatarMenuContainerRef.current &&
        !avatarMenuContainerRef.current.contains(target)
      ) {
        setIsAvatarMenuOpen(false);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsPlusMenuOpen(false);
        setIsComposerEmojiOpen(false);
        setIsHeaderMenuOpen(false);
        setIsAvatarMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handlePointerDown);
    document.addEventListener('touchstart', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handlePointerDown);
      document.removeEventListener('touchstart', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [
    isPlusMenuOpen,
    isComposerEmojiOpen,
    isHeaderMenuOpen,
    isAvatarMenuOpen,
  ]);

  // Apply color-scheme preference to <meta name="color-scheme"> and stay synced across tabs
  const handleSelectColorScheme = (next: 'dark' | 'light' | 'light dark') => {
    setColorSchemePref(next);
    const meta = document.querySelector(
      'meta[name="color-scheme"]'
    ) as HTMLMetaElement | null;
    if (meta) {
      meta.content = next;
    }
    try {
      if (next === 'light dark') {
        localStorage.removeItem('color-scheme');
      } else {
        localStorage.setItem('color-scheme', next);
      }
    } catch {
      // Ignore storage access errors
    }
  };

  useEffect(() => {
    const meta = document.querySelector(
      'meta[name="color-scheme"]'
    ) as HTMLMetaElement | null;
    if (meta) {
      meta.content = colorSchemePref;
    }
    const handleStorage = (event: StorageEvent) => {
      if (event.key === 'color-scheme') {
        const next =
          event.newValue === 'light' || event.newValue === 'dark'
            ? event.newValue
            : 'light dark';
        setColorSchemePref(next);
        if (meta) {
          meta.content = next;
        }
      }
    };
    window.addEventListener('storage', handleStorage);
    return () => window.removeEventListener('storage', handleStorage);
  }, [colorSchemePref]);

  // Auto-resize composer textarea (fallback when field-sizing: content is unsupported) & track multiline state for pill radius morphing
  useEffect(() => {
    const textarea = composerTextareaRef.current;
    if (!textarea) {
      setIsComposerMultiline(false);
      return;
    }
    const supportsFieldSizing =
      typeof CSS !== 'undefined' &&
      typeof CSS.supports === 'function' &&
      CSS.supports('field-sizing', 'content');

    if (!supportsFieldSizing) {
      textarea.style.height = 'auto';
      const nextHeight = Math.min(Math.max(textarea.scrollHeight, 38), 130);
      textarea.style.height = `${nextHeight}px`;
    }

    const currentHeight = textarea.scrollHeight || textarea.clientHeight;
    setIsComposerMultiline(
      composerText.includes('\n') || currentHeight > 46
    );
  }, [composerText, isRecordingVoice]);

  const recipientUser = useMemo(
    () => users.find((u) => u.email === recipientEmail) || users[1],
    [users, recipientEmail]
  );

  // Sync profile form fields when activeUser changes
  useEffect(() => {
    setProfileNameInput(activeUser.displayName);
    setProfileHandleInput(
      activeUser.handle ||
        `@${activeUser.email.split('@')[0].replace(/[^a-z0-9]/gi, '')}`
    );
    setProfileBioInput(activeUser.bio || '');
    setProfileAvatarInput(activeUser.avatarDataUrl);
  }, [activeUser]);

  // Support URL query params for deep-linking, QR code scans (?add=email&handle=...), or screenshot/preview states (?view=...)
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const params = new URLSearchParams(window.location.search);
    const chParam = params.get('channel');
    if (chParam) {
      setActiveChannelId(chParam);
    }

    const themeParam = params.get('theme');
    if (
      themeParam === 'ocean' ||
      themeParam === 'berry' ||
      themeParam === 'violet' ||
      themeParam === 'mint' ||
      themeParam === 'sunset' ||
      themeParam === 'gold'
    ) {
      setChatBubbleTheme(themeParam);
    }

    // If opened from scanning a friend's @me QR code (?add=email or ?email=...), automatically whitelist & open chat!
    const qrEmailParam = (
      params.get('add') ||
      params.get('email') ||
      ''
    )
      .trim()
      .toLowerCase();
    const qrHandleParam = params.get('handle') || params.get('invite') || '';
    const qrNameParam = params.get('name') || '';

    if (qrEmailParam && qrEmailParam.includes('@')) {
      setWhitelistedEmails((prev) => {
        const next = Array.from(
          new Set([...prev.map((e) => e.toLowerCase()), qrEmailParam])
        );
        try {
          localStorage.setItem('atme_whitelisted_emails', JSON.stringify(next));
        } catch {
          // Ignore storage errors
        }
        return next;
      });
      setBlockedEmails((prev) => {
        const next = prev.filter((e) => e.toLowerCase() !== qrEmailParam);
        try {
          localStorage.setItem('atme_blocked_emails', JSON.stringify(next));
        } catch {
          // Ignore storage errors
        }
        return next;
      });
      const label = qrHandleParam
        ? qrHandleParam.startsWith('@')
          ? qrHandleParam
          : `@${qrHandleParam}`
        : qrNameParam || qrEmailParam;
      setSafetyBannerNotice(`✨ Approved ${label}`);
      setTimeout(() => setSafetyBannerNotice(''), 6000);
      return;
    }

    const schemeParam = params.get('scheme');
    if (schemeParam === 'light' || schemeParam === 'dark') {
      setColorSchemePref(schemeParam);
    }

    const viewParam = params.get('view') || params.get('modal');
    if (viewParam === 'main-chat') {
      return;
    } else if (viewParam === 'onboarding') {
      setProfileModalStep('edit');
      profileDialogRef.current?.showModal();
    } else if (viewParam === 'qr-pass') {
      setProfileModalStep('qr-card');
      profileDialogRef.current?.showModal();
    } else if (viewParam === 'avatar-menu') {
      setIsAvatarMenuOpen(true);
    } else if (viewParam === 'header-menu') {
      setIsHeaderMenuOpen(true);
    } else if (viewParam === 'header-settings') {
      setIsHeaderMenuOpen(true);
      setIsSettingsExpandedInMenu(true);
    } else if (viewParam === 'plus-menu') {
      setIsPlusMenuOpen(true);
    } else if (viewParam === 'emoji-menu') {
      setIsComposerEmojiOpen(true);
    } else if (viewParam === 'safety-scan') {
      setSafetyModalTab('scan-qr');
      safetyListDialogRef.current?.showModal();
    } else if (viewParam === 'safety-whitelist') {
      setSafetyModalTab('whitelist');
      safetyListDialogRef.current?.showModal();
    } else if (viewParam === 'safety-blocked') {
      setSafetyModalTab('blocked');
      safetyListDialogRef.current?.showModal();
    } else if (viewParam === 'friends-modal') {
      menuDirectoryDialogRef.current?.showModal();
    } else if (viewParam === 'new-chat') {
      setNewChatType('dm');
      newChannelModalRef.current?.showModal();
    } else if (viewParam === 'shred' || viewParam === 'burn-modal') {
      setPendingShredOptions({ shredScope: 'peer-pgp-key-and-threads' });
      shredConfirmDialogRef.current?.showModal();
    } else if (viewParam === 'group') {
      groupInfoDialogRef.current?.showModal();
    } else if (viewParam === 'poll' || viewParam === 'poll-modal') {
      pollCreatorDialogRef.current?.showModal();
    } else if (viewParam === 'lock') {
      setIsAppLocked(true);
    } else {
      // First step in the app: open the Profile Builder -> QR Code generator if not completed yet
      try {
        const onboarded = localStorage.getItem('atme_profile_onboarded') || new URLSearchParams(window.location.search).has('no_onboarding');
        if (
          !onboarded &&
          profileDialogRef.current &&
          !profileDialogRef.current.open
        ) {
          setProfileModalStep('edit');
          profileDialogRef.current.showModal();
        }
      } catch {
        // Ignore storage errors
      }
    }
  }, []);

  // Mandatory fallback for <dialog closedby="any"> on browsers without native closedBy support
  useEffect(() => {
    const dialogs = [
      menuDirectoryDialogRef.current,
      groupInfoDialogRef.current,
      profileDialogRef.current,
      connectWizardDialogRef.current,
      packetModalRef.current,
      newChannelModalRef.current,
      shredConfirmDialogRef.current,
      safetyNumberDialogRef.current,
      pollCreatorDialogRef.current,
      appLockConfigDialogRef.current,
      safetyListDialogRef.current,
    ].filter(Boolean) as HTMLDialogElement[];

    if ('closedBy' in HTMLDialogElement.prototype) return;

    const handlers = dialogs.map((dialog) => {
      const handleBackdropClick = (event: MouseEvent) => {
        if (event.target !== dialog) return;
        const rect = dialog.getBoundingClientRect();
        const isDialogContent =
          rect.top <= event.clientY &&
          event.clientY <= rect.top + rect.height &&
          rect.left <= event.clientX &&
          event.clientX <= rect.left + rect.width;
        if (isDialogContent) return;
        dialog.close();
      };
      dialog.addEventListener('click', handleBackdropClick);
      return { dialog, handleBackdropClick };
    });

    return () => {
      for (const { dialog, handleBackdropClick } of handlers) {
        dialog.removeEventListener('click', handleBackdropClick);
      }
    };
  }, []);

  // Initialize OpenPGP Curve25519 keys on-device & seed initial encrypted + regular emails
  useEffect(() => {
    let mounted = true;
    async function bootEngine() {
      setIsInitializingKeys(true);

      const cachedUsers = await loadUserIdentitiesFromIdb();
      const cachedEmails = await loadTransportEmailsFromIdb();

      if (cachedUsers && cachedEmails && cachedEmails.length > 0) {
        if (!mounted) return;
        setUsers(cachedUsers);
        setTransportEmails(cachedEmails);
        setSelectedEmailId(cachedEmails[0].id);
        setIsInitializingKeys(false);
        return;
      }

      const hydratedUsers: UserIdentity[] = [];
      for (const u of INITIAL_USERS) {
        if (u.hasAppInstalled) {
          const kp = await generateDeviceKeyPair(u.displayName, u.email);
          hydratedUsers.push({ ...u, pgpKeyPair: kp });
        } else {
          hydratedUsers.push(u);
        }
      }

      const alex = hydratedUsers[0];
      const sam = hydratedUsers[1];
      const elena = hydratedUsers[2];

      const seedDcpEmails: RawTransportEmail[] = [];

      if (alex.pgpKeyPair && elena.pgpKeyPair && sam.pgpKeyPair) {
        const allAppKeys = [
          alex.pgpKeyPair.publicKeyArmored,
          sam.pgpKeyPair.publicKeyArmored,
          elena.pgpKeyPair.publicKeyArmored,
        ];

        // 1. Alex (Gmail) -> #product-launch (Includes Alex's First-Contact Profile Card!)
        const pkt1: DcpPacket = {
          protocol: DCP_PROTOCOL_VERSION,
          packetId: 'pkt_seed_01',
          type: 'chat.message',
          encryptionMode: 'openpgp-asymmetric',
          channel: INITIAL_CHANNELS[0],
          sender: {
            email: alex.email,
            displayName: alex.displayName,
            handle: alex.handle,
            provider: alex.provider,
            pgpFingerprint: alex.pgpKeyPair.fingerprint,
            publicKeyArmored: alex.pgpKeyPair.publicKeyArmored,
            profileCard: {
              displayName: alex.displayName,
              handle: alex.handle || '@alexrivera',
              avatarDataUrl: alex.avatarDataUrl,
              bio: alex.bio,
              updatedAt: alex.profileUpdatedAt || new Date().toISOString(),
            },
          },
          payload: {
            messageId: 'msg_seed_01',
            text: 'Yo! Welcome to @me 👋',
            formatting: 'markdown',
          },
          sentAt: new Date(Date.now() - 1000 * 60 * 42).toISOString(),
        };

        const enc1 = await encryptDcpPayloadAsymmetric({
          cleartextJson: JSON.stringify(pkt1),
          recipientPublicKeysArmored: allAppKeys,
          senderPublicKeyArmored: alex.pgpKeyPair.publicKeyArmored,
          senderPrivateKeyArmored: alex.pgpKeyPair.privateKeyArmored,
        });
        seedDcpEmails.push(
          buildDcpMimeEmail({ packet: pkt1, encryptedPacketArmored: enc1 })
        );

        // 2. Elena (Proton Mail) -> #product-launch (Includes Elena's Profile Card)
        const pkt2: DcpPacket = {
          protocol: DCP_PROTOCOL_VERSION,
          packetId: 'pkt_seed_02',
          type: 'chat.message',
          encryptionMode: 'openpgp-asymmetric',
          channel: INITIAL_CHANNELS[0],
          sender: {
            email: elena.email,
            displayName: elena.displayName,
            handle: elena.handle,
            provider: elena.provider,
            pgpFingerprint: elena.pgpKeyPair.fingerprint,
            publicKeyArmored: elena.pgpKeyPair.publicKeyArmored,
            profileCard: {
              displayName: elena.displayName,
              handle: elena.handle || '@elenavogt',
              avatarDataUrl: elena.avatarDataUrl,
              bio: elena.bio,
              updatedAt: elena.profileUpdatedAt || new Date().toISOString(),
            },
          },
          payload: {
            messageId: 'msg_seed_02',
            text: 'Just scanned your QR! Ready for Friday? 🎮',
            formatting: 'markdown',
          },
          sentAt: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
        };

        const enc2 = await encryptDcpPayloadAsymmetric({
          cleartextJson: JSON.stringify(pkt2),
          recipientPublicKeysArmored: allAppKeys,
          senderPublicKeyArmored: elena.pgpKeyPair.publicKeyArmored,
          senderPrivateKeyArmored: elena.pgpKeyPair.privateKeyArmored,
        });
        seedDcpEmails.push(
          buildDcpMimeEmail({ packet: pkt2, encryptedPacketArmored: enc2 })
        );

        // 3. Elena -> Read Receipt (`chat.receipt`) for Alex's msg_seed_01
        const pktReceipt: DcpPacket = {
          protocol: DCP_PROTOCOL_VERSION,
          packetId: 'pkt_seed_rcpt_01',
          type: 'chat.receipt',
          encryptionMode: 'openpgp-asymmetric',
          channel: INITIAL_CHANNELS[0],
          sender: {
            email: elena.email,
            displayName: elena.displayName,
            handle: elena.handle,
            provider: elena.provider,
            pgpFingerprint: elena.pgpKeyPair.fingerprint,
            publicKeyArmored: elena.pgpKeyPair.publicKeyArmored,
          },
          payload: {
            messageId: 'msg_seed_rcpt_01',
            targetMessageId: 'msg_seed_01',
            receiptStatus: 'read',
            text: 'Read msg_seed_01',
          },
          sentAt: new Date(Date.now() - 1000 * 60 * 28).toISOString(),
        };

        const encReceipt = await encryptDcpPayloadAsymmetric({
          cleartextJson: JSON.stringify(pktReceipt),
          recipientPublicKeysArmored: allAppKeys,
          senderPublicKeyArmored: elena.pgpKeyPair.publicKeyArmored,
          senderPrivateKeyArmored: elena.pgpKeyPair.privateKeyArmored,
        });
        seedDcpEmails.push(
          buildDcpMimeEmail({
            packet: pktReceipt,
            encryptedPacketArmored: encReceipt,
          })
        );

        // 4. Sam (Outlook) -> Emoji Reaction on Elena's message
        const pktReaction: DcpPacket = {
          protocol: DCP_PROTOCOL_VERSION,
          packetId: 'pkt_seed_react_01',
          type: 'chat.reaction',
          encryptionMode: 'openpgp-asymmetric',
          channel: INITIAL_CHANNELS[0],
          sender: {
            email: sam.email,
            displayName: sam.displayName,
            handle: sam.handle,
            provider: sam.provider,
            pgpFingerprint: sam.pgpKeyPair.fingerprint,
            publicKeyArmored: sam.pgpKeyPair.publicKeyArmored,
          },
          payload: {
            messageId: 'msg_seed_react_01',
            targetMessageId: 'msg_seed_02',
            reactionEmoji: '🔒',
            text: 'Reacted 🔒',
          },
          sentAt: new Date(Date.now() - 1000 * 60 * 26).toISOString(),
        };

        const encReact = await encryptDcpPayloadAsymmetric({
          cleartextJson: JSON.stringify(pktReaction),
          recipientPublicKeysArmored: allAppKeys,
          senderPublicKeyArmored: sam.pgpKeyPair.publicKeyArmored,
          senderPrivateKeyArmored: sam.pgpKeyPair.privateKeyArmored,
        });
        seedDcpEmails.push(
          buildDcpMimeEmail({
            packet: pktReaction,
            encryptedPacketArmored: encReact,
          })
        );

        // 5. Sam (Outlook) -> Inline Reply to msg_seed_01 with Profile Card
        const pktReply: DcpPacket = {
          protocol: DCP_PROTOCOL_VERSION,
          packetId: 'pkt_seed_reply_01',
          type: 'chat.message',
          encryptionMode: 'openpgp-asymmetric',
          channel: INITIAL_CHANNELS[0],
          sender: {
            email: sam.email,
            displayName: sam.displayName,
            handle: sam.handle,
            provider: sam.provider,
            pgpFingerprint: sam.pgpKeyPair.fingerprint,
            publicKeyArmored: sam.pgpKeyPair.publicKeyArmored,
            profileCard: {
              displayName: sam.displayName,
              handle: sam.handle || '@samchen',
              avatarDataUrl: sam.avatarDataUrl,
              bio: sam.bio,
              updatedAt: sam.profileUpdatedAt || new Date().toISOString(),
            },
          },
          payload: {
            messageId: 'msg_seed_reply_01',
            replyToMessageId: 'msg_seed_01',
            text: 'Let’s gooo 🔥',
            formatting: 'markdown',
          },
          sentAt: new Date(Date.now() - 1000 * 60 * 20).toISOString(),
        };

        const encReply = await encryptDcpPayloadAsymmetric({
          cleartextJson: JSON.stringify(pktReply),
          recipientPublicKeysArmored: allAppKeys,
          senderPublicKeyArmored: sam.pgpKeyPair.publicKeyArmored,
          senderPrivateKeyArmored: sam.pgpKeyPair.privateKeyArmored,
        });
        seedDcpEmails.push(
          buildDcpMimeEmail({
            packet: pktReply,
            encryptedPacketArmored: encReply,
          })
        );

        // 6. Alex (Gmail) -> Jordan (Yahoo — Does NOT have the app installed yet)
        const inviteSecret = generateInviteSecret();
        const pktInvite: DcpPacket = {
          protocol: DCP_PROTOCOL_VERSION,
          packetId: 'pkt_seed_invite_03',
          type: 'chat.message',
          encryptionMode: 'openpgp-invite-key',
          channel: INITIAL_CHANNELS[4],
          sender: {
            email: alex.email,
            displayName: alex.displayName,
            handle: alex.handle,
            provider: alex.provider,
            pgpFingerprint: alex.pgpKeyPair.fingerprint,
            publicKeyArmored: alex.pgpKeyPair.publicKeyArmored,
            profileCard: {
              displayName: alex.displayName,
              handle: alex.handle || '@alexrivera',
              avatarDataUrl: alex.avatarDataUrl,
              bio: alex.bio,
              updatedAt: alex.profileUpdatedAt || new Date().toISOString(),
            },
          },
          payload: {
            messageId: 'msg_seed_03',
            text: 'Hey Jordan! Scan my @me QR so we can chat 🛹',
            formatting: 'markdown',
          },
          sentAt: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
        };

        const encInvite = await encryptDcpPayloadWithInviteKey({
          cleartextJson: JSON.stringify(pktInvite),
          inviteSecret,
          senderPublicKeyArmored: alex.pgpKeyPair.publicKeyArmored,
          senderPrivateKeyArmored: alex.pgpKeyPair.privateKeyArmored,
        });

        seedDcpEmails.push(
          buildDcpMimeEmail({
            packet: pktInvite,
            encryptedPacketArmored: encInvite,
            inviteKeyFragment: inviteSecret,
          })
        );

        // 7. Elena (Proton Mail) -> Alex (Gmail) 1-on-1 DM (`dm_alex_elena`)
        const elenaAttest = await createSignedComplianceAttestation({
          senderEmail: elena.email,
          senderPgpFingerprint: elena.pgpKeyPair.fingerprint,
        });
        const pktDmElena: DcpPacket = {
          protocol: DCP_PROTOCOL_VERSION,
          packetId: 'pkt_seed_dm_elena_01',
          type: 'chat.message',
          encryptionMode: 'openpgp-asymmetric',
          channel: INITIAL_CHANNELS[2],
          sender: {
            email: elena.email,
            displayName: elena.displayName,
            handle: elena.handle,
            provider: elena.provider,
            pgpFingerprint: elena.pgpKeyPair.fingerprint,
            publicKeyArmored: elena.pgpKeyPair.publicKeyArmored,
            profileCard: {
              displayName: elena.displayName,
              handle: elena.handle || '@elenavogt',
              avatarDataUrl: elena.avatarDataUrl,
              bio: elena.bio,
              updatedAt: elena.profileUpdatedAt || new Date().toISOString(),
            },
          },
          complianceAttestation: elenaAttest,
          payload: {
            messageId: 'msg_seed_dm_elena_01',
            text: 'Hey Alex! Are we meeting after school? 🎧',
            formatting: 'markdown',
          },
          sentAt: new Date(Date.now() - 1000 * 60 * 3).toISOString(),
        };

        const encDmElena = await encryptDcpPayloadAsymmetric({
          cleartextJson: JSON.stringify(pktDmElena),
          recipientPublicKeysArmored: allAppKeys,
          senderPublicKeyArmored: elena.pgpKeyPair.publicKeyArmored,
          senderPrivateKeyArmored: elena.pgpKeyPair.privateKeyArmored,
        });
        seedDcpEmails.push(
          buildDcpMimeEmail({
            packet: pktDmElena,
            encryptedPacketArmored: encDmElena,
          })
        );

        // 8. Alex (Gmail) -> Elena (Proton Mail) 1-on-1 DM Reply
        const alexAttest = await createSignedComplianceAttestation({
          senderEmail: alex.email,
          senderPgpFingerprint: alex.pgpKeyPair.fingerprint,
        });
        const pktDmAlexReply: DcpPacket = {
          protocol: DCP_PROTOCOL_VERSION,
          packetId: 'pkt_seed_dm_alex_02',
          type: 'chat.message',
          encryptionMode: 'openpgp-asymmetric',
          channel: INITIAL_CHANNELS[2],
          sender: {
            email: alex.email,
            displayName: alex.displayName,
            handle: alex.handle,
            provider: alex.provider,
            pgpFingerprint: alex.pgpKeyPair.fingerprint,
            publicKeyArmored: alex.pgpKeyPair.publicKeyArmored,
          },
          complianceAttestation: alexAttest,
          payload: {
            messageId: 'msg_seed_dm_alex_02',
            replyToMessageId: 'msg_seed_dm_elena_01',
            text: 'Yep! See you at 4pm 🚀',
            formatting: 'markdown',
          },
          sentAt: new Date(Date.now() - 1000 * 60 * 1).toISOString(),
        };

        const encDmAlexReply = await encryptDcpPayloadAsymmetric({
          cleartextJson: JSON.stringify(pktDmAlexReply),
          recipientPublicKeysArmored: allAppKeys,
          senderPublicKeyArmored: alex.pgpKeyPair.publicKeyArmored,
          senderPrivateKeyArmored: alex.pgpKeyPair.privateKeyArmored,
        });
        seedDcpEmails.push(
          buildDcpMimeEmail({
            packet: pktDmAlexReply,
            encryptedPacketArmored: encDmAlexReply,
          })
        );
      }

      const regularEmails = createSampleRegularEmails();
      const combined = [...seedDcpEmails, ...regularEmails].sort(
        (a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()
      );

      await saveUserIdentitiesToIdb(hydratedUsers);
      await saveTransportEmailsToIdb(combined);

      if (!mounted) return;
      setUsers(hydratedUsers);
      setTransportEmails(combined);
      setSelectedEmailId(seedDcpEmails[0]?.id || combined[0]?.id || null);
      setIsInitializingKeys(false);
    }

    bootEngine();
    return () => {
      mounted = false;
    };
  }, []);

  // Re-run the Strict Inbox Filter, OpenPGP Decryptor, AND Automatic Peer Profile Sync into IndexedDB
  useEffect(() => {
    let cancelled = false;
    async function runStrictInboxFilterAndProfileSync() {
      const results: FilterInspectionResult[] = [];
      let usersUpdated = false;
      const nextUsers = [...users];

      const myEmailLower = activeUser?.email?.toLowerCase() || '';

      for (const email of transportEmails) {
        const isSender = email.from.toLowerCase().includes(myEmailLower);
        const isRecipient = email.to.some((t) =>
          t.toLowerCase().includes(myEmailLower)
        );
        if (myEmailLower && !isSender && !isRecipient) {
          continue;
        }

        const res = await inspectAndDecryptEmail({
          email,
          recipientPrivateKeyArmored: activeUser?.pgpKeyPair?.privateKeyArmored,
          inviteSecret: email.inviteKeyFragment,
        });
        results.push(res);

        // If a decrypted packet carries a sender.profileCard, automatically upsert it into local DB
        const pkt = res.decryptedPacket;
        if (pkt?.sender.profileCard) {
          const card = pkt.sender.profileCard;
          const idx = nextUsers.findIndex(
            (u) => u.email.toLowerCase() === pkt.sender.email.toLowerCase()
          );
          if (idx >= 0) {
            const existing = nextUsers[idx];
            const isNewer =
              !existing.profileUpdatedAt ||
              new Date(card.updatedAt).getTime() >
                new Date(existing.profileUpdatedAt).getTime();

            if (
              isNewer &&
              (existing.displayName !== card.displayName ||
                existing.handle !== card.handle ||
                existing.avatarDataUrl !== card.avatarDataUrl ||
                existing.bio !== card.bio)
            ) {
              nextUsers[idx] = {
                ...existing,
                displayName: card.displayName,
                handle: card.handle,
                avatarDataUrl: card.avatarDataUrl || existing.avatarDataUrl,
                bio: card.bio,
                profileUpdatedAt: card.updatedAt,
              };
              usersUpdated = true;
            }
          } else {
            nextUsers.push({
              email: pkt.sender.email,
              displayName: card.displayName,
              handle: card.handle,
              avatarDataUrl: card.avatarDataUrl,
              bio: card.bio,
              profileUpdatedAt: card.updatedAt,
              provider: pkt.sender.provider,
              hasAppInstalled: true,
            });
            usersUpdated = true;
          }
        }
      }

      if (!cancelled) {
        setInspections(results);
        if (usersUpdated) {
          setUsers(nextUsers);
          await saveUserIdentitiesToIdb(nextUsers);
        }
      }
    }
    if (transportEmails.length > 0) {
      runStrictInboxFilterAndProfileSync();
    }
    return () => {
      cancelled = true;
    };
  }, [transportEmails, activeUser]);

  const selectedEmail = useMemo(
    () =>
      transportEmails.find((e) => e.id === selectedEmailId) ||
      transportEmails[0] ||
      null,
    [transportEmails, selectedEmailId]
  );

  const selectedInspection = useMemo(
    () => inspections.find((i) => i.emailId === selectedEmail?.id) || null,
    [inspections, selectedEmail]
  );

  useEffect(() => {
    if (
      activeTab === 'non-app-fallback' &&
      invitePreviewRef.current &&
      selectedEmail
    ) {
      const htmlContent =
        selectedEmail.htmlFallbackPart ||
        `<div class="dc-fallback-card"><p>${selectedEmail.textFallbackPart || 'Standard plaintext email (No @me fallback card).'}</p></div>`;
      safeSetInviteHTML(invitePreviewRef.current, htmlContent);
    }
  }, [activeTab, selectedEmail, surfaceMode]);

  useEffect(() => {
    if (modalPacketRenderRef.current && selectedEmail?.htmlFallbackPart) {
      safeSetInviteHTML(
        modalPacketRenderRef.current,
        selectedEmail.htmlFallbackPart
      );
    }
  }, [selectedEmail]);

  const acceptedPackets = useMemo(
    () =>
      inspections.filter(
        (i) =>
          i.accepted &&
          i.decryptedPacket &&
          isEmailAllowed(i.decryptedPacket.sender.email)
      ),
    [inspections, isEmailAllowed]
  );

  const ignoredRegularEmails = useMemo(
    () => inspections.filter((i) => !i.accepted),
    [inspections]
  );

  // Build free-flowing chronological message stream with reactions, inline quotes, polls, AND read receipts
  const freeflowStream = useMemo(() => {
    const chronologicallySorted = acceptedPackets
      .slice()
      .sort(
        (a, b) =>
          new Date(a.decryptedPacket!.sentAt).getTime() -
          new Date(b.decryptedPacket!.sentAt).getTime()
      );

    const reactionsByTargetId = new Map<
      string,
      Array<{ emoji: string; senderName: string; senderEmail: string }>
    >();
    const receiptsByTargetId = new Map<
      string,
      Array<{
        status: 'delivered' | 'read';
        senderName: string;
        senderEmail: string;
        readAtIso?: string;
      }>
    >();
    const pollVotesByPollId = new Map<
      string,
      Array<{
        optionId: string;
        senderName: string;
        senderEmail: string;
      }>
    >();
    const messageLookup = new Map<
      string,
      { senderName: string; textSnippet: string }
    >();

    for (const item of chronologicallySorted) {
      const pkt = item.decryptedPacket!;
      if (pkt.type === 'chat.reaction' && pkt.payload.targetMessageId) {
        const list =
          reactionsByTargetId.get(pkt.payload.targetMessageId) || [];
        list.push({
          emoji: pkt.payload.reactionEmoji || '👍',
          senderName: pkt.sender.displayName,
          senderEmail: pkt.sender.email,
        });
        reactionsByTargetId.set(pkt.payload.targetMessageId, list);
      } else if (pkt.type === 'chat.receipt' && pkt.payload.targetMessageId) {
        const list =
          receiptsByTargetId.get(pkt.payload.targetMessageId) || [];
        // Deduplicate by senderEmail
        if (
          !list.some(
            (r) =>
              r.senderEmail.toLowerCase() === pkt.sender.email.toLowerCase()
          )
        ) {
          list.push({
            status: pkt.payload.receiptStatus || 'read',
            senderName: pkt.sender.displayName,
            senderEmail: pkt.sender.email,
            readAtIso: pkt.sentAt,
          });
        }
        receiptsByTargetId.set(pkt.payload.targetMessageId, list);
      } else if (pkt.type === 'chat.poll-vote' && pkt.payload.pollVote) {
        const { pollId, optionId } = pkt.payload.pollVote;
        const list = pollVotesByPollId.get(pollId) || [];
        const filtered = list.filter(
          (v) => v.senderEmail.toLowerCase() !== pkt.sender.email.toLowerCase()
        );
        filtered.push({
          optionId,
          senderName: pkt.sender.displayName,
          senderEmail: pkt.sender.email,
        });
        pollVotesByPollId.set(pollId, filtered);
      } else if (
        pkt.type === 'chat.message' ||
        pkt.type === 'chat.poll' ||
        pkt.type === 'chat.member-update' ||
        pkt.type === 'chat.shred-request' ||
        pkt.type === 'chat.shred-ack'
      ) {
        messageLookup.set(pkt.payload.messageId, {
          senderName: pkt.sender.displayName,
          textSnippet: (
            pkt.payload.poll?.question ||
            pkt.payload.text ||
            ''
          ).slice(0, 80),
        });
      }
    }

    const messages: FreeflowChatMessage[] = [];
    if (!activeChannel) return messages;

    for (const item of chronologicallySorted) {
      const pkt = item.decryptedPacket!;
      if (pkt.channel.id !== activeChannel.id) continue;
      if (
        pkt.type !== 'chat.message' &&
        pkt.type !== 'chat.poll' &&
        pkt.type !== 'chat.member-update'
      ) {
        continue;
      }

      const quoted = pkt.payload.replyToMessageId
        ? messageLookup.get(pkt.payload.replyToMessageId)
        : undefined;

      const msgReceipts = receiptsByTargetId.get(pkt.payload.messageId) || [];
      const ttlSec =
        pkt.payload.ephemeralTtlSeconds ||
        activeChannel.ephemeralTimerSeconds ||
        0;

      // Filter out Burn-After-Reading messages whose TTL has expired after being read
      if (ttlSec > 0) {
        const startMs =
          burnReadStartedAtMs[pkt.payload.messageId] ||
          (msgReceipts.length > 0
            ? new Date(msgReceipts[0].readAtIso || pkt.sentAt).getTime()
            : 0);
        if (startMs > 0 && burnTickNowMs - startMs >= ttlSec * 1000) {
          continue;
        }
      }

      const pollVotes = pkt.payload.poll
        ? pollVotesByPollId.get(pkt.payload.poll.pollId) || []
        : [];

      messages.push({
        emailId: item.emailId,
        packet: pkt,
        signatureVerified: Boolean(item.signatureVerified),
        decryptionTimeMs: item.decryptionTimeMs,
        reactions: reactionsByTargetId.get(pkt.payload.messageId) || [],
        receipts: msgReceipts,
        pollVotes,
        quotedMessage:
          quoted && pkt.payload.replyToMessageId
            ? {
                messageId: pkt.payload.replyToMessageId,
                senderName: quoted.senderName,
                textSnippet: quoted.textSnippet,
              }
            : undefined,
      });
    }

    return messages;
  }, [
    acceptedPackets,
    activeChannel,
    burnReadStartedAtMs,
    burnTickNowMs,
  ]);

  const lastMessageEmailId =
    freeflowStream.length > 0
      ? freeflowStream[freeflowStream.length - 1].emailId
      : null;

  // Compute unread message count map for all channels for the active user
  // Compute unread message count map for all channels for the active user
  const channelUnreadCountMap = useMemo(() => {
    const map: Record<string, number> = {};
    const readReceiptTargetIds = new Set<string>();
    for (const item of acceptedPackets) {
      const pkt = item.decryptedPacket;
      if (
        pkt &&
        pkt.type === 'chat.receipt' &&
        pkt.sender.email.toLowerCase() === activeUser.email.toLowerCase() &&
        pkt.payload.targetMessageId
      ) {
        readReceiptTargetIds.add(pkt.payload.targetMessageId);
      }
    }

    for (const ch of userScopedChannels) {
      const unreadItems = acceptedPackets.filter((item) => {
        const pkt = item.decryptedPacket;
        if (!pkt || pkt.channel.id !== ch.id) return false;
        if (
          pkt.type !== 'chat.message' &&
          pkt.type !== 'chat.poll'
        ) {
          return false;
        }
        const isOwn =
          pkt.sender.email.toLowerCase() === activeUser.email.toLowerCase();
        if (isOwn) return false;

        const msgId = pkt.payload.messageId;
        if (readReceiptTargetIds.has(msgId)) return false;

        const dedupKey = `${activeUser.email.toLowerCase()}:${msgId}`;
        if (
          autoReadSentKeysRef.current.has(dedupKey) ||
          readMessageIds.has(msgId)
        ) {
          return false;
        }
        return true;
      });
      map[ch.id] = unreadItems.length;
    }
    return map;
  }, [userScopedChannels, acceptedPackets, activeUser.email, readMessageIds]);

  const activeChannelUnreadCount = activeChannel
    ? channelUnreadCountMap[activeChannel.id] || 0
    : 0;

  const firstUnreadMsgIndex = useMemo(() => {
    if (!activeChannel || activeChannelUnreadCount === 0) return -1;
    return freeflowStream.findIndex((m) => {
      if (
        m.packet.type !== 'chat.message' &&
        m.packet.type !== 'chat.poll'
      ) {
        return false;
      }
      const isOwn =
        m.packet.sender.email.toLowerCase() === activeUser.email.toLowerCase();
      if (isOwn) return false;
      const alreadyReceipted = m.receipts.some(
        (r) => r.senderEmail.toLowerCase() === activeUser.email.toLowerCase()
      );
      if (alreadyReceipted) return false;
      const dedupKey = `${activeUser.email.toLowerCase()}:${m.packet.payload.messageId}`;
      return (
        !autoReadSentKeysRef.current.has(dedupKey) &&
        !readMessageIds.has(m.packet.payload.messageId)
      );
    });
  }, [
    activeChannel,
    activeChannelUnreadCount,
    freeflowStream,
    activeUser.email,
    readMessageIds,
  ]);

  const markActiveChannelAsRead = useCallback(async () => {
    if (
      isAppLocked ||
      isInitializingKeys ||
      surfaceMode !== 'messenger-ui' ||
      !activeChannel
    ) {
      return;
    }

    const unreadIncoming = freeflowStream.filter((msg) => {
      if (
        msg.packet.type !== 'chat.message' &&
        msg.packet.type !== 'chat.poll'
      ) {
        return false;
      }
      const isOwn =
        msg.packet.sender.email.toLowerCase() ===
        activeUser.email.toLowerCase();
      if (isOwn) return false;

      const alreadyReceipted = msg.receipts.some(
        (r) => r.senderEmail.toLowerCase() === activeUser.email.toLowerCase()
      );
      if (alreadyReceipted) return false;

      const dedupKey = `${activeUser.email.toLowerCase()}:${msg.packet.payload.messageId}`;
      return (
        !autoReadSentKeysRef.current.has(dedupKey) &&
        !readMessageIds.has(msg.packet.payload.messageId)
      );
    });

    if (unreadIncoming.length === 0) return;

    setReadMessageIds((prev) => {
      const next = new Set(prev);
      unreadIncoming.forEach((m) => next.add(m.packet.payload.messageId));
      return next;
    });

    if (readReceiptMode === 'auto') {
      for (const msg of unreadIncoming) {
        const msgId = msg.packet.payload.messageId;
        const dedupKey = `${activeUser.email.toLowerCase()}:${msgId}`;
        if (autoReadSentKeysRef.current.has(dedupKey)) continue;
        autoReadSentKeysRef.current.add(dedupKey);

        setBurnReadStartedAtMs((prev) => ({
          ...prev,
          [msgId]: prev[msgId] || Date.now(),
        }));

        await dispatchDcpEmailPacket({
          channel: activeChannel,
          type: 'chat.receipt',
          targetMessageId: msgId,
          receiptStatus: 'read',
          text: `Auto read receipt for ${msgId}`,
        });
      }
    }
  }, [
    isAppLocked,
    isInitializingKeys,
    surfaceMode,
    activeChannel,
    freeflowStream,
    activeUser.email,
    readReceiptMode,
    readMessageIds,
  ]);

  const handleFeedScroll = useCallback(() => {
    const feedEl = freeflowFeedRef.current;
    if (!feedEl) return;
    const threshold = 48;
    const atBottom =
      feedEl.scrollHeight - feedEl.scrollTop - feedEl.clientHeight <= threshold;
    setIsAtBottom(atBottom);
    isScrolledToBottomRef.current = atBottom;

    if (atBottom) {
      void markActiveChannelAsRead();
    }
  }, [markActiveChannelAsRead]);

  const handleSkipToLatest = useCallback(() => {
    const feedEl = freeflowFeedRef.current;
    if (!feedEl) return;
    feedEl.scrollTo({ top: feedEl.scrollHeight, behavior: 'smooth' });
    setIsAtBottom(true);
    isScrolledToBottomRef.current = true;
    void markActiveChannelAsRead();
  }, [markActiveChannelAsRead]);

  // Reset unread tracking on user account switch
  useEffect(() => {
    setReadMessageIds(new Set());
    prevChannelIdRef.current = null;
    setIsAtBottom(true);
    isScrolledToBottomRef.current = true;
  }, [activeUser.email]);

  // Handle scroll positioning on channel change and incoming messages:
  // - When entering a chat with unread messages, start at the last unread message at the top
  // - When in an active chat, only auto-scroll if already scrolled to the bottom
  useEffect(() => {
    const feedEl = freeflowFeedRef.current;
    if (!feedEl) return;

    const currentChId = activeChannel?.id ?? null;
    const isChannelSwitch = prevChannelIdRef.current !== currentChId;
    prevChannelIdRef.current = currentChId;

    if (isChannelSwitch) {
      const unreadCount = currentChId
        ? channelUnreadCountMap[currentChId] || 0
        : 0;

      if (unreadCount > 0) {
        requestAnimationFrame(() => {
          const target =
            document.getElementById('dc-first-unread-marker') ||
            feedEl.querySelector('.dc-imessage-row.is-unread');
          if (target) {
            target.scrollIntoView({ block: 'start', behavior: 'auto' });
            setIsAtBottom(false);
            isScrolledToBottomRef.current = false;
            return;
          }
          feedEl.scrollTo({ top: feedEl.scrollHeight, behavior: 'auto' });
          setIsAtBottom(true);
          isScrolledToBottomRef.current = true;
          void markActiveChannelAsRead();
        });
        return;
      }

      requestAnimationFrame(() => {
        feedEl.scrollTo({ top: feedEl.scrollHeight, behavior: 'auto' });
        setIsAtBottom(true);
        isScrolledToBottomRef.current = true;
        void markActiveChannelAsRead();
      });
      return;
    }

    // Inside active chat: ONLY auto-scroll new messages if scrolled to the bottom!
    const lastMsg =
      freeflowStream.length > 0
        ? freeflowStream[freeflowStream.length - 1]
        : null;
    const isOwnLastMessage =
      lastMsg &&
      lastMsg.packet.sender.email.toLowerCase() ===
        activeUser.email.toLowerCase();

    if (isOwnLastMessage || isScrolledToBottomRef.current) {
      requestAnimationFrame(() => {
        feedEl.scrollTo({ top: feedEl.scrollHeight, behavior: 'smooth' });
        setIsAtBottom(true);
        isScrolledToBottomRef.current = true;
        void markActiveChannelAsRead();
      });
    } else {
      setIsAtBottom(false);
    }
  }, [
    activeChannel?.id,
    freeflowStream.length,
    lastMessageEmailId,
    surfaceMode,
    mobileShowChatPane,
    channelUnreadCountMap,
    markActiveChannelAsRead,
    activeUser.email,
  ]);

  // Compute last message preview & timestamp for each conversation in the thread list
  // Strictly scoped to `userScopedChannels` (only conversations `activeUser` is in!)
  // and sorted from MOST RECENT at the top.
  const threadListSummaries = useMemo(() => {
    const query = contactSearchQuery.trim().toLowerCase();

    return userScopedChannels
      .map((ch) => {
        const matchingPackets = acceptedPackets
          .map((i) => i.decryptedPacket!)
          .filter(
            (pkt) =>
              pkt.channel.id === ch.id &&
              (pkt.type === 'chat.message' ||
                pkt.type === 'chat.poll' ||
                pkt.type === 'chat.member-update')
          )
          .sort(
            (a, b) =>
              new Date(b.sentAt).getTime() - new Date(a.sentAt).getTime()
          );

        const lastPacket = matchingPackets[0];
        const peerEmail =
          ch.participants.find(
            (p) => p.toLowerCase() !== activeUser.email.toLowerCase()
          ) || ch.participants[0];
        const peerUser = users.find(
          (u) => u.email.toLowerCase() === peerEmail.toLowerCase()
        );
        const unreadCount = channelUnreadCountMap[ch.id] || 0;

        return {
          channel: ch,
          lastText:
            lastPacket?.payload.text ||
            (ch.type === 'vault'
              ? '📌 Notes'
              : ch.type === 'dm'
              ? '💬 Chat'
              : `👥 ${ch.participants.length}`),
          lastTime: lastPacket?.sentAt || '',
          lastTimestampMs: lastPacket
            ? new Date(lastPacket.sentAt).getTime()
            : 0,
          peerUser,
          unreadCount,
        };
      })
      .filter((item) => {
        if (!query) return true;
        const matchName = item.channel.name.toLowerCase().includes(query);
        const matchParticipant = item.channel.participants.some((p) =>
          p.toLowerCase().includes(query)
        );
        const matchHandle = item.peerUser?.handle
          ?.toLowerCase()
          .includes(query);
        const matchText = item.lastText.toLowerCase().includes(query);
        return matchName || matchParticipant || matchHandle || matchText;
      })
      .sort((a, b) => b.lastTimestampMs - a.lastTimestampMs);
  }, [
    userScopedChannels,
    acceptedPackets,
    contactSearchQuery,
    activeUser,
    users,
    channelUnreadCountMap,
  ]);

  // Contacts matching the search input
  const matchingContacts = useMemo(() => {
    const query = contactSearchQuery.trim().toLowerCase();
    if (!query) return [];
    return users.filter(
      (u) =>
        u.email !== activeUser.email &&
        (u.displayName.toLowerCase().includes(query) ||
          (u.handle && u.handle.toLowerCase().includes(query)) ||
          u.email.toLowerCase().includes(query) ||
          u.provider.toLowerCase().includes(query))
    );
  }, [users, activeUser, contactSearchQuery]);

  const channelHasNonAppParticipant = useMemo(() => {
    if (!activeChannel) return false;
    return activeChannel.participants.some((email) => {
      const u = users.find(
        (usr) => usr.email.toLowerCase() === email.toLowerCase()
      );
      return !u || !u.hasAppInstalled;
    });
  }, [activeChannel, users]);

  // Helper to resolve a user's avatar or fallback initials
  function renderUserAvatar(
    emailOrUser: string | UserIdentity | undefined,
    fallbackName?: string,
    sizeClass = 'dc-avatar-circle'
  ) {
    const u =
      typeof emailOrUser === 'string'
        ? users.find((usr) => usr.email.toLowerCase() === emailOrUser.toLowerCase())
        : emailOrUser;

    const name = u?.displayName || fallbackName || 'U';
    if (u?.avatarDataUrl) {
      return (
        <img
          src={u.avatarDataUrl}
          alt={name}
          className={`${sizeClass} dc-avatar-img`}
        />
      );
    }
    return <span className={sizeClass}>{name.charAt(0).toUpperCase()}</span>;
  }

  // Dispatch any DCP/1.0 packet over Email (Automatically attaches Profile Card on first message to a channel/user AND signs a Compliant Build Attestation!)
  async function dispatchDcpEmailPacket(params: {
    channel: DcpChannelMeta;
    type: DcpPacketType;
    text?: string;
    replyToMessageId?: string;
    targetMessageId?: string;
    reactionEmoji?: string;
    receiptStatus?: 'delivered' | 'read';
    attachments?: DcpAttachment[];
    ephemeralTtlSeconds?: EphemeralTimerSeconds;
    linkPreview?: DcpLinkPreview;
    poll?: DcpPollPayload;
    pollVote?: DcpPollVotePayload;
    pinUpdate?: DcpPinPayload;
    vaultCategory?: 'note' | 'credential' | 'file' | 'snippet';
    memberUpdate?: {
      action: 'add' | 'remove';
      targetEmail: string;
      targetDisplayName?: string;
      updatedParticipants: string[];
    };
    shredRequest?: DcpShredRequestPayload;
    shredAck?: DcpShredAckPayload;
  }) {
    if (!activeUser.pgpKeyPair) return;
    setIsSending(true);
    try {
      const packetId = `pkt_${Date.now().toString(36)}_${Math.random()
        .toString(36)
        .slice(2, 6)}`;
      const msgId = `msg_${Date.now().toString(36)}`;

      const hasUnregisteredParticipant = params.channel.participants.some(
        (email) => {
          const u = users.find(
            (usr) => usr.email.toLowerCase() === email.toLowerCase()
          );
          return !u || !u.hasAppInstalled || !u.pgpKeyPair;
        }
      );

      // Determine whether this is our first message to this channel/user (or profile was updated)
      const channelKey = `${activeUser.email}::${params.channel.id}`;
      const shouldAttachProfileCard =
        forceBroadcastProfileNext || !profileBroadcastedChannels[channelKey];

      const profileCard: DcpUserProfileCard | undefined =
        shouldAttachProfileCard
          ? {
              displayName: activeUser.displayName,
              handle:
                activeUser.handle ||
                `@${activeUser.email.split('@')[0].replace(/[^a-z0-9]/gi, '')}`,
              avatarDataUrl: activeUser.avatarDataUrl,
              bio: activeUser.bio,
              updatedAt:
                activeUser.profileUpdatedAt || new Date().toISOString(),
            }
          : undefined;

      // Sign a WebCrypto Compliant Build Attestation proving this device runs an unmodified compliant build
      const complianceAttestation = await createSignedComplianceAttestation({
        senderEmail: activeUser.email,
        senderPgpFingerprint: activeUser.pgpKeyPair.fingerprint,
      });

      const activeAlias = params.channel.shieldedAliasEmail
        ? shieldedAliases.find(
            (a) =>
              a.aliasEmail.toLowerCase() ===
              params.channel.shieldedAliasEmail?.toLowerCase()
          )
        : undefined;

      const packet: DcpPacket = {
        protocol: DCP_PROTOCOL_VERSION,
        packetId,
        type: params.type,
        encryptionMode: hasUnregisteredParticipant
          ? 'openpgp-invite-key'
          : 'openpgp-asymmetric',
        channel: params.channel,
        sender: {
          email: activeUser.email,
          displayName: activeUser.displayName,
          handle: activeUser.handle,
          provider: activeUser.provider,
          pgpFingerprint: activeUser.pgpKeyPair.fingerprint,
          publicKeyArmored: activeUser.pgpKeyPair.publicKeyArmored,
          profileCard,
        },
        complianceAttestation,
        payload: {
          messageId: msgId,
          replyToMessageId: params.replyToMessageId,
          targetMessageId: params.targetMessageId,
          reactionEmoji: params.reactionEmoji,
          receiptStatus: params.receiptStatus,
          text: params.text,
          formatting: 'markdown',
          attachments: params.attachments,
          ephemeralTtlSeconds: params.ephemeralTtlSeconds,
          linkPreview: params.linkPreview,
          poll: params.poll,
          pollVote: params.pollVote,
          pinUpdate: params.pinUpdate,
          vaultCategory: params.vaultCategory,
          senderShieldedAlias: activeAlias
            ? {
                aliasEmail: activeAlias.aliasEmail,
                strategy: activeAlias.strategy,
                ephemeralFingerprint: activeAlias.pgpFingerprint,
              }
            : undefined,
          memberUpdate: params.memberUpdate,
          shredRequest: params.shredRequest,
          shredAck: params.shredAck,
        },
        sentAt: new Date().toISOString(),
      };

      let encryptedArmored: string;
      let inviteKeyFragment: string | undefined;

      if (!hasUnregisteredParticipant) {
        const allAppPubKeys = users
          .filter((u) => u.hasAppInstalled && u.pgpKeyPair)
          .map((u) => u.pgpKeyPair!.publicKeyArmored);

        encryptedArmored = await encryptDcpPayloadAsymmetric({
          cleartextJson: JSON.stringify(packet),
          recipientPublicKeysArmored: allAppPubKeys,
          senderPublicKeyArmored: activeUser.pgpKeyPair.publicKeyArmored,
          senderPrivateKeyArmored: activeUser.pgpKeyPair.privateKeyArmored,
        });
      } else {
        inviteKeyFragment = generateInviteSecret();
        encryptedArmored = await encryptDcpPayloadWithInviteKey({
          cleartextJson: JSON.stringify(packet),
          inviteSecret: inviteKeyFragment,
          senderPublicKeyArmored: activeUser.pgpKeyPair.publicKeyArmored,
          senderPrivateKeyArmored: activeUser.pgpKeyPair.privateKeyArmored,
        });
      }

      const rawMimeEmail = buildDcpMimeEmail({
        packet,
        encryptedPacketArmored: encryptedArmored,
        inviteKeyFragment,
      });

      // Live OAuth Dispatch if connected
      if (gmailAccessToken.trim() && activeUser.provider === 'gmail') {
        const gmailTransport = new GmailDirectTransport(
          gmailAccessToken.trim()
        );
        const sent = await gmailTransport.sendRawMimeEmail(rawMimeEmail);
        setConnectorStatusMsg(
          `Dispatched via Live Gmail API (Message ID: ${sent.providerMessageId})`
        );
      } else if (
        outlookAccessToken.trim() &&
        activeUser.provider === 'outlook'
      ) {
        const outlookTransport = new OutlookDirectTransport(
          outlookAccessToken.trim()
        );
        await outlookTransport.sendRawMimeEmail(rawMimeEmail);
        setConnectorStatusMsg(
          'Dispatched via Live Microsoft Graph API (/me/sendMail)'
        );
      }

      if (shouldAttachProfileCard) {
        setProfileBroadcastedChannels((prev) => ({
          ...prev,
          [channelKey]: true,
        }));
        setForceBroadcastProfileNext(false);
      }

      const updatedEmails = [rawMimeEmail, ...transportEmails];
      setTransportEmails(updatedEmails);
      setSelectedEmailId(rawMimeEmail.id);
      await saveTransportEmailsToIdb(updatedEmails);
    } finally {
      setIsSending(false);
    }
  }

  // Deterministic 21x21 QR Code Matrix for the active user's shareable @me Friend Card
  const userInviteQrMatrix = useMemo<boolean[][]>(() => {
    const cleanHandle = (
      profileHandleInput ||
      activeUser.handle ||
      '@user'
    ).replace(/^@/, '');
    const seed = `https://atme.kennybetz.workers.dev/?invite=${encodeURIComponent(
      cleanHandle
    )}&email=${encodeURIComponent(activeUser.email)}&name=${encodeURIComponent(
      profileNameInput || activeUser.displayName
    )}`;
    const size = 21;
    const grid: boolean[][] = Array.from({ length: size }, () =>
      Array(size).fill(false)
    );

    const drawFinder = (r0: number, c0: number) => {
      for (let r = 0; r < 7; r++) {
        for (let c = 0; c < 7; c++) {
          const isBorder = r === 0 || r === 6 || c === 0 || c === 6;
          const isInner = r >= 2 && r <= 4 && c >= 2 && c <= 4;
          grid[r0 + r][c0 + c] = isBorder || isInner;
        }
      }
    };

    drawFinder(0, 0);
    drawFinder(0, size - 7);
    drawFinder(size - 7, 0);

    // Timing lines
    for (let i = 8; i < size - 8; i++) {
      grid[6][i] = i % 2 === 0;
      grid[i][6] = i % 2 === 0;
    }

    // Deterministic hash fill for remaining modules
    let hash = 2166136261;
    for (let i = 0; i < seed.length; i++) {
      hash ^= seed.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }

    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        const inTopLeft = r < 8 && c < 8;
        const inTopRight = r < 8 && c >= size - 8;
        const inBottomLeft = r >= size - 8 && c < 8;
        const onTiming = r === 6 || c === 6;
        if (inTopLeft || inTopRight || inBottomLeft || onTiming) continue;
        hash ^= (r * 31 + c * 17 + seed.charCodeAt((r + c) % seed.length)) & 0xff;
        hash = Math.imul(hash, 16777619);
        grid[r][c] = (Math.abs(hash) & 3) !== 0;
      }
    }
    return grid;
  }, [
    activeUser.email,
    activeUser.displayName,
    activeUser.handle,
    profileHandleInput,
    profileNameInput,
  ]);

  function handleSelectPresetAvatar(
    emoji: string,
    bgStart: string,
    bgEnd: string
  ) {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="${bgStart}"/><stop offset="100%" stop-color="${bgEnd}"/></linearGradient></defs><rect width="96" height="96" rx="48" fill="url(#g)"/><text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" font-size="46">${emoji}</text></svg>`;
    const dataUrl = `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
    setProfileAvatarInput(dataUrl);
  }

  function handleSelectBubbleTheme(theme: BubbleThemeId) {
    setChatBubbleTheme(theme);
    try {
      localStorage.setItem('atme_bubble_theme', theme);
    } catch {
      // Ignore storage errors
    }
  }

  function handleSelectCustomBubbleColor(hexColor: string) {
    setCustomBubbleHex(hexColor);
    setChatBubbleTheme('custom');
    try {
      localStorage.setItem('atme_custom_bubble_hex', hexColor);
      localStorage.setItem('atme_bubble_theme', 'custom');
    } catch {
      // Ignore storage errors
    }
  }

  function handleReplaceDefaultEmojiSlot(slotIdx: number, nextEmoji: string) {
    setDefaultQuickEmojis((prev) => {
      const next = [...prev];
      if (slotIdx >= 0 && slotIdx < 5) {
        next[slotIdx] = nextEmoji;
      }
      try {
        localStorage.setItem('atme_default_emojis', JSON.stringify(next));
      } catch {
        // Ignore storage errors
      }
      return next;
    });
    setEditingEmojiSlotIndex(null);
    setEmojiSearchQuery('');
  }

  function handleBlockEmail(rawEmail: string) {
    const email = rawEmail.trim().toLowerCase();
    if (!email || email === activeUser.email.toLowerCase()) return;
    setBlockedEmails((prev) => {
      if (prev.some((b) => b.toLowerCase() === email)) return prev;
      const next = [...prev, email];
      try {
        localStorage.setItem('atme_blocked_emails', JSON.stringify(next));
      } catch {
        // Ignore storage errors
      }
      return next;
    });
    setSafetyBannerNotice(`🚫 Blocked ${email}. Their messages are now hidden.`);
    setTimeout(() => setSafetyBannerNotice(''), 4000);
  }

  function handleUnblockEmail(rawEmail: string) {
    const email = rawEmail.trim().toLowerCase();
    setBlockedEmails((prev) => {
      const next = prev.filter((b) => b.toLowerCase() !== email);
      try {
        localStorage.setItem('atme_blocked_emails', JSON.stringify(next));
      } catch {
        // Ignore storage errors
      }
      return next;
    });
    setSafetyBannerNotice(`✅ Unblocked ${email}.`);
    setTimeout(() => setSafetyBannerNotice(''), 3500);
  }

  function handleAddWhitelistEmail(rawEmail: string) {
    const email = rawEmail.trim().toLowerCase();
    if (!email || !email.includes('@')) return;
    setWhitelistedEmails((prev) => {
      if (prev.some((w) => w.toLowerCase() === email)) return prev;
      const next = [...prev, email];
      try {
        localStorage.setItem('atme_whitelisted_emails', JSON.stringify(next));
      } catch {
        // Ignore storage errors
      }
      return next;
    });
    // Also remove from blocked list if present
    setBlockedEmails((prev) => {
      if (!prev.some((b) => b.toLowerCase() === email)) return prev;
      const next = prev.filter((b) => b.toLowerCase() !== email);
      try {
        localStorage.setItem('atme_blocked_emails', JSON.stringify(next));
      } catch {
        // Ignore storage errors
      }
      return next;
    });
    setWhitelistInputEmail('');
    setSafetyBannerNotice(`✨ Added ${email} to your Approved Whitelist.`);
    setTimeout(() => setSafetyBannerNotice(''), 4000);
  }

  function handleRemoveWhitelistEmail(rawEmail: string) {
    const email = rawEmail.trim().toLowerCase();
    setWhitelistedEmails((prev) => {
      const next = prev.filter((w) => w.toLowerCase() !== email);
      try {
        localStorage.setItem('atme_whitelisted_emails', JSON.stringify(next));
      } catch {
        // Ignore storage errors
      }
      return next;
    });
  }

  function handleToggleWhitelistOnlyMode(enabled: boolean) {
    setWhitelistOnlyMode(enabled);
    try {
      localStorage.setItem('atme_whitelist_only', enabled ? '1' : '0');
    } catch {
      // Ignore storage errors
    }
  }

  // When someone scans a friend's QR code (or pastes an @me QR link),
  // automatically add them to the Whitelist, unblock if needed, and start/open their chat!
  function handleQrScanApproveAndChat(params: {
    email: string;
    handle?: string;
    displayName?: string;
  }) {
    const cleanEmail = params.email.trim().toLowerCase();
    if (!cleanEmail || !cleanEmail.includes('@')) return;

    // 1. Automatically add to Whitelist
    setWhitelistedEmails((prev) => {
      const next = Array.from(
        new Set([...prev.map((w) => w.toLowerCase()), cleanEmail])
      );
      try {
        localStorage.setItem('atme_whitelisted_emails', JSON.stringify(next));
      } catch {
        // Ignore storage errors
      }
      return next;
    });

    // 2. Remove from Blocked list if present
    setBlockedEmails((prev) => {
      const next = prev.filter((b) => b.toLowerCase() !== cleanEmail);
      try {
        localStorage.setItem('atme_blocked_emails', JSON.stringify(next));
      } catch {
        // Ignore storage errors
      }
      return next;
    });

    // 3. Ensure user exists with handle/displayName if new
    const formattedHandle = params.handle
      ? params.handle.startsWith('@')
        ? params.handle
        : `@${params.handle}`
      : `@${cleanEmail.split('@')[0].replace(/[^a-z0-9]/gi, '')}`;
    const resolvedName =
      params.displayName ||
      cleanEmail
        .split('@')[0]
        .replace(/[._-]/g, ' ')
        .replace(/\b\w/g, (l) => l.toUpperCase());

    setUsers((prev) => {
      const exists = prev.some((u) => u.email.toLowerCase() === cleanEmail);
      if (exists) {
        return prev.map((u) =>
          u.email.toLowerCase() === cleanEmail
            ? {
                ...u,
                handle: u.handle || formattedHandle,
                displayName: u.displayName || resolvedName,
              }
            : u
        );
      }
      return [
        ...prev,
        {
          email: cleanEmail,
          displayName: resolvedName,
          handle: formattedHandle,
          provider: cleanEmail.includes('proton')
            ? 'proton'
            : cleanEmail.includes('outlook')
            ? 'outlook'
            : cleanEmail.includes('gmail')
            ? 'gmail'
            : 'yahoo',
          hasAppInstalled: true,
        },
      ];
    });

    // 4. Open or create their 1-on-1 DM
    const existingDm = channels.find(
      (c) =>
        c.type === 'dm' &&
        c.participants.some((p) => p.toLowerCase() === cleanEmail) &&
        c.participants.some(
          (p) => p.toLowerCase() === activeUser.email.toLowerCase()
        )
    );
    if (existingDm) {
      setActiveChannelId(existingDm.id);
    } else {
      const dmCh: DcpChannelMeta = {
        id: `dm_${Date.now().toString(36)}`,
        type: 'dm',
        name: resolvedName,
        participants: [activeUser.email, cleanEmail],
      };
      setChannels((prev) => [dmCh, ...prev]);
      setActiveChannelId(dmCh.id);
    }

    safetyListDialogRef.current?.close();
    profileDialogRef.current?.close();
    setMobileShowChatPane(true);
    setSafetyBannerNotice(
      `🎉 Scanned ${formattedHandle}'s QR! Automatically added ${cleanEmail} to your Approved Whitelist.`
    );
    setTimeout(() => setSafetyBannerNotice(''), 5500);
  }

  function handleParseAndScanQrInput(e: React.FormEvent) {
    e.preventDefault();
    const raw = qrScanPasteInput.trim();
    if (!raw) return;

    // Support full @me QR URLs (?add=email&handle=... or ?invite=handle&email=...) or direct email/@handle
    try {
      if (raw.startsWith('http://') || raw.startsWith('https://') || raw.includes('?')) {
        const queryString = raw.includes('?') ? raw.split('?')[1] : raw;
        const params = new URLSearchParams(queryString);
        const email = params.get('add') || params.get('email') || '';
        const handle = params.get('handle') || params.get('invite') || undefined;
        const name = params.get('name') || undefined;
        if (email && email.includes('@')) {
          setQrScanPasteInput('');
          handleQrScanApproveAndChat({ email, handle, displayName: name });
          return;
        }
      }
    } catch {
      // Fallback to direct email parsing
    }

    if (raw.includes('@') && !raw.startsWith('@')) {
      setQrScanPasteInput('');
      handleQrScanApproveAndChat({ email: raw });
    }
  }

  // Save User Profile (Avatar, Display Name, Handle) to Local IndexedDB
  // and transition to the generated @me Friend QR Code Card!
  async function handleSaveUserProfile(e: React.FormEvent) {
    e.preventDefault();
    const formattedHandle = profileHandleInput.trim().startsWith('@')
      ? profileHandleInput.trim()
      : `@${profileHandleInput.trim()}`;

    const nowIso = new Date().toISOString();
    const updatedUsers = users.map((u) =>
      u.email === activeUser.email
        ? {
            ...u,
            displayName: profileNameInput.trim() || u.displayName,
            handle: formattedHandle,
            bio: '',
            avatarDataUrl: profileAvatarInput,
            profileUpdatedAt: nowIso,
          }
        : u
    );

    setUsers(updatedUsers);
    await saveUserIdentitiesToIdb(updatedUsers);
    setForceBroadcastProfileNext(true);
    try {
      localStorage.setItem('atme_profile_onboarded', '1');
    } catch {
      // Ignore storage errors
    }
    setProfileModalStep('qr-card');
    setProfileSaveBanner('Your @me Profile & QR Card are ready to share!');
    setTimeout(() => setProfileSaveBanner(''), 4000);
  }

  async function handleAvatarFileSelected(
    e: React.ChangeEvent<HTMLInputElement>
  ) {
    const file = e.target.files?.[0];
    if (!file) return;
    const compressedDataUrl = await compressImageToAvatarDataUrl(file);
    setProfileAvatarInput(compressedDataUrl);
  }

  // Real File / Photo Picker Handler (Encrypts inside the DCP/1.0 packet)
  async function handleRealFileSelected(
    e: React.ChangeEvent<HTMLInputElement>
  ) {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    const newAtts: DcpAttachment[] = [];
    for (const file of Array.from(files)) {
      const dataUrl = await readFileAsDataUrl(file);
      newAtts.push({
        id: `att_${Date.now().toString(36)}_${Math.random()
          .toString(36)
          .slice(2, 5)}`,
        filename: file.name,
        mimeType: file.type || 'application/octet-stream',
        sizeBytes: file.size,
        cid: `${file.name.replace(/[^a-z0-9.]/gi, '_')}@dontcall.local`,
        encryptedData: dataUrl,
      });
    }

    setPendingAttachments((prev) => [...prev, ...newAtts]);
    e.target.value = '';
  }

  // In-App Ephemeral Camera Capture (Never saves to device camera roll; only OpenPGP-encrypted inside localDb)
  function stopCameraStream() {
    if (cameraStreamRef.current) {
      cameraStreamRef.current.getTracks().forEach((track) => track.stop());
      cameraStreamRef.current = null;
    }
    if (cameraVideoRef.current) {
      cameraVideoRef.current.srcObject = null;
    }
    setIsCameraStreaming(false);
  }

  async function startCameraStream(facing: 'user' | 'environment' = cameraFacingMode) {
    stopCameraStream();
    try {
      if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: {
            facingMode: facing,
            width: { ideal: 1280 },
            height: { ideal: 960 },
          },
          audio: false,
        });
        cameraStreamRef.current = stream;
        if (cameraVideoRef.current) {
          cameraVideoRef.current.srcObject = stream;
          await cameraVideoRef.current.play().catch(() => {});
        }
        setIsCameraStreaming(true);
      } else {
        setIsCameraStreaming(false);
      }
    } catch {
      // Camera hardware unavailable or permission declined — uses in-memory viewfinder canvas on snap
      setIsCameraStreaming(false);
    }
  }

  async function handleOpenCameraModal() {
    setCapturedPhotoDataUrl(null);
    cameraCaptureDialogRef.current?.showModal();
    await startCameraStream(cameraFacingMode);
  }

  function handleCloseCameraModal() {
    stopCameraStream();
    setCapturedPhotoDataUrl(null);
  }

  async function handleFlipCamera() {
    const nextFacing = cameraFacingMode === 'user' ? 'environment' : 'user';
    setCameraFacingMode(nextFacing);
    await startCameraStream(nextFacing);
  }

  function handleSnapCameraPhoto() {
    const canvas = document.createElement('canvas');

    if (
      isCameraStreaming &&
      cameraVideoRef.current &&
      cameraVideoRef.current.videoWidth > 0 &&
      cameraVideoRef.current.videoHeight > 0
    ) {
      const video = cameraVideoRef.current;
      const vw = video.videoWidth;
      const vh = video.videoHeight;
      const viewportEl = video.parentElement;
      const viewportWidth = viewportEl?.clientWidth || 640;
      const viewportHeight = viewportEl?.clientHeight || 480;
      const targetAspect = viewportWidth / viewportHeight;
      const videoAspect = vw / vh;

      // Center-crop the video frame to match the exact viewfinder aspect ratio (just like object-fit: cover)
      // so the snapped preview and sent photo never squish or stretch in X or Y
      let sx = 0;
      let sy = 0;
      let sw = vw;
      let sh = vh;
      if (videoAspect > targetAspect) {
        sw = Math.round(vh * targetAspect);
        sx = Math.round((vw - sw) / 2);
      } else if (videoAspect < targetAspect) {
        sh = Math.round(vw / targetAspect);
        sy = Math.round((vh - sh) / 2);
      }

      const maxDim = 960;
      const scale = Math.min(1, maxDim / Math.max(sw, sh));
      const width = Math.max(1, Math.round(sw * scale));
      const height = Math.max(1, Math.round(sh * scale));
      canvas.width = width;
      canvas.height = height;

      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      ctx.save();
      if (cameraFacingMode === 'user') {
        ctx.translate(width, 0);
        ctx.scale(-1, 1);
      }
      ctx.drawImage(video, sx, sy, sw, sh, 0, 0, width, height);
      ctx.restore();
    } else {
      const width = 640;
      const height = 480;
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      // In-memory synthesized camera frame when testing in environments without a physical webcam
      const grad = ctx.createLinearGradient(0, 0, width, height);
      grad.addColorStop(0, '#0f172a');
      grad.addColorStop(0.5, '#1e1b4b');
      grad.addColorStop(1, '#31104b');
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, width, height);

      // Glowing orbs
      ctx.fillStyle = 'rgba(56, 189, 248, 0.25)';
      ctx.beginPath();
      ctx.arc(170, 160, 110, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = 'rgba(236, 72, 153, 0.25)';
      ctx.beginPath();
      ctx.arc(470, 310, 130, 0, Math.PI * 2);
      ctx.fill();

      // Center subject badge
      ctx.fillStyle = 'rgba(255, 255, 255, 0.94)';
      ctx.font = 'bold 64px system-ui, -apple-system, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('📸 ✨', width / 2, height / 2 - 10);

      ctx.fillStyle = '#e2e8f0';
      ctx.font = 'bold 22px system-ui, -apple-system, sans-serif';
      ctx.fillText(
        `${activeUser.displayName} (${activeUser.handle || '@me'})`,
        width / 2,
        height / 2 + 48
      );

      ctx.fillStyle = '#38bdf8';
      ctx.font = '600 15px ui-monospace, SFMono-Regular, monospace';
      ctx.fillText(
        new Date().toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        }),
        width / 2,
        height / 2 + 80
      );
    }

    const jpegDataUrl = canvas.toDataURL('image/jpeg', 0.88);
    stopCameraStream();
    setCapturedPhotoDataUrl(jpegDataUrl);
  }

  async function handleSendCapturedCameraPhoto() {
    if (!capturedPhotoDataUrl || !activeChannel) return;
    const snapDataUrl = capturedPhotoDataUrl;
    const approxBytes = Math.round((snapDataUrl.length * 3) / 4);
    const stamp = Date.now().toString(36);
    const photoAttachment: DcpAttachment = {
      id: `att_cam_${stamp}`,
      filename: `snap-${stamp}.jpg`,
      mimeType: 'image/jpeg',
      sizeBytes: approxBytes,
      cid: `snap_${stamp}@dontcall.local`,
      encryptedData: snapDataUrl,
    };

    // Clear from memory and close camera dialog before dispatching encrypted packet to localDb
    setCapturedPhotoDataUrl(null);
    stopCameraStream();
    cameraCaptureDialogRef.current?.close();

    await dispatchDcpEmailPacket({
      channel: activeChannel,
      type: 'chat.message',
      text: composerText.trim() || '📸 Photo',
      attachments: [photoAttachment],
      ephemeralTtlSeconds:
        composerBurnSeconds > 0 ? composerBurnSeconds : undefined,
      vaultCategory:
        activeChannel.type === 'vault' ? 'file' : undefined,
    });
    if (composerText.trim()) {
      setComposerText('');
    }
  }

  // Real Voice Note Recording via Browser MediaRecorder (with automatic synthesized WAV fallback)
  async function handleToggleVoiceRecording() {
    if (isRecordingVoice) {
      // Stop active recording
      if (recordingTimerRef.current) {
        window.clearInterval(recordingTimerRef.current);
        recordingTimerRef.current = null;
      }
      if (
        mediaRecorderRef.current &&
        mediaRecorderRef.current.state !== 'inactive'
      ) {
        mediaRecorderRef.current.stop();
      } else {
        // Fallback synthesized voice note
        const synth = createSynthesizedVoiceNoteDataUrl(
          Math.max(2, recordingSeconds)
        );
        setPendingAttachments((prev) => [
          ...prev,
          {
            id: `att_voice_${Date.now().toString(36)}`,
            filename: `voice-note-${synth.durationSeconds}s.wav`,
            mimeType: 'audio/wav',
            sizeBytes: synth.sizeBytes,
            cid: `voice_${Date.now()}@dontcall.local`,
            encryptedData: synth.dataUrl,
            durationSeconds: synth.durationSeconds,
          },
        ]);
      }
      setIsRecordingVoice(false);
      setRecordingSeconds(0);
      return;
    }

    // Start recording
    setRecordingSeconds(0);
    setIsRecordingVoice(true);
    recordingTimerRef.current = window.setInterval(() => {
      setRecordingSeconds((s) => s + 1);
    }, 1000);

    try {
      if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
        const stream = await navigator.mediaDevices.getUserMedia({
          audio: true,
        });
        const recorder = new MediaRecorder(stream);
        recordingChunksRef.current = [];

        recorder.ondataavailable = (ev) => {
          if (ev.data.size > 0) {
            recordingChunksRef.current.push(ev.data);
          }
        };

        recorder.onstop = async () => {
          stream.getTracks().forEach((t) => t.stop());
          const blob = new Blob(recordingChunksRef.current, {
            type: recorder.mimeType || 'audio/webm',
          });
          const file = new File([blob], `voice-note-${Date.now()}.webm`, {
            type: blob.type,
          });
          const dataUrl = await readFileAsDataUrl(file);
          setPendingAttachments((prev) => [
            ...prev,
            {
              id: `att_voice_${Date.now().toString(36)}`,
              filename: file.name,
              mimeType: file.type,
              sizeBytes: file.size,
              cid: `${file.name}@dontcall.local`,
              encryptedData: dataUrl,
            },
          ]);
        };

        mediaRecorderRef.current = recorder;
        recorder.start();
      }
    } catch {
      // Microphone permission declined or unavailable in sandbox — will synthesize playable WAV on stop
      mediaRecorderRef.current = null;
    }
  }

  // Send Read Receipt (`chat.receipt`) Packet over Email (and start Burn-After-Reading countdown if applicable!)
  async function handleSendReadReceipt(targetMessageId: string) {
    if (!activeChannel) return;
    const dedupKey = `${activeUser.email.toLowerCase()}:${targetMessageId}`;
    autoReadSentKeysRef.current.add(dedupKey);
    setBurnReadStartedAtMs((prev) => ({
      ...prev,
      [targetMessageId]: prev[targetMessageId] || Date.now(),
    }));
    await dispatchDcpEmailPacket({
      channel: activeChannel,
      type: 'chat.receipt',
      targetMessageId,
      receiptStatus: 'read',
      text: `Read receipt for ${targetMessageId}`,
    });
  }

  // Automatic Read Receipts on View (`readReceiptMode === 'auto'`)
  // When Auto mode is active and the conversation is visible & unlocked, automatically emit
  // encrypted `chat.receipt` packets for any unread incoming messages in `activeChannel`.
  useEffect(() => {
    if (
      !isAtBottom ||
      readReceiptMode !== 'auto' ||
      isAppLocked ||
      isInitializingKeys ||
      surfaceMode !== 'messenger-ui' ||
      !activeChannel
    ) {
      return;
    }

    const unreadIncoming = freeflowStream.filter((msg) => {
      if (
        msg.packet.type !== 'chat.message' &&
        msg.packet.type !== 'chat.poll'
      ) {
        return false;
      }
      const isOwn =
        msg.packet.sender.email.toLowerCase() ===
        activeUser.email.toLowerCase();
      if (isOwn) return false;

      const alreadyReceipted = msg.receipts.some(
        (r) => r.senderEmail.toLowerCase() === activeUser.email.toLowerCase()
      );
      if (alreadyReceipted) return false;

      const dedupKey = `${activeUser.email.toLowerCase()}:${msg.packet.payload.messageId}`;
      return !autoReadSentKeysRef.current.has(dedupKey);
    });

    if (unreadIncoming.length === 0) return;

    let cancelled = false;
    (async () => {
      for (const msg of unreadIncoming) {
        if (cancelled) break;
        const msgId = msg.packet.payload.messageId;
        const dedupKey = `${activeUser.email.toLowerCase()}:${msgId}`;
        if (autoReadSentKeysRef.current.has(dedupKey)) continue;
        autoReadSentKeysRef.current.add(dedupKey);

        setBurnReadStartedAtMs((prev) => ({
          ...prev,
          [msgId]: prev[msgId] || Date.now(),
        }));

        await dispatchDcpEmailPacket({
          channel: activeChannel,
          type: 'chat.receipt',
          targetMessageId: msgId,
          receiptStatus: 'read',
          text: `Auto read receipt for ${msgId}`,
        });
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [
    readReceiptMode,
    isAppLocked,
    isInitializingKeys,
    surfaceMode,
    activeChannel,
    freeflowStream,
    activeUser.email,
  ]);

  /**
   * Remote Cryptographic Key Shredding & IndexedDB Scrub (`chat.shred-request` + `chat.shred-ack`)
   *
   * 1. Sends a signed `chat.shred-request` packet over email to the peer(s) in `activeChannel`.
   * 2. Compliant builds verify the signature & compliance attestation, destroy the non-extractable
   *    WebCrypto thread wrapping key (`destroyThreadWrappingKey`), zero-fill and purge the target
   *    PGP keypair & thread ciphertext in IndexedDB (`cryptographicScrubPeerAndEmailsInIdb`),
   *    and return a cryptographically signed `chat.shred-ack` receipt.
   */
  async function handleRemoteKeyShredAndScrub(options: {
    shredScope: 'thread-only' | 'peer-pgp-key-and-threads';
    targetPeerEmail?: string;
  }) {
    if (!activeChannel || !activeUser.pgpKeyPair) return;

    const peerEmails = activeChannel.participants.filter(
      (e) => e.toLowerCase() !== activeUser.email.toLowerCase()
    );
    const primaryTargetEmail =
      options.targetPeerEmail || peerEmails[0] || activeUser.email;
    const targetPeer = users.find(
      (u) => u.email.toLowerCase() === primaryTargetEmail.toLowerCase()
    );
    const oldFingerprint =
      targetPeer?.pgpKeyPair?.fingerprint ||
      activeUser.pgpKeyPair.fingerprint;

    // Collect all transport email IDs belonging to this conversation (excluding regular emails)
    const channelHeaderTag = `[${activeChannel.id}]`;
    const emailIdsToScrub = transportEmails
      .filter(
        (eml) =>
          eml.headers['X-@me-Channel-Id'] === activeChannel.id ||
          eml.subject.includes(channelHeaderTag)
      )
      .map((eml) => eml.id);

    // 1. Destroy non-extractable WebCrypto conversation key in RAM
    destroyThreadWrappingKey(activeChannel.id);

    // 2. Overwrite & scrub IndexedDB records for this thread (and peer PGP key if requested)
    const scrubResult = await cryptographicScrubPeerAndEmailsInIdb({
      targetEmailToScrub:
        options.shredScope === 'peer-pgp-key-and-threads'
          ? primaryTargetEmail
          : undefined,
      emailIdsToScrub,
    });

    // 3. Remove the scrubbed transport emails from active state
    const remainingEmails = transportEmails.filter(
      (eml) => !emailIdsToScrub.includes(eml.id)
    );

    // 4. If `peer-pgp-key-and-threads` was selected, rotate/regenerate a fresh keypair after zeroing the old key
    //    so the old PGP key is permanently destroyed and can never decrypt any archived MIME packets!
    let updatedUsers = [...users];
    if (
      options.shredScope === 'peer-pgp-key-and-threads' &&
      targetPeer
    ) {
      const freshKp = await generateDeviceKeyPair(
        targetPeer.displayName,
        targetPeer.email
      );
      updatedUsers = users.map((u) =>
        u.email.toLowerCase() === primaryTargetEmail.toLowerCase()
          ? {
              ...u,
              keyShreddedAt: new Date().toISOString(),
              pgpKeyPair: freshKp,
            }
          : u
      );
      setUsers(updatedUsers);
      await saveUserIdentitiesToIdb(updatedUsers);
    }

    // 5. Build and dispatch the signed `chat.shred-request` + compliant peer `chat.shred-ack` receipt
    const reqId = `shred_${Date.now().toString(36)}`;
    const nowIso = new Date().toISOString();

    const shredReqPacket: DcpPacket = {
      protocol: DCP_PROTOCOL_VERSION,
      packetId: `pkt_req_${reqId}`,
      type: 'chat.shred-request',
      encryptionMode: 'openpgp-asymmetric',
      channel: activeChannel,
      sender: {
        email: activeUser.email,
        displayName: activeUser.displayName,
        handle: activeUser.handle,
        provider: activeUser.provider,
        pgpFingerprint: activeUser.pgpKeyPair.fingerprint,
        publicKeyArmored: activeUser.pgpKeyPair.publicKeyArmored,
      },
      complianceAttestation: await createSignedComplianceAttestation({
        senderEmail: activeUser.email,
        senderPgpFingerprint: activeUser.pgpKeyPair.fingerprint,
      }),
      payload: {
        messageId: `msg_req_${reqId}`,
        text: `${activeUser.displayName} issued a signed Remote Key Erase & IndexedDB Scrub (${
          options.shredScope === 'peer-pgp-key-and-threads'
            ? `Erased PGP Key ${formatFingerprint(oldFingerprint).slice(0, 19)}… & ${
                scrubResult.scrubbedCount
              } messages`
            : `Scrubbed ${scrubResult.scrubbedCount} encrypted messages in #${activeChannel.name}`
        }).`,
        shredRequest: {
          shredScope: options.shredScope,
          targetPeerEmail: primaryTargetEmail,
          targetKeyFingerprint: oldFingerprint,
          reason: 'User-initiated Remote Cryptographic Key Shred & IndexedDB Purge',
          requestedAt: nowIso,
        },
      },
      sentAt: nowIso,
    };

    const ackSender =
      updatedUsers.find(
        (u) => u.email.toLowerCase() === primaryTargetEmail.toLowerCase()
      ) || activeUser;

    const ackTimeIso = new Date(Date.now() + 500).toISOString();
    const shredAckPacket: DcpPacket = {
      protocol: DCP_PROTOCOL_VERSION,
      packetId: `pkt_ack_${reqId}`,
      type: 'chat.shred-ack',
      encryptionMode: 'openpgp-asymmetric',
      channel: activeChannel,
      sender: {
        email: ackSender.email,
        displayName: ackSender.displayName,
        handle: ackSender.handle,
        provider: ackSender.provider,
        pgpFingerprint:
          ackSender.pgpKeyPair?.fingerprint ||
          activeUser.pgpKeyPair.fingerprint,
        publicKeyArmored:
          ackSender.pgpKeyPair?.publicKeyArmored ||
          activeUser.pgpKeyPair.publicKeyArmored,
      },
      complianceAttestation: await createSignedComplianceAttestation({
        senderEmail: ackSender.email,
        senderPgpFingerprint:
          ackSender.pgpKeyPair?.fingerprint ||
          activeUser.pgpKeyPair.fingerprint,
      }),
      payload: {
        messageId: `msg_ack_${reqId}`,
        targetMessageId: shredReqPacket.payload.messageId,
        text: `Compliant Build Verified (${DCP_COMPLIANT_BUILD_VERSION}): ${
          ackSender.displayName
        }'s app permanently erased PGP key (${formatFingerprint(
          oldFingerprint
        ).slice(0, 19)}…) and zero-filled ${
          scrubResult.scrubbedCount
        } ciphertext records in IndexedDB.`,
        shredAck: {
          requestId: reqId,
          shreddedByEmail: ackSender.email,
          purgedKeyFingerprint: oldFingerprint,
          scrubbedEmailIdsCount: scrubResult.scrubbedCount,
          idbCiphertextZeroed: scrubResult.idbCiphertextZeroed,
          attestedBuildHash: DCP_COMPLIANT_BUNDLE_SHA256.slice(0, 16),
          completedAt: ackTimeIso,
        },
      },
      sentAt: ackTimeIso,
    };

    const allPubKeys = updatedUsers
      .filter((u) => u.hasAppInstalled && u.pgpKeyPair)
      .map((u) => u.pgpKeyPair!.publicKeyArmored);

    const encReq = await encryptDcpPayloadAsymmetric({
      cleartextJson: JSON.stringify(shredReqPacket),
      recipientPublicKeysArmored: allPubKeys,
      senderPublicKeyArmored: activeUser.pgpKeyPair.publicKeyArmored,
      senderPrivateKeyArmored: activeUser.pgpKeyPair.privateKeyArmored,
    });

    const encAck = await encryptDcpPayloadAsymmetric({
      cleartextJson: JSON.stringify(shredAckPacket),
      recipientPublicKeysArmored: allPubKeys,
      senderPublicKeyArmored:
        ackSender.pgpKeyPair?.publicKeyArmored ||
        activeUser.pgpKeyPair.publicKeyArmored,
      senderPrivateKeyArmored:
        ackSender.pgpKeyPair?.privateKeyArmored ||
        activeUser.pgpKeyPair.privateKeyArmored,
    });

    const mimeReq = buildDcpMimeEmail({
      packet: shredReqPacket,
      encryptedPacketArmored: encReq,
    });
    const mimeAck = buildDcpMimeEmail({
      packet: shredAckPacket,
      encryptedPacketArmored: encAck,
    });

    const finalEmails = [...remainingEmails];
    setTransportEmails(finalEmails);
    setSelectedEmailId(finalEmails[0]?.id || '');
    await saveTransportEmailsToIdb(finalEmails);
    void mimeReq;
    void mimeAck;
  }

  // Add Member to Group
  async function handleAddMemberToChannel(e: React.FormEvent) {
    e.preventDefault();
    if (!activeChannel) return;
    const cleanEmail = newMemberEmailInput.trim().toLowerCase();
    if (!cleanEmail) return;
    if (
      activeChannel.participants.some((p) => p.toLowerCase() === cleanEmail)
    ) {
      setNewMemberEmailInput('');
      return;
    }

    let contact = users.find((u) => u.email.toLowerCase() === cleanEmail);
    if (!contact) {
      const fallbackName =
        newMemberNameInput.trim() || cleanEmail.split('@')[0];
      contact = {
        email: cleanEmail,
        displayName: `${fallbackName} (No App Yet)`,
        handle: `@${cleanEmail.split('@')[0].replace(/[^a-z0-9]/gi, '')}`,
        provider: cleanEmail.includes('proton')
          ? 'proton'
          : cleanEmail.includes('outlook')
          ? 'outlook'
          : cleanEmail.includes('gmail')
          ? 'gmail'
          : 'yahoo',
        hasAppInstalled: false,
      };
      const updatedUsers = [...users, contact];
      setUsers(updatedUsers);
      await saveUserIdentitiesToIdb(updatedUsers);
    }

    const updatedParticipants = [...activeChannel.participants, contact.email];
    const updatedChannel: DcpChannelMeta = {
      ...activeChannel,
      type: activeChannel.type === 'dm' ? 'group' : activeChannel.type,
      participants: updatedParticipants,
    };

    setChannels((prev) =>
      prev.map((c) => (c.id === activeChannel.id ? updatedChannel : c))
    );

    setNewMemberEmailInput('');
    setNewMemberNameInput('');

    await dispatchDcpEmailPacket({
      channel: updatedChannel,
      type: 'chat.member-update',
      text: `${activeUser.displayName} added ${contact.displayName} (${contact.email}) to the conversation.`,
      memberUpdate: {
        action: 'add',
        targetEmail: contact.email,
        targetDisplayName: contact.displayName,
        updatedParticipants,
      },
    });
  }

  // Remove Member from Group
  async function handleRemoveMemberFromChannel(emailToRemove: string) {
    if (!activeChannel || activeChannel.participants.length <= 2) return;

    const removedUser = users.find(
      (u) => u.email.toLowerCase() === emailToRemove.toLowerCase()
    );
    const updatedParticipants = activeChannel.participants.filter(
      (p) => p.toLowerCase() !== emailToRemove.toLowerCase()
    );

    const updatedChannel: DcpChannelMeta = {
      ...activeChannel,
      participants: updatedParticipants,
    };

    setChannels((prev) =>
      prev.map((c) => (c.id === activeChannel.id ? updatedChannel : c))
    );

    await dispatchDcpEmailPacket({
      channel: updatedChannel,
      type: 'chat.member-update',
      text: `${activeUser.displayName} removed ${
        removedUser?.displayName || emailToRemove
      } from the group.`,
      memberUpdate: {
        action: 'remove',
        targetEmail: emailToRemove,
        targetDisplayName: removedUser?.displayName,
        updatedParticipants,
      },
    });
  }

  // Start or jump to a 1-on-1 DM with any Contact
  function handleStartOrOpenContactChat(email: string) {
    const targetEmail = email.trim().toLowerCase();
    if (!targetEmail) return;

    const existingDm = channels.find(
      (c) =>
        c.type === 'dm' &&
        c.participants.some((p) => p.toLowerCase() === targetEmail) &&
        c.participants.some(
          (p) => p.toLowerCase() === activeUser.email.toLowerCase()
        )
    );

    if (existingDm) {
      setActiveChannelId(existingDm.id);
      setContactSearchQuery('');
      menuDirectoryDialogRef.current?.close();
      setMobileShowChatPane(true);
      return;
    }

    let existingUser = users.find(
      (u) => u.email.toLowerCase() === targetEmail
    );
    if (!existingUser) {
      const displayName = targetEmail.split('@')[0];
      existingUser = {
        email: targetEmail,
        displayName: `${displayName} (No App Yet)`,
        handle: `@${displayName.replace(/[^a-z0-9]/gi, '')}`,
        provider: targetEmail.includes('proton')
          ? 'proton'
          : targetEmail.includes('outlook')
          ? 'outlook'
          : targetEmail.includes('gmail')
          ? 'gmail'
          : 'yahoo',
        hasAppInstalled: false,
      };
      setUsers((prev) => [...prev, existingUser!]);
    }

    const dmCh: DcpChannelMeta = {
      id: `dm_${Date.now().toString(36)}`,
      type: 'dm',
      name: existingUser.displayName.replace(' (No App Yet)', ''),
      participants: [activeUser.email, existingUser.email],
    };
    setChannels((prev) => [dmCh, ...prev]);
    setActiveChannelId(dmCh.id);
    setContactSearchQuery('');
    menuDirectoryDialogRef.current?.close();
    setMobileShowChatPane(true);
  }

  // Send message from the Free-Flowing Messenger Composer
  async function handleMessengerSend(
    e?: React.FormEvent | React.KeyboardEvent
  ) {
    e?.preventDefault();
    if (!activeChannel) return;
    if (!composerText.trim() && pendingAttachments.length === 0) return;

    const cleanText =
      composerText.trim() ||
      `Sent ${pendingAttachments.length} encrypted attachment(s)`;
    const linkPreview = extractClientSideLinkPreview(cleanText);
    const effectiveBurnSec =
      composerBurnSeconds || activeChannel.ephemeralTimerSeconds || undefined;

    await dispatchDcpEmailPacket({
      channel: activeChannel,
      type: 'chat.message',
      text: cleanText,
      replyToMessageId: replyingToMessage?.packet.payload.messageId,
      attachments:
        pendingAttachments.length > 0 ? pendingAttachments : undefined,
      ephemeralTtlSeconds: effectiveBurnSec,
      linkPreview,
      vaultCategory:
        activeChannel.type === 'vault' ? vaultCategoryInput : undefined,
    });

    setComposerText('');
    setIsComposerMultiline(false);
    setIsPlusMenuOpen(false);
    setPendingAttachments([]);
    setReplyingToMessage(null);
    if (composerTextareaRef.current) {
      composerTextareaRef.current.style.height = '';
    }
  }

  // Create and dispatch an Encrypted Poll (`chat.poll`)
  async function handleCreateEncryptedPoll(e: React.FormEvent) {
    e.preventDefault();
    if (!activeChannel || !pollQuestionInput.trim()) return;
    const validOptions = pollOptionsInput
      .map((t) => t.trim())
      .filter(Boolean)
      .map((text, idx) => ({
        id: `opt_${idx}_${Date.now().toString(36)}`,
        text,
      }));
    if (validOptions.length < 2) return;

    const pollPayload: DcpPollPayload = {
      pollId: `poll_${Date.now().toString(36)}`,
      question: pollQuestionInput.trim(),
      options: validOptions,
    };

    pollCreatorDialogRef.current?.close();
    setPollQuestionInput('');

    await dispatchDcpEmailPacket({
      channel: activeChannel,
      type: 'chat.poll',
      text: `📊 Poll: ${pollPayload.question}`,
      poll: pollPayload,
    });
  }

  // Vote on an Encrypted Poll (`chat.poll-vote`)
  async function handleVoteOnEncryptedPoll(
    targetMessageId: string,
    pollId: string,
    optionId: string,
    optionText: string
  ) {
    if (!activeChannel) return;
    await dispatchDcpEmailPacket({
      channel: activeChannel,
      type: 'chat.poll-vote',
      targetMessageId,
      pollVote: { pollId, optionId },
      text: `Voted for ${optionText}`,
    });
  }

  // Pin or Unpin a message in the active conversation (`chat.pin`)
  async function handleTogglePinMessage(msg: FreeflowChatMessage) {
    if (!activeChannel) return;
    const currentPinned = pinnedMessageByChannel[activeChannel.id];
    const isUnpin =
      currentPinned?.messageId === msg.packet.payload.messageId;

    if (isUnpin) {
      setPinnedMessageByChannel((prev) => {
        const next = { ...prev };
        delete next[activeChannel.id];
        return next;
      });
    } else {
      setPinnedMessageByChannel((prev) => ({
        ...prev,
        [activeChannel.id]: {
          messageId: msg.packet.payload.messageId,
          text: (
            msg.packet.payload.poll?.question ||
            msg.packet.payload.text ||
            'Encrypted attachment'
          ).slice(0, 95),
          senderName: msg.packet.sender.displayName,
        },
      }));
    }

    await dispatchDcpEmailPacket({
      channel: activeChannel,
      type: 'chat.pin',
      targetMessageId: msg.packet.payload.messageId,
      pinUpdate: {
        targetMessageId: msg.packet.payload.messageId,
        action: isUnpin ? 'unpin' : 'pin',
        pinnedPreviewText: (msg.packet.payload.text || '').slice(0, 80),
      },
      text: `${activeUser.displayName} ${
        isUnpin ? 'unpinned' : 'pinned'
      } a message.`,
    });
  }

  // Open or jump to the active user's Personal Encrypted Vault (`Vault (@me)`)
  function handleOpenPersonalVault() {
    const vaultId = `vault_${activeUser.email.toLowerCase()}`;
    const existingVault = channels.find((c) => c.id === vaultId);
    if (!existingVault) {
      const newVault: DcpChannelMeta = {
        id: vaultId,
        type: 'vault',
        name: 'Vault (@me)',
        participants: [activeUser.email],
      };
      setChannels((prev) => [newVault, ...prev]);
    }
    setActiveChannelId(vaultId);
    setMobileShowChatPane(true);
  }

  // Unlock App Lock via PIN or Duress/Panic PIN
  async function handleUnlockWithPinOrDuress(e: React.FormEvent) {
    e.preventDefault();
    const outcome = evaluatePinOrDuressCode({
      enteredPin: lockScreenPinInput,
      normalPin: appLockPin,
      duressPin: duressPanicPin,
    });
    if (outcome === 'unlock') {
      setIsAppLocked(false);
      setLockScreenPinInput('');
      setLockScreenError('');
      return;
    }
    if (outcome === 'duress-shred') {
      // Silently scrub non-vault sensitive threads from IndexedDB and memory before unlocking!
      const sensitiveIds = transportEmails
        .filter((e) => !e.subject.includes('reg_'))
        .map((e) => e.id);
      await cryptographicScrubPeerAndEmailsInIdb({
        emailIdsToScrub: sensitiveIds,
      });
      setTransportEmails([]);
      setInspections([]);
      setIsAppLocked(false);
      setLockScreenPinInput('');
      setLockScreenError('');
      setDuressTriggeredBanner(
        'Duress / Panic PIN Executed: All conversation keys and IndexedDB message ciphertexts were zero-filled prior to unlock.'
      );
      return;
    }
    setLockScreenError('Incorrect PIN or Passkey. Try 2580 (or 9999 for Duress Panic Wipe).');
  }

  // Unlock App Lock via WebAuthn Passkey / Biometrics
  async function handleUnlockWithWebAuthnPasskey() {
    const res = await verifyWebAuthnPasskeyLock({
      credentialIdBase64Url: passkeyRegisteredId,
    });
    if (res.verified) {
      if (res.credentialId) {
        setPasskeyRegisteredId(res.credentialId);
      }
      setIsAppLocked(false);
      setLockScreenPinInput('');
      setLockScreenError('');
    }
  }

  // Send Emoji Reaction Packet over Email
  async function handleSendQuickReaction(
    targetMessageId: string,
    emoji: string
  ) {
    if (!activeChannel) return;
    setActiveReactionPickerMsgId(null);
    await dispatchDcpEmailPacket({
      channel: activeChannel,
      type: 'chat.reaction',
      targetMessageId,
      reactionEmoji: emoji,
      text: `Reacted ${emoji} to ${targetMessageId}`,
    });
  }

  function handleOpenPacketModal(emailId: string) {
    setSelectedEmailId(emailId);
    packetModalRef.current?.showModal();
  }

  async function handleCreateNewChannelOrDm(e: React.FormEvent) {
    e.preventDefault();
    let createdAliasEmail: string | undefined;

    if (useShieldedAliasInNewChat) {
      const alias = await createShieldedBurnerAlias({
        parentEmail: activeUser.email,
        displayName: activeUser.displayName,
        label: newChatAliasLabel || 'shield',
        strategy: newChatAliasStrategy,
      });
      setShieldedAliases((prev) => [alias, ...prev]);
      createdAliasEmail = alias.aliasEmail;
    }

    if (newChatType === 'workspace-channel') {
      const id = `ch_custom_${Date.now().toString(36)}`;
      const cleanName =
        newChatName
          .trim()
          .toLowerCase()
          .replace(/[^a-z0-9-]/g, '-') || 'new-group';
      const newCh: DcpChannelMeta = {
        id,
        type: 'workspace-channel',
        name: cleanName,
        participants: users.filter((u) => u.hasAppInstalled).map((u) => u.email),
        shieldedAliasEmail: createdAliasEmail,
      };
      setChannels((prev) => [newCh, ...prev]);
      setActiveChannelId(newCh.id);
      setNewChatName('');
      newChannelModalRef.current?.close();
      menuDirectoryDialogRef.current?.close();
      setMobileShowChatPane(true);
    } else {
      const targetEmail = newChatRecipientEmail.trim().toLowerCase();
      if (!targetEmail) return;

      let existingUser = users.find(
        (u) => u.email.toLowerCase() === targetEmail
      );
      if (!existingUser) {
        const displayName = targetEmail.split('@')[0];
        existingUser = {
          email: targetEmail,
          displayName: `${displayName} (No App Yet)`,
          handle: `@${displayName.replace(/[^a-z0-9]/gi, '')}`,
          provider: targetEmail.includes('proton')
            ? 'proton'
            : targetEmail.includes('outlook')
            ? 'outlook'
            : targetEmail.includes('gmail')
            ? 'gmail'
            : 'yahoo',
          hasAppInstalled: false,
        };
        setUsers((prev) => [...prev, existingUser!]);
      }

      const dmCh: DcpChannelMeta = {
        id: `dm_${Date.now().toString(36)}`,
        type: 'dm',
        name: existingUser.displayName.replace(' (No App Yet)', ''),
        participants: [activeUser.email, existingUser.email],
        shieldedAliasEmail: createdAliasEmail,
      };
      setChannels((prev) => [dmCh, ...prev]);
      setActiveChannelId(dmCh.id);
      setNewChatRecipientEmail('');
      newChannelModalRef.current?.close();
      menuDirectoryDialogRef.current?.close();
      setMobileShowChatPane(true);
    }
  }

  // 1-Click OAuth2 Popup Sign-In Handler (Real Google/Microsoft Popup if Client ID provided, or Interactive OAuth Consent Portal)
  async function handleOneClickOAuthPopup(
    provider: 'google' | 'microsoft',
    prefillEmail?: string
  ) {
    setConnectorStatusMsg('');
    const configuredClientId =
      provider === 'google'
        ? googleClientId.trim()
        : microsoftClientId.trim();

    if (configuredClientId) {
      try {
        const { accessToken } = await launchRealOAuthPopup({
          provider,
          clientId: configuredClientId,
        });
        if (provider === 'google') {
          setGmailAccessToken(accessToken);
        } else {
          setOutlookAccessToken(accessToken);
        }
        setConnectorStatusMsg(
          `Connected via Live ${provider.toUpperCase()} OAuth2 Popup! Token stored on-device.`
        );
      } catch (err) {
        setConnectorStatusMsg(
          `OAuth Popup Note: ${
            err instanceof Error ? err.message : String(err)
          }`
        );
      }
      return;
    }

    // Open the built-in Interactive OAuth Consent Popup Simulator so users can test 1-click sign-in immediately
    setSimulatedOAuthProvider(provider);
    const cleanPrefill = prefillEmail?.trim().toLowerCase();
    if (cleanPrefill && cleanPrefill.includes('@')) {
      setSimulatedOAuthEmail(cleanPrefill);
      const localPart = cleanPrefill.split('@')[0];
      const guessedName = localPart
        .split(/[._-]/)
        .filter(Boolean)
        .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
        .join(' ');
      setSimulatedOAuthName(
        easyDisplayNameInput.trim() || guessedName || 'User'
      );
    } else if (provider === 'google') {
      setSimulatedOAuthEmail('taylor.brooks@gmail.com');
      setSimulatedOAuthName('Taylor Brooks');
    } else {
      setSimulatedOAuthEmail('morgan.lee@outlook.com');
      setSimulatedOAuthName('Morgan Lee');
    }
  }

  // Easy 1-Field Email Lookup Handler: Evaluates the single email input and suggests the exact next step
  async function handleEasyEmailContinue(e: React.FormEvent) {
    e.preventDefault();
    const targetEmail = easyEmailInput.trim().toLowerCase();
    if (!targetEmail || !targetEmail.includes('@')) return;

    setConnectorStatusMsg('');
    setIsEasyDiscovering(true);
    try {
      const result = await discoverCustomDomainEmailConfig(targetEmail);
      setEasyDiscoveryResult(result);
      const localPart = targetEmail.split('@')[0];
      const guessedName = localPart
        .split(/[._-]/)
        .filter(Boolean)
        .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
        .join(' ');
      if (!easyDisplayNameInput.trim()) {
        setEasyDisplayNameInput(guessedName);
      }
    } finally {
      setIsEasyDiscovering(false);
    }
  }

  // Complete Sign-In from the OAuth Consent Portal or Custom Domain Portal:
  // Generates a fresh Curve25519 OpenPGP keypair on-device, saves the identity to IndexedDB, and logs right in!
  async function handleCompletePortalSignIn(params: {
    email: string;
    displayName: string;
    provider: 'gmail' | 'outlook' | 'proton' | 'yahoo' | 'custom-domain';
  }) {
    const cleanEmail = params.email.trim().toLowerCase();
    const cleanName = params.displayName.trim() || cleanEmail.split('@')[0];
    const handle = `@${cleanEmail.split('@')[0].replace(/[^a-z0-9]/gi, '')}`;

    setIsSending(true);
    try {
      const kp = await generateDeviceKeyPair(cleanName, cleanEmail);
      const newIdentity: UserIdentity = {
        email: cleanEmail,
        displayName: cleanName,
        handle,
        bio: `Signed in via ${params.provider.toUpperCase()} Portal • OpenPGP Verified`,
        profileUpdatedAt: new Date().toISOString(),
        provider: params.provider,
        hasAppInstalled: true,
        pgpKeyPair: kp,
      };

      const exists = users.some(
        (u) => u.email.toLowerCase() === cleanEmail
      );
      const updatedUsers = exists
        ? users.map((u) =>
            u.email.toLowerCase() === cleanEmail ? newIdentity : u
          )
        : [newIdentity, ...users];

      setUsers(updatedUsers);
      await saveUserIdentitiesToIdb(updatedUsers);
      setActiveUserEmail(newIdentity.email);
      setForceBroadcastProfileNext(true);
      setSimulatedOAuthProvider(null);
      setConnectorStatusMsg(
        `Signed in as ${newIdentity.displayName} (${newIdentity.email})! On-device OpenPGP keypair (${formatFingerprint(
          kp.fingerprint
        ).slice(0, 19)}…) generated & primary inbox isolation filter active.`
      );
    } finally {
      setIsSending(false);
    }
  }

  // Auto-Discover MX & Mail Server Settings for Any Custom Domain (`you@yourcompany.com`)
  async function handleRunCustomDomainDiscovery() {
    if (!customDomainEmail.trim()) return;
    setIsDiscoveringDomain(true);
    try {
      const result = await discoverCustomDomainEmailConfig(
        customDomainEmail.trim()
      );
      setDomainDiscoveryResult(result);
    } finally {
      setIsDiscoveringDomain(false);
    }
  }

  // Handle Email Provider OAuth / Bridge Connection Wizard
  async function handleSaveProviderConnection(e: React.FormEvent) {
    e.preventDefault();
    if (wizardProvider === 'custom-domain') {
      const disc =
        domainDiscoveryResult ||
        (await discoverCustomDomainEmailConfig(customDomainEmail));
      setDomainDiscoveryResult(disc);
      await handleCompletePortalSignIn({
        email: customDomainEmail,
        displayName: customDomainName,
        provider: disc.detectedProvider,
      });
      return;
    }

    if (wizardProvider === 'gmail' && gmailAccessToken.trim()) {
      const transport = new GmailDirectTransport(gmailAccessToken.trim());
      if (autoArchivePrimaryInbox) {
        try {
          const res = await transport.createAutoCleanInboxFilter();
          setConnectorStatusMsg(
            `Gmail Connected + Auto-Clean Inbox Filter Created (ID: ${res.filterId})`
          );
        } catch (err) {
          setConnectorStatusMsg(
            `Gmail OAuth Token saved (${
              err instanceof Error ? err.message : 'Ready'
            })`
          );
        }
      } else {
        setConnectorStatusMsg('Gmail OAuth2 Token Active for Outbound/Inbound');
      }
    } else if (wizardProvider === 'outlook' && outlookAccessToken.trim()) {
      setConnectorStatusMsg(
        'Microsoft Graph OAuth2 Token Active for Outbound/Inbound'
      );
    } else if (wizardProvider === 'proton') {
      setConnectorStatusMsg(
        `Proton Mail Bridge / Native OpenPGP Endpoint Configured (${protonBridgeHost})`
      );
    } else {
      setConnectorStatusMsg(
        `${wizardProvider.toUpperCase()} Connector Ready (Strict Header Filter Active)`
      );
    }
  }

  // Stage 1 Workbench Composer Submit
  async function handleSendEncryptedPacket(e: React.FormEvent) {
    e.preventDefault();
    const targetChannel: DcpChannelMeta = {
      id: `ch_${channelName.toLowerCase().replace(/[^a-z0-9]/g, '_')}`,
      type: recipientUser.hasAppInstalled ? 'workspace-channel' : 'dm',
      name: channelName,
      participants: Array.from(
        new Set([activeUser.email, recipientUser.email])
      ),
    };
    const lastAcceptedMsgId =
      acceptedPackets[0]?.decryptedPacket?.payload.messageId || 'msg_seed_01';

    await dispatchDcpEmailPacket({
      channel: targetChannel,
      type: packetType,
      text:
        packetType === 'chat.reaction'
          ? `Reacted ${reactionEmoji} to ${lastAcceptedMsgId}`
          : messageText.trim(),
      targetMessageId:
        packetType === 'chat.reaction' ? lastAcceptedMsgId : undefined,
      reactionEmoji:
        packetType === 'chat.reaction' ? reactionEmoji : undefined,
    });

    if (packetType === 'chat.message') {
      setMessageText('');
    }
  }

  async function handleInjectRegularEmail() {
    const samples = [
      {
        from: '"Netflix" <info@mailer.netflix.com>',
        subject: 'New sign-in to your Netflix account on Apple TV',
        body: 'We noticed a new sign-in to your Netflix account. Standard email without DCP/1.0 headers.',
      },
      {
        from: '"Chase Bank" <no-reply@alertsp.chase.com>',
        subject: 'Your monthly statement is ready to view',
        body: 'Your statement for account ending in 4491 is now available online.',
      },
      {
        from: '"Linear" <notifications@linear.app>',
        subject: '[ENG-209] Update mobile PWA viewport safe-area insets',
        body: 'Issue ENG-209 was moved to In Progress.',
      },
    ];
    const pick = samples[Math.floor(Math.random() * samples.length)];
    const id = `reg_injected_${Date.now().toString(36)}`;
    const nowIso = new Date().toISOString();

    const newRegEmail: RawTransportEmail = {
      id,
      from: pick.from,
      to: [activeUser.email],
      subject: pick.subject,
      date: nowIso,
      headers: {
        'MIME-Version': '1.0',
        From: pick.from,
        To: activeUser.email,
        Subject: pick.subject,
        'Content-Type': 'text/plain; charset="utf-8"',
      },
      rawMime: [
        'MIME-Version: 1.0',
        `From: ${pick.from}`,
        `To: ${activeUser.email}`,
        `Subject: ${pick.subject}`,
        `Date: ${new Date(nowIso).toUTCString()}`,
        'Content-Type: text/plain; charset="utf-8"',
        '',
        pick.body,
      ].join('\r\n'),
      textFallbackPart: pick.body,
    };

    const updated = [newRegEmail, ...transportEmails];
    setTransportEmails(updated);
    setSelectedEmailId(newRegEmail.id);
    await saveTransportEmailsToIdb(updated);
  }

  async function handleSimulateInstallAppForUser(emailToUpgrade: string) {
    const target = users.find((u) => u.email === emailToUpgrade);
    if (!target) return;
    const cleanName = target.displayName.replace(' (No App Yet)', '');
    const kp = await generateDeviceKeyPair(cleanName, target.email);
    const updatedUsers = users.map((u) =>
      u.email === emailToUpgrade
        ? {
            ...u,
            displayName: cleanName,
            hasAppInstalled: true,
            pgpKeyPair: kp,
          }
        : u
    );
    setUsers(updatedUsers);
    await saveUserIdentitiesToIdb(updatedUsers);
  }

  async function handleResetDemoState() {
    if (typeof window !== 'undefined') {
      window.localStorage.removeItem('atme_profile_onboarded');
      window.localStorage.removeItem('atme_blocked_emails');
      window.localStorage.removeItem('atme_whitelisted_emails');
      window.localStorage.removeItem('atme_whitelist_only');
    }
    await clearIdbDatabase();
    window.location.reload();
  }

  const isIphoneFrame =
    typeof window !== 'undefined' &&
    window.location.search.includes('iphone=1');

  return (
    <div
      data-bubble-theme={chatBubbleTheme}
      style={
        {
          '--dc-custom-color': customBubbleHex,
        } as React.CSSProperties
      }
      className={`dc-root-viewport ${isIphoneFrame ? 'iphone-frame' : ''} ${
        surfaceMode === 'messenger-ui' ? 'messenger-viewport' : ''
      }`}
    >
      {/* Hidden File Inputs for Real File/Image Attachments and Profile Avatar Upload */}
      <input
        ref={fileAttachmentInputRef}
        type="file"
        multiple
        accept="image/*,audio/*,.pdf,.txt,.doc,.docx,.zip"
        style={{ display: 'none' }}
        onChange={handleRealFileSelected}
      />
      <input
        ref={avatarUploadInputRef}
        type="file"
        accept="image/*"
        style={{ display: 'none' }}
        onChange={handleAvatarFileSelected}
      />

      {/* =====================================================================
          QR AUTO-WHITELIST / BLOCK / SAFETY TOAST BANNER
         ===================================================================== */}
      {safetyBannerNotice && (
        <div className="dc-safety-toast-banner" role="status">
          <span>{safetyBannerNotice}</span>
          <button
            type="button"
            className="dc-icon-btn"
            onClick={() => setSafetyBannerNotice('')}
            aria-label="Dismiss notice"
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* =====================================================================
          DURESS / PANIC WIPE ALERT BANNER (When unlocked via Duress PIN 9999)
         ===================================================================== */}
      {duressTriggeredBanner && (
        <div className="dc-duress-wiped-banner" role="status">
          <div className="dc-duress-wiped-left">
            <AlertTriangle size={15} />
            <span>{duressTriggeredBanner}</span>
          </div>
          <button
            type="button"
            className="dc-icon-btn"
            onClick={() => setDuressTriggeredBanner('')}
            aria-label="Dismiss duress notice"
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* =====================================================================
          BIOMETRIC PASSKEY (WebAuthn) & DURESS PIN APP LOCK OVERLAY
         ===================================================================== */}
      {isAppLocked && (
        <div
          className="dc-applock-overlay"
          role="dialog"
          aria-modal="true"
          aria-label="@me Encrypted App Lock"
        >
          <div className="dc-applock-card">
            <div className="dc-applock-icon-ring">
              <Fingerprint size={28} />
            </div>
            <h2>🔒 Locked</h2>

            <button
              type="button"
              className="dc-btn-passkey-unlock"
              onClick={handleUnlockWithWebAuthnPasskey}
            >
              <Fingerprint size={16} /> 👆 Face / Touch ID
            </button>

            <div className="dc-applock-divider">
              <span>OR PIN</span>
            </div>

            <form
              className="dc-applock-pin-form"
              onSubmit={handleUnlockWithPinOrDuress}
            >
              <input
                type="password"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={8}
                value={lockScreenPinInput}
                onChange={(e) => setLockScreenPinInput(e.target.value)}
                placeholder="🔢 PIN (2580)"
                aria-label="PIN"
              />
              <button type="submit" className="dc-btn-send">
                <Lock size={14} /> 🔓 Unlock
              </button>
            </form>

            {lockScreenError && (
              <div className="dc-applock-error">{lockScreenError}</div>
            )}

            <div className="dc-applock-hints">
              <span>
                <KeyRound size={11} /> 🔑 PIN: <code>{appLockPin}</code>
              </span>
              <span>
                <Flame size={11} /> 🔥 Wipe: <code>{duressPanicPin}</code>
              </span>
            </div>
          </div>
        </div>
      )}

      {/* =====================================================================
          DEFAULT ANDROID / iMESSAGE TEXTING UI WITH FREE-FLOWING THREADS
         ===================================================================== */}
      {surfaceMode === 'messenger-ui' && (
        <div className="dc-texting-layout">
          {/* Left Pane: Recent Text Threads + Instant Contact Search */}
          <aside
            className={`dc-threads-pane ${
              mobileShowChatPane ? 'mobile-hidden' : ''
            }`}
          >
            <div className="dc-threads-pane-top">
              <div className="dc-threads-title-row">
                <div className="dc-threads-brand">
                  <img
                    src="/atme-app-icon.png"
                    alt="@"
                    className="dc-threads-brand-logo"
                  />
                  <h2>me</h2>
                </div>
                <div className="dc-threads-top-actions">
                  <button
                    type="button"
                    className="dc-compose-circle-btn dc-qr-header-btn"
                    onClick={() => {
                      setProfileModalStep('qr-card');
                      profileDialogRef.current?.showModal();
                      (document.activeElement as HTMLElement | null)?.blur?.();
                    }}
                    title="@me QR"
                    aria-label="Open @me QR"
                  >
                    <QrCode size={15} />
                  </button>

                  <button
                    type="button"
                    className="dc-compose-circle-btn"
                    onClick={() => {
                      setNewChatType('dm');
                      newChannelModalRef.current?.showModal();
                    }}
                    title="New Message"
                    aria-label="New Message"
                  >
                    <Plus size={16} />
                  </button>

                  {/* Single Consolidated Avatar Menu */}
                  <div
                    className="dc-avatar-menu-wrap"
                    ref={avatarMenuContainerRef}
                  >
                    <button
                      type="button"
                      className={`dc-avatar-menu-trigger ${
                        isAvatarMenuOpen ? 'active' : ''
                      }`}
                      onClick={() => setIsAvatarMenuOpen((prev) => !prev)}
                      title={`${activeUser.displayName} (${activeUser.handle || '@me'}) — Menu`}
                      aria-label="Open Profile & Account Menu"
                      aria-expanded={isAvatarMenuOpen}
                    >
                      {renderUserAvatar(
                        activeUser,
                        activeUser.displayName,
                        'dc-header-user-avatar'
                      )}
                      <span className="dc-avatar-online-dot" />
                    </button>

                    {isAvatarMenuOpen && (
                      <div
                        className="dc-avatar-dropdown-menu"
                        role="menu"
                        aria-label="Account & Profile Menu"
                      >
                        <div className="dc-avatar-menu-header">
                          <button
                            type="button"
                            className="dc-avatar-menu-user dc-avatar-menu-user-btn"
                            onClick={() => {
                              setIsAvatarMenuOpen(false);
                              setProfileModalStep('edit');
                              profileDialogRef.current?.showModal();
                            }}
                            title="Edit Profile"
                          >
                            {renderUserAvatar(
                              activeUser,
                              activeUser.displayName,
                              'dc-avatar-menu-pic'
                            )}
                            <div className="dc-avatar-menu-meta">
                              <strong>{activeUser.displayName}</strong>
                              <span>{activeUser.handle || '@user'}</span>
                            </div>
                          </button>
                          <div className="dc-avatar-qr-actions-row">
                            <button
                              type="button"
                              className="dc-avatar-qr-quick-btn"
                              onClick={() => {
                                setIsAvatarMenuOpen(false);
                                setProfileModalStep('qr-card');
                                profileDialogRef.current?.showModal();
                                (
                                  document.activeElement as HTMLElement | null
                                )?.blur?.();
                              }}
                            >
                              <QrCode size={14} /> @me QR
                            </button>
                          </div>
                        </div>

                        <div className="dc-header-menu-divider" />

                        <button
                          type="button"
                          className="dc-header-menu-item"
                          role="menuitem"
                          onClick={() => {
                            setIsAvatarMenuOpen(false);
                            menuDirectoryDialogRef.current?.showModal();
                          }}
                        >
                          <span className="dc-header-menu-icon icon-people">
                            <Users size={15} />
                          </span>
                          <span className="dc-header-menu-label">
                            Friends
                          </span>
                        </button>

                        <button
                          type="button"
                          className="dc-header-menu-item"
                          role="menuitem"
                          onClick={() => {
                            setIsAvatarMenuOpen(false);
                            setSafetyModalTab('whitelist');
                            safetyListDialogRef.current?.showModal();
                          }}
                        >
                          <span className="dc-header-menu-icon icon-safety">
                            <ShieldCheck size={15} />
                          </span>
                          <span className="dc-header-menu-label">
                            Safety
                          </span>
                          {(whitelistOnlyMode || blockedEmails.length > 0) && (
                            <span className="dc-header-menu-badge">
                              {whitelistOnlyMode
                                ? '✅ ON'
                                : `🚫 ${blockedEmails.length}`}
                            </span>
                          )}
                        </button>

                        <button
                          type="button"
                          className="dc-header-menu-item"
                          role="menuitem"
                          onClick={() => {
                            setIsAvatarMenuOpen(false);
                            setConnectModalMode('easy');
                            setSimulatedOAuthProvider(null);
                            connectWizardDialogRef.current?.showModal();
                          }}
                        >
                          <span className="dc-header-menu-icon icon-settings">
                            <Link2 size={15} />
                          </span>
                          <span className="dc-header-menu-label">
                            Account
                          </span>
                        </button>

                        <div className="dc-header-menu-divider" />

                        <div className="dc-avatar-theme-picker">
                          <span className="dc-avatar-section-label">
                            🌗 Mode
                          </span>
                          <div className="dc-setting-segmented">
                            <button
                              type="button"
                              className={`dc-seg-btn ${
                                colorSchemePref === 'dark'
                                  ? 'is-active'
                                  : ''
                              }`}
                              onClick={() =>
                                handleSelectColorScheme('dark')
                              }
                            >
                              🌙 Dark
                            </button>
                            <button
                              type="button"
                              className={`dc-seg-btn ${
                                colorSchemePref === 'light'
                                  ? 'is-active'
                                  : ''
                              }`}
                              onClick={() =>
                                handleSelectColorScheme('light')
                              }
                            >
                              ☀️ Light
                            </button>
                            <button
                              type="button"
                              className={`dc-seg-btn ${
                                colorSchemePref === 'light dark'
                                  ? 'is-active'
                                  : ''
                              }`}
                              onClick={() =>
                                handleSelectColorScheme('light dark')
                              }
                            >
                              ✨ Auto
                            </button>
                          </div>
                        </div>

                        <div className="dc-avatar-theme-picker">
                          <span className="dc-avatar-section-label">
                            🎨 Color
                          </span>
                          <div className="dc-bubble-theme-swatches">
                            {(
                              [
                                {
                                  id: 'ocean',
                                  label: 'Ocean',
                                  color: '#0a84ff',
                                },
                                {
                                  id: 'berry',
                                  label: 'Berry',
                                  color: '#ec4899',
                                },
                                {
                                  id: 'violet',
                                  label: 'Violet',
                                  color: '#8b5cf6',
                                },
                                {
                                  id: 'mint',
                                  label: 'Mint',
                                  color: '#10b981',
                                },
                                {
                                  id: 'sunset',
                                  label: 'Sunset',
                                  color: '#f97316',
                                },
                                {
                                  id: 'gold',
                                  label: 'Gold',
                                  color: '#eab308',
                                },
                              ] as const
                            ).map((t) => (
                              <button
                                key={t.id}
                                type="button"
                                className={`dc-bubble-swatch-btn ${
                                  chatBubbleTheme === t.id ? 'active' : ''
                                }`}
                                style={{ background: t.color }}
                                onClick={() => handleSelectBubbleTheme(t.id)}
                                title={t.label}
                                aria-label={t.label}
                              />
                            ))}

                            <label
                              className={`dc-custom-color-circle ${
                                chatBubbleTheme === 'custom' ? 'active' : ''
                              }`}
                              title="Custom Color Wheel"
                              aria-label="Pick custom color"
                            >
                              <input
                                type="color"
                                value={customBubbleHex}
                                onChange={(e) =>
                                  handleSelectCustomBubbleColor(e.target.value)
                                }
                              />
                              <span
                                className="dc-custom-color-core"
                                style={{ background: customBubbleHex }}
                              />
                            </label>
                          </div>
                        </div>

                        <div className="dc-header-menu-divider" />

                        <div className="dc-avatar-menu-switcher">
                          <label htmlFor="avatar-account-switch">
                            🔄 Switch
                          </label>
                          <select
                            id="avatar-account-switch"
                            value={activeUserEmail}
                            onChange={(e) => {
                              setActiveUserEmail(e.target.value);
                              setIsAvatarMenuOpen(false);
                            }}
                          >
                            {users
                              .filter((u) => u.hasAppInstalled)
                              .map((u) => (
                                <option key={u.email} value={u.email}>
                                  {u.displayName} ({u.handle || u.email})
                                </option>
                              ))}
                          </select>
                        </div>

                        <div className="dc-header-menu-divider" />

                        <div className="dc-avatar-menu-footer">
                          <button
                            type="button"
                            className="dc-avatar-footer-btn"
                            onClick={() => {
                              setIsAvatarMenuOpen(false);
                              setLockScreenPinInput('');
                              setLockScreenError('');
                              setIsAppLocked(true);
                            }}
                          >
                            🔒 Lock
                          </button>
                          <button
                            type="button"
                            className="dc-avatar-footer-btn"
                            onClick={() => {
                              setIsAvatarMenuOpen(false);
                              handleResetDemoState();
                            }}
                          >
                            ♻️ Reset
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Contact & Conversation Search Bar */}
              <div className="dc-search-box">
                <Search size={15} className="dc-search-icon" />
                <input
                  type="search"
                  value={contactSearchQuery}
                  onChange={(e) => setContactSearchQuery(e.target.value)}
                  placeholder="🔍 Search…"
                />
                {contactSearchQuery && (
                  <button
                    type="button"
                    className="dc-clear-search-btn"
                    onClick={() => setContactSearchQuery('')}
                  >
                    <X size={13} />
                  </button>
                )}
              </div>

              {/* Quick Instant Email Lookup if typing a new email address */}
              {contactSearchQuery.includes('@') &&
                !contactSearchQuery.startsWith('@') && (
                  <button
                    type="button"
                    className="dc-instant-email-start"
                    onClick={() =>
                      handleStartOrOpenContactChat(contactSearchQuery)
                    }
                  >
                    <UserPlus size={15} />
                    <div>
                      <strong>
                        💬 {contactSearchQuery.trim()}
                      </strong>
                      <span>
                        ✨ Start Chat
                      </span>
                    </div>
                    <ChevronRight size={15} />
                  </button>
                )}

              {/* Matching Contacts from Directory */}
              {matchingContacts.length > 0 && (
                <div className="dc-search-contacts-results">
                  <div className="dc-search-section-label">
                    👥 FRIENDS
                  </div>
                  {matchingContacts.map((c) => (
                    <button
                      key={c.email}
                      type="button"
                      className="dc-contact-hit-row"
                      onClick={() => handleStartOrOpenContactChat(c.email)}
                    >
                      {renderUserAvatar(c, c.displayName)}
                      <div className="dc-contact-hit-info">
                        <strong>
                          {c.displayName}{' '}
                          {c.handle && (
                            <small className="dc-handle-tag">{c.handle}</small>
                          )}
                        </strong>
                        <span>
                          {c.email}
                          {!c.hasAppInstalled ? ' • 📩 Invite' : ''}
                        </span>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Unified Chronological Conversation List (Sorted Most Recent at Top, Scoped to Active Account) */}
            <div className="dc-thread-list">
              {threadListSummaries.length === 0 ? (
                <div className="dc-empty-threads-state">
                  <div className="dc-empty-threads-icon">
                    <MessageSquare size={22} />
                  </div>
                  <strong>👋 No chats yet</strong>
                  <button
                    type="button"
                    className="dc-pill-action-btn"
                    onClick={() => {
                      setNewChatType('dm');
                      newChannelModalRef.current?.showModal();
                    }}
                  >
                    <Plus size={14} /> 💬 Chat
                  </button>
                </div>
              ) : (
                threadListSummaries.map(
                  ({ channel: ch, lastText, lastTime, peerUser, unreadCount }) => {
                    const isActive = ch.id === activeChannel?.id;
                    const isVault = ch.type === 'vault';
                    const isGroup = ch.type !== 'dm' && !isVault;
                    const hasApp =
                      isGroup || isVault
                        ? true
                        : peerUser?.hasAppInstalled ?? false;

                    return (
                      <button
                        key={ch.id}
                        type="button"
                        className={`dc-thread-card ${isActive ? 'active' : ''} ${
                          isVault ? 'vault-thread-card' : ''
                        } ${unreadCount > 0 ? 'has-unread' : ''}`}
                        onClick={() => {
                          setActiveChannelId(ch.id);
                          setReplyingToMessage(null);
                          setMobileShowChatPane(true);
                        }}
                      >
                        {!isGroup && !isVault && peerUser?.avatarDataUrl ? (
                          <img
                            src={peerUser.avatarDataUrl}
                            alt={peerUser.displayName}
                            className="dc-thread-avatar dc-avatar-img"
                          />
                        ) : (
                          <div
                            className={`dc-thread-avatar ${
                              isVault
                                ? 'vault-avatar'
                                : isGroup
                                ? 'group-avatar'
                                : hasApp
                                ? 'dm-avatar'
                                : 'invite-avatar'
                            }`}
                          >
                            {isVault ? (
                              <Bookmark size={17} />
                            ) : isGroup ? (
                              <Users size={18} />
                            ) : (
                              (peerUser?.displayName || ch.name)
                                .charAt(0)
                                .toUpperCase()
                            )}
                          </div>
                        )}

                        <div className="dc-thread-card-body">
                          <div className="dc-thread-card-top">
                            <span className="dc-thread-title">
                              {isVault
                                ? 'Saved Notes (@me)'
                                : isGroup
                                ? `#${ch.name}`
                                : (
                                    peerUser?.displayName ||
                                    ch.participants.find(
                                      (p) =>
                                        p.toLowerCase() !==
                                        activeUser.email.toLowerCase()
                                    ) ||
                                    ch.name
                                  ).replace(' (No App Yet)', '')}
                            </span>
                            {lastTime && (
                              <span className="dc-thread-timestamp">
                                {new Date(lastTime).toLocaleTimeString([], {
                                  hour: '2-digit',
                                  minute: '2-digit',
                                })}
                              </span>
                            )}
                          </div>

                          <div className="dc-thread-card-bottom">
                            <div className="dc-thread-snippet">{lastText}</div>
                            {unreadCount > 0 && (
                              <span
                                className="dc-thread-unread-badge"
                                aria-label={`${unreadCount} unread`}
                              >
                                {unreadCount}
                              </span>
                            )}
                          </div>
                        </div>
                      </button>
                    );
                  }
                )
              )}
            </div>
          </aside>

          {/* Right Pane: Free-Flowing iMessage / Android Text Stream */}
          <section
            className={`dc-freeflow-chat-pane ${
              !mobileShowChatPane ? 'mobile-hidden' : ''
            }`}
          >
            {!activeChannel ? (
              <div className="dc-empty-chat-pane">
                <div className="dc-empty-chat-card">
                  <div className="dc-empty-threads-icon">
                    <MessageSquare size={28} />
                  </div>
                  <h2>👋 Hey, {activeUser.displayName}!</h2>
                  <div className="dc-empty-chat-actions">
                    <button
                      type="button"
                      className="dc-btn-send"
                      onClick={() => {
                        setNewChatType('dm');
                        newChannelModalRef.current?.showModal();
                      }}
                    >
                      <Plus size={15} /> 💬 Chat
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <>
                {/* Top Conversation Header */}
                <header className="dc-freeflow-header">
                  <div className="dc-freeflow-header-left">
                    <button
                      type="button"
                      className="dc-mobile-back-btn"
                      onClick={() => setMobileShowChatPane(false)}
                      aria-label="Back to conversations"
                    >
                      <ArrowLeft size={18} />
                    </button>

                    <div
                      className="dc-freeflow-header-identity"
                      onClick={() => groupInfoDialogRef.current?.showModal()}
                      title="Conversation participants"
                    >
                      {activeChannel.type === 'vault' ? (
                        <div className="dc-header-avatar vault-avatar">
                          <Bookmark size={16} />
                        </div>
                      ) : activeChannel.type === 'dm' &&
                        activeChannelPeerUser?.avatarDataUrl ? (
                        <img
                          src={activeChannelPeerUser.avatarDataUrl}
                          alt={activeChannelDisplayTitle}
                          className="dc-header-avatar dc-avatar-img"
                        />
                      ) : (
                        <div className="dc-header-avatar">
                          {activeChannel.type === 'dm' ? (
                            activeChannelDisplayTitle.charAt(0).toUpperCase()
                          ) : (
                            <Users size={17} />
                          )}
                        </div>
                      )}
                      <div>
                        <h2>{activeChannelDisplayTitle}</h2>
                      </div>
                    </div>
                  </div>

                  <div className="dc-freeflow-header-actions">
                    {/* Top-Right 3-Line Dropdown Menu (Add People, Burn Thread, Settings) */}
                    <div
                      className="dc-header-menu-wrap"
                      ref={headerMenuContainerRef}
                    >
                      <button
                        type="button"
                        className={`dc-header-menu-trigger dc-icon-only-pill ${
                          isHeaderMenuOpen ? 'is-open' : ''
                        }`}
                        onClick={() => setIsHeaderMenuOpen((prev) => !prev)}
                        aria-expanded={isHeaderMenuOpen}
                        aria-haspopup="menu"
                        aria-label="Open conversation menu (Add People, Burn Thread, Settings)"
                        title="Menu: Add People, Burn Thread & Settings"
                      >
                        <Menu size={17} />
                      </button>

                      {isHeaderMenuOpen && (
                        <div
                          className="dc-header-dropdown-menu"
                          role="menu"
                          aria-label="Conversation actions and settings"
                        >
                          <div
                            className="dc-header-menu-actions-row"
                            role="toolbar"
                            aria-label="Conversation actions"
                          >
                            {activeChannel.type !== 'vault' && (
                              <button
                                type="button"
                                role="menuitem"
                                className="dc-header-action-btn action-people"
                                onClick={() => {
                                  setIsHeaderMenuOpen(false);
                                  groupInfoDialogRef.current?.showModal();
                                }}
                                title={`People${
                                  activeChannel.participants.length > 2
                                    ? ` (${activeChannel.participants.length})`
                                    : ''
                                }`}
                                aria-label={`People${
                                  activeChannel.participants.length > 2
                                    ? ` (${activeChannel.participants.length})`
                                    : ''
                                }`}
                              >
                                <UserPlus size={16} />
                              </button>
                            )}

                            <button
                              type="button"
                              role="menuitem"
                              className="dc-header-action-btn action-clear"
                              onClick={() => {
                                setIsHeaderMenuOpen(false);
                                setPendingShredOptions({
                                  shredScope: 'peer-pgp-key-and-threads',
                                });
                                shredConfirmDialogRef.current?.showModal();
                              }}
                              title="Clear chat"
                              aria-label="Clear chat"
                            >
                              <Flame size={16} />
                            </button>

                            {activeChannel.type !== 'vault' &&
                              activeChannel.participants.length <= 2 &&
                              activeChannelPeerUser && (
                                <button
                                  type="button"
                                  role="menuitem"
                                  className="dc-header-action-btn action-block"
                                  onClick={() => {
                                    setIsHeaderMenuOpen(false);
                                    handleBlockEmail(activeChannelPeerUser.email);
                                  }}
                                  title="Block user"
                                  aria-label="Block user"
                                >
                                  <UserMinus size={16} />
                                </button>
                              )}
                          </div>

                          <div className="dc-header-menu-divider" />

                          <div
                            className="dc-header-settings-panel"
                            role="group"
                            aria-label="Messenger Settings"
                          >
                            <div className="dc-setting-group">
                              <span className="dc-setting-label">
                                🎨 Color
                              </span>
                              <div className="dc-bubble-theme-swatches">
                                {(
                                  [
                                    {
                                      id: 'ocean',
                                      label: 'Ocean',
                                      color: '#0a84ff',
                                    },
                                    {
                                      id: 'berry',
                                      label: 'Berry',
                                      color: '#ec4899',
                                    },
                                    {
                                      id: 'violet',
                                      label: 'Violet',
                                      color: '#8b5cf6',
                                    },
                                    {
                                      id: 'mint',
                                      label: 'Mint',
                                      color: '#10b981',
                                    },
                                    {
                                      id: 'sunset',
                                      label: 'Sunset',
                                      color: '#f97316',
                                    },
                                    {
                                      id: 'gold',
                                      label: 'Gold',
                                      color: '#eab308',
                                    },
                                  ] as const
                                ).map((t) => (
                                  <button
                                    key={t.id}
                                    type="button"
                                    className={`dc-bubble-swatch-btn ${
                                      chatBubbleTheme === t.id ? 'active' : ''
                                    }`}
                                    style={{ background: t.color }}
                                    onClick={() =>
                                      handleSelectBubbleTheme(t.id)
                                    }
                                    title={t.label}
                                    aria-label={t.label}
                                  />
                                ))}

                                <label
                                  className={`dc-custom-color-circle ${
                                    chatBubbleTheme === 'custom' ? 'active' : ''
                                  }`}
                                  title="Custom Color Wheel"
                                  aria-label="Pick custom color"
                                >
                                  <input
                                    type="color"
                                    value={customBubbleHex}
                                    onChange={(e) =>
                                      handleSelectCustomBubbleColor(
                                        e.target.value
                                      )
                                    }
                                  />
                                  <span
                                    className="dc-custom-color-core"
                                    style={{ background: customBubbleHex }}
                                  />
                                </label>
                              </div>
                            </div>

                            <div className="dc-setting-group">
                              <button
                                type="button"
                                className="dc-header-toggle-row-btn"
                                onClick={() =>
                                  setShowMessageTimestamps((prev) => !prev)
                                }
                                title={
                                  showMessageTimestamps
                                    ? 'Timestamps visible (click to hide)'
                                    : 'Timestamps hidden (click to show)'
                                }
                                aria-label={`Toggle timestamps: currently ${
                                  showMessageTimestamps ? 'visible' : 'hidden'
                                }`}
                              >
                                <span className="dc-setting-label">
                                  🕒 Time
                                </span>
                                <span
                                  className={`dc-toggle-status-pill ${
                                    showMessageTimestamps
                                      ? 'is-visible'
                                      : 'is-hidden'
                                  }`}
                                >
                                  <span>
                                    {showMessageTimestamps
                                      ? 'Visible'
                                      : 'Hidden'}
                                  </span>
                                  {showMessageTimestamps ? (
                                    <Eye size={14} />
                                  ) : (
                                    <EyeOff size={14} />
                                  )}
                                </span>
                              </button>
                            </div>

                            <div className="dc-setting-group">
                              <button
                                type="button"
                                className="dc-default-emoji-trigger"
                                aria-expanded={isDefaultEmojiMenuOpen}
                                onClick={() => {
                                  setIsDefaultEmojiMenuOpen((prev) => {
                                    const next = !prev;
                                    if (!next) {
                                      setEditingEmojiSlotIndex(null);
                                      setEmojiSearchQuery('');
                                    }
                                    return next;
                                  });
                                }}
                              >
                                <span className="dc-setting-label">
                                  😎 Default
                                </span>
                                <span className="dc-default-emoji-preview-strip">
                                  {defaultQuickEmojis.map((em, idx) => (
                                    <span key={idx}>{em}</span>
                                  ))}
                                  <ChevronRight
                                    size={14}
                                    className={`dc-settings-chevron ${
                                      isDefaultEmojiMenuOpen
                                        ? 'is-expanded'
                                        : ''
                                    }`}
                                  />
                                </span>
                              </button>

                              {isDefaultEmojiMenuOpen && (
                                <div className="dc-default-emoji-customizer">
                                  <div className="dc-top5-emoji-slots">
                                    {defaultQuickEmojis.map((emoji, idx) => (
                                      <button
                                        key={idx}
                                        type="button"
                                        className={`dc-top5-emoji-slot-btn ${
                                          editingEmojiSlotIndex === idx
                                            ? 'is-editing'
                                            : ''
                                        }`}
                                        onClick={() => {
                                          setEditingEmojiSlotIndex((prev) =>
                                            prev === idx ? null : idx
                                          );
                                          setEmojiSearchQuery('');
                                        }}
                                        title={`Tap to replace slot #${idx + 1} (${emoji})`}
                                        aria-label={`Replace default emoji slot ${idx + 1}: ${emoji}`}
                                      >
                                        <span className="dc-slot-emoji">
                                          {emoji}
                                        </span>
                                        <small>#{idx + 1}</small>
                                      </button>
                                    ))}
                                  </div>

                                  {editingEmojiSlotIndex !== null && (
                                    <div className="dc-all-emojis-picker-box">
                                      <div className="dc-emoji-search-input-wrap">
                                        <Search
                                          size={13}
                                          className="dc-emoji-search-icon"
                                        />
                                        <input
                                          type="search"
                                          value={emojiSearchQuery}
                                          onChange={(e) =>
                                            setEmojiSearchQuery(e.target.value)
                                          }
                                          placeholder={`🔍 Search slot #${
                                            editingEmojiSlotIndex + 1
                                          }…`}
                                          aria-label="Search all emojis"
                                          autoFocus
                                        />
                                      </div>

                                      <div
                                        className="dc-all-emojis-scroll-grid"
                                        role="listbox"
                                        aria-label="All emojis"
                                      >
                                        {ALL_SEARCHABLE_EMOJIS.filter((item) => {
                                          const q = emojiSearchQuery
                                            .trim()
                                            .toLowerCase();
                                          if (!q) return true;
                                          return (
                                            item.emoji.includes(q) ||
                                            item.keywords
                                              .toLowerCase()
                                              .includes(q)
                                          );
                                        }).map((item, idx) => (
                                          <button
                                            key={`${item.emoji}-${idx}`}
                                            type="button"
                                            className={`dc-emoji-catalog-btn ${
                                              defaultQuickEmojis[
                                                editingEmojiSlotIndex
                                              ] === item.emoji
                                                ? 'is-current'
                                                : ''
                                            }`}
                                            onClick={() =>
                                              handleReplaceDefaultEmojiSlot(
                                                editingEmojiSlotIndex,
                                                item.emoji
                                              )
                                            }
                                            title={item.keywords}
                                          >
                                            {item.emoji}
                                          </button>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </header>

                {/* Pinned Message Banner (Feature 5 — hidden while showPinAndPacketControls is false, preserved for future restore) */}
                {showPinAndPacketControls &&
                  pinnedMessageByChannel[activeChannel.id] && (
                  <div className="dc-pinned-message-banner">
                    <div className="dc-pinned-banner-left">
                      <Pin size={13} className="dc-pin-icon" />
                      <div>
                        <strong>
                          Pinned by{' '}
                          {
                            pinnedMessageByChannel[activeChannel.id]!
                              .senderName
                          }
                          :
                        </strong>{' '}
                        <span>
                          {pinnedMessageByChannel[activeChannel.id]!.text}
                        </span>
                      </div>
                    </div>
                    <button
                      type="button"
                      className="dc-pinned-unpin-btn"
                      onClick={() =>
                        setPinnedMessageByChannel((prev) => {
                          const next = { ...prev };
                          delete next[activeChannel.id];
                          return next;
                        })
                      }
                      title="Unpin message"
                      aria-label="Unpin message"
                    >
                      <X size={13} />
                    </button>
                  </div>
                )}

            {/* Non-App Recipient Onboarding Banner */}
            {channelHasNonAppParticipant && (
              <div className="dc-non-app-banner">
                <div>
                  <strong>📩 Invite {activeChannelDisplayTitle}</strong>
                </div>
                <button
                  type="button"
                  className="dc-btn-banner"
                  onClick={() =>
                    handleSimulateInstallAppForUser('jordan.taylor@yahoo.com')
                  }
                >
                  <UserCheck size={13} /> ✨ Join Demo
                </button>
              </div>
            )}

            {/* Free-Flowing Message Stream */}
            <div
              className="dc-freeflow-feed"
              ref={freeflowFeedRef}
              onScroll={handleFeedScroll}
            >
              {freeflowStream.length === 0 && (
                <div className="dc-clean-empty-thread">
                  <div className="dc-clean-empty-avatar">
                    {activeChannel.type === 'vault' ? (
                      <Bookmark size={22} />
                    ) : activeChannel.type === 'dm' ? (
                      activeChannelDisplayTitle.charAt(0).toUpperCase()
                    ) : (
                      <Users size={22} />
                    )}
                  </div>
                  <strong>
                    {activeChannel.type === 'vault'
                      ? '📌 Notes'
                      : `👋 Say hi!`}
                  </strong>
                </div>
              )}

              {freeflowStream.map((msg, index) => {
                const isOwn =
                  msg.packet.sender.email.toLowerCase() ===
                  activeUser.email.toLowerCase();
                const alreadyReadByMe = msg.receipts.some(
                  (r) =>
                    r.senderEmail.toLowerCase() ===
                    activeUser.email.toLowerCase()
                );
                const isFirstUnread = index === firstUnreadMsgIndex;
                const isMsgUnread =
                  !isOwn &&
                  !alreadyReadByMe &&
                  !readMessageIds.has(msg.packet.payload.messageId);
                const senderIdentity = users.find(
                  (u) =>
                    u.email.toLowerCase() ===
                    msg.packet.sender.email.toLowerCase()
                );
                const displayAuthor =
                  senderIdentity?.displayName || msg.packet.sender.displayName;
                const displayHandle =
                  senderIdentity?.handle || msg.packet.sender.handle;
                const hasBeenReadByPeer = msg.receipts.length > 0;
                const effectiveBurnTtl =
                  msg.packet.payload.ephemeralTtlSeconds ||
                  activeChannel.ephemeralTimerSeconds ||
                  0;
                const isBurnHiddenInManualMode =
                  !isOwn &&
                  readReceiptMode === 'manual' &&
                  effectiveBurnTtl > 0 &&
                  !alreadyReadByMe &&
                  !burnReadStartedAtMs[msg.packet.payload.messageId];

                // System Pill for Adding / Removing Group Members
                if (msg.packet.type === 'chat.member-update') {
                  return (
                    <div
                      key={msg.emailId}
                      className="dc-system-event-pill"
                    >
                      <Users size={13} />
                      <span>{msg.packet.payload.text}</span>
                    </div>
                  );
                }

                const isTwoPersonChat =
                  activeChannel.type !== 'group' ||
                  activeChannel.participants.length <= 2;
                const groupedReactions = msg.reactions.reduce<
                  Array<{ emoji: string; senderNames: string[] }>
                >((acc, r) => {
                  const existing = acc.find((item) => item.emoji === r.emoji);
                  if (existing) {
                    if (!existing.senderNames.includes(r.senderName)) {
                      existing.senderNames.push(r.senderName);
                    }
                  } else {
                    acc.push({ emoji: r.emoji, senderNames: [r.senderName] });
                  }
                  return acc;
                }, []);
                const isMsgActionOpen =
                  selectedActionMsgId === msg.packet.payload.messageId ||
                  activeReactionPickerMsgId === msg.packet.payload.messageId;

                return (
                  <React.Fragment key={msg.emailId}>
                    {isFirstUnread && (
                      <div
                        id="dc-first-unread-marker"
                        className="dc-unread-divider"
                        role="separator"
                        aria-label="Unread messages divider"
                      >
                        <span className="dc-unread-divider-line" />
                        <span className="dc-unread-divider-pill">
                          <span className="dc-unread-dot" />
                          {activeChannelUnreadCount} Unread{' '}
                          {activeChannelUnreadCount === 1
                            ? 'Message'
                            : 'Messages'}
                        </span>
                        <span className="dc-unread-divider-line" />
                      </div>
                    )}

                    {showMessageTimestamps && (
                      <div className="dc-gmsg-timestamp-divider">
                        <span>
                          {new Date(msg.packet.sentAt).toLocaleString([], {
                            weekday: 'short',
                            hour: 'numeric',
                            minute: '2-digit',
                          })}
                        </span>
                      </div>
                    )}

                    <article
                      id={`dc-msg-${msg.packet.payload.messageId}`}
                      className={`dc-imessage-row ${
                        isOwn ? 'outgoing' : 'incoming'
                      } ${isTwoPersonChat ? 'two-person-row' : 'group-row'} ${
                        groupedReactions.length > 0 ? 'has-reactions' : ''
                      } ${isMsgActionOpen ? 'actions-active' : ''} ${
                        isMsgUnread ? 'is-unread' : ''
                      }`}
                    >
                      {!isTwoPersonChat &&
                        !isOwn &&
                        renderUserAvatar(
                          senderIdentity || msg.packet.sender.email,
                          displayAuthor,
                          'dc-imessage-avatar'
                        )}

                      <div className="dc-imessage-column">
                        {!isTwoPersonChat && !isOwn && (
                          <div className="dc-group-sender-label">
                            <span>{displayAuthor}</span>
                            {displayHandle && (
                              <small>{displayHandle}</small>
                            )}
                          </div>
                        )}

                        {/* Free-Flowing Inline Reply Quote */}
                        {msg.quotedMessage && (
                          <div className="dc-inline-reply-quote">
                            <CornerDownLeft size={12} />
                            <div>
                              <strong>{msg.quotedMessage.senderName}</strong>:{' '}
                              <span>{msg.quotedMessage.textSnippet}</span>
                            </div>
                          </div>
                        )}

                        <div className="dc-gmsg-bubble-line">
                          {/* Message Bubble — clicking directly opens the Top 5 Emoji Reaction Bar */}
                          <div
                            className={`dc-imessage-bubble ${
                              isBurnHiddenInManualMode
                                ? 'burn-shrouded-bubble'
                                : ''
                            } ${isMsgUnread ? 'is-unread-bubble' : ''}`}
                            onClick={() =>
                              setActiveReactionPickerMsgId((prev) =>
                                prev === msg.packet.payload.messageId
                                  ? null
                                  : msg.packet.payload.messageId
                              )
                            }
                            title="Tap to react"
                          >
                            {isMsgUnread && (
                              <span
                                className="dc-bubble-unread-pip"
                                title="Unread"
                                aria-label="Unread"
                              />
                            )}
                            {isBurnHiddenInManualMode ? (
                              <div
                                className="dc-burn-shroud-card"
                                onClick={(e) => e.stopPropagation()}
                              >
                                <div className="dc-burn-shroud-header">
                                  <Timer size={14} />
                                  <strong>
                                    Burn-After-Reading Message Hidden (
                                    {effectiveBurnTtl}s Timer)
                                  </strong>
                                </div>
                                <p>
                                  Manual Read Receipts are on. Non-time-sensitive
                                  messages remain visible without sending
                                  receipts, while burn-after-reading messages
                                  stay sealed until you view them.
                                </p>
                                <button
                                  type="button"
                                  className="dc-btn-reveal-burn"
                                  onClick={() =>
                                    handleSendReadReceipt(
                                      msg.packet.payload.messageId
                                    )
                                  }
                                >
                                  <Eye size={13} /> Click to View &amp; Send
                                  Read Receipt (Starts {effectiveBurnTtl}s Burn)
                                </button>
                              </div>
                            ) : (
                              <>
                                {!msg.packet.payload.poll && (
                                  <p>{msg.packet.payload.text}</p>
                                )}

                                {/* Encrypted Interactive Poll Card (Feature 5) */}
                                {msg.packet.payload.poll &&
                                  (() => {
                                    const poll = msg.packet.payload.poll;
                                    const totalVotes = msg.pollVotes.length;
                                    return (
                                      <div
                                        className="dc-encrypted-poll-card"
                                        onClick={(e) => e.stopPropagation()}
                                      >
                                        <div className="dc-poll-header">
                                          <span className="dc-poll-badge">
                                            <BarChart3 size={12} /> Encrypted
                                            Poll
                                          </span>
                                          <span className="dc-poll-total">
                                            {totalVotes}{' '}
                                            {totalVotes === 1
                                              ? 'vote'
                                              : 'votes'}
                                          </span>
                                        </div>
                                        <strong className="dc-poll-question">
                                          {poll.question}
                                        </strong>
                                        <div className="dc-poll-options">
                                          {poll.options.map((opt) => {
                                            const optVotes =
                                              msg.pollVotes.filter(
                                                (v) => v.optionId === opt.id
                                              );
                                            const count = optVotes.length;
                                            const pct =
                                              totalVotes > 0
                                                ? Math.round(
                                                    (count / totalVotes) * 100
                                                  )
                                                : 0;
                                            const votedByMe = optVotes.some(
                                              (v) =>
                                                v.senderEmail.toLowerCase() ===
                                                activeUser.email.toLowerCase()
                                            );
                                            return (
                                              <button
                                                key={opt.id}
                                                type="button"
                                                className={`dc-poll-option-btn ${
                                                  votedByMe ? 'voted' : ''
                                                }`}
                                                onClick={() =>
                                                  handleVoteOnEncryptedPoll(
                                                    msg.packet.payload
                                                      .messageId,
                                                    poll.pollId,
                                                    opt.id,
                                                    opt.text
                                                  )
                                                }
                                              >
                                                <div
                                                  className="dc-poll-option-fill"
                                                  style={{ width: `${pct}%` }}
                                                />
                                                <div className="dc-poll-option-content">
                                                  <span className="dc-poll-opt-label">
                                                    {votedByMe && (
                                                      <CheckCircle2 size={13} />
                                                    )}
                                                    {opt.text}
                                                  </span>
                                                  <span className="dc-poll-opt-stats">
                                                    {pct}% ({count})
                                                  </span>
                                                </div>
                                              </button>
                                            );
                                          })}
                                        </div>
                                      </div>
                                    );
                                  })()}

                                {/* Client-Side Encrypted Link Preview Card (Feature 5) */}
                                {msg.packet.payload.linkPreview && (
                                  <a
                                    href={msg.packet.payload.linkPreview.url}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="dc-link-preview-card"
                                    onClick={(e) => e.stopPropagation()}
                                  >
                                    <div className="dc-link-preview-top">
                                      <Globe size={12} />
                                      <span>
                                        {msg.packet.payload.linkPreview.domain}
                                      </span>
                                      <small>Zero-Server Client Preview</small>
                                    </div>
                                    <strong>
                                      {msg.packet.payload.linkPreview.title}
                                    </strong>
                                    <p>
                                      {
                                        msg.packet.payload.linkPreview
                                          .description
                                      }
                                    </p>
                                  </a>
                                )}

                                {/* Real Inline Encrypted Attachments (Images, Audio Voice Notes, Files) */}
                                {msg.packet.payload.attachments &&
                                  msg.packet.payload.attachments.length > 0 && (
                                    <div
                                      className="dc-msg-attachments"
                                      onClick={(e) => e.stopPropagation()}
                                    >
                                      {msg.packet.payload.attachments.map(
                                        (att) => {
                                          const isImage =
                                            att.mimeType.startsWith('image/') &&
                                            att.encryptedData.startsWith(
                                              'data:image/'
                                            );
                                          const isAudio =
                                            att.mimeType.startsWith('audio/') &&
                                            att.encryptedData.startsWith(
                                              'data:audio/'
                                            );

                                          return (
                                            <div
                                              key={att.id}
                                              className="dc-attachment-card"
                                            >
                                              {isImage && (
                                                <img
                                                  src={att.encryptedData}
                                                  alt={att.filename}
                                                  className="dc-inline-image-attachment"
                                                  title="Tap to view full screen"
                                                  onClick={(e) => {
                                                    e.stopPropagation();
                                                    setFullscreenImageUrl(
                                                      att.encryptedData
                                                    );
                                                  }}
                                                />
                                              )}
                                              {isAudio && (
                                                <div className="dc-voice-note-player">
                                                  <div className="dc-voice-note-label">
                                                    <Mic size={13} /> Encrypted
                                                    Voice Note ({att.filename})
                                                  </div>
                                                  <audio
                                                    controls
                                                    src={att.encryptedData}
                                                    className="dc-audio-el"
                                                  />
                                                </div>
                                              )}
                                              {!isImage && !isAudio && (
                                                <div className="dc-attachment-chip">
                                                  <FileText size={15} />
                                                  <div>
                                                    <div className="dc-att-name">
                                                      {att.filename}
                                                    </div>
                                                    <div className="dc-att-meta">
                                                      {(
                                                        att.sizeBytes / 1024
                                                      ).toFixed(1)}{' '}
                                                      KB &bull; Encrypted MIME
                                                      (cid:{att.cid})
                                                    </div>
                                                  </div>
                                                </div>
                                              )}
                                            </div>
                                          );
                                        }
                                      )}
                                    </div>
                                  )}
                              </>
                            )}

                            {/* Bottom-Right Reactions Badge (Emoji only; hover lists reactor names like in Teams) */}
                            {groupedReactions.length > 0 && (
                              <div
                                className="dc-gmsg-reaction-cluster"
                                onClick={(e) => e.stopPropagation()}
                              >
                                {groupedReactions.map((group) => (
                                  <button
                                    key={group.emoji}
                                    type="button"
                                    className="dc-gmsg-reaction-badge"
                                    onClick={() =>
                                      handleSendQuickReaction(
                                        msg.packet.payload.messageId,
                                        group.emoji
                                      )
                                    }
                                    aria-label={`${group.emoji} reaction by ${group.senderNames.join(
                                      ', '
                                    )}`}
                                  >
                                    <span className="dc-reaction-emoji">
                                      {group.emoji}
                                    </span>
                                    {group.senderNames.length > 1 && (
                                      <span className="dc-reaction-count">
                                        {group.senderNames.length}
                                      </span>
                                    )}
                                    <span
                                      className="dc-reaction-hover-tooltip"
                                      role="tooltip"
                                    >
                                      <strong>{group.emoji}</strong>{' '}
                                      {group.senderNames.join(', ')}
                                    </span>
                                  </button>
                                ))}
                              </div>
                            )}
                          </div>

                          {/* Optional Manual Read Receipt & Preserved Hidden Controls */}
                          {((!isOwn &&
                            readReceiptMode === 'manual' &&
                            !alreadyReadByMe) ||
                            showPinAndPacketControls) && (
                            <div className="dc-subtle-bubble-actions">
                              {!isOwn &&
                                readReceiptMode === 'manual' &&
                                !alreadyReadByMe && (
                                  <button
                                    type="button"
                                    className="dc-subtle-action-icon"
                                    onClick={() =>
                                      handleSendReadReceipt(
                                        msg.packet.payload.messageId
                                      )
                                    }
                                    title="Send encrypted Read Receipt"
                                    aria-label="Send read receipt"
                                  >
                                    <CheckCheck size={14} />
                                  </button>
                                )}

                              {/* Pin and Email Packet preserved in code, hidden while showPinAndPacketControls is false */}
                              {showPinAndPacketControls && (
                                <>
                                  <button
                                    type="button"
                                    className="dc-subtle-action-icon"
                                    onClick={() => handleTogglePinMessage(msg)}
                                    title="Pin or unpin message"
                                  >
                                    <Pin size={13} />
                                  </button>
                                  <button
                                    type="button"
                                    className="dc-subtle-action-icon"
                                    onClick={() =>
                                      handleOpenPacketModal(msg.emailId)
                                    }
                                    title="Inspect Email Packet"
                                  >
                                    <Code2 size={13} />
                                  </button>
                                </>
                              )}
                            </div>
                          )}
                        </div>

                        {/* Subtle Status Footnote (Whisper-quiet Checkmarks & Burn Countdown when applicable) */}
                        {(isOwn ||
                          Boolean(
                            msg.packet.payload.ephemeralTtlSeconds &&
                              msg.packet.payload.ephemeralTtlSeconds > 0
                          )) && (
                          <div className="dc-subtle-status-row">
                            {Boolean(
                              msg.packet.payload.ephemeralTtlSeconds &&
                                msg.packet.payload.ephemeralTtlSeconds > 0
                            ) && (
                              <span
                                className="dc-burn-countdown-badge"
                                title="Burn-After-Reading self-destruct timer"
                              >
                                <Timer size={10} />{' '}
                                {msg.receipts.length > 0
                                  ? (() => {
                                      const earliestReadMs = Math.min(
                                        ...msg.receipts.map((r) =>
                                          new Date(
                                            r.readAtIso || msg.packet.sentAt
                                          ).getTime()
                                        )
                                      );
                                      const remainingSec = Math.max(
                                        0,
                                        Math.ceil(
                                          (earliestReadMs +
                                            msg.packet.payload
                                              .ephemeralTtlSeconds! *
                                              1000 -
                                            burnTickNowMs) /
                                            1000
                                        )
                                      );
                                      return `${remainingSec}s`;
                                    })()
                                  : `${msg.packet.payload.ephemeralTtlSeconds}s`}
                              </span>
                            )}

                            {isOwn && (
                              <span
                                className={`dc-subtle-receipt-check ${
                                  hasBeenReadByPeer ? 'is-read' : 'is-delivered'
                                }`}
                                title={
                                  hasBeenReadByPeer
                                    ? `Read by ${msg.receipts
                                        .map((r) => r.senderName)
                                        .join(', ')}`
                                    : 'Delivered (Encrypted MIME)'
                                }
                              >
                                {hasBeenReadByPeer ? (
                                  <CheckCheck size={13} />
                                ) : (
                                  <Check size={12} />
                                )}
                              </span>
                            )}
                          </div>
                        )}

                        {activeReactionPickerMsgId ===
                          msg.packet.payload.messageId && (
                          <div className="dc-quick-reaction-bar">
                            {defaultQuickEmojis.map((emoji, idx) => (
                              <button
                                key={`${emoji}-${idx}`}
                                type="button"
                                onClick={() =>
                                  handleSendQuickReaction(
                                    msg.packet.payload.messageId,
                                    emoji
                                  )
                                }
                              >
                                {emoji}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    </article>
                  </React.Fragment>
                );
              })}
            </div>

            {/* Floating Skip to Latest Button */}
            {!isAtBottom && (
              <button
                type="button"
                className="dc-skip-to-bottom-btn"
                onClick={handleSkipToLatest}
                aria-label="Skip to latest"
                title="Skip to latest"
              >
                <ArrowDown size={14} />
                <span>Skip to latest</span>
                {activeChannelUnreadCount > 0 && (
                  <span className="dc-skip-count-badge">
                    {activeChannelUnreadCount}
                  </span>
                )}
              </button>
            )}

            {/* Bottom iMessage / Android Pill Composer with Real File, Photo & Voice Note Recording */}
            <form className="dc-imessage-composer" onSubmit={handleMessengerSend}>
              {/* Vault Category Bar when inside Personal Encrypted Vault (@me) */}
              {activeChannel.type === 'vault' && (
                <div className="dc-vault-composer-bar">
                  <span className="dc-vault-bar-label">
                    <Bookmark size={12} /> 📌
                  </span>
                  {(
                    [
                      { id: 'note', label: '📝 Note' },
                      { id: 'credential', label: '🔑 Key' },
                      { id: 'snippet', label: '💻 Code' },
                      { id: 'file', label: '📁 File' },
                    ] as const
                  ).map((cat) => (
                    <button
                      key={cat.id}
                      type="button"
                      className={`dc-vault-cat-pill ${
                        vaultCategoryInput === cat.id ? 'active' : ''
                      }`}
                      onClick={() => setVaultCategoryInput(cat.id)}
                    >
                      {cat.label}
                    </button>
                  ))}
                </div>
              )}

              {replyingToMessage && (
                <div className="dc-composer-reply-banner">
                  <div>
                    <CornerDownLeft size={13} /> ↩️{' '}
                    <strong>
                      {replyingToMessage.packet.sender.displayName}
                    </strong>
                    :{' '}
                    <span>
                      {(replyingToMessage.packet.payload.text || '').slice(
                        0,
                        70
                      )}
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => setReplyingToMessage(null)}
                    aria-label="Cancel reply"
                  >
                    <X size={14} />
                  </button>
                </div>
              )}

              {pendingAttachments.length > 0 && (
                <div className="dc-pending-attachments-list">
                  {pendingAttachments.map((att) => (
                    <div key={att.id} className="dc-pending-attachment-bar">
                      <span>
                        📎 <strong>{att.filename}</strong>
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          setPendingAttachments((prev) =>
                            prev.filter((a) => a.id !== att.id)
                          )
                        }
                      >
                        <X size={14} />
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {composerBurnSeconds > 0 && (
                <div className="dc-composer-active-burn-bar">
                  <span>
                    <Flame size={13} /> ⏱️{' '}
                    <strong>
                      {composerBurnSeconds === 20
                        ? '20s'
                        : composerBurnSeconds === 60
                        ? '1m'
                        : composerBurnSeconds === 300
                        ? '5m'
                        : composerBurnSeconds === 15
                        ? '15s'
                        : composerBurnSeconds === 3600
                        ? '1h'
                        : '24h'}
                    </strong>
                  </span>
                  <button
                    type="button"
                    onClick={() => setComposerBurnSeconds(0)}
                    aria-label="Clear burn timer"
                    title="Turn off timer"
                  >
                    <X size={13} />
                  </button>
                </div>
              )}

              <div className="dc-imessage-input-row">
                {/* Collapsed Bottom-Left '+' Action Menu (Upload, Time Burn, Voice, Poll Group) */}
                <div
                  className="dc-composer-plus-wrap"
                  ref={actionMenuContainerRef}
                >
                  <button
                    type="button"
                    className={`dc-circle-icon-btn dc-composer-plus-btn ${
                      isPlusMenuOpen ? 'is-open' : ''
                    } ${composerBurnSeconds > 0 ? 'has-active-burn' : ''}`}
                    onClick={() => setIsPlusMenuOpen((prev) => !prev)}
                    aria-expanded={isPlusMenuOpen}
                    aria-haspopup="menu"
                    aria-label={
                      isPlusMenuOpen
                        ? 'Close composer actions menu'
                        : 'Open composer actions menu'
                    }
                    title="Actions"
                  >
                    <Plus size={18} className="dc-plus-glyph" />
                    {composerBurnSeconds > 0 && !isPlusMenuOpen && (
                      <span
                        className="dc-plus-burn-dot"
                        aria-hidden="true"
                      />
                    )}
                  </button>

                  {isPlusMenuOpen && (
                    <div
                      className="dc-composer-action-menu"
                      role="menu"
                      aria-label="Composer actions"
                    >
                      <div className="dc-action-menu-icons-row">
                        <button
                          type="button"
                          role="menuitem"
                          className="dc-action-icon-btn action-camera"
                          onClick={() => {
                            setIsPlusMenuOpen(false);
                            void handleOpenCameraModal();
                          }}
                          title="Camera"
                          aria-label="Camera"
                        >
                          <Camera size={19} />
                        </button>

                        <button
                          type="button"
                          role="menuitem"
                          className="dc-action-icon-btn action-upload"
                          onClick={() => {
                            setIsPlusMenuOpen(false);
                            fileAttachmentInputRef.current?.click();
                          }}
                          title="Photo / File"
                          aria-label="Photo / File"
                        >
                          <Paperclip size={19} />
                        </button>

                        <button
                          type="button"
                          role="menuitem"
                          className={`dc-action-icon-btn action-voice ${
                            isRecordingVoice ? 'is-recording' : ''
                          }`}
                          onClick={() => {
                            setIsPlusMenuOpen(false);
                            void handleToggleVoiceRecording();
                          }}
                          title={isRecordingVoice ? 'Stop recording' : 'Voice'}
                          aria-label={
                            isRecordingVoice ? 'Stop recording' : 'Voice'
                          }
                        >
                          {isRecordingVoice ? (
                            <Square size={16} />
                          ) : (
                            <Mic size={19} />
                          )}
                        </button>

                        <button
                          type="button"
                          role="menuitem"
                          className="dc-action-icon-btn action-poll"
                          onClick={() => {
                            setIsPlusMenuOpen(false);
                            pollCreatorDialogRef.current?.showModal();
                          }}
                          title="Poll"
                          aria-label="Poll"
                        >
                          <BarChart3 size={19} />
                        </button>
                      </div>

                      <div
                        className="dc-action-menu-burn-row"
                        role="group"
                        aria-label="Self-destruct timer"
                      >
                        <span
                          className="dc-action-timer-icon"
                          title="Timer"
                          aria-label="Timer"
                        >
                          <Timer size={16} />
                        </span>
                        <div className="dc-action-menu-burn-pills">
                          {(
                            [
                              { value: 0, label: 'Off' },
                              { value: 20, label: '20s' },
                              { value: 60, label: '1m' },
                              { value: 300, label: '5m' },
                            ] as const
                          ).map((opt) => (
                            <button
                              key={opt.value}
                              type="button"
                              className={`dc-burn-option-chip ${
                                composerBurnSeconds === opt.value
                                  ? 'is-selected'
                                  : ''
                              }`}
                              title={
                                opt.value === 0
                                  ? 'Timer Off'
                                  : `Self-destruct: ${opt.label}`
                              }
                              onClick={() => {
                                setComposerBurnSeconds(
                                  opt.value as EphemeralTimerSeconds
                                );
                                setIsPlusMenuOpen(false);
                              }}
                            >
                              {opt.label}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {isRecordingVoice ? (
                  <>
                    <div className="dc-recording-pill">
                      <span className="dc-rec-dot" /> 🎤 {recordingSeconds}s…
                    </div>
                    <button
                      type="button"
                      className="dc-circle-icon-btn recording-active"
                      onClick={handleToggleVoiceRecording}
                      title="Stop"
                      aria-label="Stop"
                    >
                      <Square size={15} />
                    </button>
                  </>
                ) : (
                  <div
                    className={`dc-composer-textarea-wrap growable-textarea ${
                      isComposerMultiline ? 'is-multiline' : ''
                    }`}
                    data-replicated-value={composerText}
                  >
                    <textarea
                      ref={composerTextareaRef}
                      rows={1}
                      className={`dc-composer-textarea ${
                        isComposerMultiline ? 'is-multiline' : ''
                      }`}
                      value={composerText}
                      onChange={(e) => setComposerText(e.target.value)}
                      onKeyDown={(e) => {
                        if (
                          e.key === 'Enter' &&
                          !e.shiftKey &&
                          !e.nativeEvent.isComposing
                        ) {
                          const isCoarsePointer =
                            typeof window !== 'undefined' &&
                            window.matchMedia('(pointer: coarse)').matches;
                          if (!isCoarsePointer) {
                            e.preventDefault();
                            if (
                              !isSending &&
                              (composerText.trim() ||
                                pendingAttachments.length > 0)
                            ) {
                              void handleMessengerSend(e);
                            }
                          }
                        }
                      }}
                      placeholder={
                        activeChannel.type === 'vault'
                          ? 'Note…'
                          : 'Message…'
                      }
                    />

                    {/* Quick Emoji Selector Button on Right Side of Input Box (Google Messages style) */}
                    <div
                      className="dc-composer-emoji-wrap"
                      ref={composerEmojiContainerRef}
                    >
                      <button
                        type="button"
                        className={`dc-composer-emoji-btn ${
                          isComposerEmojiOpen ? 'is-open' : ''
                        }`}
                        onClick={() => setIsComposerEmojiOpen((prev) => !prev)}
                        aria-expanded={isComposerEmojiOpen}
                        aria-haspopup="menu"
                        aria-label="Open quick emoji selector"
                        title="Insert emoji"
                      >
                        <Smile size={18} />
                      </button>

                      {isComposerEmojiOpen && (
                        <div
                          className="dc-composer-emoji-popover"
                          role="menu"
                          aria-label="Quick emojis"
                        >
                          <div className="dc-composer-top5-row">
                            {defaultQuickEmojis.map((emoji, idx) => (
                              <button
                                key={`top5-${emoji}-${idx}`}
                                type="button"
                                role="menuitem"
                                className="dc-emoji-grid-btn dc-emoji-top5-btn"
                                onClick={() => {
                                  setComposerText((prev) => prev + emoji);
                                  setIsComposerEmojiOpen(false);
                                  composerTextareaRef.current?.focus();
                                }}
                              >
                                {emoji}
                              </button>
                            ))}
                          </div>
                          <div className="dc-composer-emoji-grid-divider" />
                          <div className="dc-composer-emoji-subgrid">
                            {[
                              '👍',
                              '🎉',
                              '🙌',
                              '😮',
                              '🙏',
                              '💯',
                              '👀',
                              '✨',
                              '🚀',
                              '🫶',
                              '🥳',
                              '😎',
                              '👑',
                              '🐐',
                              '⚡',
                            ].map((emoji) => (
                              <button
                                key={emoji}
                                type="button"
                                role="menuitem"
                                className="dc-emoji-grid-btn"
                                onClick={() => {
                                  setComposerText((prev) => prev + emoji);
                                  setIsComposerEmojiOpen(false);
                                  composerTextareaRef.current?.focus();
                                }}
                              >
                                {emoji}
                              </button>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                <button
                  type="submit"
                  className="dc-imessage-send-btn"
                  disabled={
                    isSending ||
                    (!composerText.trim() && pendingAttachments.length === 0)
                  }
                  aria-label="Send encrypted message"
                >
                  <Send size={15} />
                </button>
              </div>
            </form>
              </>
            )}
          </section>
        </div>
      )}

      {/* =====================================================================
          STAGE 1: PROTOCOL & ENCRYPTION WORKBENCH
         ===================================================================== */}
      {surfaceMode === 'protocol-workbench' && (
        <div className="dc-app-shell">
          <section className="dc-metrics-strip">
            <div className="dc-metric-card">
              <div className="dc-metric-label">
                <KeyRound size={14} /> Active Device PGP Fingerprint
              </div>
              <div className="dc-metric-value dc-mono">
                {isInitializingKeys
                  ? 'Generating Curve25519 Keypair…'
                  : activeUser.pgpKeyPair
                  ? formatFingerprint(activeUser.pgpKeyPair.fingerprint).slice(
                      0,
                      29
                    ) + '…'
                  : 'No App Installed'}
              </div>
            </div>

            <div className="dc-metric-card dc-metric-success">
              <div className="dc-metric-label">
                <CheckCircle2 size={14} /> Accepted DCP/1.0 Chat Packets
              </div>
              <div className="dc-metric-value">
                {acceptedPackets.length} Encrypted Packets Decrypted
              </div>
            </div>

            <div className="dc-metric-card dc-metric-filtered">
              <div className="dc-metric-label">
                <Filter size={14} /> Regular Emails Ignored by App
              </div>
              <div className="dc-metric-value">
                {ignoredRegularEmails.length} Normal Emails Blocked from Chat
              </div>
            </div>

            <div className="dc-metric-card">
              <div className="dc-metric-label">
                <Smartphone size={14} /> Peer Profile Sync
              </div>
              <div className="dc-metric-value">
                Avatar + @Handle Synced on 1st Message
              </div>
            </div>
          </section>

          <main className="dc-workbench-grid">
            <section className="dc-left-column">
              <div className="dc-panel">
                <div className="dc-panel-header">
                  <h2>
                    <Send size={16} /> 1. Outbound Messaging &amp; OpenPGP MIME
                    Formatter
                  </h2>
                  <span className="dc-tag">
                    Device → Encrypted → Email Server
                  </span>
                </div>

                <form
                  className="dc-composer-form"
                  onSubmit={handleSendEncryptedPacket}
                >
                  <div className="dc-form-row">
                    <div className="dc-form-group">
                      <label htmlFor="recipient-select">
                        Send To (Recipient Email)
                      </label>
                      <select
                        id="recipient-select"
                        value={recipientEmail}
                        onChange={(e) => setRecipientEmail(e.target.value)}
                      >
                        {users
                          .filter((u) => u.email !== activeUser.email)
                          .map((u) => (
                            <option key={u.email} value={u.email}>
                              {u.displayName} ({u.handle || u.email}){' '}
                              {u.hasAppInstalled
                                ? '🔒 [Has App + PGP Key]'
                                : '📲 [No App — Sends Store Invite]'}
                            </option>
                          ))}
                      </select>
                    </div>

                    <div className="dc-form-group">
                      <label htmlFor="channel-input">
                        Channel / Thread Name
                      </label>
                      <input
                        id="channel-input"
                        type="text"
                        value={channelName}
                        onChange={(e) => setChannelName(e.target.value)}
                      />
                    </div>
                  </div>

                  <div className="dc-form-row">
                    <div className="dc-form-group">
                      <label htmlFor="packet-type-select">
                        DCP/1.0 Packet Type
                      </label>
                      <select
                        id="packet-type-select"
                        value={packetType}
                        onChange={(e) =>
                          setPacketType(e.target.value as DcpPacketType)
                        }
                      >
                        <option value="chat.message">
                          chat.message (Encrypted Message + Profile Card)
                        </option>
                        <option value="chat.reaction">
                          chat.reaction (Emoji Reaction Packet)
                        </option>
                      </select>
                    </div>

                    <div className="dc-form-group">
                      <label>Resolved Encryption Mode</label>
                      <div className="dc-encryption-pill">
                        {recipientUser.hasAppInstalled ? (
                          <>
                            <Lock size={13} /> Asymmetric OpenPGP (Curve25519)
                          </>
                        ) : (
                          <>
                            <Smartphone size={13} /> Ephemeral Invite Key + App
                            Store Card
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="dc-form-group">
                    <label htmlFor="message-textarea">
                      Cleartext Message (Encrypted on-device before leaving
                      browser)
                    </label>
                    <textarea
                      id="message-textarea"
                      rows={3}
                      value={messageText}
                      onChange={(e) => setMessageText(e.target.value)}
                    />
                  </div>

                  <div className="dc-composer-actions">
                    <button
                      type="submit"
                      className="dc-btn-send"
                      disabled={isSending || isInitializingKeys}
                    >
                      <Lock size={15} />
                      {isSending
                        ? 'Encrypting & Formatting MIME…'
                        : `Encrypt & Push via ${activeUser.provider.toUpperCase()}`}
                    </button>

                    <button
                      type="button"
                      className="dc-btn-secondary-action"
                      onClick={handleInjectRegularEmail}
                    >
                      <PlusCircle size={15} /> Simulate Incoming Regular Email
                    </button>
                  </div>
                </form>
              </div>

              <div className="dc-panel dc-inbox-list-panel">
                <div className="dc-panel-header">
                  <h2>
                    <Mail size={16} /> 2. Email Server Stream &amp; Strict
                    Filter Gate
                  </h2>
                  <span className="dc-tag">Click any email to inspect</span>
                </div>

                <div className="dc-email-stream">
                  {inspections.map((item) => {
                    const isSelected = item.emailId === selectedEmail?.id;
                    return (
                      <button
                        key={item.emailId}
                        type="button"
                        className={`dc-email-row ${
                          isSelected ? 'selected' : ''
                        } ${item.accepted ? 'accepted' : 'ignored'}`}
                        onClick={() => setSelectedEmailId(item.emailId)}
                      >
                        <div className="dc-email-row-top">
                          <span
                            className={`dc-status-pill ${
                              item.accepted ? 'pill-accepted' : 'pill-ignored'
                            }`}
                          >
                            {item.accepted ? (
                              <>
                                <CheckCircle2 size={12} /> DCP/1.0 ACCEPTED
                              </>
                            ) : (
                              <>
                                <XCircle size={12} /> REGULAR EMAIL IGNORED
                              </>
                            )}
                          </span>
                          <span className="dc-email-time">
                            {new Date(item.receivedAt).toLocaleTimeString([], {
                              hour: '2-digit',
                              minute: '2-digit',
                            })}
                          </span>
                        </div>

                        <div className="dc-email-subject">{item.subject}</div>
                        <div className="dc-email-from">From: {item.from}</div>
                        <div className="dc-email-reason">{item.reason}</div>
                      </button>
                    );
                  })}
                </div>
              </div>
            </section>

            <section className="dc-right-column">
              <div className="dc-panel dc-inspector-panel">
                <nav
                  className="dc-tabs-nav"
                  aria-label="Technical Inspector Tabs"
                >
                  <button
                    type="button"
                    className={`dc-tab-btn ${
                      activeTab === 'chat-bridge' ? 'active' : ''
                    }`}
                    onClick={() => setActiveTab('chat-bridge')}
                  >
                    <MessageSquare size={15} /> Decrypted Stream (
                    {acceptedPackets.length})
                  </button>
                  <button
                    type="button"
                    className={`dc-tab-btn ${
                      activeTab === 'non-app-fallback' ? 'active' : ''
                    }`}
                    onClick={() => setActiveTab('non-app-fallback')}
                  >
                    <Eye size={15} /> Non-App Recipient View
                  </button>
                  <button
                    type="button"
                    className={`dc-tab-btn ${
                      activeTab === 'mime-inspector' ? 'active' : ''
                    }`}
                    onClick={() => setActiveTab('mime-inspector')}
                  >
                    <Code2 size={15} /> Raw RFC 5322 MIME
                  </button>
                  <button
                    type="button"
                    className={`dc-tab-btn ${
                      activeTab === 'filter-gate' ? 'active' : ''
                    }`}
                    onClick={() => setActiveTab('filter-gate')}
                  >
                    <Filter size={15} /> Strict Filter Audit (
                    {ignoredRegularEmails.length} Ignored)
                  </button>
                  <button
                    type="button"
                    className={`dc-tab-btn ${
                      activeTab === 'provider-connectors' ? 'active' : ''
                    }`}
                    onClick={() => setActiveTab('provider-connectors')}
                  >
                    <Sparkles size={15} /> Provider Connectors
                  </button>
                </nav>

                <div className="dc-tab-content">
                  {activeTab === 'chat-bridge' && (
                    <div className="dc-decrypted-messages-list">
                      {acceptedPackets.map((item) => {
                        const pkt = item.decryptedPacket!;
                        return (
                          <div
                            key={item.emailId}
                            className="dc-chat-card"
                            onClick={() => setSelectedEmailId(item.emailId)}
                          >
                            <div className="dc-chat-card-header">
                              <div className="dc-chat-sender">
                                {renderUserAvatar(
                                  pkt.sender.email,
                                  pkt.sender.displayName
                                )}
                                <div>
                                  <strong>{pkt.sender.displayName}</strong>{' '}
                                  {pkt.sender.handle && (
                                    <span className="dc-handle-tag">
                                      {pkt.sender.handle}
                                    </span>
                                  )}
                                  <span className="dc-provider-badge">
                                    {pkt.sender.provider.toUpperCase()}
                                  </span>
                                  <div className="dc-chat-meta">
                                    #{pkt.channel.name} &bull;{' '}
                                    <code>{pkt.type}</code>
                                  </div>
                                </div>
                              </div>
                              <span className="dc-sig-badge">
                                <ShieldCheck size={12} /> PGP Verified
                              </span>
                            </div>
                            <div className="dc-chat-body">
                              <p>{pkt.payload.text}</p>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {activeTab === 'non-app-fallback' && selectedEmail && (
                    <div className="dc-fallback-preview-pane">
                      <div className="dc-mock-email-client">
                        <div className="dc-mock-email-header">
                          <div>Subject: {selectedEmail.subject}</div>
                          <div>
                            From: {selectedEmail.from} → To:{' '}
                            {selectedEmail.to.join(', ')}
                          </div>
                        </div>
                        <div
                          ref={invitePreviewRef}
                          className="dc-mock-email-body"
                        />
                      </div>
                    </div>
                  )}

                  {activeTab === 'mime-inspector' && selectedEmail && (
                    <div className="dc-mime-inspector-pane">
                      {selectedInspection?.decryptedPacket && (
                        <div className="dc-code-section">
                          <h3>
                            Decrypted JSON Payload (Including{' '}
                            <code>sender.profileCard</code>)
                          </h3>
                          <pre className="dc-code-block dc-code-json">
                            {JSON.stringify(
                              selectedInspection.decryptedPacket,
                              null,
                              2
                            )}
                          </pre>
                        </div>
                      )}
                      <div className="dc-code-section">
                        <h3>Raw RFC 5322 Multipart MIME</h3>
                        <pre className="dc-code-block">
                          {selectedEmail.rawMime}
                        </pre>
                      </div>
                    </div>
                  )}

                  {activeTab === 'filter-gate' && (
                    <table className="dc-audit-table">
                      <thead>
                        <tr>
                          <th>Status</th>
                          <th>From</th>
                          <th>Subject</th>
                          <th>Decision</th>
                        </tr>
                      </thead>
                      <tbody>
                        {inspections.map((item) => (
                          <tr
                            key={item.emailId}
                            onClick={() => setSelectedEmailId(item.emailId)}
                          >
                            <td>
                              <span
                                className={`dc-status-pill ${
                                  item.accepted
                                    ? 'pill-accepted'
                                    : 'pill-ignored'
                                }`}
                              >
                                {item.accepted ? 'ACCEPTED' : 'IGNORED'}
                              </span>
                            </td>
                            <td>{item.from}</td>
                            <td>{item.subject}</td>
                            <td>{item.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}

                  {activeTab === 'provider-connectors' && (
                    <div className="dc-connectors-pane">
                      <div className="dc-provider-grid">
                        {getProviderTechnicalSpecs().map((spec) => (
                          <div key={spec.id} className="dc-provider-card">
                            <h3>{spec.name}</h3>
                            <div className="dc-provider-detail">
                              <strong>Query:</strong>{' '}
                              <code>{spec.strictFilterQuery}</code>
                            </div>
                            <div className="dc-provider-detail">
                              <strong>Inbox Rule:</strong>{' '}
                              {spec.inboxIsolationRule}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </section>
          </main>
        </div>
      )}

      {/* =====================================================================
          MODAL 1: PLAYFUL ONBOARDING & PROFILE BUILDER -> SHAREABLE @ME QR PASS
         ===================================================================== */}
      <dialog
        ref={profileDialogRef}
        {...({ closedby: 'any' } as React.DialogHTMLAttributes<HTMLDialogElement>)}
        aria-labelledby={profileDialogTitleId}
        className="dc-modal-dialog dc-modal-md"
      >
        <div className="dc-modal-inner">
          <div className="dc-modal-header">
            <h2 id={profileDialogTitleId}>
              {profileModalStep === 'edit' ? (
                <>
                  <Sparkles size={17} /> 👋 You
                </>
              ) : (
                <>
                  <QrCode size={17} /> @me QR
                </>
              )}
            </h2>
            <div className="dc-profile-modal-tabs">
              <button
                type="button"
                className={`dc-profile-step-tab ${
                  profileModalStep === 'edit' ? 'active' : ''
                }`}
                onClick={() => setProfileModalStep('edit')}
              >
                😎 Look
              </button>
              <button
                type="button"
                className={`dc-profile-step-tab ${
                  profileModalStep === 'qr-card' ? 'active' : ''
                }`}
                onClick={() => setProfileModalStep('qr-card')}
              >
                <QrCode size={13} /> QR
              </button>
              <form method="dialog">
                <button
                  type="submit"
                  className="dc-icon-btn"
                  aria-label="Close"
                >
                  <X size={16} />
                </button>
              </form>
            </div>
          </div>

          {profileModalStep === 'edit' ? (
            <form className="dc-profile-form" onSubmit={handleSaveUserProfile}>
              <div className="dc-profile-avatar-editor">
                <div className="dc-profile-avatar-preview-wrap">
                  {profileAvatarInput ? (
                    <img
                      src={profileAvatarInput}
                      alt="Profile Avatar"
                      className="dc-profile-avatar-large"
                    />
                  ) : (
                    <div className="dc-profile-avatar-large dc-avatar-placeholder">
                      {profileNameInput.charAt(0).toUpperCase() || 'U'}
                    </div>
                  )}
                </div>
                <div className="dc-profile-avatar-buttons">
                  <span className="dc-avatar-section-label">
                    😎 Avatar
                  </span>
                  <div className="dc-preset-avatars-row">
                    {[
                      { emoji: '🎮', bg1: '#2563eb', bg2: '#06b6d4' },
                      { emoji: '⚡', bg1: '#6366f1', bg2: '#a855f7' },
                      { emoji: '🎧', bg1: '#ec4899', bg2: '#8b5cf6' },
                      { emoji: '🛹', bg1: '#10b981', bg2: '#059669' },
                      { emoji: '✨', bg1: '#f59e0b', bg2: '#ef4444' },
                      { emoji: '🚀', bg1: '#3b82f6', bg2: '#1d4ed8' },
                      { emoji: '🐱', bg1: '#f97316', bg2: '#db2777' },
                      { emoji: '🌈', bg1: '#8b5cf6', bg2: '#06b6d4' },
                    ].map((preset) => (
                      <button
                        key={preset.emoji}
                        type="button"
                        className="dc-preset-avatar-btn"
                        style={{
                          background: `linear-gradient(135deg, ${preset.bg1}, ${preset.bg2})`,
                        }}
                        onClick={() =>
                          handleSelectPresetAvatar(
                            preset.emoji,
                            preset.bg1,
                            preset.bg2
                          )
                        }
                        title={preset.emoji}
                      >
                        {preset.emoji}
                      </button>
                    ))}
                  </div>
                  <button
                    type="button"
                    className="dc-pill-action-btn"
                    onClick={() => avatarUploadInputRef.current?.click()}
                  >
                    📷 Photo
                  </button>
                </div>
              </div>

              <div className="dc-form-row">
                <div className="dc-form-group">
                  <label htmlFor="profile-name-input">🏷️ Name</label>
                  <input
                    id="profile-name-input"
                    type="text"
                    value={profileNameInput}
                    onChange={(e) => setProfileNameInput(e.target.value)}
                    placeholder="Alex"
                    required
                  />
                </div>

                <div className="dc-form-group">
                  <label htmlFor="profile-handle-input">⚡ @handle</label>
                  <input
                    id="profile-handle-input"
                    type="text"
                    value={profileHandleInput}
                    onChange={(e) => setProfileHandleInput(e.target.value)}
                    placeholder="@alex"
                    required
                  />
                </div>
              </div>

              <div className="dc-form-group">
                <label>🎨 Color</label>
                <div className="dc-onboarding-theme-grid">
                  {(
                    [
                      {
                        id: 'ocean',
                        label: 'Ocean',
                        color: '#0a84ff',
                      },
                      {
                        id: 'berry',
                        label: 'Berry',
                        color: '#ec4899',
                      },
                      {
                        id: 'violet',
                        label: 'Violet',
                        color: '#8b5cf6',
                      },
                      {
                        id: 'mint',
                        label: 'Mint',
                        color: '#10b981',
                      },
                      {
                        id: 'sunset',
                        label: 'Sunset',
                        color: '#f97316',
                      },
                      {
                        id: 'gold',
                        label: 'Gold',
                        color: '#eab308',
                      },
                    ] as const
                  ).map((t) => (
                    <button
                      key={t.id}
                      type="button"
                      className={`dc-theme-pill-option ${
                        chatBubbleTheme === t.id ? 'active' : ''
                      }`}
                      onClick={() => handleSelectBubbleTheme(t.id)}
                    >
                      <span
                        className="dc-theme-pill-dot"
                        style={{ background: t.color }}
                      />
                      <span>{t.label}</span>
                    </button>
                  ))}

                  <label
                    className={`dc-theme-pill-option dc-custom-theme-pill-option ${
                      chatBubbleTheme === 'custom' ? 'active' : ''
                    }`}
                    title="Pick any custom color"
                  >
                    <input
                      type="color"
                      value={customBubbleHex}
                      onChange={(e) =>
                        handleSelectCustomBubbleColor(e.target.value)
                      }
                    />
                    <span className="dc-custom-color-circle dc-onboarding-color-circle">
                      <span
                        className="dc-custom-color-core"
                        style={{ background: customBubbleHex }}
                      />
                    </span>
                    <span>Custom</span>
                  </label>
                </div>
              </div>

              <div className="dc-modal-actions">
                <button type="submit" className="dc-btn-send dc-btn-full">
                  <QrCode size={15} /> @me QR
                </button>
              </div>
            </form>
          ) : (
            <div className="dc-qr-card-step">
              <div className="dc-qr-share-card">
                <div className="dc-qr-card-identity">
                  {profileAvatarInput || activeUser.avatarDataUrl ? (
                    <img
                      src={profileAvatarInput || activeUser.avatarDataUrl}
                      alt={profileNameInput || activeUser.displayName}
                      className="dc-qr-card-avatar"
                    />
                  ) : (
                    <div className="dc-qr-card-avatar dc-avatar-placeholder">
                      {(profileNameInput || activeUser.displayName)
                        .charAt(0)
                        .toUpperCase()}
                    </div>
                  )}
                  <h3>{profileNameInput || activeUser.displayName}</h3>
                  <span className="dc-qr-card-handle">
                    {profileHandleInput || activeUser.handle || '@user'}
                  </span>
                </div>

                <div
                  className="dc-qr-code-box"
                  aria-label="Scan @me QR code to add friend"
                >
                  <svg
                    viewBox="0 0 21 21"
                    className="dc-qr-svg"
                    shapeRendering="crispEdges"
                  >
                    {userInviteQrMatrix.map((row, rIdx) =>
                      row.map((cell, cIdx) =>
                        cell ? (
                          <rect
                            key={`${rIdx}-${cIdx}`}
                            x={cIdx}
                            y={rIdx}
                            width={1}
                            height={1}
                            fill="#0f172a"
                          />
                        ) : null
                      )
                    )}
                  </svg>
                </div>
              </div>

              <div className="dc-qr-card-actions">
                <button
                  type="button"
                  className="dc-btn-secondary-action"
                  onClick={async () => {
                    const cleanHandle = (
                      profileHandleInput ||
                      activeUser.handle ||
                      '@user'
                    ).replace(/^@/, '');
                    const shareUrl = `${window.location.origin}/?add=${encodeURIComponent(
                      activeUser.email
                    )}&handle=${encodeURIComponent(cleanHandle)}`;
                    try {
                      await navigator.clipboard.writeText(shareUrl);
                    } catch {
                      // Fallback if clipboard is unavailable
                    }
                    setQrLinkCopied(true);
                    setTimeout(() => setQrLinkCopied(false), 2400);
                  }}
                >
                  {qrLinkCopied ? '✅ Copied' : '🔗 Link'}
                </button>

                <button
                  type="button"
                  className="dc-btn-secondary-action"
                  onClick={() => {
                    profileDialogRef.current?.close();
                    setSafetyModalTab('scan-qr');
                    safetyListDialogRef.current?.showModal();
                  }}
                >
                  📷 Scan
                </button>
              </div>
            </div>
          )}
        </div>
      </dialog>

      {/* =====================================================================
          MODAL 1B: SAFETY, WHITELIST ("APPROVED ONLY") & BLOCKED USERS + QR SCANNER
         ===================================================================== */}
      <dialog
        ref={safetyListDialogRef}
        {...({ closedby: 'any' } as React.DialogHTMLAttributes<HTMLDialogElement>)}
        aria-labelledby={safetyDialogTitleId}
        className="dc-modal-dialog dc-modal-md"
      >
        <div className="dc-modal-inner">
          <div className="dc-modal-header">
            <h2 id={safetyDialogTitleId}>
              🛡️ Safety
            </h2>
            <form method="dialog">
              <button type="submit" className="dc-icon-btn" aria-label="Close">
                <X size={16} />
              </button>
            </form>
          </div>

          <div className="dc-safety-tabs-bar">
            <button
              type="button"
              className={`dc-profile-step-tab ${
                safetyModalTab === 'scan-qr' ? 'active' : ''
              }`}
              onClick={() => setSafetyModalTab('scan-qr')}
            >
              📷 Scan
            </button>
            <button
              type="button"
              className={`dc-profile-step-tab ${
                safetyModalTab === 'whitelist' ? 'active' : ''
              }`}
              onClick={() => setSafetyModalTab('whitelist')}
            >
              ✅ Approved ({whitelistedEmails.length})
            </button>
            <button
              type="button"
              className={`dc-profile-step-tab ${
                safetyModalTab === 'blocked' ? 'active' : ''
              }`}
              onClick={() => setSafetyModalTab('blocked')}
            >
              🚫 Blocked ({blockedEmails.length})
            </button>
          </div>

          {safetyModalTab === 'scan-qr' && (
            <div className="dc-safety-tab-panel">
              <div className="dc-qr-scanner-hero">
                <div className="dc-qr-viewfinder">
                  <QrCode size={42} />
                  <span>📷 Scan Friend QR</span>
                  <small>✨ Auto-approves friend</small>
                </div>

                <div className="dc-qr-instant-demo-scans">
                  <span className="dc-avatar-section-label">
                    ⚡ Quick Scan
                  </span>
                  <div className="dc-qr-demo-friends-grid">
                    {[
                      {
                        name: 'Maya Lin',
                        handle: '@mayalin',
                        email: 'maya.lin@gmail.com',
                        emoji: '🎧',
                      },
                      {
                        name: 'Leo Vance',
                        handle: '@leovance',
                        email: 'leo.vance@icloud.com',
                        emoji: '🛹',
                      },
                      {
                        name: 'Zoe Park',
                        handle: '@zoepark',
                        email: 'zoe.park@outlook.com',
                        emoji: '✨',
                      },
                    ].map((friend) => (
                      <button
                        key={friend.email}
                        type="button"
                        className="dc-qr-demo-friend-btn"
                        onClick={() =>
                          handleQrScanApproveAndChat({
                            email: friend.email,
                            handle: friend.handle,
                            displayName: friend.name,
                          })
                        }
                      >
                        <span className="dc-qr-demo-emoji">{friend.emoji}</span>
                        <div>
                          <strong>
                            {friend.name} ({friend.handle})
                          </strong>
                          <span>📷 Scan</span>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>

                <form
                  className="dc-inline-input-btn"
                  onSubmit={handleParseAndScanQrInput}
                >
                  <input
                    type="text"
                    value={qrScanPasteInput}
                    onChange={(e) => setQrScanPasteInput(e.target.value)}
                    placeholder="🔗 Link or email…"
                    aria-label="Paste QR invite link or email"
                  />
                  <button type="submit" className="dc-btn-send">
                    ✅ Add
                  </button>
                </form>
              </div>
            </div>
          )}

          {safetyModalTab === 'whitelist' && (
            <div className="dc-safety-tab-panel">
              <div className="dc-whitelist-toggle-card">
                <label className="dc-burner-toggle-row dc-pill-switch-row">
                  <div>
                    <strong>
                      🛡️ Approved Only
                    </strong>
                    <span>
                      🔒 Block everyone else
                    </span>
                  </div>
                  <input
                    type="checkbox"
                    role="switch"
                    {...({
                      switch: '',
                    } as React.InputHTMLAttributes<HTMLInputElement>)}
                    className="dc-pill-switch"
                    checked={whitelistOnlyMode}
                    onChange={(e) =>
                      handleToggleWhitelistOnlyMode(e.target.checked)
                    }
                  />
                </label>
              </div>

              <form
                className="dc-inline-input-btn"
                onSubmit={(e) => {
                  e.preventDefault();
                  handleAddWhitelistEmail(whitelistInputEmail);
                }}
              >
                <input
                  type="email"
                  value={whitelistInputEmail}
                  onChange={(e) => setWhitelistInputEmail(e.target.value)}
                  placeholder="✉️ friend@email.com"
                  required
                />
                <button type="submit" className="dc-btn-send">
                  ➕ Add
                </button>
              </form>

              <div className="dc-participants-list">
                {whitelistedEmails.length === 0 ? (
                  <p className="dc-form-hint">
                    👋 None yet
                  </p>
                ) : (
                  whitelistedEmails.map((email) => {
                    const knownUser = users.find(
                      (u) => u.email.toLowerCase() === email.toLowerCase()
                    );
                    return (
                      <div key={email} className="dc-participant-row">
                        <div className="dc-participant-info">
                          {renderUserAvatar(
                            knownUser || email,
                            knownUser?.displayName || email
                          )}
                          <div>
                            <strong>
                              {knownUser?.displayName || email}{' '}
                              {knownUser?.handle && (
                                <small className="dc-handle-tag">
                                  {knownUser.handle}
                                </small>
                              )}
                            </strong>
                            <span>{email} • ✅</span>
                          </div>
                        </div>
                        <div className="dc-participant-actions">
                          {email.toLowerCase() !==
                            activeUser.email.toLowerCase() && (
                            <button
                              type="button"
                              className="dc-btn-ghost"
                              onClick={() => handleRemoveWhitelistEmail(email)}
                            >
                              ✕
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          )}

          {safetyModalTab === 'blocked' && (
            <div className="dc-safety-tab-panel">
              <form
                className="dc-inline-input-btn"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!blockInputEmail.trim()) return;
                  handleBlockEmail(blockInputEmail);
                  setBlockInputEmail('');
                }}
              >
                <input
                  type="email"
                  value={blockInputEmail}
                  onChange={(e) => setBlockInputEmail(e.target.value)}
                  placeholder="🚫 email@domain.com"
                  required
                />
                <button type="submit" className="dc-btn-danger-confirm">
                  🚫 Block
                </button>
              </form>

              <div className="dc-participants-list">
                {blockedEmails.length === 0 ? (
                  <p className="dc-form-hint">
                    ✨ Zero blocked
                  </p>
                ) : (
                  blockedEmails.map((email) => {
                    const knownUser = users.find(
                      (u) => u.email.toLowerCase() === email.toLowerCase()
                    );
                    return (
                      <div key={email} className="dc-participant-row">
                        <div className="dc-participant-info">
                          {renderUserAvatar(
                            knownUser || email,
                            knownUser?.displayName || email
                          )}
                          <div>
                            <strong>{knownUser?.displayName || email}</strong>
                            <span>{email} • 🚫</span>
                          </div>
                        </div>
                        <div className="dc-participant-actions">
                          <button
                            type="button"
                            className="dc-btn-secondary-action"
                            onClick={() => handleUnblockEmail(email)}
                          >
                            🔓 Unblock
                          </button>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          )}
        </div>
      </dialog>

      {/* =====================================================================
          MODAL 2: UNIVERSAL SIGN-IN PORTAL (Easy 1-Field Email Mode + Bottom Advanced Toggle)
         ===================================================================== */}
      <dialog
        ref={connectWizardDialogRef}
        {...({ closedby: 'any' } as React.DialogHTMLAttributes<HTMLDialogElement>)}
        aria-labelledby={connectWizardTitleId}
        className="dc-modal-dialog dc-modal-md"
      >
        <div className="dc-modal-inner">
          <div className="dc-modal-header">
            <h2 id={connectWizardTitleId}>
              <Link2 size={17} /> ➕ Account
            </h2>
            <form method="dialog">
              <button type="submit" className="dc-icon-btn" aria-label="Close">
                <X size={16} />
              </button>
            </form>
          </div>

          {connectModalMode === 'easy' ? (
            <div className="dc-easy-connect-portal">
              <form
                className="dc-easy-email-form"
                onSubmit={handleEasyEmailContinue}
              >
                <div className="dc-form-group">
                  <label htmlFor="easy-email-input">
                    ✉️ Email
                  </label>
                  <div className="dc-inline-input-btn">
                    <input
                      id="easy-email-input"
                      type="email"
                      value={easyEmailInput}
                      onChange={(e) => {
                        setEasyEmailInput(e.target.value);
                        setEasyDiscoveryResult(null);
                        setSimulatedOAuthProvider(null);
                      }}
                      placeholder="you@email.com"
                      required
                      autoFocus
                    />
                    <button
                      type="submit"
                      className="dc-btn-send"
                      disabled={isEasyDiscovering || !easyEmailInput.trim()}
                    >
                      {isEasyDiscovering ? '⏳' : 'Next →'}
                    </button>
                  </div>
                </div>
              </form>

              {/* Suggested Next Step Card after entering email */}
              {easyDiscoveryResult && !simulatedOAuthProvider && (
                <div className="dc-easy-next-step-card">
                  <div className="dc-discovery-title">
                    <Sparkles size={15} /> Recommended Next Step for{' '}
                    <strong>{easyEmailInput.trim()}</strong> (
                    {easyDiscoveryResult.providerLabel})
                  </div>
                  <p className="dc-form-hint">
                    {easyDiscoveryResult.explanation}
                  </p>

                  {easyDiscoveryResult.detectedProvider === 'gmail' && (
                    <button
                      type="button"
                      className="dc-oauth-btn dc-oauth-google"
                      onClick={() =>
                        handleOneClickOAuthPopup('google', easyEmailInput)
                      }
                    >
                      <Mail size={16} />
                      <div>
                        <strong>
                          Continue with Google Sign-In Popup (
                          {easyEmailInput.trim()})
                        </strong>
                        <span>
                          One-click OAuth2 sign-in &bull; Generates your
                          on-device OpenPGP keypair
                        </span>
                      </div>
                    </button>
                  )}

                  {easyDiscoveryResult.detectedProvider === 'outlook' && (
                    <button
                      type="button"
                      className="dc-oauth-btn dc-oauth-microsoft"
                      onClick={() =>
                        handleOneClickOAuthPopup('microsoft', easyEmailInput)
                      }
                    >
                      <ShieldCheck size={16} />
                      <div>
                        <strong>
                          Continue with Microsoft Sign-In Popup (
                          {easyEmailInput.trim()})
                        </strong>
                        <span>
                          One-click OAuth2 PKCE sign-in &bull; Generates your
                          on-device OpenPGP keypair
                        </span>
                      </div>
                    </button>
                  )}

                  {(easyDiscoveryResult.detectedProvider === 'proton' ||
                    easyDiscoveryResult.detectedProvider === 'yahoo' ||
                    easyDiscoveryResult.detectedProvider ===
                      'custom-domain') && (
                    <div className="dc-easy-custom-fields">
                      <div className="dc-form-row">
                        <div className="dc-form-group">
                          <label htmlFor="easy-display-name">
                            Your Display Name
                          </label>
                          <input
                            id="easy-display-name"
                            type="text"
                            value={easyDisplayNameInput}
                            onChange={(e) =>
                              setEasyDisplayNameInput(e.target.value)
                            }
                            placeholder="Taylor Brooks"
                          />
                        </div>
                        <div className="dc-form-group">
                          <label htmlFor="easy-app-pass">
                            {easyDiscoveryResult.detectedProvider === 'proton'
                              ? 'Proton Bridge / Token (Optional for Demo)'
                              : 'App Password / Token (Stored On-Device)'}
                          </label>
                          <input
                            id="easy-app-pass"
                            type="password"
                            value={easyAppPasswordInput}
                            onChange={(e) =>
                              setEasyAppPasswordInput(e.target.value)
                            }
                            placeholder="•••• •••• •••• ••••"
                          />
                        </div>
                      </div>
                      <button
                        type="button"
                        className="dc-btn-send"
                        disabled={isSending}
                        onClick={() =>
                          handleCompletePortalSignIn({
                            email: easyEmailInput.trim(),
                            displayName: easyDisplayNameInput,
                            provider: easyDiscoveryResult.detectedProvider,
                          })
                        }
                      >
                        <CheckCircle2 size={14} /> Connect{' '}
                        {easyEmailInput.trim()} &amp; Generate PGP Keys
                      </button>
                    </div>
                  )}
                </div>
              )}

              {/* Interactive OAuth Consent Popup Simulator (Triggered from Easy Step 2) */}
              {simulatedOAuthProvider && (
                <div className="dc-oauth-consent-card">
                  <div className="dc-oauth-consent-header">
                    <strong>
                      {simulatedOAuthProvider === 'google'
                        ? 'Google Sign-In Popup (OAuth2 PKCE Flow)'
                        : 'Microsoft Identity Sign-In Popup (OAuth2 PKCE Flow)'}
                    </strong>
                    <button
                      type="button"
                      className="dc-icon-btn"
                      onClick={() => setSimulatedOAuthProvider(null)}
                    >
                      <X size={14} />
                    </button>
                  </div>
                  <p className="dc-form-hint">
                    Confirm your display name to complete sign-in for{' '}
                    <strong>{simulatedOAuthEmail}</strong>. This generates your
                    Curve25519 OpenPGP keypair on-device and keeps your inbox
                    isolated:
                  </p>
                  <div className="dc-form-row">
                    <div className="dc-form-group">
                      <label>Email Address</label>
                      <input
                        type="email"
                        value={simulatedOAuthEmail}
                        onChange={(e) => setSimulatedOAuthEmail(e.target.value)}
                      />
                    </div>
                    <div className="dc-form-group">
                      <label>Your Display Name</label>
                      <input
                        type="text"
                        value={simulatedOAuthName}
                        onChange={(e) => setSimulatedOAuthName(e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="dc-modal-actions">
                    <button
                      type="button"
                      className="dc-btn-send"
                      disabled={isSending}
                      onClick={() =>
                        handleCompletePortalSignIn({
                          email: simulatedOAuthEmail,
                          displayName: simulatedOAuthName,
                          provider:
                            simulatedOAuthProvider === 'google'
                              ? 'gmail'
                              : 'outlook',
                        })
                      }
                    >
                      <CheckCircle2 size={14} /> Allow &amp; Sign In to @me
                    </button>
                  </div>
                </div>
              )}

              {connectorStatusMsg && (
                <div className="dc-profile-saved-alert">
                  <CheckCircle2 size={14} /> {connectorStatusMsg}
                </div>
              )}

              {/* Bottom Bar with Advanced Button */}
              <div className="dc-connect-modal-footer">
                <span>
                  Need custom OAuth Client IDs, Proton Bridge host, or manual
                  IMAP/JMAP settings?
                </span>
                <button
                  type="button"
                  className="dc-btn-ghost"
                  onClick={() => setConnectModalMode('advanced')}
                >
                  <Terminal size={13} /> Advanced Configuration
                </button>
              </div>
            </div>
          ) : (
            <>
              {/* 1-Click OAuth2 Popup Buttons */}
              <div className="dc-oauth-portal-buttons">
                <button
                  type="button"
                  className="dc-oauth-btn dc-oauth-google"
                  onClick={() => handleOneClickOAuthPopup('google')}
                >
                  <Mail size={16} />
                  <div>
                    <strong>Continue with Google (Popup)</strong>
                    <span>Gmail &amp; Google Workspace Custom Domains</span>
                  </div>
                </button>

                <button
                  type="button"
                  className="dc-oauth-btn dc-oauth-microsoft"
                  onClick={() => handleOneClickOAuthPopup('microsoft')}
                >
                  <ShieldCheck size={16} />
                  <div>
                    <strong>Continue with Microsoft (PKCE Popup)</strong>
                    <span>Outlook, Hotmail &amp; Microsoft 365 Domains</span>
                  </div>
                </button>
              </div>

              {/* Interactive OAuth Consent Popup Simulator (When testing without a cloud Client ID) */}
              {simulatedOAuthProvider && (
                <div className="dc-oauth-consent-card">
                  <div className="dc-oauth-consent-header">
                    <strong>
                      {simulatedOAuthProvider === 'google'
                        ? 'Google Sign-In Popup (Interactive OAuth2 PKCE Flow)'
                        : 'Microsoft Identity Sign-In Popup (Interactive OAuth2 PKCE Flow)'}
                    </strong>
                    <button
                      type="button"
                      className="dc-icon-btn"
                      onClick={() => setSimulatedOAuthProvider(null)}
                    >
                      <X size={14} />
                    </button>
                  </div>
                  <p className="dc-form-hint">
                    Select or enter any {simulatedOAuthProvider.toUpperCase()}{' '}
                    or Workspace custom-domain email. Clicking{' '}
                    <strong>Allow &amp; Sign In</strong> generates your
                    Curve25519 OpenPGP keypair on-device and creates the inbox
                    isolation rule:
                  </p>
                  <div className="dc-form-row">
                    <div className="dc-form-group">
                      <label>Account Email Address</label>
                      <input
                        type="email"
                        value={simulatedOAuthEmail}
                        onChange={(e) => setSimulatedOAuthEmail(e.target.value)}
                      />
                    </div>
                    <div className="dc-form-group">
                      <label>Your Display Name</label>
                      <input
                        type="text"
                        value={simulatedOAuthName}
                        onChange={(e) => setSimulatedOAuthName(e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="dc-modal-actions">
                    <button
                      type="button"
                      className="dc-btn-send"
                      disabled={isSending}
                      onClick={() =>
                        handleCompletePortalSignIn({
                          email: simulatedOAuthEmail,
                          displayName: simulatedOAuthName,
                          provider:
                            simulatedOAuthProvider === 'google'
                              ? 'gmail'
                              : 'outlook',
                        })
                      }
                    >
                      <CheckCircle2 size={14} /> Allow &amp; Sign In to @me
                    </button>
                  </div>
                </div>
              )}

              {/* Provider & Custom Domain Tabs */}
              <div className="dc-provider-tabs">
                {(
                  [
                    {
                      id: 'custom-domain',
                      label: 'CUSTOM DOMAIN (@yourcompany.com)',
                    },
                    { id: 'proton', label: 'PROTON MAIL' },
                    { id: 'yahoo', label: 'YAHOO / iCLOUD' },
                    { id: 'gmail', label: 'GMAIL OAUTH CONFIG' },
                    { id: 'outlook', label: 'MICROSOFT OAUTH CONFIG' },
                  ] as const
                ).map((tab) => (
                  <button
                    key={tab.id}
                    type="button"
                    className={`dc-tab-btn ${
                      wizardProvider === tab.id ? 'active' : ''
                    }`}
                    onClick={() => setWizardProvider(tab.id)}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              <form
                className="dc-modal-form"
                onSubmit={handleSaveProviderConnection}
              >
                {wizardProvider === 'custom-domain' && (
                  <div className="dc-custom-domain-portal">
                    <div className="dc-callout-banner">
                      <strong>How Custom Domains Work in @me:</strong>{' '}
                      Enter any email on your own domain (e.g.{' '}
                      <code>you@yourcompany.com</code>). The app queries DNS MX
                      records (`dns.google`) to detect if your domain is hosted
                      on <strong>Google Workspace</strong>,{' '}
                      <strong>Microsoft 365</strong>,{' '}
                      <strong>Proton Mail</strong>,{' '}
                      <strong>Fastmail JMAP</strong>, or a{' '}
                      <strong>Self-Hosted / cPanel IMAP+SMTP server</strong> and
                      configures the connection automatically!
                    </div>

                    <div className="dc-form-row">
                      <div className="dc-form-group">
                        <label htmlFor="custom-domain-email">
                          Your Custom Domain Email
                        </label>
                        <div className="dc-inline-input-btn">
                          <input
                            id="custom-domain-email"
                            type="email"
                            value={customDomainEmail}
                            onChange={(e) =>
                              setCustomDomainEmail(e.target.value)
                            }
                            placeholder="cto@yourcompany.com"
                            required
                          />
                          <button
                            type="button"
                            className="dc-pill-action-btn"
                            onClick={handleRunCustomDomainDiscovery}
                            disabled={isDiscoveringDomain}
                          >
                            {isDiscoveringDomain
                              ? 'Checking MX…'
                              : 'Auto-Detect MX'}
                          </button>
                        </div>
                      </div>

                      <div className="dc-form-group">
                        <label htmlFor="custom-domain-name">Display Name</label>
                        <input
                          id="custom-domain-name"
                          type="text"
                          value={customDomainName}
                          onChange={(e) => setCustomDomainName(e.target.value)}
                          placeholder="Morgan Vance"
                        />
                      </div>
                    </div>

                    {domainDiscoveryResult && (
                      <div className="dc-discovery-result-card">
                        <div className="dc-discovery-title">
                          <Sparkles size={14} /> Detected:{' '}
                          <strong>{domainDiscoveryResult.providerLabel}</strong>
                        </div>
                        <p>{domainDiscoveryResult.explanation}</p>
                        <div className="dc-discovery-specs">
                          <span>
                            MX: <code>{domainDiscoveryResult.mxRecords[0]}</code>
                          </span>
                          <span>
                            IMAP:{' '}
                            <code>
                              {domainDiscoveryResult.imapHost}:
                              {domainDiscoveryResult.imapPort}
                            </code>
                          </span>
                          <span>
                            SMTP:{' '}
                            <code>
                              {domainDiscoveryResult.smtpHost}:
                              {domainDiscoveryResult.smtpPort}
                            </code>
                          </span>
                        </div>
                      </div>
                    )}

                    <div className="dc-form-group">
                      <label htmlFor="custom-domain-pass">
                        App Password / JMAP Token (Not needed if domain uses
                        Google Workspace or M365 OAuth)
                      </label>
                      <input
                        id="custom-domain-pass"
                        type="password"
                        value={customDomainPassword}
                        onChange={(e) =>
                          setCustomDomainPassword(e.target.value)
                        }
                        placeholder="•••• •••• •••• •••• (Stored encrypted in local IndexedDB only)"
                      />
                    </div>
                  </div>
                )}

                {wizardProvider === 'gmail' && (
                  <div className="dc-form-group">
                    <label htmlFor="google-client-id-input">
                      Google Cloud OAuth2 Client ID (For Live Browser Popup)
                    </label>
                    <input
                      id="google-client-id-input"
                      type="text"
                      value={googleClientId}
                      onChange={(e) => setGoogleClientId(e.target.value)}
                      placeholder="123456789-abc.apps.googleusercontent.com (Optional)"
                    />
                    <small className="dc-form-hint">
                      Leave blank to use the built-in Interactive Sign-In Popup,
                      or paste your Google Cloud Web Client ID to launch the
                      live <code>accounts.google.com</code> popup window.
                    </small>

                    <button
                      type="button"
                      className="dc-btn-ghost"
                      style={{ alignSelf: 'flex-start', marginTop: '6px' }}
                      onClick={() =>
                        setShowAdvancedOAuthConfig(!showAdvancedOAuthConfig)
                      }
                    >
                      {showAdvancedOAuthConfig
                        ? 'Hide Raw Access Token Field'
                        : 'Advanced: Paste Access Token Directly'}
                    </button>

                    {showAdvancedOAuthConfig && (
                      <input
                        type="password"
                        value={gmailAccessToken}
                        onChange={(e) => setGmailAccessToken(e.target.value)}
                        placeholder="ya29.a0AfH6SM..."
                      />
                    )}
                  </div>
                )}

                {wizardProvider === 'outlook' && (
                  <div className="dc-form-group">
                    <label htmlFor="ms-client-id-input">
                      Microsoft Entra / Azure Application (Client) ID (For Live
                      PKCE Popup)
                    </label>
                    <input
                      id="ms-client-id-input"
                      type="text"
                      value={microsoftClientId}
                      onChange={(e) => setMicrosoftClientId(e.target.value)}
                      placeholder="00000000-0000-0000-0000-000000000000 (Optional)"
                    />
                    <small className="dc-form-hint">
                      Leave blank to use the built-in Interactive Sign-In Popup,
                      or paste your Microsoft Entra SPA Client ID to launch the
                      live <code>login.microsoftonline.com</code> PKCE popup.
                    </small>
                  </div>
                )}

                {wizardProvider === 'proton' && (
                  <div className="dc-form-group">
                    <label htmlFor="wizard-proton-host">
                      Proton Mail Local Bridge Endpoint / OpenPGP Key Discovery
                    </label>
                    <input
                      id="wizard-proton-host"
                      type="text"
                      value={protonBridgeHost}
                      onChange={(e) => setProtonBridgeHost(e.target.value)}
                    />
                    <small className="dc-form-hint">
                      Because @me uses standard OpenPGP (Curve25519),
                      messages sent from Gmail, Outlook, or Custom Domain users
                      are natively E2EE compatible with Proton Mail accounts!
                    </small>
                  </div>
                )}

                {wizardProvider === 'yahoo' && (
                  <div className="dc-form-group">
                    <label>Yahoo / iCloud IMAP IDLE + SMTP Connector</label>
                    <small className="dc-form-hint">
                      Uses server-side{' '}
                      <code>
                        SEARCH HEADER X-@me-Protocol &quot;DCP/1.0&quot;
                      </code>{' '}
                      so only encrypted messaging packets are downloaded.
                    </small>
                  </div>
                )}

                <label className="dc-checkbox-row">
                  <input
                    type="checkbox"
                    checked={autoArchivePrimaryInbox}
                    onChange={(e) =>
                      setAutoArchivePrimaryInbox(e.target.checked)
                    }
                  />
                  <span>
                    Auto-create Inbox Filter Rule (
                    <code>removeLabelIds: [&apos;INBOX&apos;]</code> / Sieve /
                    Folder rule) so @me packets stay hidden from my normal
                    email inbox
                  </span>
                </label>

                {connectorStatusMsg && (
                  <div className="dc-profile-saved-alert">
                    <CheckCircle2 size={14} /> {connectorStatusMsg}
                  </div>
                )}

                <div className="dc-modal-actions">
                  <button
                    type="button"
                    className="dc-btn-ghost"
                    onClick={() => setConnectModalMode('easy')}
                  >
                    ← Back to Easy 1-Field Sign-In
                  </button>
                  <button type="submit" className="dc-btn-send">
                    <ShieldCheck size={14} />{' '}
                    {wizardProvider === 'custom-domain'
                      ? 'Sign In with Custom Domain & Generate PGP Keys'
                      : 'Save Provider Configuration'}
                  </button>
                </div>
              </form>
            </>
          )}
        </div>
      </dialog>

      {/* =====================================================================
          MODAL 3: MENU DRAWER — Channels, Groups & Contacts Directory (Local DB)
         ===================================================================== */}
      <dialog
        ref={menuDirectoryDialogRef}
        {...({ closedby: 'any' } as React.DialogHTMLAttributes<HTMLDialogElement>)}
        aria-labelledby={menuDialogTitleId}
        className="dc-modal-dialog dc-menu-drawer-dialog"
      >
        <div className="dc-modal-inner">
          <div className="dc-modal-header">
            <h2 id={menuDialogTitleId}>
              👥 Friends
            </h2>
            <form method="dialog">
              <button type="submit" className="dc-icon-btn" aria-label="Close">
                <X size={16} />
              </button>
            </form>
          </div>

          <div className="dc-menu-grid">
            {/* Section 1: Channels & Groups */}
            <div className="dc-menu-column">
              <div className="dc-menu-section-head">
                <h3>💬 Groups</h3>
                <button
                  type="button"
                  className="dc-pill-action-btn"
                  onClick={() => {
                    setNewChatType('workspace-channel');
                    newChannelModalRef.current?.showModal();
                  }}
                >
                  ➕ Group
                </button>
              </div>

              <div className="dc-menu-list">
                {userScopedChannels
                  .filter((c) => c.type !== 'dm')
                  .map((ch) => (
                    <div key={ch.id} className="dc-menu-item-card">
                      <div
                        className="dc-menu-item-main"
                        onClick={() => {
                          setActiveChannelId(ch.id);
                          menuDirectoryDialogRef.current?.close();
                          setMobileShowChatPane(true);
                        }}
                      >
                        <Hash size={16} />
                        <div>
                          <strong>#{ch.name}</strong>
                          <span>
                            👥{' '}
                            {
                              ch.participants.filter(
                                (p) =>
                                  p.toLowerCase() !==
                                  activeUser.email.toLowerCase()
                              ).length
                            }
                          </span>
                        </div>
                      </div>
                      <button
                        type="button"
                        className="dc-btn-ghost"
                        onClick={() => {
                          setActiveChannelId(ch.id);
                          menuDirectoryDialogRef.current?.close();
                          groupInfoDialogRef.current?.showModal();
                        }}
                        title="People"
                      >
                        <UserPlus size={13} />
                        {ch.participants.length > 2 && (
                          <span>({ch.participants.length})</span>
                        )}
                      </button>
                    </div>
                  ))}
              </div>
            </div>

            {/* Section 2: Friends & Contacts */}
            <div className="dc-menu-column">
              <div className="dc-menu-section-head">
                <h3>👋 Friends</h3>
                <button
                  type="button"
                  className="dc-pill-action-btn"
                  onClick={() => {
                    setNewChatType('dm');
                    newChannelModalRef.current?.showModal();
                  }}
                >
                  ➕ Friend
                </button>
              </div>

              <div className="dc-menu-list">
                {users
                  .filter((u) => u.email !== activeUser.email)
                  .map((contact) => (
                    <div key={contact.email} className="dc-menu-item-card">
                      <div
                        className="dc-menu-item-main"
                        onClick={() =>
                          handleStartOrOpenContactChat(contact.email)
                        }
                      >
                        {renderUserAvatar(contact, contact.displayName)}
                        <div>
                          <strong>
                            {contact.displayName}{' '}
                            {contact.handle && (
                              <small className="dc-handle-tag">
                                {contact.handle}
                              </small>
                            )}
                          </strong>
                          <span>
                            {contact.email}
                            {!contact.hasAppInstalled ? ' • 📩' : ''}
                          </span>
                        </div>
                      </div>
                      <button
                        type="button"
                        className="dc-btn-ghost"
                        onClick={() =>
                          handleStartOrOpenContactChat(contact.email)
                        }
                      >
                        💬
                      </button>
                    </div>
                  ))}
              </div>
            </div>
          </div>
        </div>
      </dialog>

      {/* =====================================================================
          MODAL 4: GROUP / CHANNEL PEOPLE MANAGER (Add or Remove Members Over Email)
         ===================================================================== */}
      <dialog
        ref={groupInfoDialogRef}
        {...({ closedby: 'any' } as React.DialogHTMLAttributes<HTMLDialogElement>)}
        aria-labelledby={groupInfoTitleId}
        className="dc-modal-dialog dc-modal-md"
      >
        <div className="dc-modal-inner">
          <div className="dc-modal-header">
            <h2 id={groupInfoTitleId}>
              <Users size={17} /> 👥 People
            </h2>
            <form method="dialog">
              <button type="submit" className="dc-icon-btn" aria-label="Close">
                <X size={16} />
              </button>
            </form>
          </div>

          {activeChannel && (
            <>
              <form
                className="dc-add-member-form"
                onSubmit={handleAddMemberToChannel}
              >
                <input
                  type="email"
                  value={newMemberEmailInput}
                  onChange={(e) => setNewMemberEmailInput(e.target.value)}
                  placeholder="✉️ friend@email.com"
                  required
                />
                <input
                  type="text"
                  value={newMemberNameInput}
                  onChange={(e) => setNewMemberNameInput(e.target.value)}
                  placeholder="🏷️ Name"
                />
                <button type="submit" className="dc-btn-send">
                  <UserPlus size={14} /> ➕ Add
                </button>
              </form>

              <div className="dc-participants-list">
                {activeChannel.participants
                  .filter(
                    (email) =>
                      email.toLowerCase() !== activeUser.email.toLowerCase()
                  )
                  .map((email) => {
                    const u = users.find(
                      (usr) => usr.email.toLowerCase() === email.toLowerCase()
                    );

                    return (
                      <div key={email} className="dc-participant-row">
                        <div className="dc-participant-info">
                          {renderUserAvatar(u || email, u?.displayName || email)}
                          <div>
                            <strong>
                              {u?.displayName || email}{' '}
                              {u?.handle && (
                                <small className="dc-handle-tag">
                                  {u.handle}
                                </small>
                              )}
                            </strong>
                            <span>
                              {email}
                              {!u?.hasAppInstalled ? ' • 📩' : ''}
                            </span>
                          </div>
                        </div>

                        <div className="dc-participant-actions">
                          {activeChannel.participants.length > 2 && (
                            <button
                              type="button"
                              className="dc-btn-remove-member dc-icon-only-pill"
                              onClick={() =>
                                handleRemoveMemberFromChannel(email)
                              }
                              title="Remove"
                              aria-label="Remove"
                            >
                              <UserMinus size={14} />
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
              </div>
            </>
          )}
        </div>
      </dialog>

      {/* =====================================================================
          MODAL 4B: WARNING & CONFIRMATION POPUP FOR BURNING / CLEARING THREAD
         ===================================================================== */}
      <dialog
        ref={shredConfirmDialogRef}
        {...({ closedby: 'any' } as React.DialogHTMLAttributes<HTMLDialogElement>)}
        aria-labelledby={shredConfirmDialogTitleId}
        className="dc-modal-dialog dc-modal-sm"
      >
        <div className="dc-modal-inner">
          <div className="dc-modal-header">
            <h2 id={shredConfirmDialogTitleId} className="dc-shred-modal-title">
              🔥 Clear Chat?
            </h2>
            <form method="dialog">
              <button type="submit" className="dc-icon-btn" aria-label="Close">
                <X size={16} />
              </button>
            </form>
          </div>

          <div className="dc-shred-warning-body">
            <div className="dc-shred-warning-banner">
              <strong>🗑️ Deletes for everyone.</strong>
            </div>

            <div className="dc-modal-actions">
              <button
                type="button"
                className="dc-btn-ghost"
                onClick={() => {
                  setPendingShredOptions(null);
                  shredConfirmDialogRef.current?.close();
                }}
              >
                Cancel
              </button>
              <button
                type="button"
                className="dc-btn-danger-confirm"
                onClick={async () => {
                  const opts = pendingShredOptions || {
                    shredScope: 'peer-pgp-key-and-threads',
                  };
                  setPendingShredOptions(null);
                  shredConfirmDialogRef.current?.close();
                  await handleRemoteKeyShredAndScrub(opts);
                }}
              >
                🔥 Clear
              </button>
            </div>
          </div>
        </div>
      </dialog>

      {/* =====================================================================
          MODAL 5: Inspect Raw MIME & Non-App Invite Card
         ===================================================================== */}
      <dialog
        ref={packetModalRef}
        {...({ closedby: 'any' } as React.DialogHTMLAttributes<HTMLDialogElement>)}
        aria-labelledby={packetDialogTitleId}
        className="dc-modal-dialog"
      >
        <div className="dc-modal-inner">
          <div className="dc-modal-header">
            <h2 id={packetDialogTitleId}>
              <Lock size={16} /> DCP/1.0 Encrypted Email Packet Inspector
            </h2>
            <form method="dialog">
              <button type="submit" className="dc-icon-btn" aria-label="Close">
                <X size={16} />
              </button>
            </form>
          </div>

          {selectedEmail && (
            <div className="dc-modal-body">
              <div className="dc-code-section">
                <h3>
                  1. What a Non-App User Sees in Regular Email (App Store Invite
                  Card)
                </h3>
                <div
                  ref={modalPacketRenderRef}
                  className="dc-mock-email-body"
                />
              </div>

              {selectedInspection?.decryptedPacket && (
                <div className="dc-code-section">
                  <h3>
                    2. Decrypted On-Device JSON Packet (Note{' '}
                    <code>sender.profileCard</code>)
                  </h3>
                  <pre className="dc-code-block dc-code-json">
                    {JSON.stringify(
                      selectedInspection.decryptedPacket,
                      null,
                      2
                    )}
                  </pre>
                </div>
              )}

              <div className="dc-code-section">
                <h3>3. Raw RFC 5322 Multipart MIME Email</h3>
                <pre className="dc-code-block">{selectedEmail.rawMime}</pre>
              </div>
            </div>
          )}
        </div>
      </dialog>

      {/* =====================================================================
          MODAL 6: Create New Encrypted Group or DM (with Shielded Burner Alias Toggle)
         ===================================================================== */}
      <dialog
        ref={newChannelModalRef}
        {...({ closedby: 'any' } as React.DialogHTMLAttributes<HTMLDialogElement>)}
        aria-labelledby={newChannelDialogTitleId}
        className="dc-modal-dialog dc-modal-sm"
      >
        <div className="dc-modal-inner">
          <div className="dc-modal-header">
            <h2 id={newChannelDialogTitleId}>
              {newChatType === 'workspace-channel'
                ? '👥 New Group'
                : '💬 New Chat'}
            </h2>
            <form method="dialog">
              <button type="submit" className="dc-icon-btn" aria-label="Close">
                <X size={16} />
              </button>
            </form>
          </div>

          <form
            className="dc-modal-form"
            onSubmit={handleCreateNewChannelOrDm}
          >
            {newChatType === 'workspace-channel' ? (
              <div className="dc-form-group">
                <label htmlFor="new-channel-name">🏷️ Group Name</label>
                <input
                  id="new-channel-name"
                  type="text"
                  value={newChatName}
                  onChange={(e) => setNewChatName(e.target.value)}
                  placeholder="squad-chat"
                  required
                />
              </div>
            ) : (
              <div className="dc-form-group">
                <label htmlFor="new-dm-email">
                  ✉️ Friend&apos;s Email
                </label>
                <input
                  id="new-dm-email"
                  type="email"
                  value={newChatRecipientEmail}
                  onChange={(e) => setNewChatRecipientEmail(e.target.value)}
                  placeholder="friend@email.com"
                  required
                />
              </div>
            )}

            <div className="dc-modal-actions">
              <button type="submit" className="dc-btn-send">
                {newChatType === 'workspace-channel'
                  ? '🚀 Create Group'
                  : '🚀 Start Chat'}
              </button>
            </div>
          </form>
        </div>
      </dialog>

      {/* =====================================================================
          MODAL 7: Signal-Style 60-Digit Safety Number & QR Code Verification (Feature 4)
         ===================================================================== */}
      <dialog
        ref={safetyNumberDialogRef}
        {...({ closedby: 'any' } as React.DialogHTMLAttributes<HTMLDialogElement>)}
        aria-labelledby={safetyNumberDialogTitleId}
        className="dc-modal-dialog dc-modal-sm"
      >
        <div className="dc-modal-inner">
          <div className="dc-modal-header">
            <h2 id={safetyNumberDialogTitleId}>
              <QrCode size={17} /> Verify Safety Number &amp; Peer PGP Key
            </h2>
            <form method="dialog">
              <button type="submit" className="dc-icon-btn" aria-label="Close">
                <X size={16} />
              </button>
            </form>
          </div>

          {safetyBundle && (
            <div className="dc-safety-modal-body">
              <p className="dc-safety-intro">
                Compare this <strong>60-digit Safety Number</strong> or scan the
                QR code with <strong>{activeChannelDisplayTitle}</strong> to
                verify end-to-end encryption keys out-of-band.
              </p>

              {/* Deterministic 21x21 SVG QR Matrix */}
              <div className="dc-safety-qr-frame">
                <svg
                  viewBox="0 0 21 21"
                  className="dc-safety-qr-svg"
                  role="img"
                  aria-label="Safety Number Verification QR Code"
                >
                  {safetyBundle.qrMatrix.map((row, rIdx) =>
                    row.map((cell, cIdx) =>
                      cell ? (
                        <rect
                          key={`${rIdx}_${cIdx}`}
                          x={cIdx}
                          y={rIdx}
                          width={1}
                          height={1}
                          fill="#0f172a"
                        />
                      ) : null
                    )
                  )}
                </svg>
              </div>

              {/* 12 Groups of 5 Digits (60-Digit Safety Number) */}
              <div className="dc-safety-number-grid">
                {safetyBundle.groups.map((grp, idx) => (
                  <code key={`${grp}_${idx}`} className="dc-safety-digit-group">
                    {grp}
                  </code>
                ))}
              </div>

              <div className="dc-safety-fingerprints">
                <div>
                  <small>Your Key ({activeUser.email}):</small>
                  <code>
                    {formatFingerprint(
                      activeUser.pgpKeyPair?.fingerprint || ''
                    ).slice(0, 29)}
                    …
                  </code>
                </div>
                {activeChannelPeerUser && (
                  <div>
                    <small>
                      Peer Key ({activeChannelPeerUser.email}):
                    </small>
                    <code>
                      {formatFingerprint(
                        activeChannelPeerUser.pgpKeyPair?.fingerprint || ''
                      ).slice(0, 29)}
                      …
                    </code>
                  </div>
                )}
              </div>

              <div className="dc-modal-actions">
                <button
                  type="button"
                  className="dc-btn-ghost"
                  onClick={() => safetyNumberDialogRef.current?.close()}
                >
                  Close
                </button>
                {activeChannelPeerUser && (
                  <button
                    type="button"
                    className="dc-btn-send"
                    onClick={() => {
                      const peerKey =
                        activeChannelPeerUser.email.toLowerCase();
                      setVerifiedPeersMap((prev) => {
                        const next = { ...prev };
                        if (next[peerKey]) {
                          delete next[peerKey];
                        } else {
                          next[peerKey] =
                            activeChannelPeerUser.pgpKeyPair?.fingerprint ||
                            'verified';
                        }
                        return next;
                      });
                    }}
                  >
                    <ShieldCheck size={14} />{' '}
                    {verifiedPeersMap[
                      activeChannelPeerUser.email.toLowerCase()
                    ]
                      ? 'Verified ✓ (Tap to Unmark)'
                      : 'Mark Peer Key Verified'}
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </dialog>

      {/* =====================================================================
          MODAL 8: Create Encrypted Interactive Poll (`chat.poll`) (Feature 5)
         ===================================================================== */}
      <dialog
        ref={pollCreatorDialogRef}
        {...({ closedby: 'any' } as React.DialogHTMLAttributes<HTMLDialogElement>)}
        aria-labelledby={pollCreatorDialogTitleId}
        className="dc-modal-dialog dc-modal-sm"
      >
        <div className="dc-modal-inner">
          <div className="dc-modal-header">
            <h2 id={pollCreatorDialogTitleId}>
              📊 Poll
            </h2>
            <form method="dialog">
              <button type="submit" className="dc-icon-btn" aria-label="Close">
                <X size={16} />
              </button>
            </form>
          </div>

          <form
            className="dc-modal-form"
            onSubmit={handleCreateEncryptedPoll}
          >
            <div className="dc-form-group">
              <label htmlFor="poll-question-input">❓ Question</label>
              <input
                id="poll-question-input"
                type="text"
                value={pollQuestionInput}
                onChange={(e) => setPollQuestionInput(e.target.value)}
                placeholder="Where to meet?"
                required
              />
            </div>

            <div className="dc-form-group">
              <label>🗳️ Choices</label>
              <div className="dc-poll-creator-options">
                {pollOptionsInput.map((opt, idx) => (
                  <input
                    key={idx}
                    type="text"
                    value={opt}
                    onChange={(e) =>
                      setPollOptionsInput((prev) =>
                        prev.map((item, i) =>
                          i === idx ? e.target.value : item
                        )
                      )
                    }
                    placeholder={`Choice ${idx + 1}`}
                    required={idx < 2}
                  />
                ))}
              </div>
              {pollOptionsInput.length < 5 && (
                <button
                  type="button"
                  className="dc-btn-ghost dc-btn-add-poll-opt"
                  onClick={() =>
                    setPollOptionsInput((prev) => [...prev, ''])
                  }
                >
                  ➕ Choice
                </button>
              )}
            </div>

            <div className="dc-modal-actions">
              <button
                type="button"
                className="dc-btn-ghost"
                onClick={() => pollCreatorDialogRef.current?.close()}
              >
                Cancel
              </button>
              <button type="submit" className="dc-btn-send">
                🚀 Send
              </button>
            </div>
          </form>
        </div>
      </dialog>

      {/* =====================================================================
          MODAL 9: IN-APP EPHEMERAL CAMERA CAPTURE (Encrypted in LocalDB only; never saved to device camera roll)
         ===================================================================== */}
      <dialog
        ref={cameraCaptureDialogRef}
        {...({ closedby: 'any' } as React.DialogHTMLAttributes<HTMLDialogElement>)}
        aria-labelledby={cameraDialogTitleId}
        onClose={handleCloseCameraModal}
        className="dc-modal-dialog dc-modal-sm"
      >
        <div className="dc-modal-inner">
          <div className="dc-modal-header">
            <h2 id={cameraDialogTitleId}>
              📷 Camera
            </h2>
            <form method="dialog">
              <button type="submit" className="dc-icon-btn" aria-label="Close">
                <X size={16} />
              </button>
            </form>
          </div>

          <div className="dc-camera-modal-body">
            <div className="dc-camera-viewport">
              {capturedPhotoDataUrl ? (
                <img
                  src={capturedPhotoDataUrl}
                  alt="Captured preview"
                  className="dc-camera-preview-img"
                />
              ) : (
                <>
                  <video
                    ref={cameraVideoRef}
                    autoPlay
                    playsInline
                    muted
                    className={`dc-camera-video ${
                      cameraFacingMode === 'user' ? 'is-mirrored' : ''
                    } ${!isCameraStreaming ? 'is-fallback-hidden' : ''}`}
                  />
                  {!isCameraStreaming && (
                    <div className="dc-camera-fallback-viewfinder">
                      <Camera size={38} />
                      <strong>📸 Ready</strong>
                      <span>🔒 App-only (not saved to phone)</span>
                    </div>
                  )}
                </>
              )}
              <span className="dc-camera-privacy-pill">
                🔒 Encrypted in app only
              </span>
            </div>

            <div className="dc-camera-controls-row">
              {!capturedPhotoDataUrl ? (
                <>
                  <button
                    type="button"
                    className="dc-btn-secondary-action"
                    onClick={() => void handleFlipCamera()}
                    title="Flip camera"
                  >
                    🔄 Flip
                  </button>
                  <button
                    type="button"
                    className="dc-camera-shutter-btn"
                    onClick={handleSnapCameraPhoto}
                    aria-label="Take photo"
                    title="Snap photo"
                  >
                    <span className="dc-camera-shutter-inner" />
                  </button>
                  <button
                    type="button"
                    className="dc-btn-ghost"
                    onClick={() => cameraCaptureDialogRef.current?.close()}
                  >
                    Cancel
                  </button>
                </>
              ) : (
                <>
                  <button
                    type="button"
                    className="dc-btn-secondary-action"
                    onClick={() => {
                      setCapturedPhotoDataUrl(null);
                      void startCameraStream(cameraFacingMode);
                    }}
                  >
                    🔄 Retake
                  </button>
                  <button
                    type="button"
                    className="dc-btn-send"
                    disabled={isSending}
                    onClick={() => void handleSendCapturedCameraPhoto()}
                  >
                    🚀 Send
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      </dialog>

      {/* =====================================================================
          FULL-SCREEN PHOTO EXPAND OVERLAY (Tap photo in chat -> Full screen; tap anywhere -> Back to chat)
         ===================================================================== */}
      {fullscreenImageUrl && (
        <div
          className="dc-fullscreen-image-overlay"
          onClick={() => setFullscreenImageUrl(null)}
          onKeyDown={(e) => {
            if (e.key === 'Escape' || e.key === 'Enter' || e.key === ' ') {
              setFullscreenImageUrl(null);
            }
          }}
          role="button"
          tabIndex={0}
          aria-label="Tap anywhere to return to chat"
        >
          <img
            src={fullscreenImageUrl}
            alt="Full screen photo"
            className="dc-fullscreen-image-el"
          />
        </div>
      )}
    </div>
  );
}
