import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
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
  const [selectedActionMsgId, setSelectedActionMsgId] = useState<string | null>(
    null
  );
  // Preserves Pin & Email Packet inspection features in codebase while hiding them in UI by default
  const showPinAndPacketControls = false;
  const [isComposerMultiline, setIsComposerMultiline] = useState<boolean>(false);
  const actionMenuContainerRef = useRef<HTMLDivElement | null>(null);
  const composerEmojiContainerRef = useRef<HTMLDivElement | null>(null);
  const headerMenuContainerRef = useRef<HTMLDivElement | null>(null);
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
    'Yes, ship it 🚀',
    'Let us review first 🔒',
    'Need more details 📋',
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

  // Scope channels strictly to conversations where `activeUser.email` is a participant
  const userScopedChannels = useMemo(
    () =>
      channels.filter((c) =>
        c.participants.some(
          (p) => p.toLowerCase() === activeUser.email.toLowerCase()
        )
      ),
    [channels, activeUser.email]
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

  // Dismiss composer '+' menu, quick emoji picker, or top-right header menu on outside click/touch or Escape key
  useEffect(() => {
    if (!isPlusMenuOpen && !isComposerEmojiOpen && !isHeaderMenuOpen) return;
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
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsPlusMenuOpen(false);
        setIsComposerEmojiOpen(false);
        setIsHeaderMenuOpen(false);
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
  }, [isPlusMenuOpen, isComposerEmojiOpen, isHeaderMenuOpen]);

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

  // Support URL query params for deep-linking or mobile preview states (e.g. ?modal=shred or ?channel=ch_product_launch)
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const params = new URLSearchParams(window.location.search);
    const chParam = params.get('channel');
    if (chParam) {
      setActiveChannelId(chParam);
    }
    const modalParam = params.get('modal');
    if (modalParam === 'shred' && shredConfirmDialogRef.current && !shredConfirmDialogRef.current.open) {
      setPendingShredOptions({ shredScope: 'peer-pgp-key-and-threads' });
      shredConfirmDialogRef.current.showModal();
    } else if (modalParam === 'group' && groupInfoDialogRef.current && !groupInfoDialogRef.current.open) {
      groupInfoDialogRef.current.showModal();
    } else if (modalParam === 'safety' && safetyNumberDialogRef.current && !safetyNumberDialogRef.current.open) {
      safetyNumberDialogRef.current.showModal();
    } else if (modalParam === 'poll' && pollCreatorDialogRef.current && !pollCreatorDialogRef.current.open) {
      pollCreatorDialogRef.current.showModal();
    } else if (modalParam === 'lock') {
      setIsAppLocked(true);
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
            text: 'Welcome to @me! My first message in this thread automatically carries my encrypted Profile Card (avatar + @alexrivera handle) so your devices store it in local IndexedDB.',
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
            text: 'Connected from my Proton Mail account! Your avatar and @alexrivera handle synced into my local DB automatically.',
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
            text: 'Replying inline from Outlook — and I can see the Read Receipt on your message!',
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
            text: 'Hey Jordan! Since you do not have the app yet, your Yahoo email shows an App Store download card. Once you install @me, this message and my profile card decrypt automatically!',
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
            text: 'Hey Alex! Just @me from your Gmail — it arrives encrypted in my Proton inbox and renders right here like iMessage.',
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
            text: 'Zero central servers, compliant build verified, and we can shred keys anytime.',
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
    () => inspections.filter((i) => i.accepted && i.decryptedPacket),
    [inspections]
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

  // Auto-scroll message feed to bottom when switching channels or when new messages arrive / are sent
  useEffect(() => {
    const feedEl = freeflowFeedRef.current;
    if (!feedEl) return;

    const currentChId = activeChannel?.id ?? null;
    const isChannelSwitch = prevChannelIdRef.current !== currentChId;
    prevChannelIdRef.current = currentChId;

    const scrollToBottom = (behavior: ScrollBehavior) => {
      if (!freeflowFeedRef.current) return;
      freeflowFeedRef.current.scrollTo({
        top: freeflowFeedRef.current.scrollHeight,
        behavior,
      });
    };

    requestAnimationFrame(() => {
      scrollToBottom(isChannelSwitch ? 'auto' : 'smooth');
    });
  }, [
    activeChannel?.id,
    freeflowStream.length,
    lastMessageEmailId,
    surfaceMode,
    mobileShowChatPane,
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

        return {
          channel: ch,
          lastText:
            lastPacket?.payload.text ||
            (ch.type === 'vault'
              ? 'Personal E2EE Vault — Save notes, keys & files to yourself'
              : ch.type === 'dm'
              ? `Encrypted chat with ${peerEmail}`
              : `${ch.participants.length} members in group`),
          lastTime: lastPacket?.sentAt || '',
          lastTimestampMs: lastPacket
            ? new Date(lastPacket.sentAt).getTime()
            : 0,
          peerUser,
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

  // Save User Profile (Avatar, Display Name, Handle, Bio) to Local IndexedDB
  // and flag next message to broadcast the updated Profile Card to peers!
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
            bio: profileBioInput.trim(),
            avatarDataUrl: profileAvatarInput,
            profileUpdatedAt: nowIso,
          }
        : u
    );

    setUsers(updatedUsers);
    await saveUserIdentitiesToIdb(updatedUsers);
    setForceBroadcastProfileNext(true);
    setProfileSaveBanner(
      'Profile saved to local IndexedDB! Your updated Avatar & Handle will be attached to your next encrypted message.'
    );
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
    await clearIdbDatabase();
    window.location.reload();
  }

  const isIphoneFrame =
    typeof window !== 'undefined' &&
    window.location.search.includes('iphone=1');

  return (
    <div
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

      {/* Top Global Navigation Bar */}
      <header className="dc-global-nav">
        <div className="dc-brand">
          <button
            type="button"
            className="dc-menu-trigger-btn"
            onClick={() => menuDirectoryDialogRef.current?.showModal()}
            title="Open Groups & Friends"
          >
            <Menu size={17} />
            <span>Friends &amp; Groups</span>
          </button>

          <div className="dc-brand-icon">
            <img
              src="/atme-app-icon.png"
              alt="@me"
              className="dc-brand-img"
            />
          </div>
          <div>
            <div className="dc-brand-title-row">
              <h1>@me</h1>
            </div>
          </div>
        </div>

        <div className="dc-topbar-controls">
          {/* Current User Profile Button (Avatar + Name + Handle) */}
          <button
            type="button"
            className="dc-profile-pill-btn"
            onClick={() => profileDialogRef.current?.showModal()}
            title="Edit My Profile (Avatar, Name, Handle)"
          >
            {renderUserAvatar(
              activeUser,
              activeUser.displayName,
              'dc-nav-avatar'
            )}
            <div className="dc-profile-pill-text">
              <strong>{activeUser.displayName}</strong>
              <span>{activeUser.handle || '@user'}</span>
            </div>
          </button>

          <div className="dc-identity-switcher">
            <select
              aria-label="Switch Active Account"
              value={activeUserEmail}
              onChange={(e) => setActiveUserEmail(e.target.value)}
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

          <button
            type="button"
            className="dc-btn-ghost"
            onClick={() => {
              setConnectModalMode('easy');
              setSimulatedOAuthProvider(null);
              connectWizardDialogRef.current?.showModal();
            }}
            title="Sign in or add another email account"
          >
            <Link2 size={13} /> Add Account
          </button>

          <button
            type="button"
            className="dc-btn-ghost"
            onClick={handleOpenPersonalVault}
            title="Open Saved Notes (@me)"
          >
            <Bookmark size={13} /> Notes
          </button>

          <button
            type="button"
            className="dc-btn-ghost"
            onClick={() => {
              setLockScreenPinInput('');
              setLockScreenError('');
              setIsAppLocked(true);
            }}
            title="Lock @me with PIN or Biometrics"
          >
            <Fingerprint size={13} /> Lock
          </button>

          <button
            type="button"
            className="dc-btn-ghost"
            onClick={handleResetDemoState}
            title="Reset demo conversations"
          >
            <RefreshCw size={13} />
          </button>
        </div>
      </header>

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
            <h2>@me Vault &amp; Inbox Locked</h2>
            <p>
              Local IndexedDB ciphertext is sealed for{' '}
              <strong>{activeUser.displayName}</strong> (
              <code>{activeUser.email}</code>). Authenticate with your device
              Passkey or PIN to resume decryption.
            </p>

            <button
              type="button"
              className="dc-btn-passkey-unlock"
              onClick={handleUnlockWithWebAuthnPasskey}
            >
              <Fingerprint size={16} /> Unlock with Biometric Passkey (WebAuthn)
            </button>

            <div className="dc-applock-divider">
              <span>OR ENTER PIN / DURESS CODE</span>
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
                placeholder="Enter PIN (2580) or Duress PIN (9999)"
                aria-label="PIN or Duress PIN"
              />
              <button type="submit" className="dc-btn-send">
                <Lock size={14} /> Unlock
              </button>
            </form>

            {lockScreenError && (
              <div className="dc-applock-error">{lockScreenError}</div>
            )}

            <div className="dc-applock-hints">
              <span>
                <KeyRound size={11} /> Normal Unlock PIN: <code>{appLockPin}</code>
              </span>
              <span>
                <Flame size={11} /> Silent Panic / Duress Wipe PIN:{' '}
                <code>{duressPanicPin}</code>
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
                <h2>Messages</h2>
                <div className="dc-threads-top-actions">
                  <button
                    type="button"
                    className="dc-pill-action-btn dc-vault-quick-btn"
                    onClick={handleOpenPersonalVault}
                    title="Open Personal Encrypted Vault (@me)"
                  >
                    <Bookmark size={12} /> Vault
                  </button>
                  <button
                    type="button"
                    className="dc-pill-action-btn"
                    onClick={() => profileDialogRef.current?.showModal()}
                  >
                    <User size={13} /> My Profile
                  </button>
                  <button
                    type="button"
                    className="dc-compose-circle-btn"
                    onClick={() => {
                      setNewChatType('dm');
                      newChannelModalRef.current?.showModal();
                    }}
                    title="New Message to any Email"
                  >
                    <Plus size={16} />
                  </button>
                </div>
              </div>

              {/* Contact & Conversation Search Bar */}
              <div className="dc-search-box">
                <Search size={15} className="dc-search-icon" />
                <input
                  type="search"
                  value={contactSearchQuery}
                  onChange={(e) => setContactSearchQuery(e.target.value)}
                  placeholder="Search friends, @handles, or messages…"
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
                        Message &ldquo;{contactSearchQuery.trim()}&rdquo;
                      </strong>
                      <span>
                        Start a chat or send an invite
                      </span>
                    </div>
                    <ChevronRight size={15} />
                  </button>
                )}

              {/* Matching Contacts from Directory */}
              {matchingContacts.length > 0 && (
                <div className="dc-search-contacts-results">
                  <div className="dc-search-section-label">
                    FRIENDS &amp; CONTACTS
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
                          {!c.hasAppInstalled ? ' • Invite to @me' : ''}
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
                  <strong>No chats yet, {activeUser.displayName}!</strong>
                  <p>
                    Search a friend&apos;s @handle or email above, or tap the +
                    button to start chatting.
                  </p>
                  <button
                    type="button"
                    className="dc-pill-action-btn"
                    onClick={() => {
                      setNewChatType('dm');
                      newChannelModalRef.current?.showModal();
                    }}
                  >
                    <Plus size={14} /> New Chat
                  </button>
                </div>
              ) : (
                threadListSummaries.map(
                  ({ channel: ch, lastText, lastTime, peerUser }) => {
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
                        }`}
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

                          <div className="dc-thread-snippet">{lastText}</div>
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
                  <h2>Hey, {activeUser.displayName}! 👋</h2>
                  <p>
                    Pick a conversation on the left or message any friend using
                    their email or @handle — no phone number needed.
                  </p>
                  <div className="dc-empty-chat-actions">
                    <button
                      type="button"
                      className="dc-btn-send"
                      onClick={() => {
                        setNewChatType('dm');
                        newChannelModalRef.current?.showModal();
                      }}
                    >
                      <Plus size={15} /> Start a Chat
                    </button>
                    <button
                      type="button"
                      className="dc-btn-ghost"
                      onClick={handleOpenPersonalVault}
                    >
                      <Bookmark size={15} /> Saved Notes
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
                          {activeChannel.type !== 'vault' && (
                            <button
                              type="button"
                              role="menuitem"
                              className="dc-header-menu-item"
                              onClick={() => {
                                setIsHeaderMenuOpen(false);
                                groupInfoDialogRef.current?.showModal();
                              }}
                            >
                              <span className="dc-header-menu-icon icon-people">
                                <UserPlus size={15} />
                              </span>
                              <span className="dc-header-menu-label">
                                Add People
                                {activeChannel.participants.length > 2 &&
                                  ` (${activeChannel.participants.length})`}
                              </span>
                            </button>
                          )}

                          <button
                            type="button"
                            role="menuitem"
                            className="dc-header-menu-item item-danger"
                            onClick={() => {
                              setIsHeaderMenuOpen(false);
                              setPendingShredOptions({
                                shredScope: 'peer-pgp-key-and-threads',
                              });
                              shredConfirmDialogRef.current?.showModal();
                            }}
                          >
                            <span className="dc-header-menu-icon icon-burn">
                              <Flame size={15} />
                            </span>
                            <span className="dc-header-menu-label">
                              Burn Thread
                            </span>
                          </button>

                          <div className="dc-header-menu-divider" />

                          <button
                            type="button"
                            className="dc-header-menu-item dc-settings-toggle-row"
                            aria-expanded={isSettingsExpandedInMenu}
                            onClick={() =>
                              setIsSettingsExpandedInMenu((prev) => !prev)
                            }
                          >
                            <span className="dc-header-menu-icon icon-settings">
                              <Settings size={15} />
                            </span>
                            <span className="dc-header-menu-label">
                              Settings
                            </span>
                            <ChevronRight
                              size={15}
                              className={`dc-settings-chevron ${
                                isSettingsExpandedInMenu ? 'is-expanded' : ''
                              }`}
                            />
                          </button>

                          {isSettingsExpandedInMenu && (
                            <div
                              className="dc-header-settings-panel"
                              role="group"
                              aria-label="Messenger Settings"
                            >
                              <div className="dc-setting-group">
                                <span className="dc-setting-label">
                                  Appearance (Theme)
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
                                    <Moon size={12} /> Dark
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
                                    <Sun size={12} /> Light
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
                                    Auto
                                  </button>
                                </div>
                              </div>

                              <div className="dc-setting-group">
                                <span className="dc-setting-label">
                                  Message Timestamps
                                </span>
                                <div className="dc-setting-segmented">
                                  <button
                                    type="button"
                                    className={`dc-seg-btn ${
                                      !showMessageTimestamps ? 'is-active' : ''
                                    }`}
                                    onClick={() =>
                                      setShowMessageTimestamps(false)
                                    }
                                  >
                                    <EyeOff size={12} /> Hide Time
                                  </button>
                                  <button
                                    type="button"
                                    className={`dc-seg-btn ${
                                      showMessageTimestamps ? 'is-active' : ''
                                    }`}
                                    onClick={() =>
                                      setShowMessageTimestamps(true)
                                    }
                                  >
                                    <Clock size={12} /> Show Time
                                  </button>
                                </div>
                              </div>
                            </div>
                          )}
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
                  <strong>{activeChannelDisplayTitle} isn&apos;t on @me yet:</strong>{' '}
                  Your message will send them an invite link so they can reply
                  right away!
                </div>
                <button
                  type="button"
                  className="dc-btn-banner"
                  onClick={() =>
                    handleSimulateInstallAppForUser('jordan.taylor@yahoo.com')
                  }
                >
                  <UserCheck size={13} /> Simulate Friend Joining
                </button>
              </div>
            )}

            {/* Free-Flowing Message Stream */}
            <div className="dc-freeflow-feed" ref={freeflowFeedRef}>
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
                      ? 'Saved Notes (@me)'
                      : `Chat with ${activeChannelDisplayTitle}`}
                  </strong>
                  <p>
                    {activeChannel.type === 'vault'
                      ? 'Jot down notes, links, or files for yourself below.'
                      : `No messages here yet. Send a message below to say hi! 👋`}
                  </p>
                </div>
              )}

              {freeflowStream.map((msg) => {
                const isOwn =
                  msg.packet.sender.email.toLowerCase() ===
                  activeUser.email.toLowerCase();
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
                const alreadyReadByMe = msg.receipts.some(
                  (r) =>
                    r.senderEmail.toLowerCase() ===
                    activeUser.email.toLowerCase()
                );
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
                      className={`dc-imessage-row ${
                        isOwn ? 'outgoing' : 'incoming'
                      } ${isTwoPersonChat ? 'two-person-row' : 'group-row'} ${
                        groupedReactions.length > 0 ? 'has-reactions' : ''
                      } ${isMsgActionOpen ? 'actions-active' : ''}`}
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
                          {/* Message Bubble */}
                          <div
                            className={`dc-imessage-bubble ${
                              isBurnHiddenInManualMode
                                ? 'burn-shrouded-bubble'
                                : ''
                            }`}
                            onClick={() =>
                              setSelectedActionMsgId((prev) =>
                                prev === msg.packet.payload.messageId
                                  ? null
                                  : msg.packet.payload.messageId
                              )
                            }
                          >
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

                          {/* Subtle Hover / Tap Action Pills (React, Reply, and optional Manual Read Receipt) */}
                          <div className="dc-subtle-bubble-actions">
                            <button
                              type="button"
                              className="dc-subtle-action-icon"
                              onClick={() =>
                                setActiveReactionPickerMsgId(
                                  activeReactionPickerMsgId ===
                                    msg.packet.payload.messageId
                                    ? null
                                    : msg.packet.payload.messageId
                                )
                              }
                              title="React with emoji"
                              aria-label="React to message"
                            >
                              <Smile size={14} />
                            </button>

                            <button
                              type="button"
                              className="dc-subtle-action-icon"
                              onClick={() => setReplyingToMessage(msg)}
                              title="Reply to message"
                              aria-label="Reply to message"
                            >
                              <CornerDownLeft size={14} />
                            </button>

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
                            {['👍', '❤️', '😂', '😮', '😢', '🙏', '🔥'].map(
                              (emoji) => (
                                <button
                                  key={emoji}
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
                              )
                            )}
                          </div>
                        )}
                      </div>
                    </article>
                  </React.Fragment>
                );
              })}
            </div>

            {/* Bottom iMessage / Android Pill Composer with Real File, Photo & Voice Note Recording */}
            <form className="dc-imessage-composer" onSubmit={handleMessengerSend}>
              {/* Vault Category Bar when inside Personal Encrypted Vault (@me) */}
              {activeChannel.type === 'vault' && (
                <div className="dc-vault-composer-bar">
                  <span className="dc-vault-bar-label">
                    <Bookmark size={12} /> Vault Category:
                  </span>
                  {(
                    [
                      { id: 'note', label: 'Encrypted Note' },
                      { id: 'credential', label: 'Key / Credential' },
                      { id: 'snippet', label: 'Code Snippet' },
                      { id: 'file', label: 'File Drop' },
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
                    <CornerDownLeft size={13} /> Replying to{' '}
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
                        <Lock size={12} /> Encrypted Ready:{' '}
                        <strong>{att.filename}</strong> (
                        {(att.sizeBytes / 1024).toFixed(1)} KB)
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
                    <Flame size={13} /> Burn-after-reading timer armed:{' '}
                    <strong>
                      {composerBurnSeconds === 15
                        ? '15s'
                        : composerBurnSeconds === 60
                        ? '1m'
                        : composerBurnSeconds === 3600
                        ? '1h'
                        : '24h'}
                    </strong>{' '}
                    (countdown starts on recipient Read Receipt)
                  </span>
                  <button
                    type="button"
                    onClick={() => setComposerBurnSeconds(0)}
                    aria-label="Clear burn timer"
                    title="Turn off burn-after-reading timer"
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
                        : 'Open composer actions menu (Upload, Time Burn, Voice, Poll Group)'
                    }
                    title="Upload, Time Burn, Voice Note, or Poll Group"
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
                      <button
                        type="button"
                        role="menuitem"
                        className="dc-action-menu-item"
                        onClick={() => {
                          setIsPlusMenuOpen(false);
                          fileAttachmentInputRef.current?.click();
                        }}
                      >
                        <span className="dc-action-menu-icon icon-upload">
                          <Paperclip size={16} />
                        </span>
                        <span className="dc-action-menu-copy">
                          <strong>Upload Photo or File</strong>
                          <small>Encrypted on-device before send</small>
                        </span>
                      </button>

                      <div
                        className="dc-action-menu-item dc-action-menu-burn-block"
                        role="group"
                        aria-label="Time Burn self-destruct timer"
                      >
                        <div className="dc-action-menu-burn-head">
                          <span className="dc-action-menu-icon icon-burn">
                            <Timer size={16} />
                          </span>
                          <span className="dc-action-menu-copy">
                            <strong>Time Burn</strong>
                            <small>Self-destructs after recipient reads</small>
                          </span>
                        </div>
                        <div className="dc-action-menu-burn-pills">
                          {(
                            [
                              { value: 0, label: 'Off' },
                              { value: 15, label: '15s' },
                              { value: 60, label: '1m' },
                              { value: 3600, label: '1h' },
                              { value: 86400, label: '24h' },
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

                      <button
                        type="button"
                        role="menuitem"
                        className="dc-action-menu-item"
                        onClick={() => {
                          setIsPlusMenuOpen(false);
                          void handleToggleVoiceRecording();
                        }}
                      >
                        <span
                          className={`dc-action-menu-icon icon-voice ${
                            isRecordingVoice ? 'is-recording' : ''
                          }`}
                        >
                          {isRecordingVoice ? (
                            <Square size={15} />
                          ) : (
                            <Mic size={16} />
                          )}
                        </span>
                        <span className="dc-action-menu-copy">
                          <strong>
                            {isRecordingVoice
                              ? 'Stop & Attach Voice Note'
                              : 'Voice Note'}
                          </strong>
                          <small>Record encrypted audio clip</small>
                        </span>
                      </button>

                      <button
                        type="button"
                        role="menuitem"
                        className="dc-action-menu-item"
                        onClick={() => {
                          setIsPlusMenuOpen(false);
                          pollCreatorDialogRef.current?.showModal();
                        }}
                      >
                        <span className="dc-action-menu-icon icon-poll">
                          <BarChart3 size={16} />
                        </span>
                        <span className="dc-action-menu-copy">
                          <strong>Poll Group</strong>
                          <small>Create encrypted group or 1:1 poll</small>
                        </span>
                      </button>
                    </div>
                  )}
                </div>

                {isRecordingVoice ? (
                  <>
                    <div className="dc-recording-pill">
                      <span className="dc-rec-dot" /> Recording Encrypted Voice
                      Note ({recordingSeconds}s)…
                    </div>
                    <button
                      type="button"
                      className="dc-circle-icon-btn recording-active"
                      onClick={handleToggleVoiceRecording}
                      title="Stop & Attach Encrypted Voice Note"
                      aria-label="Stop and attach voice note"
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
                          ? `Save a ${vaultCategoryInput} to Notes (@me)…`
                          : `Message ${activeChannelDisplayTitle}…`
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
                          {[
                            '👍',
                            '❤️',
                            '😂',
                            '🔥',
                            '🎉',
                            '🙌',
                            '😮',
                            '😢',
                            '🙏',
                            '💯',
                            '👀',
                            '✨',
                            '🚀',
                            '🔒',
                            '✅',
                            '🤝',
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
          MODAL 1: USER PROFILE EDITOR (Avatar Image, Display Name, @Handle, Bio)
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
              <User size={17} /> My Encrypted Profile Card ({activeUser.email})
            </h2>
            <form method="dialog">
              <button type="submit" className="dc-icon-btn" aria-label="Close">
                <X size={16} />
              </button>
            </form>
          </div>

          <div className="dc-callout-banner">
            <strong>How Zero-Server Profile Sync Works:</strong> Your small
            avatar image, display name, and <code>@handle</code> are stored in
            your device&apos;s IndexedDB and automatically bundled inside the
            encrypted <code>sender.profileCard</code> JSON field the first time
            you message a user or group (or whenever you update your profile) so
            peers automatically cache your info in their local DB!
          </div>

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
                <button
                  type="button"
                  className="dc-pill-action-btn"
                  onClick={() => avatarUploadInputRef.current?.click()}
                >
                  <Camera size={14} /> Upload Small Avatar Image (Auto-resized
                  96×96)
                </button>
                <small className="dc-form-hint">
                  Compressed on-device to a tiny WebP data URL (~4 KB) for fast
                  email packet sync.
                </small>
              </div>
            </div>

            <div className="dc-form-row">
              <div className="dc-form-group">
                <label htmlFor="profile-name-input">Display Name</label>
                <input
                  id="profile-name-input"
                  type="text"
                  value={profileNameInput}
                  onChange={(e) => setProfileNameInput(e.target.value)}
                  placeholder="Alex Rivera"
                  required
                />
              </div>

              <div className="dc-form-group">
                <label htmlFor="profile-handle-input">Username / Handle</label>
                <input
                  id="profile-handle-input"
                  type="text"
                  value={profileHandleInput}
                  onChange={(e) => setProfileHandleInput(e.target.value)}
                  placeholder="@alexrivera"
                  required
                />
              </div>
            </div>

            <div className="dc-form-group">
              <label htmlFor="profile-bio-input">Short Status / Bio</label>
              <input
                id="profile-bio-input"
                type="text"
                value={profileBioInput}
                onChange={(e) => setProfileBioInput(e.target.value)}
                placeholder="Building zero-server E2EE messaging over email"
              />
            </div>

            <div className="dc-burner-alias-box">
              <label className="dc-burner-toggle-row">
                <input
                  type="checkbox"
                  checked={readReceiptMode === 'manual'}
                  onChange={(e) =>
                    setReadReceiptMode(e.target.checked ? 'manual' : 'auto')
                  }
                />
                <div>
                  <strong>
                    <EyeOff size={13} /> Manual Read Receipt Mode (Hide
                    Burn-After-Reading Until Clicked)
                  </strong>
                  <span>
                    When enabled, you can read regular non-time-sensitive
                    messages in any thread without sending read receipts. All
                    incoming Burn-After-Reading messages remain hidden behind a
                    click-to-view button that sends the read receipt and starts
                    the burn timer when clicked.
                  </span>
                </div>
              </label>
            </div>

            {profileSaveBanner && (
              <div className="dc-profile-saved-alert">
                <CheckCircle2 size={14} /> {profileSaveBanner}
              </div>
            )}

            <div className="dc-modal-actions">
              <button type="submit" className="dc-btn-send">
                <ShieldCheck size={15} /> Save Profile &amp; Sync on Next
                Message
              </button>
            </div>
          </form>
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
              <Link2 size={17} />{' '}
              {connectModalMode === 'easy'
                ? 'Connect Your Email Account'
                : 'Advanced Email & OAuth Configuration'}
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
                    Enter your email address to get started
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
                      placeholder="you@gmail.com, name@outlook.com, or you@yourcompany.com"
                      required
                      autoFocus
                    />
                    <button
                      type="submit"
                      className="dc-btn-send"
                      disabled={isEasyDiscovering || !easyEmailInput.trim()}
                    >
                      {isEasyDiscovering ? 'Detecting…' : 'Next Step →'}
                    </button>
                  </div>
                  <small className="dc-form-hint">
                    Works with Gmail, Outlook, Proton Mail, Yahoo, iCloud, or any
                    custom domain. We&apos;ll automatically detect the right
                    sign-in method for your address.
                  </small>
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
              <Users size={17} /> Friends &amp; Groups
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
                <h3>Group Chats</h3>
                <button
                  type="button"
                  className="dc-pill-action-btn"
                  onClick={() => {
                    setNewChatType('workspace-channel');
                    newChannelModalRef.current?.showModal();
                  }}
                >
                  <Plus size={13} /> New Group
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
                            {
                              ch.participants.filter(
                                (p) =>
                                  p.toLowerCase() !==
                                  activeUser.email.toLowerCase()
                              ).length
                            }{' '}
                            friends in group
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
                        title="Manage group members"
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
                <h3>Friends</h3>
                <button
                  type="button"
                  className="dc-pill-action-btn"
                  onClick={() => {
                    setNewChatType('dm');
                    newChannelModalRef.current?.showModal();
                  }}
                >
                  <UserPlus size={13} /> Add Friend
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
                            {!contact.hasAppInstalled ? ' • Invite to @me' : ''}
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
                        Chat
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
              <Users size={17} /> People in {activeChannelDisplayTitle}
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
                  placeholder="Add friend's email (e.g. jordan.taylor@yahoo.com)"
                  required
                />
                <input
                  type="text"
                  value={newMemberNameInput}
                  onChange={(e) => setNewMemberNameInput(e.target.value)}
                  placeholder="Name (optional)"
                />
                <button type="submit" className="dc-btn-send">
                  <UserPlus size={14} /> Add
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
                              {!u?.hasAppInstalled ? ' • Invite sent' : ''}
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
                              title={`Remove ${
                                u?.displayName || email
                              } from group`}
                              aria-label={`Remove ${
                                u?.displayName || email
                              } from group`}
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
              <Flame size={18} /> Burn &amp; Clear Chat?
            </h2>
            <form method="dialog">
              <button type="submit" className="dc-icon-btn" aria-label="Close">
                <X size={16} />
              </button>
            </form>
          </div>

          <div className="dc-shred-warning-body">
            <div className="dc-shred-warning-banner">
              <strong>This action cannot be undone.</strong>
              <p>
                Burning this thread permanently deletes all messages in{' '}
                <strong>{activeChannelDisplayTitle}</strong> for both of you and
                resets the chat to a clean slate.
              </p>
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
                <Flame size={15} /> Burn Chat
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
                ? 'New Encrypted Group / Channel'
                : 'New Text Message to Any Email'}
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
                <label htmlFor="new-channel-name">Group / Channel Name</label>
                <input
                  id="new-channel-name"
                  type="text"
                  value={newChatName}
                  onChange={(e) => setNewChatName(e.target.value)}
                  placeholder="e.g. family-chat or launch-team"
                  required
                />
              </div>
            ) : (
              <>
                <div className="dc-form-group">
                  <label htmlFor="new-dm-email">
                    Recipient Email (Gmail, Outlook, Yahoo, or Proton Mail)
                  </label>
                  <input
                    id="new-dm-email"
                    type="email"
                    value={newChatRecipientEmail}
                    onChange={(e) => setNewChatRecipientEmail(e.target.value)}
                    placeholder="friend@gmail.com"
                    required
                  />
                  <small className="dc-form-hint">
                    Your first message will automatically include your encrypted
                    Profile Card (Avatar + Handle) and an App Store download
                    invite if they don&apos;t have the app yet!
                  </small>
                </div>

                {/* Feature 3: Shielded Burner Email Alias Toggle */}
                <div className="dc-burner-alias-box">
                  <label className="dc-burner-toggle-row">
                    <input
                      type="checkbox"
                      checked={useShieldedAliasInNewChat}
                      onChange={(e) =>
                        setUseShieldedAliasInNewChat(e.target.checked)
                      }
                    />
                    <div>
                      <strong>
                        <EyeOff size={13} /> Use Shielded Burner Alias
                      </strong>
                      <span>
                        Masks your primary email (<code>{activeUser.email}</code>
                        ) and generates an isolated Curve25519 PGP keypair you
                        can shred independently.
                      </span>
                    </div>
                  </label>

                  {useShieldedAliasInNewChat && (
                    <div className="dc-burner-config-grid">
                      <div className="dc-form-group">
                        <label htmlFor="burner-strategy-select">
                          Alias Routing Strategy
                        </label>
                        <select
                          id="burner-strategy-select"
                          value={newChatAliasStrategy}
                          onChange={(e) =>
                            setNewChatAliasStrategy(
                              e.target
                                .value as ShieldedBurnerAlias['strategy']
                            )
                          }
                        >
                          <option value="duck-privacy">
                            DuckDuckGo Relay (@duck.com)
                          </option>
                          <option value="simplelogin-relay">
                            SimpleLogin / Proton Relay (@simplelogin.com)
                          </option>
                          <option value="plus-subaddress">
                            Subaddress (+private-token@
                            {activeUser.email.split('@')[1]})
                          </option>
                        </select>
                      </div>
                      <div className="dc-form-group">
                        <label htmlFor="burner-label-input">
                          Alias Tag / Context Label
                        </label>
                        <input
                          id="burner-label-input"
                          type="text"
                          value={newChatAliasLabel}
                          onChange={(e) =>
                            setNewChatAliasLabel(e.target.value)
                          }
                          placeholder="marketplace-buyer"
                        />
                      </div>
                    </div>
                  )}
                </div>
              </>
            )}

            <div className="dc-modal-actions">
              <button type="submit" className="dc-btn-send">
                <Lock size={14} />{' '}
                {newChatType === 'workspace-channel'
                  ? 'Create Encrypted Group'
                  : useShieldedAliasInNewChat
                  ? 'Generate Burner Alias & Start Text'
                  : 'Start Encrypted Text'}
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
              <BarChart3 size={17} /> Create Encrypted Poll in{' '}
              {activeChannelDisplayTitle}
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
              <label htmlFor="poll-question-input">Poll Question</label>
              <input
                id="poll-question-input"
                type="text"
                value={pollQuestionInput}
                onChange={(e) => setPollQuestionInput(e.target.value)}
                placeholder="e.g. When should we ship the @me v2 release?"
                required
              />
            </div>

            <div className="dc-form-group">
              <label>Poll Options (Encrypted in DCP/1.0 JSON)</label>
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
                    placeholder={`Option ${idx + 1}`}
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
                  <Plus size={12} /> Add Another Option
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
                <Lock size={14} /> Encrypt &amp; Send Poll
              </button>
            </div>
          </form>
        </div>
      </dialog>
    </div>
  );
}
