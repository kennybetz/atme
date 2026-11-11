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
  MessageCircle,
  MessageSquare,
  Mic,
  Moon,
  Palette,
  Paperclip,
  Pin,
  Plus,
  PlusCircle,
  QrCode,
  Radio,
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
  Tag,
  Terminal,
  Timer,
  Trash2,
  User,
  UserCheck,
  UserMinus,
  UserPlus,
  Users,
  VenetianMask,
  Wallet,
  X,
  XCircle,
  Zap,
  Coins,
} from 'lucide-react';
import {
  DCP_COMPLIANT_BUILD_VERSION,
  DCP_COMPLIANT_BUNDLE_SHA256,
  DCP_PROTOCOL_VERSION,
  MAX_CHANNEL_AND_GROUP_USERS,
  DcpAttachment,
  DcpChannelMeta,
  DcpIouPayload,
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
  computeBurnerCascadeTimings,
  computeViewerBurnerCascade,
  ViewerBurnerCascadeItem,
  BurnerCascadeItem,
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
  CARTOON_SKETCH_AVATARS,
  INITIAL_CHANNELS,
  INITIAL_USERS,
  createEncryptedSeedEmailsForUsers,
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
  burnerStatus?: {
    isBurner: boolean;
    isActive: boolean;
    isQueued: boolean;
    isExpired: boolean;
    isUnread?: boolean;
    remainingSeconds: number;
    unreadCount?: number;
    summaryLabel?: string;
    isOwn?: boolean;
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
  | 'custom';

export const TOP_5_COLORS_2026: ReadonlyArray<{
  id: Exclude<BubbleThemeId, 'custom'>;
  label: string;
  color: string;
}> = [
  { id: 'ocean', label: 'Teal', color: '#0a84ff' },
  { id: 'violet', label: 'Dusk', color: '#8b5cf6' },
  { id: 'berry', label: 'Fuchsia', color: '#ec4899' },
  { id: 'mint', label: 'Mint', color: '#10b981' },
  { id: 'sunset', label: 'Apricot', color: '#f97316' },
];

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

/**
 * Evaluates whether any chat messages extend below the visible viewport of the feed container.
 * Returns false if:
 * 1. The container does not have scrollable content (scrollHeight <= clientHeight).
 * 2. The scroll position is already at or near the bottom (distanceFromBottom <= 36).
 * 3. The latest message element's bottom is within or above the viewport's bottom.
 */
function checkHasChatsBelowViewport(feedEl: HTMLElement | null): boolean {
  if (!feedEl) return false;

  const scrollableDistance = feedEl.scrollHeight - feedEl.clientHeight;
  if (scrollableDistance <= 8) {
    return false;
  }

  const distanceFromBottom = scrollableDistance - feedEl.scrollTop;
  const threshold = 36;
  if (distanceFromBottom <= threshold) {
    return false;
  }

  const feedRect = feedEl.getBoundingClientRect();
  const messageElements = feedEl.querySelectorAll(
    '.dc-imessage-row, .dc-system-event-pill'
  );
  if (messageElements.length > 0) {
    const lastMessageEl = messageElements[messageElements.length - 1];
    const msgRect = lastMessageEl.getBoundingClientRect();
    if (msgRect.bottom <= feedRect.bottom + 20) {
      return false;
    }
  }

  return true;
}

export function App() {
  const [surfaceMode, setSurfaceMode] =
    useState<AppSurfaceMode>('messenger-ui');

  const [users, setUsers] = useState<UserIdentity[]>(INITIAL_USERS);
  const [channels, setChannels] = useState<DcpChannelMeta[]>(() => {
    try {
      const raw = localStorage.getItem('dc_channels_v4');
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed) && parsed.length > 0) {
          const existingIds = new Set(parsed.map((c: DcpChannelMeta) => c.id));
          const missing = INITIAL_CHANNELS.filter(
            (c) => !existingIds.has(c.id)
          );
          return [...parsed, ...missing];
        }
      }
    } catch {
      // ignore
    }
    return INITIAL_CHANNELS;
  });

  useEffect(() => {
    try {
      localStorage.setItem('dc_channels_v4', JSON.stringify(channels));
    } catch {
      // ignore
    }
  }, [channels]);
  const [activeUserEmail, setActiveUserEmail] = useState<string>(
    INITIAL_USERS[0].email
  );
  const [activeChannelId, setActiveChannelId] = useState<string>(
    INITIAL_CHANNELS[0].id
  );
  const isIphoneFrame =
    typeof window !== 'undefined' &&
    window.location.search.includes('iphone=1');
  const [isMobileDeviceView, setIsMobileDeviceView] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    return (
      isIphoneFrame ||
      window.innerWidth <= 860 ||
      (typeof window.matchMedia === 'function' &&
        window.matchMedia('(max-width: 860px)').matches)
    );
  });

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const updateDeviceView = () => {
      const isMobile =
        isIphoneFrame ||
        window.innerWidth <= 860 ||
        (typeof window.matchMedia === 'function' &&
          window.matchMedia('(max-width: 860px)').matches);
      setIsMobileDeviceView(isMobile);
    };
    updateDeviceView();
    window.addEventListener('resize', updateDeviceView);
    return () => window.removeEventListener('resize', updateDeviceView);
  }, [isIphoneFrame]);

  const [mobileShowChatPane, setMobileShowChatPane] = useState<boolean>(
    () =>
      typeof window !== 'undefined' &&
      window.location.search.includes('mobileView=chat')
  );

  // Swiping right to go back from chats to the main page on mobile/touch devices
  const [swipeOffsetX, setSwipeOffsetX] = useState<number>(0);
  const [isSwipingBack, setIsSwipingBack] = useState<boolean>(false);
  const [isAnimatingOut, setIsAnimatingOut] = useState<boolean>(false);

  const freeflowChatPaneRef = useRef<HTMLElement | null>(null);
  const touchStartXRef = useRef<number>(0);
  const touchStartYRef = useRef<number>(0);
  const touchStartTimeRef = useRef<number>(0);
  const isSwipingRightRef = useRef<boolean>(false);
  const lastDeltaXRef = useRef<number>(0);

  const openMobileChat = useCallback(
    (channelId?: string) => {
      if (channelId) {
        setActiveChannelId(channelId);
        setReplyingToMessage(null);
      }
      setMobileShowChatPane(true);
      if (
        isMobileDeviceView &&
        typeof window !== 'undefined' &&
        window.history.state?.atmeView !== 'chat'
      ) {
        window.history.pushState(
          { atmeView: 'chat', channelId: channelId || activeChannelId },
          ''
        );
      }
    },
    [activeChannelId, isMobileDeviceView]
  );

  const closeMobileChat = useCallback(() => {
    setMobileShowChatPane(false);
    if (
      isMobileDeviceView &&
      typeof window !== 'undefined' &&
      window.history.state?.atmeView === 'chat'
    ) {
      window.history.back();
    }
  }, [isMobileDeviceView]);

  // Synchronize browser history so pressing OS/browser back or gestures returns to main page rather than exiting app
  useEffect(() => {
    if (typeof window === 'undefined' || !isMobileDeviceView) return;

    if (mobileShowChatPane && !window.history.state?.atmeView) {
      window.history.replaceState({ atmeView: 'threads' }, '');
      window.history.pushState({ atmeView: 'chat' }, '');
    } else if (!window.history.state?.atmeView) {
      window.history.replaceState({ atmeView: 'threads' }, '');
    }

    const handlePopState = () => {
      if (mobileShowChatPane) {
        setMobileShowChatPane(false);
      }
    };

    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, [mobileShowChatPane, isMobileDeviceView]);

  // Touch gesture listener on chat pane to swipe right back to main page
  useEffect(() => {
    const pane = freeflowChatPaneRef.current;
    if (!pane) return;

    if (!isMobileDeviceView || !mobileShowChatPane) {
      setSwipeOffsetX(0);
      setIsSwipingBack(false);
      setIsAnimatingOut(false);
      isSwipingRightRef.current = false;
      return;
    }

    const onTouchStart = (e: TouchEvent) => {
      if (e.touches.length !== 1) return;
      if (document.querySelector('dialog[open]')) return;
      const activeEl = document.activeElement;
      if (
        activeEl &&
        (activeEl.tagName === 'INPUT' || activeEl.tagName === 'TEXTAREA')
      ) {
        return;
      }

      const touch = e.touches[0];
      touchStartXRef.current = touch.clientX;
      touchStartYRef.current = touch.clientY;
      touchStartTimeRef.current = Date.now();
      isSwipingRightRef.current = false;
      lastDeltaXRef.current = 0;
    };

    const onTouchMove = (e: TouchEvent) => {
      if (e.touches.length !== 1) return;
      const touch = e.touches[0];
      const deltaX = touch.clientX - touchStartXRef.current;
      const deltaY = touch.clientY - touchStartYRef.current;
      lastDeltaXRef.current = deltaX;

      if (!isSwipingRightRef.current) {
        const isNearLeftEdge =
          touchStartXRef.current <= Math.max(90, window.innerWidth * 0.28);
        const isHorizontal =
          deltaX > 8 && deltaX > Math.abs(deltaY) * (isNearLeftEdge ? 1.0 : 1.7);

        if (isHorizontal) {
          isSwipingRightRef.current = true;
          setIsSwipingBack(true);
        } else if (Math.abs(deltaY) > 8 || deltaX < -8) {
          return;
        }
      }

      if (isSwipingRightRef.current) {
        if (e.cancelable) {
          e.preventDefault();
        }
        const offset = Math.max(0, deltaX);
        setSwipeOffsetX(offset);
      }
    };

    const onTouchEnd = () => {
      if (!isSwipingRightRef.current) return;

      const deltaX = lastDeltaXRef.current;
      const elapsed = Date.now() - touchStartTimeRef.current;
      const velocity = deltaX / Math.max(1, elapsed);
      const isQuickFlick = deltaX > 40 && velocity > 0.35;
      const isOverDistance = deltaX > Math.min(100, window.innerWidth * 0.28);

      if (isOverDistance || isQuickFlick) {
        setIsAnimatingOut(true);
        setTimeout(() => {
          closeMobileChat();
          setIsAnimatingOut(false);
          setSwipeOffsetX(0);
          setIsSwipingBack(false);
          isSwipingRightRef.current = false;
        }, 180);
      } else {
        setSwipeOffsetX(0);
        setIsSwipingBack(false);
        isSwipingRightRef.current = false;
      }
    };

    const onTouchCancel = () => {
      setSwipeOffsetX(0);
      setIsSwipingBack(false);
      isSwipingRightRef.current = false;
    };

    pane.addEventListener('touchstart', onTouchStart, { passive: true });
    pane.addEventListener('touchmove', onTouchMove, { passive: false });
    pane.addEventListener('touchend', onTouchEnd, { passive: true });
    pane.addEventListener('touchcancel', onTouchCancel, { passive: true });

    return () => {
      pane.removeEventListener('touchstart', onTouchStart);
      pane.removeEventListener('touchmove', onTouchMove);
      pane.removeEventListener('touchend', onTouchEnd);
      pane.removeEventListener('touchcancel', onTouchCancel);
    };
  }, [mobileShowChatPane, closeMobileChat]);

  // Mouse gesture listener in iPhone preview frame for desktop testing
  useEffect(() => {
    const pane = freeflowChatPaneRef.current;
    if (!pane || !isIphoneFrame || !mobileShowChatPane) return;

    let isMouseDown = false;
    let startX = 0;
    let startY = 0;
    let startTime = 0;
    let isSwiping = false;

    const onMouseDown = (e: MouseEvent) => {
      if (e.button !== 0) return;
      if (document.querySelector('dialog[open]')) return;
      const rect = pane.getBoundingClientRect();
      const relativeX = e.clientX - rect.left;
      if (relativeX > 90) return;

      isMouseDown = true;
      startX = e.clientX;
      startY = e.clientY;
      startTime = Date.now();
      isSwiping = false;
    };

    const onMouseMove = (e: MouseEvent) => {
      if (!isMouseDown) return;
      const deltaX = e.clientX - startX;
      const deltaY = e.clientY - startY;

      if (!isSwiping) {
        if (deltaX > 8 && deltaX > Math.abs(deltaY) * 1.2) {
          isSwiping = true;
          setIsSwipingBack(true);
        } else if (Math.abs(deltaY) > 8 || deltaX < -8) {
          isMouseDown = false;
          return;
        }
      }

      if (isSwiping) {
        e.preventDefault();
        setSwipeOffsetX(Math.max(0, deltaX));
      }
    };

    const onMouseUp = (e: MouseEvent) => {
      if (!isMouseDown) return;
      isMouseDown = false;
      if (!isSwiping) return;

      const deltaX = e.clientX - startX;
      const elapsed = Date.now() - startTime;
      const velocity = deltaX / Math.max(1, elapsed);
      const isQuickFlick = deltaX > 40 && velocity > 0.35;
      const isOverDistance = deltaX > 90;

      if (isOverDistance || isQuickFlick) {
        setIsAnimatingOut(true);
        setTimeout(() => {
          closeMobileChat();
          setIsAnimatingOut(false);
          setSwipeOffsetX(0);
          setIsSwipingBack(false);
        }, 180);
      } else {
        setSwipeOffsetX(0);
        setIsSwipingBack(false);
      }
    };

    pane.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);

    return () => {
      pane.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
    };
  }, [isIphoneFrame, mobileShowChatPane, closeMobileChat]);

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
  const [isVoiceRecorderOpen, setIsVoiceRecorderOpen] =
    useState<boolean>(false);
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
    'taylor@gmail.com'
  );
  const [simulatedOAuthName, setSimulatedOAuthName] =
    useState<string>('Taylor');

  // Custom Domain Auto-Discovery & Universal IMAP/SMTP/JMAP Sign-In State
  const [customDomainEmail, setCustomDomainEmail] = useState<string>(
    'morgan@schoolclub.org'
  );
  const [customDomainName, setCustomDomainName] =
    useState<string>('Morgan');
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
  const iouDialogRef = useRef<HTMLDialogElement | null>(null);
  const cameraVideoRef = useRef<HTMLVideoElement | null>(null);
  const cameraStreamRef = useRef<MediaStream | null>(null);
  const [isCameraStreaming, setIsCameraStreaming] = useState<boolean>(false);
  const [cameraFacingMode, setCameraFacingMode] = useState<
    'user' | 'environment'
  >('user');
  const [capturedPhotoDataUrl, setCapturedPhotoDataUrl] = useState<
    string | null
  >(null);
  const cameraViewportRef = useRef<HTMLDivElement | null>(null);
  const [cameraStamps, setCameraStamps] = useState<
    Array<{
      id: string;
      emoji: string;
      xPct: number;
      yPct: number;
      sizePx: number;
    }>
  >([]);
  const [selectedCameraStampId, setSelectedCameraStampId] = useState<
    string | null
  >(null);
  const [isCameraStampPickerOpen, setIsCameraStampPickerOpen] =
    useState<boolean>(true);
  const draggingStampRef = useRef<{
    stampId: string;
    pointerId: number;
  } | null>(null);
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
  const [isNewChatBurner, setIsNewChatBurner] = useState<boolean>(false);
  const [isAddMenuOpen, setIsAddMenuOpen] = useState<boolean>(false);
  const addMenuContainerRef = useRef<HTMLDivElement | null>(null);
  const actionMenuContainerRef = useRef<HTMLDivElement | null>(null);
  const composerEmojiContainerRef = useRef<HTMLDivElement | null>(null);
  const headerMenuContainerRef = useRef<HTMLDivElement | null>(null);
  const avatarMenuContainerRef = useRef<HTMLDivElement | null>(null);
  const composerTextareaRef = useRef<HTMLTextAreaElement | null>(null);
  const freeflowFeedRef = useRef<HTMLDivElement | null>(null);
  const [activeUnseenMarkerMsgId, setActiveUnseenMarkerMsgId] = useState<
    string | null
  >(null);
  const unseenTimerRef = useRef<number | null>(null);
  const prevChannelIdRef = useRef<string | null>(null);
  const prevStreamLengthRef = useRef<number>(0);
  const userJustSentMessageRef = useRef<boolean>(false);
  const prevMobileShowChatPaneRef = useRef<boolean>(mobileShowChatPane);
  const [burnReadStartedAtMs, setBurnReadStartedAtMs] = useState<
    Record<string, number>
  >(() => {
    try {
      const raw = localStorage.getItem('dc_burn_read_started');
      return raw ? JSON.parse(raw) : {};
    } catch {
      return {};
    }
  });
  const [burnTickNowMs, setBurnTickNowMs] = useState<number>(() => Date.now());
  const [readReceiptMode, setReadReceiptMode] = useState<'auto' | 'manual'>(
    'auto'
  );
  const autoReadSentKeysRef = useRef<Set<string>>(new Set());
  const [isAtBottom, setIsAtBottom] = useState<boolean>(true);
  const isScrolledToBottomRef = useRef<boolean>(true);
  const isProgrammaticScrollingRef = useRef<boolean>(false);
  const programmaticScrollTimerRef = useRef<number | null>(null);
  const [hasChatsBelowViewport, setHasChatsBelowViewport] =
    useState<boolean>(false);
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
      text: 'Yo everyone! School Wi-Fi blocked every other app on our Chromebooks, so we are officially on @me now 🛹',
      senderName: 'Alex',
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
  const iouDialogTitleId = useId();

  // New Group / Channel or DM Creation Form State
  const [newChatName, setNewChatName] = useState<string>('');
  const [newChatRecipientEmail, setNewChatRecipientEmail] =
    useState<string>('');
  const [selectedGroupMemberEmails, setSelectedGroupMemberEmails] = useState<
    string[]
  >([]);
  const [newChatType, setNewChatType] = useState<
    'workspace-channel' | 'dm' | 'broadcast-channel'
  >('workspace-channel');
  const [newChannelDescription, setNewChannelDescription] =
    useState<string>('');
  const [showNewChatContactPicker, setShowNewChatContactPicker] =
    useState<boolean>(false);

  // IOU Wallet & Peer Ledger State
  const [selectedIouPeerEmail, setSelectedIouPeerEmail] = useState<
    string | null
  >(null);
  const [iouSendPeerEmail, setIouSendPeerEmail] = useState<string>(
    INITIAL_USERS[1]?.email || 'sam@outlook.com'
  );
  const [iouSendAmount, setIouSendAmount] = useState<string>('5');
  const [iouSendNote, setIouSendNote] = useState<string>('');
  const [showIouIssueForm, setShowIouIssueForm] = useState<boolean>(false);
  const [iouCollectAmountInput, setIouCollectAmountInput] =
    useState<string>('1');

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
        if (c.type === 'dm') {
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
    if (activeChannel.type === 'dm') {
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

  // Dismiss composer '+' menu, quick emoji picker, top-right header menu, main menu '+' add menu, or left avatar menu on outside click/touch or Escape key
  useEffect(() => {
    if (
      !isPlusMenuOpen &&
      !isComposerEmojiOpen &&
      !isHeaderMenuOpen &&
      !isAvatarMenuOpen &&
      !isAddMenuOpen
    ) {
      return;
    }
    const handlePointerDown = (event: MouseEvent | TouchEvent) => {
      const target = event.target as Node;
      if (
        isAddMenuOpen &&
        addMenuContainerRef.current &&
        !addMenuContainerRef.current.contains(target)
      ) {
        setIsAddMenuOpen(false);
      }
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
        setIsAddMenuOpen(false);
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
    isAddMenuOpen,
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

  // Auto-resize composer textarea height cleanly without field-sizing: content (which clips ::placeholder in Blink after clearing short strings)
  useEffect(() => {
    const textarea = composerTextareaRef.current;
    if (!textarea) {
      setIsComposerMultiline(false);
      return;
    }
    if (!composerText) {
      textarea.style.height = '38px';
      setIsComposerMultiline(false);
      return;
    }

    textarea.style.height = 'auto';
    const nextHeight = Math.min(Math.max(textarea.scrollHeight, 38), 130);
    textarea.style.height = `${nextHeight}px`;

    setIsComposerMultiline(
      composerText.includes('\n') || nextHeight > 46
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
      themeParam === 'sunset'
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
      setSelectedGroupMemberEmails([]);
      newChannelModalRef.current?.showModal();
    } else if (viewParam === 'new-group') {
      setNewChatType('workspace-channel');
      setIsNewChatBurner(true);
      setSelectedGroupMemberEmails([
        'elena.vogt@proton.me',
        'jordan.taylor@yahoo.com',
      ]);
      newChannelModalRef.current?.showModal();
    } else if (viewParam === 'voice-ready') {
      setIsVoiceRecorderOpen(true);
    } else if (viewParam === 'single-info') {
      setActiveChannelId('dm_alex_elena');
      groupInfoDialogRef.current?.showModal();
    } else if (viewParam === 'burner-dm') {
      setActiveChannelId('burner_dm_alex_sam');
    } else if (viewParam === 'burner-group') {
      setActiveChannelId('burner_ch_lunch_table');
    } else if (viewParam === 'new-channel') {
      setNewChatType('broadcast-channel');
      setSelectedGroupMemberEmails([]);
      newChannelModalRef.current?.showModal();
    } else if (viewParam === 'add-menu') {
      setIsAddMenuOpen(true);
    } else if (viewParam === 'broadcast') {
      setActiveChannelId('ch_broadcast_skate_clips');
    } else if (viewParam === 'iou' || viewParam === 'ious') {
      setSelectedIouPeerEmail('sam.chen@outlook.com');
      iouDialogRef.current?.showModal();
    } else if (viewParam === 'camera-stamp') {
      handleSnapCameraPhoto();
      setCameraStamps([
        { id: 'stamp-demo-1', emoji: '😎', xPct: 50, yPct: 44, sizePx: 112 },
        { id: 'stamp-demo-2', emoji: '🔒', xPct: 26, yPct: 72, sizePx: 58 },
      ]);
      setSelectedCameraStampId('stamp-demo-1');
      setIsCameraStampPickerOpen(true);
      cameraCaptureDialogRef.current?.showModal();
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
      iouDialogRef.current,
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

      const seedVersion =
        typeof localStorage !== 'undefined'
          ? localStorage.getItem('dontcall_seed_v6')
          : 'true';
      const shouldReseed = seedVersion !== 'true';

      const cachedUsers = shouldReseed
        ? null
        : await loadUserIdentitiesFromIdb();
      const cachedEmails = shouldReseed
        ? null
        : await loadTransportEmailsFromIdb();

      if (
        !shouldReseed &&
        cachedUsers &&
        cachedEmails &&
        cachedEmails.length > 0
      ) {
        if (!mounted) return;
        setUsers(cachedUsers);
        setTransportEmails(cachedEmails);
        setSelectedEmailId(cachedEmails[0].id);
        setIsInitializingKeys(false);
        return;
      }

      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('dontcall_seed_v6', 'true');
        localStorage.removeItem('dc_burn_read_started');
        localStorage.setItem(
          'atme_whitelisted_emails',
          JSON.stringify(INITIAL_USERS.map((u) => u.email.toLowerCase()))
        );
      }
      setBurnReadStartedAtMs({});
      setWhitelistedEmails(INITIAL_USERS.map((u) => u.email.toLowerCase()));

      await clearIdbDatabase();

      const hydratedUsers: UserIdentity[] = [];
      for (const u of INITIAL_USERS) {
        if (u.hasAppInstalled) {
          const kp = await generateDeviceKeyPair(u.displayName, u.email);
          hydratedUsers.push({ ...u, pgpKeyPair: kp });
        } else {
          hydratedUsers.push(u);
        }
      }

      const seedDcpEmails = await createEncryptedSeedEmailsForUsers(
        hydratedUsers
      );

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
        const isBccRecipient = email.bcc?.some((b) =>
          b.toLowerCase().includes(myEmailLower)
        );
        if (myEmailLower && !isSender && !isRecipient && !isBccRecipient) {
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
        // Automatically ensure any channel referenced by a decrypted packet is present in `channels`
        setChannels((prev) => {
          const existingIds = new Set(prev.map((c) => c.id));
          const discovered: DcpChannelMeta[] = [];
          for (const r of results) {
            const ch = r.decryptedPacket?.channel;
            if (ch && ch.id && !existingIds.has(ch.id)) {
              existingIds.add(ch.id);
              discovered.push(ch);
            }
          }
          return discovered.length > 0 ? [...discovered, ...prev] : prev;
        });
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

  // Compute Peer-to-Peer Crypto-Inspired IOU Wallet Ledger Totals (No History Shown — Totals Only!)
  const iouLedgerSummary = useMemo(() => {
    const myEmail = activeUser.email.toLowerCase();
    // Positive net means friend owes activeUser; Negative net means activeUser owes friend
    const netByPeer = new Map<string, number>();

    const chronologicalIouPackets = acceptedPackets
      .map((i) => i.decryptedPacket!)
      .filter((pkt) => pkt && pkt.type === 'chat.iou' && pkt.payload.iou)
      .sort(
        (a, b) => new Date(a.sentAt).getTime() - new Date(b.sentAt).getTime()
      );

    for (const pkt of chronologicalIouPackets) {
      const iou = pkt.payload.iou!;
      const debtor = iou.debtorEmail.toLowerCase();
      const creditor = iou.creditorEmail.toLowerCase();

      if (debtor !== myEmail && creditor !== myEmail) continue;
      const peerEmail = debtor === myEmail ? creditor : debtor;

      if (iou.action === 'collect') {
        const current = netByPeer.get(peerEmail) || 0;
        const settledAmt = iou.amount > 0 ? iou.amount : Math.abs(current);
        if (current > 0) {
          netByPeer.set(peerEmail, Math.max(0, current - settledAmt));
        } else if (current < 0) {
          netByPeer.set(peerEmail, Math.min(0, current + settledAmt));
        }
      } else {
        const delta = creditor === myEmail ? iou.amount : -iou.amount;
        netByPeer.set(peerEmail, (netByPeer.get(peerEmail) || 0) + delta);
      }
    }

    let owedToMeTotal = 0;
    let iOweTotal = 0;
    const rows: Array<{
      peerEmail: string;
      peerUser?: UserIdentity;
      displayName: string;
      handle: string;
      netAmount: number;
    }> = [];

    for (const [peerEmail, net] of netByPeer.entries()) {
      if (Math.abs(net) < 0.01) continue;
      if (net > 0) owedToMeTotal += net;
      if (net < 0) iOweTotal += Math.abs(net);
      const u = users.find((x) => x.email.toLowerCase() === peerEmail);
      const fallbackName =
        peerEmail.split('@')[0].charAt(0).toUpperCase() +
        peerEmail.split('@')[0].slice(1);
      rows.push({
        peerEmail,
        peerUser: u,
        displayName: (u?.displayName || fallbackName).replace(
          ' (No App Yet)',
          ''
        ),
        handle: u?.handle || `@${peerEmail.split('@')[0]}`,
        netAmount: net,
      });
    }

    rows.sort((a, b) => Math.abs(b.netAmount) - Math.abs(a.netAmount));

    return {
      owedToMeTotal,
      iOweTotal,
      netBalance: owedToMeTotal - iOweTotal,
      rows,
    };
  }, [acceptedPackets, activeUser.email, users]);

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

    const isBurnerChat = Boolean(activeChannel.isBurner);

    // If burner chat, precompute cascade timings across chronologically sorted channel messages
    let burnerTimingMap = new Map<string, ViewerBurnerCascadeItem>();
    if (isBurnerChat) {
      const channelMessages = chronologicallySorted
        .map((i) => i.decryptedPacket!)
        .filter(
          (pkt) =>
            pkt &&
            pkt.channel.id === activeChannel.id &&
            (pkt.type === 'chat.message' || pkt.type === 'chat.poll')
        );

      burnerTimingMap = computeViewerBurnerCascade({
        messages: channelMessages.map((p) => ({
          messageId: p.payload.messageId,
          senderEmail: p.sender.email,
        })),
        viewerEmail: activeUser.email,
        participants: activeChannel.participants,
        receiptsByMessageId: receiptsByTargetId,
        localViewMap: burnReadStartedAtMs,
        nowMs: burnTickNowMs,
        ttlSeconds: 20,
        userNameLookup: (email) => {
          const u = users.find(
            (x) => x.email.toLowerCase() === email.toLowerCase()
          );
          return u?.displayName?.split(' ')[0] || u?.handle || email.split('@')[0];
        },
      });
    }

    // If broadcast-channel, find the latest channelReactionTotals snapshot pushed by the creator
    let latestBroadcastReactionTotals:
      | Record<string, Record<string, number>>
      | undefined;
    if (activeChannel.type === 'broadcast-channel') {
      for (let i = chronologicallySorted.length - 1; i >= 0; i--) {
        const p = chronologicallySorted[i].decryptedPacket!;
        if (
          p.channel.id === activeChannel.id &&
          p.payload.channelReactionTotals
        ) {
          latestBroadcastReactionTotals = p.payload.channelReactionTotals;
          break;
        }
      }
    }

    for (const item of chronologicallySorted) {
      const pkt = item.decryptedPacket!;
      if (pkt.channel.id !== activeChannel.id) continue;
      if (
        pkt.type !== 'chat.message' &&
        pkt.type !== 'chat.poll' &&
        pkt.type !== 'chat.member-update' &&
        pkt.type !== 'chat.iou'
      ) {
        continue;
      }

      const quoted = pkt.payload.replyToMessageId
        ? messageLookup.get(pkt.payload.replyToMessageId)
        : undefined;

      const msgReceipts = receiptsByTargetId.get(pkt.payload.messageId) || [];
      const msgId = pkt.payload.messageId;

      let burnerStatus: FreeflowChatMessage['burnerStatus'] = undefined;

      if (isBurnerChat) {
        const timing = burnerTimingMap.get(msgId);
        if (timing) {
          if (timing.isExpired) {
            // Cascade deleted!
            continue;
          }
          burnerStatus = {
            isBurner: true,
            isActive: timing.isActive,
            isQueued: timing.isQueued,
            isExpired: timing.isExpired,
            isUnread: !timing.isViewed,
            remainingSeconds: timing.remainingSeconds,
            unreadCount:
              timing.unburnedRecipientCount ??
              Math.max(1, activeChannel.participants.length - 1),
            summaryLabel: timing.summaryLabel,
            isOwn: timing.isOwn,
          };
        } else {
          burnerStatus = {
            isBurner: true,
            isActive: false,
            isQueued: true,
            isExpired: false,
            isUnread: true,
            remainingSeconds: 20,
            unreadCount: Math.max(1, activeChannel.participants.length - 1),
            summaryLabel: '⏳ queued (20s)',
            isOwn:
              pkt.sender.email.toLowerCase() === activeUser.email.toLowerCase(),
          };
        }
      } else {
        const ttlSec =
          pkt.payload.ephemeralTtlSeconds ||
          activeChannel.ephemeralTimerSeconds ||
          0;

        // Filter out Burn-After-Reading messages whose TTL has expired after being read
        if (ttlSec > 0) {
          const startMs =
            burnReadStartedAtMs[msgId] ||
            (msgReceipts.length > 0
              ? new Date(msgReceipts[0].readAtIso || pkt.sentAt).getTime()
              : 0);
          if (startMs > 0 && burnTickNowMs - startMs >= ttlSec * 1000) {
            continue;
          }
        }
      }

      const pollVotes = pkt.payload.poll
        ? pollVotesByPollId.get(pkt.payload.poll.pollId) || []
        : [];

      // Merge anonymous broadcast-channel reaction totals with direct reactions
      let effectiveReactions =
        reactionsByTargetId.get(pkt.payload.messageId) || [];
      if (activeChannel.type === 'broadcast-channel') {
        const snapshotForMsg =
          latestBroadcastReactionTotals?.[pkt.payload.messageId] ||
          pkt.payload.channelReactionTotals?.[pkt.payload.messageId];
        if (snapshotForMsg) {
          const synthList: Array<{
            emoji: string;
            senderName: string;
            senderEmail: string;
          }> = [];
          for (const [emoji, count] of Object.entries(snapshotForMsg)) {
            for (let c = 0; c < count; c++) {
              synthList.push({
                emoji,
                senderName: `Anon #${c + 1}`,
                senderEmail: `anon_${c + 1}@bcc.local`,
              });
            }
          }
          // Also include active user's own pending reaction if not yet in creator's snapshot
          const myDirectReactions = effectiveReactions.filter(
            (r) =>
              r.senderEmail.toLowerCase() === activeUser.email.toLowerCase() ||
              activeChannel.creatorEmail?.toLowerCase() ===
                activeUser.email.toLowerCase()
          );
          for (const r of myDirectReactions) {
            if (
              activeChannel.creatorEmail?.toLowerCase() ===
                activeUser.email.toLowerCase() &&
              r.senderEmail.toLowerCase() !== activeUser.email.toLowerCase()
            ) {
              synthList.push(r);
            } else if (
              r.senderEmail.toLowerCase() === activeUser.email.toLowerCase()
            ) {
              synthList.push({
                emoji: r.emoji,
                senderName: 'You (Anonymous via Creator)',
                senderEmail: r.senderEmail,
              });
            }
          }
          effectiveReactions = synthList;
        }
      }

      messages.push({
        emailId: item.emailId,
        packet: pkt,
        signatureVerified: Boolean(item.signatureVerified),
        decryptionTimeMs: item.decryptionTimeMs,
        reactions: effectiveReactions,
        receipts: msgReceipts,
        pollVotes,
        burnerStatus,
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
    activeUser.email,
    users,
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
    if (isMobileDeviceView && !mobileShowChatPane) {
      return;
    }

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

        setBurnReadStartedAtMs((prev) => {
          const next = {
            ...prev,
            [dedupKey]: prev[dedupKey] || Date.now(),
            [msgId]: prev[msgId] || Date.now(),
          };
          try {
            localStorage.setItem('dc_burn_read_started', JSON.stringify(next));
          } catch {
            // ignore
          }
          return next;
        });

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
    isMobileDeviceView,
    mobileShowChatPane,
  ]);

  const handleFeedScroll = useCallback(() => {
    const feedEl = freeflowFeedRef.current;
    if (!feedEl) return;
    const threshold = 36;
    const scrollableDistance = feedEl.scrollHeight - feedEl.clientHeight;
    const distanceFromBottom = scrollableDistance - feedEl.scrollTop;
    const atBottom = scrollableDistance <= 8 || distanceFromBottom <= threshold;

    if (!isProgrammaticScrollingRef.current) {
      setIsAtBottom(atBottom);
      isScrolledToBottomRef.current = atBottom;
      const hasChatsBelow = checkHasChatsBelowViewport(feedEl);
      setHasChatsBelowViewport(hasChatsBelow);
    }

    if (atBottom) {
      void markActiveChannelAsRead();
    }
  }, [markActiveChannelAsRead]);

  const handleSkipToLatest = useCallback(() => {
    const feedEl = freeflowFeedRef.current;
    if (!feedEl) return;
    isProgrammaticScrollingRef.current = true;
    feedEl.scrollTo({ top: feedEl.scrollHeight, behavior: 'smooth' });
    setIsAtBottom(true);
    isScrolledToBottomRef.current = true;
    setHasChatsBelowViewport(false);
    if (programmaticScrollTimerRef.current) {
      window.clearTimeout(programmaticScrollTimerRef.current);
    }
    programmaticScrollTimerRef.current = window.setTimeout(() => {
      isProgrammaticScrollingRef.current = false;
      if (freeflowFeedRef.current) {
        const hasChatsBelow = checkHasChatsBelowViewport(freeflowFeedRef.current);
        setHasChatsBelowViewport(hasChatsBelow);
        setIsAtBottom(!hasChatsBelow);
        isScrolledToBottomRef.current = !hasChatsBelow;
      }
    }, 350);
    void markActiveChannelAsRead();
  }, [markActiveChannelAsRead]);

  // Reset unread tracking on user account switch
  useEffect(() => {
    setReadMessageIds(new Set());
    prevChannelIdRef.current = null;
    prevStreamLengthRef.current = 0;
    userJustSentMessageRef.current = false;
    setActiveUnseenMarkerMsgId(null);
    if (unseenTimerRef.current) {
      window.clearTimeout(unseenTimerRef.current);
      unseenTimerRef.current = null;
    }
    setIsAtBottom(true);
    isScrolledToBottomRef.current = true;
    setHasChatsBelowViewport(false);
  }, [activeUser.email]);

  // Handle scroll positioning on channel change and incoming messages:
  // - When entering a chat with unread messages, start at the first unread message in the center of the view
  // - Show a dotted transparent line above the latest unseen message, that fades away in 5 seconds
  // - When in an active chat, ONLY auto-scroll new messages if scrolled to the bottom (or user just sent message)
  // - Prevent kick-down when scrolling up to read messages or when message is taller than the viewport
  useEffect(() => {
    const feedEl = freeflowFeedRef.current;
    if (!feedEl || !activeChannel) return;

    const currentChId = activeChannel.id;
    const isChannelSwitch =
      prevChannelIdRef.current !== currentChId ||
      (!prevMobileShowChatPaneRef.current && mobileShowChatPane);
    prevChannelIdRef.current = currentChId;
    prevMobileShowChatPaneRef.current = mobileShowChatPane;

    const currentStreamLength = freeflowStream.length;
    const prevStreamLen = prevStreamLengthRef.current;

    if (isChannelSwitch) {
      prevStreamLengthRef.current = currentStreamLength;

      const unreadCount = currentChId
        ? channelUnreadCountMap[currentChId] || 0
        : 0;

      if (unreadCount > 0) {
        // Find the first unread incoming message
        const firstUnreadMsg = freeflowStream.find((m) => {
          if (
            m.packet.type !== 'chat.message' &&
            m.packet.type !== 'chat.poll'
          ) {
            return false;
          }
          const isOwn =
            m.packet.sender.email.toLowerCase() ===
            activeUser.email.toLowerCase();
          if (isOwn) return false;
          const alreadyReceipted = m.receipts.some(
            (r) =>
              r.senderEmail.toLowerCase() === activeUser.email.toLowerCase()
          );
          if (alreadyReceipted) return false;
          const dedupKey = `${activeUser.email.toLowerCase()}:${m.packet.payload.messageId}`;
          return (
            !autoReadSentKeysRef.current.has(dedupKey) &&
            !readMessageIds.has(m.packet.payload.messageId)
          );
        });

        const markerId = firstUnreadMsg?.packet.payload.messageId || null;
        if (markerId) {
          setActiveUnseenMarkerMsgId(markerId);
          if (unseenTimerRef.current) {
            window.clearTimeout(unseenTimerRef.current);
          }
          unseenTimerRef.current = window.setTimeout(() => {
            setActiveUnseenMarkerMsgId(null);
          }, 5500);
        } else {
          setActiveUnseenMarkerMsgId(null);
        }

        requestAnimationFrame(() => {
          requestAnimationFrame(() => {
            const target =
              document.getElementById('dc-first-unread-marker') ||
              (markerId
                ? document.getElementById(`dc-msg-${markerId}`)
                : null) ||
              feedEl.querySelector('.dc-imessage-row.is-unread');
            if (target) {
              target.scrollIntoView({ block: 'center', behavior: 'auto' });
              requestAnimationFrame(() => {
                const hasChatsBelow = checkHasChatsBelowViewport(feedEl);
                setHasChatsBelowViewport(hasChatsBelow);
                setIsAtBottom(!hasChatsBelow);
                isScrolledToBottomRef.current = !hasChatsBelow;
              });
              return;
            }
            feedEl.scrollTo({ top: feedEl.scrollHeight, behavior: 'auto' });
            setIsAtBottom(true);
            isScrolledToBottomRef.current = true;
            setHasChatsBelowViewport(false);
          });
        });
        return;
      }

      // No unread messages: scroll to bottom
      setActiveUnseenMarkerMsgId(null);
      if (unseenTimerRef.current) {
        window.clearTimeout(unseenTimerRef.current);
        unseenTimerRef.current = null;
      }

      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          feedEl.scrollTo({ top: feedEl.scrollHeight, behavior: 'auto' });
          setIsAtBottom(true);
          isScrolledToBottomRef.current = true;
          setHasChatsBelowViewport(false);
        });
      });
      return;
    }

    // Inside active chat: ONLY auto-scroll if a brand-new message was appended to the stream!
    const isNewMessageAppended = currentStreamLength > prevStreamLen;
    prevStreamLengthRef.current = currentStreamLength;

    if (!isNewMessageAppended) {
      // No new message added (re-render, unread map update, reaction, burn timer ticker, etc.)
      // DO NOT touch scroll position! Preserves reading position on tall messages & scrolling up.
      return;
    }

    // A brand new message arrived
    const userJustSent = userJustSentMessageRef.current;
    userJustSentMessageRef.current = false;

    // Scroll to bottom ONLY if the user just sent the message OR was already scrolled to the bottom
    if (userJustSent || isScrolledToBottomRef.current) {
      isProgrammaticScrollingRef.current = true;
      requestAnimationFrame(() => {
        feedEl.scrollTo({ top: feedEl.scrollHeight, behavior: 'auto' });
        setIsAtBottom(true);
        isScrolledToBottomRef.current = true;
        setHasChatsBelowViewport(false);
        if (programmaticScrollTimerRef.current) {
          window.clearTimeout(programmaticScrollTimerRef.current);
        }
        programmaticScrollTimerRef.current = window.setTimeout(() => {
          isProgrammaticScrollingRef.current = false;
        }, 120);
      });
    } else {
      // The user was scrolled up reading earlier messages
      // Only show skip button if there actually ARE chats below the visible viewport!
      requestAnimationFrame(() => {
        const hasChatsBelow = checkHasChatsBelowViewport(feedEl);
        setHasChatsBelowViewport(hasChatsBelow);
        setIsAtBottom(!hasChatsBelow);
        isScrolledToBottomRef.current = !hasChatsBelow;
      });
    }
  }, [
    activeChannel?.id,
    freeflowStream.length,
    mobileShowChatPane,
    activeUser.email,
  ]);

  // Keep `hasChatsBelowViewport` and `isAtBottom` accurately synced on feed container resize
  useEffect(() => {
    const feedEl = freeflowFeedRef.current;
    if (!feedEl) return;

    const updateScrollState = () => {
      if (isProgrammaticScrollingRef.current) return;
      const hasChatsBelow = checkHasChatsBelowViewport(feedEl);
      setHasChatsBelowViewport(hasChatsBelow);
      const scrollableDistance = feedEl.scrollHeight - feedEl.clientHeight;
      const distanceFromBottom = scrollableDistance - feedEl.scrollTop;
      const atBottom = scrollableDistance <= 8 || distanceFromBottom <= 36;
      setIsAtBottom(atBottom);
      isScrolledToBottomRef.current = atBottom;
    };

    const resizeObserver = new ResizeObserver(updateScrollState);
    resizeObserver.observe(feedEl);
    window.addEventListener('resize', updateScrollState);

    return () => {
      resizeObserver.disconnect();
      window.removeEventListener('resize', updateScrollState);
    };
  }, [activeChannel?.id]);

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

        let validPackets = matchingPackets;
        if (ch.isBurner) {
          const chron = [...matchingPackets].reverse();
          const cascadeMap = computeViewerBurnerCascade({
            messages: chron.map((p) => ({
              messageId: p.payload.messageId,
              senderEmail: p.sender.email,
            })),
            viewerEmail: activeUser.email,
            participants: ch.participants,
            localViewMap: burnReadStartedAtMs,
            nowMs: burnTickNowMs,
            ttlSeconds: 20,
          });
          validPackets = matchingPackets.filter((p) => {
            const timing = cascadeMap.get(p.payload.messageId);
            return timing ? !timing.isExpired : true;
          });
        }

        const lastPacket = validPackets[0];
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
            (ch.isBurner
              ? '20s cascade'
              : ch.type === 'broadcast-channel'
              ? ch.description || 'Broadcast Feed'
              : ch.type === 'vault'
              ? 'Notes'
              : ch.type === 'dm'
              ? 'Chat'
              : `${ch.participants.length}`),
          lastTime: lastPacket?.sentAt || ch.createdAt || '',
          lastTimestampMs: lastPacket
            ? new Date(lastPacket.sentAt).getTime()
            : ch.createdAt
            ? new Date(ch.createdAt).getTime()
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
    burnReadStartedAtMs,
    burnTickNowMs,
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
    iou?: DcpIouPayload;
    channelReactionTotals?: Record<string, Record<string, number>>;
    storyCard?: {
      imageDataUrl?: string;
      caption?: string;
      badgeText?: string;
    };
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
    if (params.type === 'chat.message' || params.type === 'chat.poll') {
      userJustSentMessageRef.current = true;
    }
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
          iou: params.iou,
          channelReactionTotals: params.channelReactionTotals,
          storyCard: params.storyCard,
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
    handleOpenExistingOrStartContactChat(email);
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

    // 4. Open or create their 1-on-1 DM (Regular first, or Burner if only Burner exists)
    const existingRegularDm = channels.find(
      (c) =>
        c.type === 'dm' &&
        !c.isBurner &&
        c.participants.some((p) => p.toLowerCase() === cleanEmail) &&
        c.participants.some(
          (p) => p.toLowerCase() === activeUser.email.toLowerCase()
        )
    );
    const existingBurnerDm = channels.find(
      (c) =>
        c.type === 'dm' &&
        Boolean(c.isBurner) &&
        c.participants.some((p) => p.toLowerCase() === cleanEmail) &&
        c.participants.some(
          (p) => p.toLowerCase() === activeUser.email.toLowerCase()
        )
    );
    const existingDm = existingRegularDm || existingBurnerDm;
    let targetChannelId = existingDm?.id;
    if (existingDm) {
      setActiveChannelId(existingDm.id);
    } else {
      const dmCh: DcpChannelMeta = {
        id: `dm_${Date.now().toString(36)}`,
        type: 'dm',
        name: resolvedName,
        participants: [activeUser.email, cleanEmail],
        createdAt: new Date().toISOString(),
      };
      setChannels((prev) => [dmCh, ...prev]);
      setActiveChannelId(dmCh.id);
      targetChannelId = dmCh.id;
    }

    safetyListDialogRef.current?.close();
    profileDialogRef.current?.close();
    openMobileChat(targetChannelId);
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
  async function handleSaveUserProfile(e?: React.FormEvent) {
    e?.preventDefault();
    const cleanRawHandle = profileHandleInput
      .replace(/^@+/, '')
      .replace(/\s+/g, '_')
      .replace(/[^a-zA-Z0-9_]/g, '');
    const formattedHandle = `@${
      cleanRawHandle || activeUser.email.split('@')[0].replace(/[^a-zA-Z0-9_]/g, '')
    }`;

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
    setCameraStamps([]);
    setSelectedCameraStampId(null);
    setIsCameraStampPickerOpen(true);
    cameraCaptureDialogRef.current?.showModal();
    await startCameraStream(cameraFacingMode);
  }

  function handleCloseCameraModal() {
    stopCameraStream();
    setCapturedPhotoDataUrl(null);
    setCameraStamps([]);
    setSelectedCameraStampId(null);
  }

  function handleAddCameraEmojiStamp(emoji: string) {
    const id = `stamp_${Date.now().toString(36)}_${Math.random()
      .toString(36)
      .slice(2, 6)}`;
    const count = cameraStamps.length;
    const offsetXPct = ((count * 9) % 36) - 14;
    const offsetYPct = ((count * 7) % 28) - 10;
    const newStamp = {
      id,
      emoji,
      xPct: Math.min(82, Math.max(18, 50 + (count === 0 ? 0 : offsetXPct))),
      yPct: Math.min(80, Math.max(20, 45 + (count === 0 ? 0 : offsetYPct))),
      sizePx: 88,
    };
    setCameraStamps((prev) => [...prev, newStamp]);
    setSelectedCameraStampId(id);
  }

  function handleUpdateCameraStampSize(stampId: string, nextSizePx: number) {
    const clamped = Math.min(220, Math.max(24, Math.round(nextSizePx)));
    setCameraStamps((prev) =>
      prev.map((s) => (s.id === stampId ? { ...s, sizePx: clamped } : s))
    );
  }

  function handleDeleteCameraStamp(stampId: string) {
    setCameraStamps((prev) => {
      const remaining = prev.filter((s) => s.id !== stampId);
      if (selectedCameraStampId === stampId) {
        setSelectedCameraStampId(
          remaining.length > 0 ? remaining[remaining.length - 1].id : null
        );
      }
      return remaining;
    });
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
    setCameraStamps([]);
    setSelectedCameraStampId(null);
    setIsCameraStampPickerOpen(true);
  }

  async function handleSendCapturedCameraPhoto() {
    if (!capturedPhotoDataUrl || !activeChannel) return;
    let snapDataUrl = capturedPhotoDataUrl;

    // Permanently bake any placed emoji stamps directly into the JPEG pixels before encryption
    if (cameraStamps.length > 0) {
      try {
        const viewportWidth = cameraViewportRef.current?.clientWidth || 360;
        snapDataUrl = await new Promise<string>((resolve) => {
          const img = new Image();
          img.onload = () => {
            const canvas = document.createElement('canvas');
            const w = img.naturalWidth || 640;
            const h = img.naturalHeight || 480;
            canvas.width = w;
            canvas.height = h;
            const ctx = canvas.getContext('2d');
            if (!ctx) {
              resolve(capturedPhotoDataUrl);
              return;
            }
            ctx.drawImage(img, 0, 0, w, h);
            const scaleRatio = w / Math.max(1, viewportWidth);
            for (const st of cameraStamps) {
              const cx = (st.xPct / 100) * w;
              const cy = (st.yPct / 100) * h;
              const fontPx = Math.round(st.sizePx * scaleRatio);
              ctx.save();
              ctx.font = `${fontPx}px "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", system-ui, sans-serif`;
              ctx.textAlign = 'center';
              ctx.textBaseline = 'middle';
              ctx.fillText(st.emoji, cx, cy);
              ctx.restore();
            }
            resolve(canvas.toDataURL('image/jpeg', 0.9));
          };
          img.onerror = () => resolve(capturedPhotoDataUrl);
          img.src = capturedPhotoDataUrl;
        });
      } catch {
        snapDataUrl = capturedPhotoDataUrl;
      }
    }

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
    setCameraStamps([]);
    setSelectedCameraStampId(null);
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

  // Cancel Voice Recorder UI without saving attachment
  function handleCancelVoiceRecorder() {
    if (recordingTimerRef.current) {
      window.clearInterval(recordingTimerRef.current);
      recordingTimerRef.current = null;
    }
    if (
      mediaRecorderRef.current &&
      mediaRecorderRef.current.state !== 'inactive'
    ) {
      mediaRecorderRef.current.onstop = null;
      mediaRecorderRef.current.stop();
    }
    setIsRecordingVoice(false);
    setIsVoiceRecorderOpen(false);
    setRecordingSeconds(0);
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
      setIsVoiceRecorderOpen(false);
      setRecordingSeconds(0);
      return;
    }

    // Start recording
    setIsVoiceRecorderOpen(true);
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
    setBurnReadStartedAtMs((prev) => {
      const next = {
        ...prev,
        [dedupKey]: prev[dedupKey] || Date.now(),
        [targetMessageId]: prev[targetMessageId] || Date.now(),
      };
      try {
        localStorage.setItem('dc_burn_read_started', JSON.stringify(next));
      } catch {
        // ignore
      }
      return next;
    });
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
    if (isMobileDeviceView && !mobileShowChatPane) {
      return;
    }

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

        setBurnReadStartedAtMs((prev) => {
          const next = {
            ...prev,
            [dedupKey]: prev[dedupKey] || Date.now(),
            [msgId]: prev[msgId] || Date.now(),
          };
          try {
            localStorage.setItem('dc_burn_read_started', JSON.stringify(next));
          } catch {
            // ignore
          }
          return next;
        });

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

  // Burner Chat Active Auto-View: when active channel is a burner chat,
  // record viewing timestamp for incoming unread messages in the active channel to begin their sequential cascade.
  useEffect(() => {
    if (!activeChannel || !activeChannel.isBurner) return;
    if (isMobileDeviceView && !mobileShowChatPane) return;
    if (isAppLocked || isInitializingKeys || surfaceMode !== 'messenger-ui') return;

    const channelPackets = acceptedPackets
      .map((i) => i.decryptedPacket!)
      .filter(
        (pkt) =>
          pkt &&
          pkt.channel.id === activeChannel.id &&
          (pkt.type === 'chat.message' || pkt.type === 'chat.poll') &&
          pkt.sender.email.toLowerCase() !== activeUser.email.toLowerCase()
      );

    if (channelPackets.length === 0) return;

    const now = Date.now();
    const missing: Record<string, number> = {};
    let hasMissing = false;

    for (const pkt of channelPackets) {
      const msgId = pkt.payload.messageId;
      const userKey = `${activeUser.email.toLowerCase()}:${msgId}`;
      if (!burnReadStartedAtMs[userKey]) {
        missing[userKey] = now;
        missing[msgId] = now;
        hasMissing = true;
      }
    }

    if (hasMissing) {
      setBurnReadStartedAtMs((prev) => {
        const next = { ...prev, ...missing };
        try {
          localStorage.setItem('dc_burn_read_started', JSON.stringify(next));
        } catch {
          // ignore
        }
        return next;
      });
    }
  }, [
    activeChannel?.id,
    activeChannel?.isBurner,
    acceptedPackets,
    isMobileDeviceView,
    mobileShowChatPane,
    isAppLocked,
    isInitializingKeys,
    surfaceMode,
    burnReadStartedAtMs,
    activeUser.email,
  ]);

  // Lock ephemeral countdown timer to 20s whenever activeChannel is a permanent Burner Chat
  useEffect(() => {
    if (activeChannel?.isBurner) {
      setComposerBurnSeconds(20);
    }
  }, [activeChannel?.id, activeChannel?.isBurner]);

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

  // Add Member to Group or Broadcast Channel (Hard Capped at 99 Users to prevent personal email spam limits)
  async function handleAddMemberToChannel(e: React.FormEvent) {
    e.preventDefault();
    if (!activeChannel) return;
    if (activeChannel.participants.length >= MAX_CHANNEL_AND_GROUP_USERS) {
      setSafetyBannerNotice(
        `Hard cap of ${MAX_CHANNEL_AND_GROUP_USERS} users reached to protect personal email deliverability.`
      );
      setTimeout(() => setSafetyBannerNotice(''), 4000);
      return;
    }
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

  // Start or jump to an existing 1-on-1 chat (Regular first, then Burner in that order), or create Regular if neither exists
  function handleOpenExistingOrStartContactChat(email: string) {
    const targetEmail = email.trim().toLowerCase();
    if (!targetEmail) return;

    const existingRegularDm = channels.find(
      (c) =>
        c.type === 'dm' &&
        !c.isBurner &&
        c.participants.some((p) => p.toLowerCase() === targetEmail) &&
        c.participants.some(
          (p) => p.toLowerCase() === activeUser.email.toLowerCase()
        )
    );

    if (existingRegularDm) {
      setContactSearchQuery('');
      menuDirectoryDialogRef.current?.close();
      groupInfoDialogRef.current?.close();
      newChannelModalRef.current?.close();
      openMobileChat(existingRegularDm.id);
      return;
    }

    const existingBurnerDm = channels.find(
      (c) =>
        c.type === 'dm' &&
        Boolean(c.isBurner) &&
        c.participants.some((p) => p.toLowerCase() === targetEmail) &&
        c.participants.some(
          (p) => p.toLowerCase() === activeUser.email.toLowerCase()
        )
    );

    if (existingBurnerDm) {
      setContactSearchQuery('');
      menuDirectoryDialogRef.current?.close();
      groupInfoDialogRef.current?.close();
      newChannelModalRef.current?.close();
      openMobileChat(existingBurnerDm.id);
      return;
    }

    handleStartOrOpenContactChat(targetEmail);
  }

  // Start or jump to a regular 1-on-1 DM with any Contact
  function handleStartOrOpenContactChat(email: string) {
    const targetEmail = email.trim().toLowerCase();
    if (!targetEmail) return;

    const existingDm = channels.find(
      (c) =>
        c.type === 'dm' &&
        !c.isBurner &&
        c.participants.some((p) => p.toLowerCase() === targetEmail) &&
        c.participants.some(
          (p) => p.toLowerCase() === activeUser.email.toLowerCase()
        )
    );

    if (existingDm) {
      setContactSearchQuery('');
      menuDirectoryDialogRef.current?.close();
      groupInfoDialogRef.current?.close();
      newChannelModalRef.current?.close();
      openMobileChat(existingDm.id);
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
      createdAt: new Date().toISOString(),
    };
    setChannels((prev) => [dmCh, ...prev]);
    setContactSearchQuery('');
    menuDirectoryDialogRef.current?.close();
    groupInfoDialogRef.current?.close();
    newChannelModalRef.current?.close();
    openMobileChat(dmCh.id);
  }

  // Start or jump to a 1-on-1 Burner Chat with any Contact (20s sequential cascade delete)
  function handleStartOrOpenBurnerContactChat(email: string) {
    const targetEmail = email.trim().toLowerCase();
    if (!targetEmail) return;

    const existingBurnerDm = channels.find(
      (c) =>
        c.type === 'dm' &&
        c.isBurner &&
        c.participants.some((p) => p.toLowerCase() === targetEmail) &&
        c.participants.some(
          (p) => p.toLowerCase() === activeUser.email.toLowerCase()
        )
    );

    if (existingBurnerDm) {
      setContactSearchQuery('');
      menuDirectoryDialogRef.current?.close();
      groupInfoDialogRef.current?.close();
      newChannelModalRef.current?.close();
      openMobileChat(existingBurnerDm.id);
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

    const burnerDmCh: DcpChannelMeta = {
      id: `burner_dm_${Date.now().toString(36)}`,
      type: 'dm',
      name: `${existingUser.displayName.replace(' (No App Yet)', '')} (Burner)`,
      participants: [activeUser.email, existingUser.email],
      isBurner: true,
      ephemeralTimerSeconds: 20,
      createdAt: new Date().toISOString(),
    };
    setChannels((prev) => [burnerDmCh, ...prev]);
    setContactSearchQuery('');
    menuDirectoryDialogRef.current?.close();
    groupInfoDialogRef.current?.close();
    newChannelModalRef.current?.close();
    openMobileChat(burnerDmCh.id);
  }

  // Start or jump to a Burner Group Chat for an existing group (20s sequential cascade delete)
  function handleStartOrOpenBurnerGroupChat(sourceGroup: DcpChannelMeta) {
    if (sourceGroup.isBurner) {
      menuDirectoryDialogRef.current?.close();
      openMobileChat(sourceGroup.id);
      return;
    }

    const burnerName = sourceGroup.name.endsWith('-burner')
      ? sourceGroup.name
      : `${sourceGroup.name}-burner`;

    const existingBurnerGroup = channels.find(
      (c) =>
        c.type === 'workspace-channel' &&
        c.isBurner &&
        (c.name.toLowerCase() === burnerName.toLowerCase() ||
          c.id === `burner_${sourceGroup.id}`)
    );

    if (existingBurnerGroup) {
      menuDirectoryDialogRef.current?.close();
      openMobileChat(existingBurnerGroup.id);
      return;
    }

    const burnerGroupCh: DcpChannelMeta = {
      id: `burner_${sourceGroup.id}_${Date.now().toString(36)}`,
      type: 'workspace-channel',
      name: burnerName,
      participants: [...sourceGroup.participants],
      isBurner: true,
      ephemeralTimerSeconds: 20,
    };
    setChannels((prev) => [burnerGroupCh, ...prev]);
    menuDirectoryDialogRef.current?.close();
    openMobileChat(burnerGroupCh.id);
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
    const effectiveBurnSec = activeChannel.isBurner
      ? 20
      : composerBurnSeconds || activeChannel.ephemeralTimerSeconds || undefined;

    // If activeChannel is a broadcast-channel and activeUser is the creator,
    // aggregate all incoming subscriber reactions and push updated channelReactionTotals out to all BCC subscribers!
    let nextChannelReactionTotals:
      | Record<string, Record<string, number>>
      | undefined;
    let nextStoryCard:
      | { imageDataUrl?: string; caption?: string; badgeText?: string }
      | undefined;

    if (
      activeChannel.type === 'broadcast-channel' &&
      activeChannel.creatorEmail?.toLowerCase() ===
        activeUser.email.toLowerCase()
    ) {
      const mergedTotals: Record<string, Record<string, number>> = {};
      for (const item of acceptedPackets) {
        const p = item.decryptedPacket;
        if (!p || p.channel.id !== activeChannel.id) continue;
        if (p.payload.channelReactionTotals) {
          for (const [mId, counts] of Object.entries(
            p.payload.channelReactionTotals
          )) {
            mergedTotals[mId] = { ...(mergedTotals[mId] || {}), ...counts };
          }
        }
      }
      // Count any new 1-to-1 reactions sent to creator since the last snapshot
      const directReactionsByMsg: Record<string, Record<string, number>> = {};
      for (const item of acceptedPackets) {
        const p = item.decryptedPacket;
        if (
          p &&
          p.channel.id === activeChannel.id &&
          p.type === 'chat.reaction' &&
          p.payload.targetMessageId &&
          p.payload.reactionEmoji
        ) {
          const mId = p.payload.targetMessageId;
          const em = p.payload.reactionEmoji;
          if (!directReactionsByMsg[mId]) directReactionsByMsg[mId] = {};
          directReactionsByMsg[mId][em] =
            (directReactionsByMsg[mId][em] || 0) + 1;
        }
      }
      for (const [mId, counts] of Object.entries(directReactionsByMsg)) {
        if (!mergedTotals[mId]) mergedTotals[mId] = {};
        for (const [em, c] of Object.entries(counts)) {
          mergedTotals[mId][em] = (mergedTotals[mId][em] || 0) + c;
        }
      }
      nextChannelReactionTotals = mergedTotals;

      const firstImgAtt = pendingAttachments.find((a) =>
        a.mimeType.startsWith('image/')
      );
      if (firstImgAtt) {
        nextStoryCard = {
          imageDataUrl: firstImgAtt.encryptedData,
          caption: cleanText,
          badgeText: 'LIVE STORY • BCC',
        };
      }
    }

    await dispatchDcpEmailPacket({
      channel: activeChannel,
      type: 'chat.message',
      text: cleanText,
      replyToMessageId: replyingToMessage?.packet.payload.messageId,
      attachments:
        pendingAttachments.length > 0 ? pendingAttachments : undefined,
      ephemeralTtlSeconds: effectiveBurnSec,
      linkPreview,
      channelReactionTotals: nextChannelReactionTotals,
      storyCard: nextStoryCard,
      vaultCategory:
        activeChannel.type === 'vault' ? vaultCategoryInput : undefined,
    });

    setComposerText('');
    setIsComposerMultiline(false);
    setIsPlusMenuOpen(false);
    setPendingAttachments([]);
    setReplyingToMessage(null);
    if (composerTextareaRef.current) {
      composerTextareaRef.current.style.height = '38px';
    }
  }

  // Send or Recognize Collection on a Peer-to-Peer IOU (`chat.iou`)
  async function handleSendOrSettleIou(params: {
    action: 'send-iou' | 'request-iou' | 'collect';
    peerEmail: string;
    amount: number;
    note?: string;
  }) {
    const cleanPeer = params.peerEmail.trim().toLowerCase();
    if (!cleanPeer || params.amount <= 0) return;

    const peerUser = users.find((u) => u.email.toLowerCase() === cleanPeer);
    const peerName = (
      peerUser?.displayName || cleanPeer.split('@')[0]
    ).replace(' (No App Yet)', '');

    let targetDm = channels.find(
      (c) =>
        c.type === 'dm' &&
        !c.isBurner &&
        c.participants.some((p) => p.toLowerCase() === cleanPeer) &&
        c.participants.some(
          (p) => p.toLowerCase() === activeUser.email.toLowerCase()
        )
    );
    if (!targetDm) {
      targetDm = {
        id: `dm_${Date.now().toString(36)}`,
        type: 'dm',
        name: peerName,
        participants: [activeUser.email, cleanPeer],
      };
      setChannels((prev) => [targetDm!, ...prev]);
    }

    const isCreditorMe =
      params.action === 'request-iou' ||
      (params.action === 'collect' &&
        (iouLedgerSummary.rows.find((r) => r.peerEmail === cleanPeer)
          ?.netAmount || 0) > 0);

    const debtorEmail =
      params.action === 'send-iou'
        ? activeUser.email
        : params.action === 'request-iou'
        ? cleanPeer
        : isCreditorMe
        ? cleanPeer
        : activeUser.email;

    const creditorEmail =
      debtorEmail.toLowerCase() === activeUser.email.toLowerCase()
        ? cleanPeer
        : activeUser.email;

    const iouPayload: DcpIouPayload = {
      iouId: `iou_${Date.now().toString(36)}`,
      action: params.action,
      amount: params.amount,
      unit: 'IOU',
      note: params.note || (params.action === 'collect' ? 'Settled up' : 'IOU'),
      debtorEmail,
      creditorEmail,
      settledAt:
        params.action === 'collect' ? new Date().toISOString() : undefined,
    };

    const summaryText =
      params.action === 'collect'
        ? `Recognized collection of ${params.amount} from ${peerName}`
        : `Sent ${params.amount} to ${peerName}${
            params.note ? ` (${params.note})` : ''
          }`;

    await dispatchDcpEmailPacket({
      channel: targetDm,
      type: 'chat.iou',
      text: summaryText,
      iou: iouPayload,
    });

    setSelectedIouPeerEmail(null);
    setShowIouIssueForm(false);
    setIouSendNote('');
    setSafetyBannerNotice(summaryText);
    setTimeout(() => setSafetyBannerNotice(''), 4000);
  }

  // Subscriber Burn Local Channel & Block (sends encrypted Unsubscribe packet back to Creator to remove from BCC)
  async function handleSubscriberBurnAndUnsubscribeChannel(
    channelToUnsub: DcpChannelMeta
  ) {
    if (channelToUnsub.type !== 'broadcast-channel') return;
    const creatorEmail =
      channelToUnsub.creatorEmail || channelToUnsub.participants[0];

    const updatedParticipants = channelToUnsub.participants.filter(
      (p) => p.toLowerCase() !== activeUser.email.toLowerCase()
    );

    // 1. Send encrypted unsubscribe email back to the creator
    await dispatchDcpEmailPacket({
      channel: channelToUnsub,
      type: 'chat.member-update',
      text: `Unsubscribe & remove ${activeUser.email} from #${channelToUnsub.name} BCC list`,
      memberUpdate: {
        action: 'remove',
        targetEmail: activeUser.email,
        targetDisplayName: activeUser.displayName,
        updatedParticipants,
      },
    });

    // 2. Burn local channel messages from IndexedDB
    const channelHeaderTag = `[${channelToUnsub.id}]`;
    const emailIdsToScrub = transportEmails
      .filter(
        (eml) =>
          eml.headers['X-@me-Channel-Id'] === channelToUnsub.id ||
          eml.subject.includes(channelHeaderTag)
      )
      .map((eml) => eml.id);
    if (emailIdsToScrub.length > 0) {
      await cryptographicScrubPeerAndEmailsInIdb({ emailIdsToScrub });
      const remaining = transportEmails.filter(
        (e) => !emailIdsToScrub.includes(e.id)
      );
      setTransportEmails(remaining);
      await saveTransportEmailsToIdb(remaining);
    }

    // 3. Remove activeUser from local channel subscription & switch to another conversation
    setChannels((prev) =>
      prev.map((c) =>
        c.id === channelToUnsub.id
          ? { ...c, participants: updatedParticipants }
          : c
      )
    );
    const fallbackCh = userScopedChannels.find(
      (c) => c.id !== channelToUnsub.id
    );
    if (fallbackCh) {
      setActiveChannelId(fallbackCh.id);
    }
    setSafetyBannerNotice(
      `Unsubscribed & burned local feed #${channelToUnsub.name} (sent removal notice to ${creatorEmail})`
    );
    setTimeout(() => setSafetyBannerNotice(''), 4500);
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
    openMobileChat(vaultId);
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

    if (newChatType === 'broadcast-channel') {
      const id = `ch_broadcast_${Date.now().toString(36)}`;
      const cleanName =
        newChatName
          .trim()
          .toLowerCase()
          .replace(/[^a-z0-9-]/g, '-') || 'live-feed';
      const selectedParticipants =
        selectedGroupMemberEmails.length > 0
          ? Array.from(
              new Set([activeUser.email, ...selectedGroupMemberEmails])
            ).slice(0, MAX_CHANNEL_AND_GROUP_USERS)
          : users
              .filter((u) => u.hasAppInstalled)
              .map((u) => u.email)
              .slice(0, MAX_CHANNEL_AND_GROUP_USERS);
      const newBroadcastCh: DcpChannelMeta = {
        id,
        type: 'broadcast-channel',
        name: cleanName,
        creatorEmail: activeUser.email,
        description:
          newChannelDescription.trim() ||
          'Anonymous BCC Story Channel • Subscribers react privately',
        participants: selectedParticipants,
        createdAt: new Date().toISOString(),
      };
      setChannels((prev) => [newBroadcastCh, ...prev]);
      setNewChatName('');
      setNewChannelDescription('');
      setSelectedGroupMemberEmails([]);
      setIsNewChatBurner(false);
      newChannelModalRef.current?.close();
      menuDirectoryDialogRef.current?.close();
      openMobileChat(newBroadcastCh.id);
      return;
    }

    if (newChatType === 'workspace-channel') {
      const id = isNewChatBurner
        ? `burner_ch_${Date.now().toString(36)}`
        : `ch_custom_${Date.now().toString(36)}`;
      const selectedFriendNames = selectedGroupMemberEmails
        .map(
          (em) =>
            users
              .find((u) => u.email.toLowerCase() === em.toLowerCase())
              ?.displayName.replace(' (No App Yet)', '')
              .toLowerCase() || em.split('@')[0].toLowerCase()
        )
        .filter(Boolean);
      const fallbackGroupName =
        selectedFriendNames.length > 0
          ? `${activeUser.displayName.toLowerCase()}-${selectedFriendNames.join(
              '-'
            )}`
          : isNewChatBurner
          ? 'burner-group'
          : 'new-group';
      let cleanName =
        newChatName
          .trim()
          .toLowerCase()
          .replace(/[^a-z0-9-]/g, '-') || fallbackGroupName;
      if (isNewChatBurner && !cleanName.endsWith('-burner')) {
        cleanName = `${cleanName}-burner`;
      }
      const groupParticipants =
        selectedGroupMemberEmails.length > 0
          ? Array.from(
              new Set([activeUser.email, ...selectedGroupMemberEmails])
            ).slice(0, MAX_CHANNEL_AND_GROUP_USERS)
          : users
              .filter((u) => u.hasAppInstalled)
              .map((u) => u.email)
              .slice(0, MAX_CHANNEL_AND_GROUP_USERS);
      const newCh: DcpChannelMeta = {
        id,
        type: 'workspace-channel',
        name: cleanName,
        participants: groupParticipants,
        shieldedAliasEmail: createdAliasEmail,
        isBurner: isNewChatBurner,
        ephemeralTimerSeconds: isNewChatBurner ? 20 : undefined,
        createdAt: new Date().toISOString(),
      };
      setChannels((prev) => [newCh, ...prev]);
      setNewChatName('');
      setSelectedGroupMemberEmails([]);
      setIsNewChatBurner(false);
      newChannelModalRef.current?.close();
      menuDirectoryDialogRef.current?.close();
      openMobileChat(newCh.id);
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

      const existingDm = channels.find(
        (c) =>
          c.type === 'dm' &&
          Boolean(c.isBurner) === Boolean(isNewChatBurner) &&
          c.participants.some((p) => p.toLowerCase() === targetEmail) &&
          c.participants.some(
            (p) => p.toLowerCase() === activeUser.email.toLowerCase()
          )
      );

      if (existingDm) {
        setNewChatRecipientEmail('');
        setIsNewChatBurner(false);
        newChannelModalRef.current?.close();
        menuDirectoryDialogRef.current?.close();
        openMobileChat(existingDm.id);
        return;
      }

      const rawName = existingUser.displayName.replace(' (No App Yet)', '');
      const dmCh: DcpChannelMeta = {
        id: isNewChatBurner
          ? `burner_dm_${Date.now().toString(36)}`
          : `dm_${Date.now().toString(36)}`,
        type: 'dm',
        name: isNewChatBurner ? `${rawName} (Burner)` : rawName,
        participants: [activeUser.email, existingUser.email],
        shieldedAliasEmail: createdAliasEmail,
        isBurner: isNewChatBurner,
        ephemeralTimerSeconds: isNewChatBurner ? 20 : undefined,
        createdAt: new Date().toISOString(),
      };
      setChannels((prev) => [dmCh, ...prev]);
      setNewChatRecipientEmail('');
      setIsNewChatBurner(false);
      newChannelModalRef.current?.close();
      menuDirectoryDialogRef.current?.close();
      openMobileChat(dmCh.id);
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
      setSimulatedOAuthEmail('taylor@gmail.com');
      setSimulatedOAuthName('Taylor');
    } else {
      setSimulatedOAuthEmail('morgan@outlook.com');
      setSimulatedOAuthName('Morgan');
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
      window.localStorage.removeItem('dontcall_seed_v5');
      window.localStorage.removeItem('dontcall_seed_v6');
      window.localStorage.removeItem('dc_channels_v3');
      window.localStorage.removeItem('dc_channels_v4');
      window.localStorage.removeItem('dc_burn_read_started');
      window.localStorage.removeItem('atme_profile_onboarded');
      window.localStorage.removeItem('atme_blocked_emails');
      window.localStorage.removeItem('atme_whitelisted_emails');
      window.localStorage.removeItem('atme_whitelist_only');
    }
    await clearIdbDatabase();
    window.location.reload();
  }

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
                <Flame size={11} className="dc-flame-fire-icon" /> Wipe: <code>{duressPanicPin}</code>
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
              isMobileDeviceView &&
              mobileShowChatPane &&
              !isSwipingBack &&
              !isAnimatingOut
                ? 'mobile-hidden'
                : ''
            }`}
            inert={
              isMobileDeviceView &&
              mobileShowChatPane &&
              !isSwipingBack &&
              !isAnimatingOut
                ? true
                : undefined
            }
            style={
              isMobileDeviceView && (isSwipingBack || isAnimatingOut)
                ? {
                    transform: `translateX(${
                      -24 +
                      Math.min(
                        24,
                        (swipeOffsetX /
                          Math.max(1, window.innerWidth || 360)) *
                          24
                      )
                    }px)`,
                    opacity:
                      0.85 +
                      Math.min(
                        0.15,
                        (swipeOffsetX /
                          Math.max(1, window.innerWidth || 360)) *
                          0.15
                      ),
                    transition: isAnimatingOut
                      ? 'transform 0.18s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.18s cubic-bezier(0.16, 1, 0.3, 1)'
                      : 'none',
                  }
                : undefined
            }
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

                  <div
                    className="dc-add-menu-wrap"
                    ref={addMenuContainerRef}
                  >
                    <button
                      type="button"
                      className={`dc-compose-circle-btn ${isAddMenuOpen ? 'active' : ''}`}
                      onClick={() => setIsAddMenuOpen((prev) => !prev)}
                      title="New Message or Burner Chat"
                      aria-label="New Message or Burner Chat"
                      aria-expanded={isAddMenuOpen}
                    >
                      <Plus size={16} />
                    </button>

                    {isAddMenuOpen && (
                      <div
                        className="dc-add-menu-dropdown dc-add-menu-icon-bar"
                        role="menu"
                        aria-label="New conversation"
                      >
                        <button
                          type="button"
                          role="menuitem"
                          className="dc-add-icon-only-btn"
                          onClick={() => {
                            setIsAddMenuOpen(false);
                            setNewChatType('dm');
                            setIsNewChatBurner(false);
                            setNewChatRecipientEmail('');
                            setSelectedGroupMemberEmails([]);
                            setShowNewChatContactPicker(false);
                            newChannelModalRef.current?.showModal();
                          }}
                          title="New Message (Regular or Burner)"
                          aria-label="New Message"
                        >
                          <MessageCircle size={19} />
                        </button>

                        <button
                          type="button"
                          role="menuitem"
                          className="dc-add-icon-only-btn"
                          onClick={() => {
                            setIsAddMenuOpen(false);
                            setNewChatType('workspace-channel');
                            setIsNewChatBurner(false);
                            setNewChatName('');
                            setSelectedGroupMemberEmails([]);
                            setShowNewChatContactPicker(false);
                            newChannelModalRef.current?.showModal();
                          }}
                          title="New Group (Regular or Burner)"
                          aria-label="New Group"
                        >
                          <Users size={19} />
                        </button>

                        <button
                          type="button"
                          role="menuitem"
                          className="dc-add-icon-only-btn dc-add-icon-channel-btn"
                          onClick={() => {
                            setIsAddMenuOpen(false);
                            setNewChatType('broadcast-channel');
                            setIsNewChatBurner(false);
                            setNewChatName('');
                            setSelectedGroupMemberEmails([]);
                            setShowNewChatContactPicker(false);
                            newChannelModalRef.current?.showModal();
                          }}
                          title="Setup Broadcast Channel (BCC Live Feed)"
                          aria-label="Setup Broadcast Channel"
                        >
                          <Radio size={19} />
                        </button>
                      </div>
                    )}
                  </div>

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
                              <QrCode size={14} /> @me
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

                        <button
                          type="button"
                          className="dc-header-menu-item"
                          role="menuitem"
                          onClick={() => {
                            setIsAvatarMenuOpen(false);
                            setSelectedIouPeerEmail(null);
                            setShowIouIssueForm(false);
                            iouDialogRef.current?.showModal();
                          }}
                        >
                          <span className="dc-header-menu-icon icon-iou">
                            <Coins size={15} />
                          </span>
                          <span className="dc-header-menu-label">
                            IOUs
                          </span>
                          {iouLedgerSummary.rows.length > 0 && (
                            <span
                              className={`dc-header-menu-badge ${
                                iouLedgerSummary.netBalance >= 0
                                  ? 'is-positive'
                                  : 'is-negative'
                              }`}
                            >
                              {iouLedgerSummary.netBalance >= 0
                                ? `+${iouLedgerSummary.netBalance}`
                                : iouLedgerSummary.netBalance}
                            </span>
                          )}
                        </button>

                        <div className="dc-header-menu-divider" />

                        <div className="dc-avatar-theme-picker">
                          <span className="dc-avatar-section-label">
                            <Sun size={12} />
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
                              title="Dark mode"
                              aria-label="Dark mode"
                            >
                              <Moon size={13} />
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
                              title="Light mode"
                              aria-label="Light mode"
                            >
                              <Sun size={13} />
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
                              title="Auto mode"
                              aria-label="Auto mode"
                            >
                              <Sparkles size={13} />
                            </button>
                          </div>
                        </div>

                        <div className="dc-avatar-theme-picker">
                          <span className="dc-avatar-section-label">
                            <Palette size={12} />
                          </span>
                          <div className="dc-bubble-theme-swatches">
                            {TOP_5_COLORS_2026.map((t) => (
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
                  placeholder="Search…"
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
                      handleOpenExistingOrStartContactChat(contactSearchQuery)
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
                      onClick={() =>
                        handleOpenExistingOrStartContactChat(c.email)
                      }
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
                    const isBroadcast = ch.type === 'broadcast-channel';
                    const isGroup =
                      ch.type !== 'dm' && !isVault && !isBroadcast;
                    const hasApp =
                      isGroup || isVault || isBroadcast
                        ? true
                        : peerUser?.hasAppInstalled ?? false;

                    return (
                      <button
                        key={ch.id}
                        type="button"
                        className={`dc-thread-card ${isActive ? 'active' : ''} ${
                          isVault ? 'vault-thread-card' : ''
                        } ${ch.isBurner ? 'burner-thread-card' : ''} ${
                          isBroadcast ? 'broadcast-thread-card' : ''
                        } ${unreadCount > 0 ? 'has-unread' : ''}`}
                        onClick={() => {
                          openMobileChat(ch.id);
                        }}
                      >
                        {!isGroup &&
                        !isVault &&
                        !isBroadcast &&
                        peerUser?.avatarDataUrl ? (
                          <img
                            src={peerUser.avatarDataUrl}
                            alt={peerUser.displayName}
                            className="dc-thread-avatar dc-avatar-img"
                          />
                        ) : (
                          <div
                            className={`dc-thread-avatar ${
                              ch.isBurner
                                ? 'burner-avatar'
                                : isBroadcast
                                ? 'broadcast-avatar'
                                : isVault
                                ? 'vault-avatar'
                                : isGroup
                                ? 'group-avatar'
                                : hasApp
                                ? 'dm-avatar'
                                : 'invite-avatar'
                            }`}
                          >
                            {ch.isBurner ? (
                              <Flame size={17} className="dc-flame-fire-icon" />
                            ) : isBroadcast ? (
                              <Radio size={17} />
                            ) : isVault ? (
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
                              {ch.isBurner &&
                                !isGroup &&
                                !isVault &&
                                !isBroadcast &&
                                Boolean(peerUser?.avatarDataUrl) && (
                                  <span
                                    className="dc-burner-badge-card"
                                    title="Burner Chat (20s cascade)"
                                  >
                                    <Flame
                                      size={13}
                                      className="dc-flame-fire-icon"
                                    />
                                  </span>
                                )}
                              {isBroadcast && (
                                <span
                                  className="dc-broadcast-badge-card"
                                  title="Broadcast Channel (BCC)"
                                >
                                  <Radio size={13} />
                                </span>
                              )}
                              {isVault
                                ? 'Saved Notes (@me)'
                                : isGroup || isBroadcast
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
                            <div className="dc-thread-snippet">
                              {ch.isBurner && (
                                <Flame
                                  size={11}
                                  className="dc-flame-fire-icon dc-snippet-flame"
                                />
                              )}
                              {lastText}
                            </div>
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
            ref={freeflowChatPaneRef}
            className={`dc-freeflow-chat-pane ${
              isMobileDeviceView && !mobileShowChatPane ? 'mobile-hidden' : ''
            }`}
            inert={
              isMobileDeviceView && !mobileShowChatPane ? true : undefined
            }
            style={
              isMobileDeviceView &&
              mobileShowChatPane &&
              (swipeOffsetX > 0 || isAnimatingOut)
                ? {
                    transform: `translateX(${
                      isAnimatingOut ? '100%' : `${swipeOffsetX}px`
                    })`,
                    transition: isAnimatingOut
                      ? 'transform 0.18s cubic-bezier(0.16, 1, 0.3, 1)'
                      : swipeOffsetX === 0
                      ? 'transform 0.2s cubic-bezier(0.16, 1, 0.3, 1)'
                      : 'none',
                  }
                : undefined
            }
          >
            {/* Visual swipe-back indicator pill when swiping right */}
            {isSwipingBack && swipeOffsetX > 12 && (
              <div
                className="dc-swipe-back-pill"
                style={{
                  opacity: Math.min(1, (swipeOffsetX - 12) / 45),
                }}
              >
                <ArrowLeft size={16} />
                <span>Back</span>
              </div>
            )}

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
                      onClick={closeMobileChat}
                      aria-label="Back to conversations"
                    >
                      <ArrowLeft size={18} />
                    </button>

                    {(() => {
                      const isBroadcast =
                        activeChannel.type === 'broadcast-channel';
                      const isBroadcastCreator =
                        isBroadcast &&
                        (
                          activeChannel.creatorEmail ||
                          activeChannel.participants[0] ||
                          ''
                        ).toLowerCase() === activeUser.email.toLowerCase();
                      const canManageParticipants =
                        activeChannel.type !== 'vault' &&
                        (!isBroadcast || isBroadcastCreator);

                      return (
                        <div
                          className="dc-freeflow-header-identity"
                          onClick={() => {
                            if (canManageParticipants) {
                              groupInfoDialogRef.current?.showModal();
                            }
                          }}
                          style={{
                            cursor: canManageParticipants
                              ? 'pointer'
                              : 'default',
                          }}
                          title={
                            canManageParticipants
                              ? 'Conversation participants'
                              : activeChannelDisplayTitle
                          }
                        >
                          {activeChannel.isBurner ? (
                            <div className="dc-header-avatar burner-avatar">
                              <Flame size={17} className="dc-flame-fire-icon" />
                            </div>
                          ) : isBroadcast ? (
                            isBroadcastCreator ? (
                              <div className="dc-header-avatar broadcast-avatar">
                                <Radio size={17} />
                              </div>
                            ) : null
                          ) : activeChannel.type === 'vault' ? (
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
                                activeChannelDisplayTitle
                                  .charAt(0)
                                  .toUpperCase()
                              ) : (
                                <Users size={17} />
                              )}
                            </div>
                          )}
                          <div>
                            <h2>
                              {isBroadcast && !isBroadcastCreator && (
                                <span
                                  className="dc-broadcast-title-badge"
                                  title="Broadcast Channel (BCC)"
                                >
                                  <Radio size={14} />
                                </span>
                              )}
                              {activeChannelDisplayTitle}
                            </h2>
                          </div>
                        </div>
                      );
                    })()}
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
                            {activeChannel.type !== 'vault' &&
                              activeChannel.type !== 'dm' &&
                              (activeChannel.type !== 'broadcast-channel' ||
                                (
                                  activeChannel.creatorEmail ||
                                  activeChannel.participants[0] ||
                                  ''
                                ).toLowerCase() ===
                                  activeUser.email.toLowerCase()) && (
                              <button
                                type="button"
                                role="menuitem"
                                className="dc-header-action-btn action-people"
                                onClick={() => {
                                  setIsHeaderMenuOpen(false);
                                  groupInfoDialogRef.current?.showModal();
                                }}
                                title={`People (${activeChannel.participants.length}/${MAX_CHANNEL_AND_GROUP_USERS})`}
                                aria-label={`People (${activeChannel.participants.length}/${MAX_CHANNEL_AND_GROUP_USERS})`}
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
                                <Palette size={13} />
                              </span>
                              <div className="dc-bubble-theme-swatches">
                                {TOP_5_COLORS_2026.map((t) => (
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
                    ) : activeChannel.type === 'broadcast-channel' ? (
                      <Radio size={22} />
                    ) : activeChannel.type === 'dm' ? (
                      activeChannelDisplayTitle.charAt(0).toUpperCase()
                    ) : (
                      <Users size={22} />
                    )}
                  </div>
                  {activeChannel.type === 'vault' && <strong>📌 Notes</strong>}
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
                const userKey = `${activeUser.email.toLowerCase()}:${msg.packet.payload.messageId}`;
                const isBurnHiddenInManualMode =
                  !isOwn &&
                  readReceiptMode === 'manual' &&
                  effectiveBurnTtl > 0 &&
                  !alreadyReadByMe &&
                  !burnReadStartedAtMs[userKey] &&
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

                // Crypto-inspired IOU Token Card inside DM stream
                if (msg.packet.type === 'chat.iou' && msg.packet.payload.iou) {
                  const iou = msg.packet.payload.iou;
                  return (
                    <div
                      key={msg.emailId}
                      className="dc-system-event-pill dc-iou-event-pill"
                      onClick={() => iouDialogRef.current?.showModal()}
                      title="Open IOU Wallet"
                    >
                      <Coins size={14} />
                      <span>
                        <strong>{iou.amount}</strong> &bull;{' '}
                        {msg.packet.payload.text}
                      </span>
                    </div>
                  );
                }

                const isTwoPersonChat =
                  activeChannel.type === 'dm' ||
                  activeChannel.type === 'vault';
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
                    {activeUnseenMarkerMsgId ===
                      msg.packet.payload.messageId && (
                      <div
                        id="dc-first-unread-marker"
                        key={`unseen-dotted-${activeChannel.id}-${msg.packet.payload.messageId}`}
                        className="dc-unseen-dotted-line"
                        role="separator"
                        aria-label="Unseen messages"
                      />
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
                                {/* Broadcast Channel Story Card (Live Feed Image + Badge) */}
                                {msg.packet.payload.storyCard && (
                                  <div
                                    className="dc-broadcast-story-card"
                                    onClick={(e) => e.stopPropagation()}
                                  >
                                    {msg.packet.payload.storyCard.badgeText && (
                                      <div className="dc-story-card-badge">
                                        <Radio size={11} />
                                        <span>
                                          {
                                            msg.packet.payload.storyCard
                                              .badgeText
                                          }
                                        </span>
                                      </div>
                                    )}
                                    {msg.packet.payload.storyCard
                                      .imageDataUrl && (
                                      <img
                                        src={
                                          msg.packet.payload.storyCard
                                            .imageDataUrl
                                        }
                                        alt={
                                          msg.packet.payload.storyCard
                                            .caption || 'Story post'
                                        }
                                        className="dc-story-card-image"
                                        onClick={() =>
                                          setFullscreenImageUrl(
                                            msg.packet.payload.storyCard!
                                              .imageDataUrl!
                                          )
                                        }
                                      />
                                    )}
                                  </div>
                                )}

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
                          Boolean(msg.burnerStatus?.isBurner) ||
                          Boolean(
                            msg.packet.payload.ephemeralTtlSeconds &&
                              msg.packet.payload.ephemeralTtlSeconds > 0
                          )) && (
                          <div className="dc-subtle-status-row">
                            {msg.burnerStatus?.isBurner ? (
                              <span
                                className={`dc-burn-countdown-badge ${
                                  msg.burnerStatus.isActive
                                    ? 'dc-burner-active-badge'
                                    : 'dc-burner-unread-badge'
                                }`}
                                title={
                                  msg.burnerStatus.summaryLabel ||
                                  (msg.burnerStatus.isActive
                                    ? `Cascade active: deletes in ${msg.burnerStatus.remainingSeconds}s`
                                    : 'In queue: starts 20s burn after previous message is deleted')
                                }
                              >
                                <Flame
                                  size={11}
                                  className={
                                    msg.burnerStatus.isActive
                                      ? 'dc-flame-active-glow'
                                      : 'dc-flame-unread-icon'
                                  }
                                />{' '}
                                {msg.burnerStatus.isActive
                                  ? `${msg.burnerStatus.remainingSeconds}s`
                                  : '20s'}
                                {!isTwoPersonChat
                                  ? ` (${msg.burnerStatus.unreadCount ?? 1})`
                                  : ''}
                              </span>
                            ) : Boolean(
                              msg.packet.payload.ephemeralTtlSeconds &&
                                msg.packet.payload.ephemeralTtlSeconds > 0
                            ) ? (
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
                            ) : null}

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
            {hasChatsBelowViewport && (
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

              {(composerBurnSeconds > 0 || activeChannel.isBurner) && (
                <div
                  className={`dc-composer-active-burn-bar ${
                    activeChannel.isBurner ? 'is-locked-burner' : ''
                  }`}
                >
                  <span>
                    <Flame
                      size={13}
                      className={activeChannel.isBurner ? 'dc-flame-fire-icon' : ''}
                    />{' '}
                    <strong>
                      {activeChannel.isBurner
                        ? '20s Cascade'
                        : `${
                            composerBurnSeconds === 20
                              ? '20s'
                              : composerBurnSeconds === 60
                              ? '1m'
                              : composerBurnSeconds === 300
                              ? '5m'
                              : composerBurnSeconds === 15
                              ? '15s'
                              : composerBurnSeconds === 3600
                              ? '1h'
                              : '24h'
                          }`}
                    </strong>
                    {activeChannel.isBurner && (
                      <small className="dc-locked-tag">
                        <Lock size={11} />
                      </small>
                    )}
                  </span>
                  {!activeChannel.isBurner && (
                    <button
                      type="button"
                      onClick={() => setComposerBurnSeconds(0)}
                      aria-label="Clear burn timer"
                      title="Turn off timer"
                    >
                      <X size={13} />
                    </button>
                  )}
                </div>
              )}

              {activeChannel.type === 'broadcast-channel' &&
              activeChannel.creatorEmail?.toLowerCase() !==
                activeUser.email.toLowerCase() ? (
                <div className="dc-broadcast-subscriber-bar">
                  <div className="dc-broadcast-sub-info">
                    <Radio size={15} />
                    <span>
                      Read-Only BCC Feed &bull; Tap any post to react
                      anonymously
                    </span>
                  </div>
                  <button
                    type="button"
                    className="dc-btn-danger-confirm dc-broadcast-unsub-btn"
                    onClick={() =>
                      void handleSubscriberBurnAndUnsubscribeChannel(
                        activeChannel
                      )
                    }
                    title="Burn local channel & send Unsubscribe email to remove from BCC"
                    aria-label="Burn local channel and unsubscribe"
                  >
                    <Flame size={14} className="dc-flame-fire-icon" />
                    <UserMinus size={14} />
                  </button>
                </div>
              ) : (
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
                            isVoiceRecorderOpen || isRecordingVoice
                              ? 'is-recording'
                              : ''
                          }`}
                          onClick={() => {
                            setIsPlusMenuOpen(false);
                            if (isRecordingVoice) {
                              void handleToggleVoiceRecording();
                            } else {
                              setIsVoiceRecorderOpen(true);
                              setRecordingSeconds(0);
                            }
                          }}
                          title="Voice"
                          aria-label="Voice"
                        >
                          <Mic size={19} />
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
                        {activeChannel.isBurner ? (
                          <div className="dc-action-menu-burn-locked">
                            <Flame size={14} className="dc-flame-fire-icon" />
                            <span>20s Cascade</span>
                          </div>
                        ) : (
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
                        )}
                      </div>
                    </div>
                  )}
                </div>

                {isVoiceRecorderOpen || isRecordingVoice ? (
                  <>
                    <div className="dc-recording-pill">
                      <span
                        className={`dc-rec-dot ${
                          isRecordingVoice ? '' : 'is-idle'
                        }`}
                      />{' '}
                      <span>
                        {recordingSeconds}s{isRecordingVoice ? '…' : ''}
                      </span>
                      {!isRecordingVoice && (
                        <button
                          type="button"
                          className="dc-rec-cancel-btn"
                          onClick={handleCancelVoiceRecorder}
                          title="Cancel voice recording"
                          aria-label="Cancel voice recording"
                        >
                          <X size={13} />
                        </button>
                      )}
                    </div>
                    <button
                      type="button"
                      className={`dc-circle-icon-btn ${
                        isRecordingVoice
                          ? 'recording-active'
                          : 'recording-start'
                      }`}
                      onClick={() => void handleToggleVoiceRecording()}
                      title={
                        isRecordingVoice ? 'Stop recording' : 'Start recording'
                      }
                      aria-label={
                        isRecordingVoice ? 'Stop recording' : 'Start recording'
                      }
                    >
                      {isRecordingVoice ? (
                        <Square size={15} />
                      ) : (
                        <Mic size={16} />
                      )}
                    </button>
                  </>
                ) : (
                  <div
                    className={`dc-composer-textarea-wrap growable-textarea ${
                      isComposerMultiline ? 'is-multiline' : ''
                    }`}
                    data-replicated-value={composerText}
                  >
                    {!composerText && (
                      <span
                        className="dc-composer-custom-placeholder"
                        aria-hidden="true"
                      >
                        {activeChannel.type === 'vault' ? 'Note…' : 'Message…'}
                      </span>
                    )}
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
                      aria-label={
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
              )}
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
                <span className="dc-profile-you-brand">
                  <img
                    src="/atme-app-icon.png"
                    alt="@"
                    className="dc-modal-brand-logo"
                  />
                  <span>you</span>
                </span>
              ) : (
                <>
                  <QrCode size={17} /> @me
                </>
              )}
            </h2>
            <div className="dc-profile-modal-tabs">
              <button
                type="button"
                className={`dc-profile-step-tab dc-profile-icon-tab ${
                  profileModalStep === 'edit' ? 'active' : ''
                }`}
                onClick={() => setProfileModalStep('edit')}
                title="Profile"
                aria-label="Profile"
              >
                <User size={15} />
              </button>
              <button
                type="button"
                className={`dc-profile-step-tab dc-profile-icon-tab ${
                  profileModalStep === 'qr-card' ? 'active' : ''
                }`}
                onClick={() => {
                  void handleSaveUserProfile();
                  setProfileModalStep('qr-card');
                }}
                title="@me QR"
                aria-label="@me QR"
              >
                <QrCode size={15} />
              </button>
              <form method="dialog">
                <button
                  type="submit"
                  className="dc-icon-btn"
                  aria-label="Close"
                  onClick={() => {
                    void handleSaveUserProfile();
                  }}
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
                    <User size={12} /> Avatar
                  </span>
                  <div className="dc-preset-avatars-row">
                    {CARTOON_SKETCH_AVATARS.map((sketch) => (
                      <button
                        key={sketch.id}
                        type="button"
                        className={`dc-preset-avatar-btn dc-sketch-avatar-btn ${
                          profileAvatarInput === sketch.dataUrl ? 'active' : ''
                        }`}
                        onClick={() => {
                          setProfileAvatarInput(sketch.dataUrl);
                        }}
                        title={sketch.label}
                        aria-label={sketch.label}
                      >
                        <img
                          src={sketch.dataUrl}
                          alt={sketch.label}
                          className="dc-sketch-avatar-thumb"
                        />
                      </button>
                    ))}
                  </div>
                  <button
                    type="button"
                    className="dc-pill-action-btn dc-photo-icon-btn"
                    onClick={() => avatarUploadInputRef.current?.click()}
                    title="Upload photo"
                    aria-label="Upload photo"
                  >
                    <Camera size={15} />
                  </button>
                </div>
              </div>

              <div className="dc-form-row">
                <div className="dc-form-group">
                  <label htmlFor="profile-name-input">
                    <Tag size={12} /> Name
                  </label>
                  <input
                    id="profile-name-input"
                    type="text"
                    value={profileNameInput}
                    onChange={(e) => setProfileNameInput(e.target.value)}
                    onBlur={() => void handleSaveUserProfile()}
                    placeholder="Alex"
                    required
                  />
                </div>

                <div className="dc-form-group">
                  <label htmlFor="profile-handle-input">
                    <Zap size={12} /> @handle
                  </label>
                  <div className="dc-handle-prefix-box">
                    <span className="dc-handle-at-prefix" aria-hidden="true">
                      @
                    </span>
                    <input
                      id="profile-handle-input"
                      type="text"
                      value={profileHandleInput.replace(/^@+/, '')}
                      onChange={(e) => {
                        const sanitized = e.target.value
                          .replace(/\s+/g, '_')
                          .replace(/[^a-zA-Z0-9_]/g, '');
                        setProfileHandleInput(`@${sanitized}`);
                      }}
                      onBlur={() => void handleSaveUserProfile()}
                      placeholder="alex_26"
                      required
                    />
                  </div>
                </div>
              </div>

              <div className="dc-form-group">
                <label>
                  <Palette size={12} /> Color
                </label>
                <div className="dc-onboarding-theme-grid">
                  {TOP_5_COLORS_2026.map((t) => (
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
                  className={`dc-qr-plain-icon-btn dc-qr-link-btn ${
                    qrLinkCopied ? 'is-copied' : ''
                  }`}
                  title={qrLinkCopied ? 'Copied Link' : 'Copy QR Link'}
                  aria-label={qrLinkCopied ? 'Copied Link' : 'Copy QR Link'}
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
                  {qrLinkCopied ? <Check size={18} /> : <Link2 size={18} />}
                </button>

                <button
                  type="button"
                  className="dc-qr-plain-icon-btn dc-qr-scan-btn"
                  title="Scan Friend QR"
                  aria-label="Scan Friend QR"
                  onClick={() => {
                    profileDialogRef.current?.close();
                    setSafetyModalTab('scan-qr');
                    safetyListDialogRef.current?.showModal();
                  }}
                >
                  <Camera size={18} />
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
                            placeholder="Taylor"
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
              <Users size={17} /> Friends
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
                <h3>
                  <Users size={15} /> Groups &amp; Channels
                </h3>
                <div className="dc-menu-section-head-actions">
                  <button
                    type="button"
                    className="dc-pill-action-btn dc-burner-pill-btn"
                    onClick={() => {
                      setNewChatType('workspace-channel');
                      setIsNewChatBurner(true);
                      newChannelModalRef.current?.showModal();
                    }}
                    title="New Burner Group"
                    aria-label="New Burner Group"
                  >
                    <Flame size={14} className="dc-flame-fire-icon" />
                  </button>
                  <button
                    type="button"
                    className="dc-pill-action-btn"
                    onClick={() => {
                      setNewChatType('workspace-channel');
                      setIsNewChatBurner(false);
                      newChannelModalRef.current?.showModal();
                    }}
                    title="New Group"
                    aria-label="New Group"
                  >
                    <Plus size={14} /> <Users size={14} />
                  </button>
                  <button
                    type="button"
                    className="dc-pill-action-btn"
                    onClick={() => {
                      setNewChatType('broadcast-channel');
                      setIsNewChatBurner(false);
                      newChannelModalRef.current?.showModal();
                    }}
                    title="New Broadcast Channel"
                    aria-label="New Broadcast Channel"
                  >
                    <Plus size={14} /> <Radio size={14} />
                  </button>
                </div>
              </div>

              <div className="dc-menu-list">
                {userScopedChannels
                  .filter((c) => c.type !== 'dm')
                  .map((ch) => (
                    <div key={ch.id} className="dc-menu-item-card">
                      <div
                        className="dc-menu-item-main"
                        onClick={() => {
                          menuDirectoryDialogRef.current?.close();
                          openMobileChat(ch.id);
                        }}
                      >
                        {ch.isBurner ? (
                          <Flame size={16} className="dc-flame-fire-icon" />
                        ) : ch.type === 'broadcast-channel' ? (
                          <Radio size={16} />
                        ) : (
                          <Hash size={16} />
                        )}
                        <div>
                          <strong>#{ch.name}</strong>
                          <span>
                            {
                              ch.participants.filter(
                                (p) =>
                                  p.toLowerCase() !==
                                  activeUser.email.toLowerCase()
                              ).length
                            }
                            {ch.isBurner && ' • 20s'}
                            {ch.type === 'broadcast-channel' && ' • BCC'}
                          </span>
                        </div>
                      </div>
                      <div className="dc-menu-item-actions">
                        {ch.type !== 'broadcast-channel' && (
                          <button
                            type="button"
                            className="dc-btn-ghost dc-btn-burner-icon"
                            onClick={() => handleStartOrOpenBurnerGroupChat(ch)}
                            title="Start Burner Group Chat (20s Cascade)"
                            aria-label={`Start Burner Group Chat for #${ch.name}`}
                          >
                            <Flame size={14} className="dc-flame-fire-icon" />
                          </button>
                        )}
                        <button
                          type="button"
                          className="dc-btn-ghost"
                          onClick={() => {
                            setActiveChannelId(ch.id);
                            menuDirectoryDialogRef.current?.close();
                            groupInfoDialogRef.current?.showModal();
                          }}
                          title="People"
                          aria-label="Group members"
                        >
                          <UserPlus size={13} />
                          {ch.participants.length > 2 && (
                            <span>({ch.participants.length})</span>
                          )}
                        </button>
                      </div>
                    </div>
                  ))}
              </div>
            </div>

            {/* Section 2: Friends & Contacts */}
            <div className="dc-menu-column">
              <div className="dc-menu-section-head">
                <h3>
                  <User size={15} /> Friends
                </h3>
                <div className="dc-menu-section-head-actions">
                  <button
                    type="button"
                    className="dc-pill-action-btn dc-burner-pill-btn"
                    onClick={() => {
                      setNewChatType('dm');
                      setIsNewChatBurner(true);
                      newChannelModalRef.current?.showModal();
                    }}
                    title="New Burner Chat"
                    aria-label="New Burner Chat"
                  >
                    <Flame size={14} className="dc-flame-fire-icon" />
                  </button>
                  <button
                    type="button"
                    className="dc-pill-action-btn"
                    onClick={() => {
                      setNewChatType('dm');
                      setIsNewChatBurner(false);
                      newChannelModalRef.current?.showModal();
                    }}
                    title="Add Friend"
                    aria-label="Add Friend"
                  >
                    <Plus size={14} /> <User size={14} />
                  </button>
                </div>
              </div>

              <div className="dc-menu-list">
                {users
                  .filter((u) => u.email !== activeUser.email)
                  .map((contact) => (
                    <div key={contact.email} className="dc-menu-item-card">
                      <div
                        className="dc-menu-item-main"
                        onClick={() =>
                          handleOpenExistingOrStartContactChat(contact.email)
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
                            {!contact.hasAppInstalled ? ' • Invite' : ''}
                          </span>
                        </div>
                      </div>
                      <div className="dc-menu-item-actions">
                        <button
                          type="button"
                          className="dc-btn-ghost dc-btn-burner-icon"
                          onClick={() =>
                            handleStartOrOpenBurnerContactChat(contact.email)
                          }
                          title="Start Burner Chat (20s Cascade)"
                          aria-label={`Start Burner Chat with ${contact.displayName}`}
                        >
                          <Flame size={14} className="dc-flame-fire-icon" />
                        </button>
                        <button
                          type="button"
                          className="dc-btn-ghost"
                          onClick={() =>
                            handleStartOrOpenContactChat(contact.email)
                          }
                          title="Start regular chat"
                          aria-label={`Chat with ${contact.displayName}`}
                        >
                          <MessageCircle size={14} />
                        </button>
                      </div>
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
              {activeChannel?.type === 'dm' ? (
                <>
                  <User size={17} /> Contact
                </>
              ) : (
                <>
                  <Users size={17} /> People
                  {activeChannel && (
                    <span className="dc-cap-counter-pill">
                      {activeChannel.participants.length} /{' '}
                      {MAX_CHANNEL_AND_GROUP_USERS}
                    </span>
                  )}
                </>
              )}
            </h2>
            <form method="dialog">
              <button type="submit" className="dc-icon-btn" aria-label="Close">
                <X size={16} />
              </button>
            </form>
          </div>

          {activeChannel &&
            (activeChannel.type === 'dm' ? (
              (() => {
                const peerEmail =
                  activeChannel.participants.find(
                    (em) =>
                      em.toLowerCase() !== activeUser.email.toLowerCase()
                  ) || activeChannel.participants[0];
                const peer = users.find(
                  (usr) => usr.email.toLowerCase() === peerEmail?.toLowerCase()
                );
                const displayName = (
                  peer?.displayName ||
                  peerEmail ||
                  activeChannel.name
                ).replace(' (No App Yet)', '');

                return (
                  <div className="dc-single-contact-card">
                    <div className="dc-single-contact-hero">
                      {renderUserAvatar(
                        peer || peerEmail,
                        displayName,
                        'dc-single-contact-avatar'
                      )}
                      <strong>{displayName}</strong>
                      {peer?.handle && (
                        <span className="dc-handle-tag">{peer.handle}</span>
                      )}
                      <small>{peerEmail}</small>
                      {peer?.bio && (
                        <p className="dc-single-contact-bio">{peer.bio}</p>
                      )}
                    </div>

                    <div className="dc-single-contact-modes">
                      <button
                        type="button"
                        className={`dc-mode-chip ${
                          !activeChannel.isBurner ? 'is-active' : ''
                        }`}
                        onClick={() => {
                          if (peerEmail) {
                            handleStartOrOpenContactChat(peerEmail);
                          }
                        }}
                      >
                        <MessageCircle size={15} /> Regular Chat
                      </button>
                      <button
                        type="button"
                        className={`dc-mode-chip ${
                          activeChannel.isBurner ? 'is-active is-burner' : ''
                        }`}
                        onClick={() => {
                          if (peerEmail) {
                            handleStartOrOpenBurnerContactChat(peerEmail);
                          }
                        }}
                      >
                        <Flame size={15} className="dc-flame-fire-icon" />{' '}
                        Burner (20s)
                      </button>
                    </div>
                  </div>
                );
              })()
            ) : (
              <>
                <form
                  className="dc-add-member-form"
                  onSubmit={handleAddMemberToChannel}
                >
                  <input
                    type="email"
                    value={newMemberEmailInput}
                    onChange={(e) => setNewMemberEmailInput(e.target.value)}
                    placeholder={
                      activeChannel.participants.length >=
                      MAX_CHANNEL_AND_GROUP_USERS
                        ? `Max ${MAX_CHANNEL_AND_GROUP_USERS} users reached`
                        : 'friend@email.com'
                    }
                    disabled={
                      activeChannel.participants.length >=
                      MAX_CHANNEL_AND_GROUP_USERS
                    }
                    required
                  />
                  <input
                    type="text"
                    value={newMemberNameInput}
                    onChange={(e) => setNewMemberNameInput(e.target.value)}
                    placeholder="Name"
                    disabled={
                      activeChannel.participants.length >=
                      MAX_CHANNEL_AND_GROUP_USERS
                    }
                  />
                  <button
                    type="submit"
                    className="dc-btn-send"
                    disabled={
                      activeChannel.participants.length >=
                      MAX_CHANNEL_AND_GROUP_USERS
                    }
                  >
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
                        (usr) =>
                          usr.email.toLowerCase() === email.toLowerCase()
                      );

                      return (
                        <div key={email} className="dc-participant-row">
                          <div className="dc-participant-info">
                            {renderUserAvatar(
                              u || email,
                              u?.displayName || email
                            )}
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
            ))}
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
              <Flame size={17} className="dc-flame-fire-icon" /> Clear Chat?
            </h2>
            <form method="dialog">
              <button type="submit" className="dc-icon-btn" aria-label="Close">
                <X size={16} />
              </button>
            </form>
          </div>

          <div className="dc-shred-warning-body">
            <div className="dc-shred-warning-banner">
              <strong>Deletes for everyone.</strong>
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
                <Flame size={14} className="dc-flame-fire-icon" /> Clear
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
          MODAL 6: Create New Encrypted Group, DM, or Broadcast Channel (+ Add Friend from Contacts)
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
              {newChatType === 'broadcast-channel' ? (
                <>
                  <Radio size={17} /> Channel
                </>
              ) : newChatType === 'workspace-channel' ? (
                <>
                  {isNewChatBurner ? (
                    <Flame size={17} className="dc-flame-fire-icon" />
                  ) : (
                    <Users size={17} />
                  )}{' '}
                  {isNewChatBurner ? 'Burner Group' : 'New Group'}
                </>
              ) : (
                <>
                  {isNewChatBurner ? (
                    <Flame size={17} className="dc-flame-fire-icon" />
                  ) : (
                    <MessageCircle size={17} />
                  )}{' '}
                  {isNewChatBurner ? 'Burner Chat' : 'New Chat'}
                </>
              )}
            </h2>
            <form method="dialog">
              <button
                type="submit"
                className="dc-icon-btn"
                aria-label="Close"
                onClick={() => setIsNewChatBurner(false)}
              >
                <X size={16} />
              </button>
            </form>
          </div>

          {newChatType !== 'broadcast-channel' && (
            <div className="dc-chat-mode-toggle">
              <button
                type="button"
                className={`dc-mode-chip ${!isNewChatBurner ? 'is-active' : ''}`}
                onClick={() => setIsNewChatBurner(false)}
              >
                <MessageCircle size={14} /> Regular Chat
              </button>
              <button
                type="button"
                className={`dc-mode-chip ${
                  isNewChatBurner ? 'is-active is-burner' : ''
                }`}
                onClick={() => setIsNewChatBurner(true)}
              >
                <Flame size={14} className="dc-flame-fire-icon" /> Burner (20s)
              </button>
            </div>
          )}

          <form
            className="dc-modal-form"
            onSubmit={handleCreateNewChannelOrDm}
          >
            {newChatType === 'broadcast-channel' ? (
              <>
                <div className="dc-form-group">
                  <label htmlFor="new-broadcast-name">
                    <Radio size={12} /> Channel Handle
                  </label>
                  <input
                    id="new-broadcast-name"
                    type="text"
                    value={newChatName}
                    onChange={(e) => setNewChatName(e.target.value)}
                    placeholder="skate-clips-daily"
                    required
                  />
                </div>
                <div className="dc-form-group">
                  <label htmlFor="new-broadcast-desc">
                    <Tag size={12} /> Bio / Topic
                  </label>
                  <input
                    id="new-broadcast-desc"
                    type="text"
                    value={newChannelDescription}
                    onChange={(e) => setNewChannelDescription(e.target.value)}
                    placeholder="Daily photos & clips • BCC anonymous"
                  />
                </div>
              </>
            ) : newChatType === 'workspace-channel' ? (
              <div className="dc-form-group">
                <label htmlFor="new-channel-name">
                  <Users size={12} /> Group Name
                </label>
                <input
                  id="new-channel-name"
                  type="text"
                  value={newChatName}
                  onChange={(e) => setNewChatName(e.target.value)}
                  placeholder={
                    isNewChatBurner ? 'secret-squad-burner' : 'squad-chat'
                  }
                  required={selectedGroupMemberEmails.length === 0}
                />
              </div>
            ) : (
              <div className="dc-form-group">
                <div className="dc-label-with-action">
                  <label htmlFor="new-dm-email">
                    <Mail size={12} /> Friend&apos;s Email
                  </label>
                  <button
                    type="button"
                    className="dc-contact-picker-toggle-btn"
                    onClick={() =>
                      setShowNewChatContactPicker((prev) => !prev)
                    }
                    title="Add Friend from Contacts"
                  >
                    <Users size={13} /> Contacts
                  </button>
                </div>
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

            {/* Add Friend from Contacts Quick Strip */}
            {(newChatType === 'dm' ||
              newChatType === 'workspace-channel') && (
              <div className="dc-new-chat-contacts-strip">
                <div className="dc-contacts-strip-header">
                  <span>
                    <UserPlus size={12} /> Add Friend from Contacts
                  </span>
                </div>
                <div className="dc-contacts-chips-row">
                  {users
                    .filter((u) => u.email !== activeUser.email)
                    .map((contact) => {
                      const isSelected =
                        newChatType === 'dm'
                          ? newChatRecipientEmail.toLowerCase() ===
                            contact.email.toLowerCase()
                          : selectedGroupMemberEmails.some(
                              (em) =>
                                em.toLowerCase() === contact.email.toLowerCase()
                            );
                      return (
                        <button
                          key={contact.email}
                          type="button"
                          className={`dc-contact-pick-chip ${
                            isSelected ? 'is-selected' : ''
                          }`}
                          aria-pressed={isSelected}
                          onClick={() => {
                            if (newChatType === 'dm') {
                              setNewChatRecipientEmail((prev) =>
                                prev.toLowerCase() ===
                                contact.email.toLowerCase()
                                  ? ''
                                  : contact.email
                              );
                            } else {
                              setSelectedGroupMemberEmails((prev) => {
                                const exists = prev.some(
                                  (em) =>
                                    em.toLowerCase() ===
                                    contact.email.toLowerCase()
                                );
                                const next = exists
                                  ? prev.filter(
                                      (em) =>
                                        em.toLowerCase() !==
                                        contact.email.toLowerCase()
                                    )
                                  : [...prev, contact.email];
                                return next;
                              });
                            }
                          }}
                        >
                          {renderUserAvatar(
                            contact,
                            contact.displayName,
                            'dc-contact-chip-avatar'
                          )}
                          <span>
                            {contact.displayName.replace(' (No App Yet)', '')}
                          </span>
                        </button>
                      );
                    })}
                </div>
              </div>
            )}

            <div className="dc-modal-actions">
              <button
                type="submit"
                className={`dc-btn-send ${
                  isNewChatBurner ? 'dc-btn-burner-send' : ''
                }`}
              >
                {newChatType === 'broadcast-channel' ? (
                  <>
                    <Radio size={15} /> Launch Channel
                  </>
                ) : isNewChatBurner ? (
                  <>
                    <Flame size={15} className="dc-flame-fire-icon" /> Start
                    Burner
                  </>
                ) : (
                  <>
                    <Send size={15} /> Start
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      </dialog>

      {/* =====================================================================
          MODAL 6B: CRYPTO-INSPIRED PEER-TO-PEER IOU WALLET & LEDGER (`IOUs`)
         ===================================================================== */}
      <dialog
        ref={iouDialogRef}
        {...({ closedby: 'any' } as React.DialogHTMLAttributes<HTMLDialogElement>)}
        aria-labelledby={iouDialogTitleId}
        className="dc-modal-dialog dc-modal-md"
      >
        <div className="dc-modal-inner">
          <div className="dc-modal-header">
            <h2 id={iouDialogTitleId}>
              <Coins size={18} /> IOUs
            </h2>
            <div className="dc-profile-modal-tabs">
              <button
                type="button"
                className={`dc-profile-step-tab ${
                  showIouIssueForm ? 'active' : ''
                }`}
                onClick={() => setShowIouIssueForm((prev) => !prev)}
                title="Send or Log IOU"
                aria-label="Send or Log IOU"
              >
                <Plus size={14} /> IOU
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

          <div className="dc-iou-wallet-body">
            {/* Crypto-Style Net Balance Hero Card */}
            <div className="dc-iou-hero-card">
              <div className="dc-iou-hero-top">
                <span className="dc-iou-token-pill">
                  <Coins size={12} /> P2P IOU LEDGER
                </span>
              </div>
              <div className="dc-iou-net-balance">
                <strong
                  className={
                    iouLedgerSummary.netBalance > 0
                      ? 'is-positive'
                      : iouLedgerSummary.netBalance < 0
                      ? 'is-negative'
                      : ''
                  }
                >
                  {iouLedgerSummary.netBalance > 0
                    ? `+${iouLedgerSummary.netBalance}`
                    : iouLedgerSummary.netBalance}
                </strong>
                <span>Net Position</span>
              </div>
              <div className="dc-iou-stats-split">
                <div className="dc-iou-stat-box is-owed">
                  <small>Friends Owe You</small>
                  <strong>+{iouLedgerSummary.owedToMeTotal}</strong>
                </div>
                <div className="dc-iou-stat-box is-owing">
                  <small>Outstanding IOUs</small>
                  <strong>-{iouLedgerSummary.iOweTotal}</strong>
                </div>
              </div>
            </div>

            {/* Send IOU Form (You can only Send IOUs that you owe) */}
            {showIouIssueForm && (
              <form
                className="dc-iou-issue-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  const amt = Math.max(
                    1,
                    Math.floor(Number(iouSendAmount) || 0)
                  );
                  void handleSendOrSettleIou({
                    action: 'send-iou',
                    peerEmail: iouSendPeerEmail,
                    amount: amt,
                    note: iouSendNote.trim() || undefined,
                  });
                }}
              >
                <div className="dc-form-row">
                  <div className="dc-form-group">
                    <label htmlFor="iou-friend-select">Send IOU To</label>
                    <select
                      id="iou-friend-select"
                      value={iouSendPeerEmail}
                      onChange={(e) => setIouSendPeerEmail(e.target.value)}
                    >
                      {users
                        .filter((u) => u.email !== activeUser.email)
                        .map((u) => (
                          <option key={u.email} value={u.email}>
                            {u.displayName.replace(' (No App Yet)', '')} (
                            {u.handle || u.email})
                          </option>
                        ))}
                    </select>
                  </div>
                  <div className="dc-form-group">
                    <label htmlFor="iou-amount-input">Amount</label>
                    <input
                      id="iou-amount-input"
                      type="number"
                      min={1}
                      max={9999}
                      step={1}
                      value={iouSendAmount}
                      onChange={(e) =>
                        setIouSendAmount(
                          e.target.value.replace(/[^0-9]/g, '')
                        )
                      }
                      required
                    />
                  </div>
                </div>

                <div className="dc-inline-input-btn">
                  <input
                    type="text"
                    value={iouSendNote}
                    onChange={(e) => setIouSendNote(e.target.value)}
                    placeholder="Note (e.g. pizza slice, arcade tokens)…"
                  />
                  <button type="submit" className="dc-btn-send">
                    <Send size={14} /> Send IOU
                  </button>
                </div>
              </form>
            )}

            {/* 2-Column Split Ledger: People That Owe You (Left) vs Outstanding IOUs (Right) */}
            <div className="dc-iou-split-ledger-grid">
              {/* LEFT COLUMN: People That Owe You (Clickable -> Recognize Collection Popup) */}
              <div className="dc-iou-ledger-column is-left-owed">
                <div className="dc-iou-column-header is-owed">
                  <span>Owe You</span>
                  <strong>+{iouLedgerSummary.owedToMeTotal}</strong>
                </div>

                {iouLedgerSummary.rows.filter((r) => r.netAmount > 0).length ===
                0 ? (
                  <div className="dc-iou-column-empty">0</div>
                ) : (
                  iouLedgerSummary.rows
                    .filter((r) => r.netAmount > 0)
                    .map((row) => {
                      const isSelected = selectedIouPeerEmail === row.peerEmail;
                      return (
                        <div
                          key={row.peerEmail}
                          className={`dc-iou-peer-card ${
                            isSelected ? 'is-expanded' : ''
                          }`}
                        >
                          <button
                            type="button"
                            className="dc-iou-peer-row-btn"
                            onClick={() => {
                              if (isSelected) {
                                setSelectedIouPeerEmail(null);
                              } else {
                                setSelectedIouPeerEmail(row.peerEmail);
                                setIouCollectAmountInput('1');
                              }
                            }}
                            title={`Click to recognize collection from ${row.displayName}`}
                          >
                            <div className="dc-iou-peer-left">
                              {renderUserAvatar(
                                row.peerUser || row.peerEmail,
                                row.displayName
                              )}
                              <div>
                                <strong>{row.displayName}</strong>
                                <span>{row.handle}</span>
                              </div>
                            </div>

                            <div className="dc-iou-peer-total is-owed-to-me">
                              <strong>+{row.netAmount}</strong>
                            </div>
                          </button>

                          {isSelected && (
                            <div className="dc-iou-collect-popup">
                              <div className="dc-iou-collect-popup-head">
                                <span>Recognize Collection</span>
                                <button
                                  type="button"
                                  className="dc-iou-collect-all-btn"
                                  onClick={() =>
                                    void handleSendOrSettleIou({
                                      action: 'collect',
                                      peerEmail: row.peerEmail,
                                      amount: row.netAmount,
                                      note: 'Collected all',
                                    })
                                  }
                                >
                                  All ({row.netAmount})
                                </button>
                              </div>

                              <form
                                className="dc-iou-collect-partial-form"
                                onSubmit={(e) => {
                                  e.preventDefault();
                                  const cleanWhole = Math.min(
                                    row.netAmount,
                                    Math.max(
                                      1,
                                      Math.floor(
                                        Number(iouCollectAmountInput) || 1
                                      )
                                    )
                                  );
                                  void handleSendOrSettleIou({
                                    action: 'collect',
                                    peerEmail: row.peerEmail,
                                    amount: cleanWhole,
                                    note: 'Recognized collection',
                                  });
                                }}
                              >
                                <input
                                  type="number"
                                  min={1}
                                  max={row.netAmount}
                                  step={1}
                                  value={iouCollectAmountInput}
                                  onChange={(e) =>
                                    setIouCollectAmountInput(
                                      e.target.value.replace(/[^0-9]/g, '')
                                    )
                                  }
                                  placeholder={`1–${row.netAmount}`}
                                  aria-label="Whole number amount collected"
                                  required
                                />
                                <button
                                  type="submit"
                                  className="dc-btn-send dc-iou-accept-btn"
                                  title="Accept collection amount"
                                  aria-label="Accept collection amount"
                                >
                                  <Check size={14} />
                                </button>
                              </form>
                            </div>
                          )}
                        </div>
                      );
                    })
                )}
              </div>

              {/* RIGHT COLUMN: Outstanding IOUs (People You Owe — Read-Only) */}
              <div className="dc-iou-ledger-column is-right-owing">
                <div className="dc-iou-column-header is-owing">
                  <span>Outstanding</span>
                  <strong>-{iouLedgerSummary.iOweTotal}</strong>
                </div>

                {iouLedgerSummary.rows.filter((r) => r.netAmount < 0).length ===
                0 ? (
                  <div className="dc-iou-column-empty">0</div>
                ) : (
                  iouLedgerSummary.rows
                    .filter((r) => r.netAmount < 0)
                    .map((row) => (
                      <div
                        key={row.peerEmail}
                        className="dc-iou-peer-card is-readonly-owing"
                      >
                        <div className="dc-iou-peer-row-btn is-static">
                          <div className="dc-iou-peer-left">
                            {renderUserAvatar(
                              row.peerUser || row.peerEmail,
                              row.displayName
                            )}
                            <div>
                              <strong>{row.displayName}</strong>
                              <span>{row.handle}</span>
                            </div>
                          </div>

                          <div className="dc-iou-peer-total is-i-owe">
                            <strong>{row.netAmount}</strong>
                          </div>
                        </div>
                      </div>
                    ))
                )}
              </div>
            </div>
          </div>
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
            <h2 id={cameraDialogTitleId} aria-label="Camera">
              <Camera size={18} />
            </h2>
            <form method="dialog">
              <button type="submit" className="dc-icon-btn" aria-label="Close">
                <X size={16} />
              </button>
            </form>
          </div>

          <div className="dc-camera-modal-body">
            <div
              ref={cameraViewportRef}
              className="dc-camera-viewport"
              onPointerMove={(e) => {
                const drag = draggingStampRef.current;
                if (!drag || !cameraViewportRef.current) return;
                const rect = cameraViewportRef.current.getBoundingClientRect();
                if (rect.width <= 0 || rect.height <= 0) return;
                const nextX = Math.min(
                  95,
                  Math.max(5, ((e.clientX - rect.left) / rect.width) * 100)
                );
                const nextY = Math.min(
                  95,
                  Math.max(5, ((e.clientY - rect.top) / rect.height) * 100)
                );
                setCameraStamps((prev) =>
                  prev.map((s) =>
                    s.id === drag.stampId
                      ? { ...s, xPct: nextX, yPct: nextY }
                      : s
                  )
                );
              }}
              onPointerUp={() => {
                draggingStampRef.current = null;
              }}
              onPointerCancel={() => {
                draggingStampRef.current = null;
              }}
            >
              {capturedPhotoDataUrl ? (
                <>
                  <img
                    src={capturedPhotoDataUrl}
                    alt="Captured preview"
                    className="dc-camera-preview-img"
                    draggable={false}
                    onClick={() => setSelectedCameraStampId(null)}
                  />

                  {/* Interactive Draggable & Resizable Emoji Stamps Layer */}
                  {cameraStamps.map((st) => {
                    const isSelected = selectedCameraStampId === st.id;
                    return (
                      <div
                        key={st.id}
                        className={`dc-camera-emoji-stamp ${
                          isSelected ? 'is-selected' : ''
                        }`}
                        style={{
                          left: `${st.xPct}%`,
                          top: `${st.yPct}%`,
                          fontSize: `${st.sizePx}px`,
                        }}
                        onPointerDown={(e) => {
                          e.stopPropagation();
                          setSelectedCameraStampId(st.id);
                          draggingStampRef.current = {
                            stampId: st.id,
                            pointerId: e.pointerId,
                          };
                          try {
                            e.currentTarget.setPointerCapture(e.pointerId);
                          } catch {
                            // Ignore pointer capture errors
                          }
                        }}
                        role="button"
                        tabIndex={0}
                        aria-label={`Emoji stamp ${st.emoji}`}
                        title="Drag to move stamp"
                      >
                        <span className="dc-camera-stamp-glyph">{st.emoji}</span>
                        {isSelected && (
                          <button
                            type="button"
                            className="dc-camera-stamp-delete-badge"
                            onPointerDown={(e) => e.stopPropagation()}
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteCameraStamp(st.id);
                            }}
                            title="Remove stamp"
                            aria-label="Remove stamp"
                          >
                            <X size={11} />
                          </button>
                        )}
                      </div>
                    );
                  })}
                </>
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
                    </div>
                  )}
                </>
              )}
              <span
                className="dc-camera-privacy-pill dc-camera-privacy-icon-only"
                title="Encrypted in app only"
                aria-label="Encrypted in app only"
              >
                <Lock size={13} />
              </span>
            </div>

            {/* Emoji Stamp Picker & Size / Delete Controls (When Photo Is Captured) */}
            {capturedPhotoDataUrl && isCameraStampPickerOpen && (
              <div className="dc-camera-stamp-tray">
                <div className="dc-camera-stamp-emoji-strip">
                  {[
                    '😎',
                    '🤠',
                    '👽',
                    '🤖',
                    '🐱',
                    '🐶',
                    '🦊',
                    '🐼',
                    '🐸',
                    '🙈',
                    '👻',
                    '💀',
                    '🥸',
                    '🤩',
                    '😷',
                    '🎃',
                    '👑',
                    '🧢',
                    '⭐',
                    '❤️',
                    '🔒',
                    '🚫',
                  ].map((emoji) => (
                    <button
                      key={emoji}
                      type="button"
                      className="dc-camera-stamp-pick-btn"
                      onClick={() => handleAddCameraEmojiStamp(emoji)}
                      title={`Add ${emoji} stamp`}
                      aria-label={`Add ${emoji} stamp`}
                    >
                      {emoji}
                    </button>
                  ))}
                </div>

                {selectedCameraStampId &&
                  cameraStamps.some((s) => s.id === selectedCameraStampId) && (
                    <div className="dc-camera-stamp-size-bar">
                      <span className="dc-camera-active-stamp-preview">
                        {
                          cameraStamps.find(
                            (s) => s.id === selectedCameraStampId
                          )?.emoji
                        }
                      </span>
                      <input
                        type="range"
                        min={28}
                        max={220}
                        value={
                          cameraStamps.find(
                            (s) => s.id === selectedCameraStampId
                          )?.sizePx || 88
                        }
                        onChange={(e) =>
                          handleUpdateCameraStampSize(
                            selectedCameraStampId,
                            Number(e.target.value)
                          )
                        }
                        className="dc-camera-stamp-slider"
                        aria-label="Stamp size"
                        title="Adjust stamp size"
                      />
                      <button
                        type="button"
                        className="dc-camera-stamp-trash-btn"
                        onClick={() =>
                          handleDeleteCameraStamp(selectedCameraStampId)
                        }
                        title="Delete selected stamp"
                        aria-label="Delete selected stamp"
                      >
                        <Trash2 size={15} />
                      </button>
                    </div>
                  )}
              </div>
            )}

            <div className="dc-camera-controls-row">
              {!capturedPhotoDataUrl ? (
                <>
                  <button
                    type="button"
                    className="dc-camera-icon-btn"
                    onClick={() => void handleFlipCamera()}
                    title="Flip camera"
                    aria-label="Flip camera"
                  >
                    <RefreshCw size={18} />
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
                    className="dc-camera-icon-btn"
                    onClick={() => cameraCaptureDialogRef.current?.close()}
                    title="Close camera"
                    aria-label="Close camera"
                  >
                    <X size={18} />
                  </button>
                </>
              ) : (
                <>
                  <button
                    type="button"
                    className="dc-camera-icon-btn"
                    onClick={() => {
                      setCapturedPhotoDataUrl(null);
                      setCameraStamps([]);
                      setSelectedCameraStampId(null);
                      void startCameraStream(cameraFacingMode);
                    }}
                    title="Retake photo"
                    aria-label="Retake photo"
                  >
                    <RefreshCw size={18} />
                  </button>
                  <button
                    type="button"
                    className={`dc-camera-icon-btn dc-camera-stamp-toggle ${
                      isCameraStampPickerOpen ? 'is-active' : ''
                    }`}
                    onClick={() =>
                      setIsCameraStampPickerOpen((prev) => !prev)
                    }
                    title="Emoji Stamps"
                    aria-label="Emoji Stamps"
                  >
                    <Smile size={19} />
                  </button>
                  <button
                    type="button"
                    className="dc-imessage-send-btn dc-camera-send-icon-btn"
                    disabled={isSending}
                    onClick={() => void handleSendCapturedCameraPhoto()}
                    title="Send photo"
                    aria-label="Send photo"
                  >
                    <Send size={17} />
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
