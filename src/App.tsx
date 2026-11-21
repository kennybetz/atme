import React, { useEffect, useId, useMemo, useRef, useState, useCallback } from 'react';
import {
  ArrowDown,
  ArrowLeft,
  Bookmark,
  Camera,
  Check,
  CheckCircle2,
  ChevronRight,
  CornerDownLeft,
  Eye,
  EyeOff,
  FileText,
  Globe,
  Hash,
  KeyRound,
  Link2,
  Mail,
  Menu,
  MessageCircle,
  MessageSquare,
  Mic,
  Moon,
  Palette,
  Paperclip,
  Plus,
  QrCode,
  RefreshCw,
  Search,
  Send,
  ShieldCheck,
  Smile,
  Sparkles,
  Square,
  Sun,
  Tag,
  Terminal,
  User,
  UserCheck,
  UserMinus,
  UserPlus,
  Users,
  X,
  Zap,
} from 'lucide-react';
import {
  ATME_PROTOCOL_VERSION,
  MAX_CHANNEL_AND_GROUP_USERS,
  DcpAttachment,
  DcpChannelMeta,
  DcpLinkPreview,
  DcpPacket,
  DcpPacketType,
  DcpUserProfileCard,
  FilterInspectionResult,
  RawTransportEmail,
  UserIdentity,
} from './protocol/types';
import { generateDeviceKeyPair } from './crypto/openpgpService';
import { extractClientSideLinkPreview } from './utils/linkPreview';
import { buildDcpMimeEmail } from './protocol/mimeBuilder';
import { inspectAndDecryptEmail } from './protocol/mimeParser';
import Avatar from 'boring-avatars';
import {
  INITIAL_CHANNELS,
  INITIAL_USERS,
  createEncryptedSeedEmailsForUsers,
  createInitialSeedInspections,
  createSampleRegularEmails,
} from './store/seedEmails';
import {
  clearIdbDatabase,
  loadTransportEmailsFromIdb,
  loadUserIdentitiesFromIdb,
  saveTransportEmailsToIdb,
  saveUserIdentitiesToIdb,
} from './store/localDb';
import {
  GmailDirectTransport,
  OutlookDirectTransport,
  reconcileLocalEmailsWithRemoteMailbox,
} from './transport/emailConnectors';
import {
  DomainAutoDiscoveryResult,
  consumeRedirectOAuthHashToken,
  discoverCustomDomainEmailConfig,
  fetchGoogleUserProfile,
  getSavedGoogleClientId,
  launchRealOAuthPopup,
  loadGoogleOAuthSession,
  sanitizeGoogleClientId,
  saveGoogleClientId,
  saveGoogleOAuthSession,
  validateGoogleClientId,
} from './transport/oauthPortal';

interface FreeflowChatMessage {
  emailId: string;
  packet: DcpPacket;
  decryptionTimeMs?: number;
  reactions: Array<{ emoji: string; senderName: string; senderEmail: string }>;
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
  const [users, setUsers] = useState<UserIdentity[]>(INITIAL_USERS);
  const [channels, setChannels] = useState<DcpChannelMeta[]>(() => {
    try {
      const raw = localStorage.getItem('atme_simple_channels_v2');
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
      localStorage.setItem('atme_simple_channels_v2', JSON.stringify(channels));
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
  const [gmailAccessToken, setGmailAccessToken] = useState<string>(
    () => loadGoogleOAuthSession()?.accessToken || ''
  );
  const [outlookAccessToken, setOutlookAccessToken] = useState<string>('');
  const [googleClientId, setGoogleClientId] = useState<string>(() =>
    getSavedGoogleClientId()
  );
  const [microsoftClientId, setMicrosoftClientId] = useState<string>(
    (import.meta.env.VITE_MICROSOFT_CLIENT_ID as string) || ''
  );
  const [showAdvancedOAuthConfig, setShowAdvancedOAuthConfig] =
    useState<boolean>(false);
  const [isSyncingGmailInbox, setIsSyncingGmailInbox] =
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

  const [transportEmails, setTransportEmails] = useState<RawTransportEmail[]>(
    []
  );
  const transportEmailsRef = useRef<RawTransportEmail[]>(transportEmails);
  transportEmailsRef.current = transportEmails;
  const [inspections, setInspections] = useState<FilterInspectionResult[]>(() =>
    createInitialSeedInspections()
  );
  const [isInitializingKeys, setIsInitializingKeys] = useState<boolean>(true);
  const [isSending, setIsSending] = useState<boolean>(false);

  // Native <dialog closedby="any"> refs
  const menuDirectoryDialogRef = useRef<HTMLDialogElement | null>(null);
  const groupInfoDialogRef = useRef<HTMLDialogElement | null>(null);
  const profileDialogRef = useRef<HTMLDialogElement | null>(null);
  const connectWizardDialogRef = useRef<HTMLDialogElement | null>(null);
  const newChannelModalRef = useRef<HTMLDialogElement | null>(null);
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

  // UI Menu & Display Preferences
  const [isPlusMenuOpen, setIsPlusMenuOpen] = useState<boolean>(false);
  const [isComposerEmojiOpen, setIsComposerEmojiOpen] =
    useState<boolean>(false);
  const [isHeaderMenuOpen, setIsHeaderMenuOpen] = useState<boolean>(false);
  const [isAvatarMenuOpen, setIsAvatarMenuOpen] = useState<boolean>(false);
  const [profileModalStep, setProfileModalStep] = useState<'edit' | 'qr-card'>(
    'edit'
  );
  const [qrLinkCopied, setQrLinkCopied] = useState<boolean>(false);
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
  const [isComposerMultiline, setIsComposerMultiline] = useState<boolean>(false);
  const [isAddMenuOpen, setIsAddMenuOpen] = useState<boolean>(false);
  const addMenuContainerRef = useRef<HTMLDivElement | null>(null);
  const actionMenuContainerRef = useRef<HTMLDivElement | null>(null);
  const composerEmojiContainerRef = useRef<HTMLDivElement | null>(null);
  const headerMenuContainerRef = useRef<HTMLDivElement | null>(null);
  const avatarMenuContainerRef = useRef<HTMLDivElement | null>(null);
  const composerTextareaRef = useRef<HTMLTextAreaElement | null>(null);
  const freeflowFeedRef = useRef<HTMLDivElement | null>(null);
  const prevChannelIdRef = useRef<string | null>(null);
  const prevStreamLengthRef = useRef<number>(0);
  const userJustSentMessageRef = useRef<boolean>(false);
  const prevMobileShowChatPaneRef = useRef<boolean>(mobileShowChatPane);
  const [isAtBottom, setIsAtBottom] = useState<boolean>(true);
  const isScrolledToBottomRef = useRef<boolean>(true);
  const isProgrammaticScrollingRef = useRef<boolean>(false);
  const programmaticScrollTimerRef = useRef<number | null>(null);
  const [hasChatsBelowViewport, setHasChatsBelowViewport] =
    useState<boolean>(false);
  const [readMessageIds, setReadMessageIds] = useState<Set<string>>(
    () => new Set()
  );

  // Personal Notes (@me) Category Tag
  const [vaultCategoryInput, setVaultCategoryInput] = useState<
    'note' | 'credential' | 'file' | 'snippet'
  >('note');

  const menuDialogTitleId = useId();
  const groupInfoTitleId = useId();
  const profileDialogTitleId = useId();
  const connectWizardTitleId = useId();
  const newChannelDialogTitleId = useId();
  const safetyDialogTitleId = useId();
  const cameraDialogTitleId = useId();

  // New Group or DM Creation Form State
  const [newChatName, setNewChatName] = useState<string>('');
  const [newChatRecipientEmail, setNewChatRecipientEmail] =
    useState<string>('');
  const [selectedGroupMemberEmails, setSelectedGroupMemberEmails] = useState<
    string[]
  >([]);
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
    } else if (viewParam === 'onboarding' || viewParam === 'profile-edit') {
      setProfileModalStep('edit');
      profileDialogRef.current?.showModal();
    } else if (viewParam === 'qr-pass') {
      setProfileModalStep('qr-card');
      profileDialogRef.current?.showModal();
    } else if (viewParam === 'avatar-menu') {
      setIsAvatarMenuOpen(true);
    } else if (viewParam === 'header-menu') {
      setIsHeaderMenuOpen(true);
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
    } else if (viewParam === 'account' || viewParam === 'google-oauth') {
      setConnectModalMode('easy');
      if (viewParam === 'google-oauth') {
        setSimulatedOAuthProvider('google');
      }
      connectWizardDialogRef.current?.showModal();
    } else if (viewParam === 'new-chat') {
      setNewChatType('dm');
      setSelectedGroupMemberEmails([]);
      newChannelModalRef.current?.showModal();
    } else if (viewParam === 'new-group') {
      setNewChatType('workspace-channel');
      setSelectedGroupMemberEmails(['elena.vogt@proton.me']);
      newChannelModalRef.current?.showModal();
    } else if (viewParam === 'voice-ready') {
      setIsVoiceRecorderOpen(true);
    } else if (viewParam === 'single-info') {
      setActiveChannelId('dm_alex_elena');
      groupInfoDialogRef.current?.showModal();
    } else if (viewParam === 'add-menu') {
      setIsAddMenuOpen(true);
    } else if (viewParam === 'group') {
      groupInfoDialogRef.current?.showModal();
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

  // Recover OAuth redirect hash token (#access_token=...) if browser redirected main window
  useEffect(() => {
    const redirectResult = consumeRedirectOAuthHashToken();
    if (!redirectResult) return;

    if (redirectResult.error) {
      setConnectModalMode('easy');
      setConnectorStatusMsg(`Google Sign-In Note: ${redirectResult.error}`);
      connectWizardDialogRef.current?.showModal();
      return;
    }

    if (redirectResult.accessToken) {
      setGmailAccessToken(redirectResult.accessToken);
      void (async () => {
        try {
          const profile = await fetchGoogleUserProfile(
            redirectResult.accessToken
          );
          await handleCompletePortalSignIn({
            email: profile.email,
            displayName: profile.name,
            provider: 'gmail',
            liveAccessToken: redirectResult.accessToken,
            expiresInSeconds: redirectResult.expiresInSeconds,
          });
        } catch (err) {
          setConnectModalMode('easy');
          setConnectorStatusMsg(
            `Google OAuth connected, could not auto-load profile: ${
              err instanceof Error ? err.message : String(err)
            }`
          );
          connectWizardDialogRef.current?.showModal();
        }
      })();
    }
  }, []);

  // Mandatory fallback for <dialog closedby="any"> on browsers without native closedBy support
  useEffect(() => {
    const dialogs = [
      menuDirectoryDialogRef.current,
      groupInfoDialogRef.current,
      profileDialogRef.current,
      connectWizardDialogRef.current,
      newChannelModalRef.current,
      safetyListDialogRef.current,
      cameraCaptureDialogRef.current,
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

  // Boot clean starter data immediately in cleartext JSON mode; hydrate OpenPGP keypairs asynchronously for ATME/1.0 interop
  useEffect(() => {
    let mounted = true;
    async function bootEngine() {
      setIsInitializingKeys(true);

      const seedVersion =
        typeof localStorage !== 'undefined'
          ? localStorage.getItem('atme_simple_seed_v3')
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
        const savedSession = loadGoogleOAuthSession();
        let hydratedUsersList = cachedUsers;
        if (savedSession?.email && savedSession?.accessToken) {
          const normSessionEmail = savedSession.email.trim().toLowerCase();
          if (
            !hydratedUsersList.some(
              (u) => u.email.toLowerCase() === normSessionEmail
            )
          ) {
            const guessName = normSessionEmail.split('@')[0];
            hydratedUsersList = [
              {
                email: normSessionEmail,
                displayName:
                  guessName.charAt(0).toUpperCase() + guessName.slice(1),
                handle: `@${guessName.replace(/[^a-z0-9_]/gi, '_')}`,
                provider: 'gmail',
                hasAppInstalled: true,
              },
              ...hydratedUsersList,
            ];
            await saveUserIdentitiesToIdb(hydratedUsersList);
          }
          setActiveUserEmail(normSessionEmail);
          setGmailAccessToken(savedSession.accessToken);
        }

        setUsers(hydratedUsersList);
        setTransportEmails(cachedEmails);
        transportEmailsRef.current = cachedEmails;
        setIsInitializingKeys(false);

        if (savedSession?.email && savedSession?.accessToken) {
          void handleSyncLiveGmailPackets(
            savedSession.accessToken,
            savedSession.email,
            cachedEmails
          );
        }
        return;
      }

      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('atme_simple_seed_v3', 'true');
        localStorage.setItem(
          'atme_whitelisted_emails',
          JSON.stringify(INITIAL_USERS.map((u) => u.email.toLowerCase()))
        );
      }
      setWhitelistedEmails(INITIAL_USERS.map((u) => u.email.toLowerCase()));

      await clearIdbDatabase();

      const seedDcpEmails = await createEncryptedSeedEmailsForUsers(
        INITIAL_USERS
      );

      const regularEmails = createSampleRegularEmails();
      const combined = [...seedDcpEmails, ...regularEmails].sort(
        (a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()
      );

      await saveUserIdentitiesToIdb(INITIAL_USERS);
      await saveTransportEmailsToIdb(combined);

      if (!mounted) return;
      setUsers(INITIAL_USERS);
      setTransportEmails(combined);
      transportEmailsRef.current = combined;
      setIsInitializingKeys(false);

      const savedSession = loadGoogleOAuthSession();
      if (savedSession?.email && savedSession?.accessToken) {
        setActiveUserEmail(savedSession.email);
        setGmailAccessToken(savedSession.accessToken);
        void handleSyncLiveGmailPackets(
          savedSession.accessToken,
          savedSession.email,
          combined
        );
      }

      // Lazily provision Curve25519 keys in background so incoming OpenPGP interop packets decrypt automatically
      const hydratedUsers: UserIdentity[] = [];
      for (const u of INITIAL_USERS) {
        if (!mounted) return;
        if (u.hasAppInstalled) {
          const kp = await generateDeviceKeyPair(u.displayName, u.email);
          hydratedUsers.push({ ...u, pgpKeyPair: kp });
        } else {
          hydratedUsers.push(u);
        }
      }
      if (!mounted) return;
      setUsers(hydratedUsers);
      await saveUserIdentitiesToIdb(hydratedUsers);
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
        const isSeedEmail = email.id.startsWith('seed_');
        const isSender = email.from.toLowerCase().includes(myEmailLower);
        const isRecipient = email.to.some((t) =>
          t.toLowerCase().includes(myEmailLower)
        );
        const isBccRecipient = email.bcc?.some((b) =>
          b.toLowerCase().includes(myEmailLower)
        );
        const deliveredTo = (
          email.headers?.['Delivered-To'] ||
          email.headers?.['X-Original-To'] ||
          ''
        ).toLowerCase();
        const isDeliveredToMe =
          Boolean(myEmailLower) && deliveredTo.includes(myEmailLower);

        if (
          myEmailLower &&
          isSeedEmail &&
          !isSender &&
          !isRecipient &&
          !isBccRecipient &&
          !isDeliveredToMe
        ) {
          continue;
        }

        const res = await inspectAndDecryptEmail({
          email,
          recipientPrivateKeyArmored: activeUser?.pgpKeyPair?.privateKeyArmored,
          inviteSecret: email.inviteKeyFragment,
        });
        results.push(res);

        // Automatically upsert sender profile/identity metadata on a new device from synced packets
        const pkt = res.decryptedPacket;
        if (pkt?.sender?.email) {
          const card = pkt.sender.profileCard;
          const idx = nextUsers.findIndex(
            (u) => u.email.toLowerCase() === pkt.sender.email.toLowerCase()
          );
          if (idx >= 0) {
            const existing = nextUsers[idx];
            if (card) {
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
            } else if (
              !existing.pgpKeyPair &&
              pkt.sender.publicKeyArmored &&
              !existing.hasAppInstalled
            ) {
              nextUsers[idx] = { ...existing, hasAppInstalled: true };
              usersUpdated = true;
            }
          } else {
            nextUsers.push({
              email: pkt.sender.email,
              displayName:
                card?.displayName ||
                pkt.sender.displayName ||
                pkt.sender.email.split('@')[0],
              handle:
                card?.handle ||
                pkt.sender.handle ||
                `@${pkt.sender.email.split('@')[0].replace(/[^a-z0-9_]/gi, '_')}`,
              avatarDataUrl: card?.avatarDataUrl,
              bio: card?.bio,
              profileUpdatedAt: card?.updatedAt || pkt.sentAt,
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
        // Automatically hydrate & merge any channels referenced by synced/decrypted packets
        setChannels((prev) => {
          let changed = false;
          const byId = new Map(prev.map((c) => [c.id, c]));
          const discovered: DcpChannelMeta[] = [];

          for (const r of results) {
            const ch = r.decryptedPacket?.channel;
            if (!ch || !ch.id) continue;
            const existing = byId.get(ch.id);
            if (!existing) {
              byId.set(ch.id, ch);
              discovered.push(ch);
              changed = true;
            } else {
              const mergedParticipants = Array.from(
                new Set([
                  ...existing.participants,
                  ...(ch.participants || []),
                ])
              );
              if (mergedParticipants.length !== existing.participants.length) {
                byId.set(ch.id, {
                  ...existing,
                  participants: mergedParticipants,
                });
                changed = true;
              }
            }
          }

          if (!changed) return prev;
          return [
            ...discovered,
            ...prev.map((c) => byId.get(c.id) || c),
          ];
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

  // Build free-flowing chronological message stream with reactions and inline quotes
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
      } else if (
        pkt.type === 'chat.message' ||
        pkt.type === 'chat.member-update'
      ) {
        messageLookup.set(pkt.payload.messageId, {
          senderName: pkt.sender.displayName,
          textSnippet: (pkt.payload.text || '').slice(0, 80),
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
        pkt.type !== 'chat.member-update'
      ) {
        continue;
      }

      const quoted = pkt.payload.replyToMessageId
        ? messageLookup.get(pkt.payload.replyToMessageId)
        : undefined;

      const effectiveReactions =
        reactionsByTargetId.get(pkt.payload.messageId) || [];

      messages.push({
        emailId: item.emailId,
        packet: pkt,
        decryptionTimeMs: item.decryptionTimeMs,
        reactions: effectiveReactions,
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
  }, [acceptedPackets, activeChannel]);

  // Compute local unread message count map across conversations for the active user
  const channelUnreadCountMap = useMemo(() => {
    const map: Record<string, number> = {};

    for (const ch of userScopedChannels) {
      const unreadItems = acceptedPackets.filter((item) => {
        const pkt = item.decryptedPacket;
        if (!pkt || pkt.channel.id !== ch.id) return false;
        if (pkt.type !== 'chat.message') {
          return false;
        }
        const isOwn =
          pkt.sender.email.toLowerCase() === activeUser.email.toLowerCase();
        if (isOwn) return false;

        return !readMessageIds.has(pkt.payload.messageId);
      });
      map[ch.id] = unreadItems.length;
    }
    return map;
  }, [userScopedChannels, acceptedPackets, activeUser.email, readMessageIds]);

  const activeChannelUnreadCount = activeChannel
    ? channelUnreadCountMap[activeChannel.id] || 0
    : 0;

  // Marks incoming messages in the active conversation as viewed locally (never sends status emails)
  const markActiveChannelAsRead = useCallback(() => {
    if (isMobileDeviceView && !mobileShowChatPane) {
      return;
    }

    if (isInitializingKeys || !activeChannel) {
      return;
    }

    const unreadIncoming = freeflowStream.filter((msg) => {
      if (msg.packet.type !== 'chat.message') {
        return false;
      }
      const isOwn =
        msg.packet.sender.email.toLowerCase() ===
        activeUser.email.toLowerCase();
      if (isOwn) return false;

      return !readMessageIds.has(msg.packet.payload.messageId);
    });

    if (unreadIncoming.length === 0) return;

    setReadMessageIds((prev) => {
      const next = new Set(prev);
      unreadIncoming.forEach((m) => next.add(m.packet.payload.messageId));
      return next;
    });
  }, [
    isInitializingKeys,
    activeChannel,
    freeflowStream,
    activeUser.email,
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
    setIsAtBottom(true);
    isScrolledToBottomRef.current = true;
    setHasChatsBelowViewport(false);
  }, [activeUser.email]);

  // Handle scroll positioning on channel change and incoming messages:
  // - When entering a chat with unread messages, scroll cleanly to the first unread message
  // - When in an active chat, ONLY auto-scroll new messages if scrolled to the bottom (or user just sent message)
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
        const firstUnreadMsg = freeflowStream.find((m) => {
          if (m.packet.type !== 'chat.message') {
            return false;
          }
          const isOwn =
            m.packet.sender.email.toLowerCase() ===
            activeUser.email.toLowerCase();
          if (isOwn) return false;
          return !readMessageIds.has(m.packet.payload.messageId);
        });

        const targetMsgId = firstUnreadMsg?.packet.payload.messageId || null;

        requestAnimationFrame(() => {
          requestAnimationFrame(() => {
            const target =
              (targetMsgId
                ? document.getElementById(`dc-msg-${targetMsgId}`)
                : null) || feedEl.querySelector('.dc-imessage-row.is-unread');
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

  // Helper to resolve a user's avatar or default Boring Avatar based on email
  function renderUserAvatar(
    emailOrUser: string | UserIdentity | undefined,
    fallbackName?: string,
    sizeClass = 'dc-avatar-circle'
  ) {
    const u =
      typeof emailOrUser === 'string'
        ? users.find(
            (usr) => usr.email.toLowerCase() === emailOrUser.toLowerCase()
          )
        : emailOrUser;

    const email =
      u?.email ||
      (typeof emailOrUser === 'string' && emailOrUser.includes('@')
        ? emailOrUser
        : '') ||
      'user@dontcall.local';
    const name = u?.displayName || fallbackName || email.split('@')[0] || 'U';

    const isCustomUpload =
      u?.avatarDataUrl &&
      !u.avatarDataUrl.includes('skater_curls') &&
      !u.avatarDataUrl.includes('spiky_grin') &&
      !u.avatarDataUrl.includes('wavy_locks') &&
      !u.avatarDataUrl.includes('sunny_bangs') &&
      !u.avatarDataUrl.includes('messy_tuft') &&
      !u.avatarDataUrl.includes('curly_bob') &&
      !u.avatarDataUrl.includes('cool_part') &&
      !u.avatarDataUrl.includes('puff_curls');

    if (isCustomUpload && u?.avatarDataUrl) {
      return (
        <img
          src={u.avatarDataUrl}
          alt={name}
          className={`${sizeClass} dc-avatar-img`}
        />
      );
    }

    return (
      <div
        className={`${sizeClass} dc-boring-avatar-wrapper`}
        title={name}
        aria-label={name}
      >
        <Avatar
          name={email.trim().toLowerCase()}
          variant="beam"
          size="100%"
          title={true}
        />
      </div>
    );
  }

  // Dispatch an ATME/1.0 JSON packet over Email (attaches Profile Card on first message or profile update)
  async function dispatchDcpEmailPacket(params: {
    channel: DcpChannelMeta;
    type: DcpPacketType;
    text?: string;
    replyToMessageId?: string;
    targetMessageId?: string;
    reactionEmoji?: string;
    attachments?: DcpAttachment[];
    linkPreview?: DcpLinkPreview;
    vaultCategory?: 'note' | 'credential' | 'file' | 'snippet';
    memberUpdate?: {
      action: 'add' | 'remove';
      targetEmail: string;
      targetDisplayName?: string;
      updatedParticipants: string[];
    };
  }) {
    if (params.type === 'chat.message') {
      userJustSentMessageRef.current = true;
    }
    setIsSending(true);
    try {
      const packetId = `pkt_${Date.now().toString(36)}_${Math.random()
        .toString(36)
        .slice(2, 6)}`;
      const msgId = `msg_${Date.now().toString(36)}`;

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

      const packet: DcpPacket = {
        protocol: ATME_PROTOCOL_VERSION,
        packetId,
        type: params.type,
        encryptionMode: 'cleartext-json',
        channel: params.channel,
        sender: {
          email: activeUser.email,
          displayName: activeUser.displayName,
          handle: activeUser.handle,
          provider: activeUser.provider,
          pgpFingerprint: activeUser.pgpKeyPair?.fingerprint || '',
          publicKeyArmored: activeUser.pgpKeyPair?.publicKeyArmored || '',
          profileCard,
        },
        payload: {
          messageId: msgId,
          replyToMessageId: params.replyToMessageId,
          targetMessageId: params.targetMessageId,
          reactionEmoji: params.reactionEmoji,
          text: params.text,
          formatting: 'markdown',
          attachments: params.attachments,
          linkPreview: params.linkPreview,
          vaultCategory: params.vaultCategory,
          memberUpdate: params.memberUpdate,
        },
        sentAt: new Date().toISOString(),
      };

      const rawMimeEmail = buildDcpMimeEmail({ packet });
      let persistedEmail: RawTransportEmail = rawMimeEmail;

      // Live OAuth Dispatch if connected
      if (gmailAccessToken.trim() && activeUser.provider === 'gmail') {
        const gmailTransport = new GmailDirectTransport(
          gmailAccessToken.trim()
        );
        const sent = await gmailTransport.sendRawMimeEmail(rawMimeEmail);
        persistedEmail = { ...rawMimeEmail, id: sent.providerMessageId };
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

      const updatedEmails = [persistedEmail, ...transportEmailsRef.current];
      transportEmailsRef.current = updatedEmails;
      setTransportEmails(updatedEmails);
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

    // 4. Open or create their 1-on-1 DM
    const existingDm = channels.find(
      (c) =>
        c.type === 'dm' &&
        c.participants.some((p) => p.toLowerCase() === cleanEmail) &&
        c.participants.some(
          (p) => p.toLowerCase() === activeUser.email.toLowerCase()
        )
    );
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

    setCapturedPhotoDataUrl(null);
    stopCameraStream();
    cameraCaptureDialogRef.current?.close();

    await dispatchDcpEmailPacket({
      channel: activeChannel,
      type: 'chat.message',
      text: composerText.trim() || '📸 Photo',
      attachments: [photoAttachment],
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

  // Local-only unread tracking when scrolled to bottom (no outbound receipt emails)
  useEffect(() => {
    if (!isAtBottom) return;
    markActiveChannelAsRead();
  }, [isAtBottom, markActiveChannelAsRead]);

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

  // Open an existing 1-on-1 DM or create a new one
  function handleOpenExistingOrStartContactChat(email: string) {
    handleStartOrOpenContactChat(email);
  }

  // Start or jump to a regular 1-on-1 DM with any Contact
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

  // Send message from the Free-Flowing Messenger Composer
  async function handleMessengerSend(
    e?: React.FormEvent | React.KeyboardEvent
  ) {
    e?.preventDefault();
    if (!activeChannel) return;
    if (!composerText.trim() && pendingAttachments.length === 0) return;

    const cleanText =
      composerText.trim() ||
      `Sent ${pendingAttachments.length} attachment(s)`;
    const linkPreview = extractClientSideLinkPreview(cleanText);

    await dispatchDcpEmailPacket({
      channel: activeChannel,
      type: 'chat.message',
      text: cleanText,
      replyToMessageId: replyingToMessage?.packet.payload.messageId,
      attachments:
        pendingAttachments.length > 0 ? pendingAttachments : undefined,
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
      composerTextareaRef.current.style.height = '38px';
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

  async function handleCreateNewChannelOrDm(e: React.FormEvent) {
    e.preventDefault();

    if (newChatType === 'workspace-channel') {
      const id = `ch_custom_${Date.now().toString(36)}`;
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
          : 'new-group';
      const cleanName =
        newChatName
          .trim()
          .toLowerCase()
          .replace(/[^a-z0-9-]/g, '-') || fallbackGroupName;
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
        createdAt: new Date().toISOString(),
      };
      setChannels((prev) => [newCh, ...prev]);
      setNewChatName('');
      setSelectedGroupMemberEmails([]);
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
          c.participants.some((p) => p.toLowerCase() === targetEmail) &&
          c.participants.some(
            (p) => p.toLowerCase() === activeUser.email.toLowerCase()
          )
      );

      if (existingDm) {
        setNewChatRecipientEmail('');
        newChannelModalRef.current?.close();
        menuDirectoryDialogRef.current?.close();
        openMobileChat(existingDm.id);
        return;
      }

      const rawName = existingUser.displayName.replace(' (No App Yet)', '');
      const dmCh: DcpChannelMeta = {
        id: `dm_${Date.now().toString(36)}`,
        type: 'dm',
        name: rawName,
        participants: [activeUser.email, existingUser.email],
        createdAt: new Date().toISOString(),
      };
      setChannels((prev) => [dmCh, ...prev]);
      setNewChatRecipientEmail('');
      newChannelModalRef.current?.close();
      menuDirectoryDialogRef.current?.close();
      openMobileChat(dmCh.id);
    }
  }

  // 1-Click OAuth2 Popup Sign-In Handler (Real Google Identity Services / OAuth2 Popup if Client ID provided, or Instant Interactive Google Picker)
  async function handleOneClickOAuthPopup(
    provider: 'google' | 'microsoft',
    prefillEmail?: string
  ) {
    setConnectorStatusMsg('');
    if (provider === 'google') {
      const check = validateGoogleClientId(googleClientId);
      if (check.sanitized !== googleClientId) {
        setGoogleClientId(check.sanitized);
        saveGoogleClientId(check.sanitized);
      }
      if (check.sanitized && !check.valid) {
        setShowAdvancedOAuthConfig(true);
        setConnectorStatusMsg(
          `⚠️ Invalid Google Client ID ("${check.sanitized.slice(0, 28)}…"): ${
            check.reason || 'Must end with .apps.googleusercontent.com'
          }`
        );
        return;
      }
    }

    const configuredClientId =
      provider === 'google'
        ? sanitizeGoogleClientId(googleClientId)
        : microsoftClientId.trim();

    if (configuredClientId) {
      if (provider === 'google') {
        saveGoogleClientId(configuredClientId);
      }
      try {
        const result = await launchRealOAuthPopup({
          provider,
          clientId: configuredClientId,
          loginHint: prefillEmail?.trim(),
        });
        if (provider === 'google') {
          setGmailAccessToken(result.accessToken);
          // Automatically fetch Google email & name if not already in result
          const profile =
            result.userProfile ||
            (await fetchGoogleUserProfile(result.accessToken).catch(
              () => undefined
            ));

          if (profile?.email) {
            await handleCompletePortalSignIn({
              email: profile.email,
              displayName: profile.name,
              provider: 'gmail',
              liveAccessToken: result.accessToken,
              expiresInSeconds: result.expiresInSeconds,
            });
            return;
          }
          setConnectorStatusMsg(
            'Google OAuth connected, but profile email could not be loaded. Check email/profile scopes.'
          );
          return;
        } else {
          setOutlookAccessToken(result.accessToken);
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

    // Open the built-in Interactive Google/Microsoft Account Picker so users can test 1-click sign-in immediately
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
      setSimulatedOAuthEmail('taylor.reed@gmail.com');
      setSimulatedOAuthName('Taylor');
    } else {
      setSimulatedOAuthEmail('morgan@outlook.com');
      setSimulatedOAuthName('Morgan');
    }
  }

  // Sync all ATME/1.0 packets from Gmail & reconcile local IndexedDB storage against remote mailbox
  async function handleSyncLiveGmailPackets(
    tokenOverride?: string,
    emailOverride?: string,
    baseLocalEmails?: RawTransportEmail[]
  ) {
    const token = (tokenOverride || gmailAccessToken).trim();
    const accountEmail = (
      emailOverride ||
      loadGoogleOAuthSession()?.email ||
      activeUserEmail
    )
      .trim()
      .toLowerCase();
    if (!token) return;
    setIsSyncingGmailInbox(true);
    try {
      const transport = new GmailDirectTransport(token);
      if (autoArchivePrimaryInbox) {
        await transport
          .createAutoCleanInboxFilter(accountEmail)
          .catch(() => undefined);
      }
      const fetchedEmails = await transport.fetchDontCallPackets(500);
      const localSnapshot = baseLocalEmails || transportEmailsRef.current;
      const reconciled = reconcileLocalEmailsWithRemoteMailbox({
        localEmails: localSnapshot,
        remoteEmails: fetchedEmails,
        accountEmail,
      });

      setTransportEmails(reconciled.reconciledEmails);
      transportEmailsRef.current = reconciled.reconciledEmails;
      await saveTransportEmailsToIdb(reconciled.reconciledEmails);

      setConnectorStatusMsg(
        `Gmail Sync Complete • +${reconciled.addedCount} pulled • ${reconciled.verifiedMatchCount} verified • ${reconciled.updatedCount} updated • ${reconciled.removedCount} pruned`
      );
    } catch (err) {
      setConnectorStatusMsg(
        `Gmail Sync Note: ${err instanceof Error ? err.message : String(err)}`
      );
    } finally {
      setIsSyncingGmailInbox(false);
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

  // Complete Sign-In from OAuth Consent Portal or Custom Domain Portal:
  // Logs in immediately without blocking, and generates an optional Curve25519 keypair in the background for encrypted peer interop.
  async function handleCompletePortalSignIn(params: {
    email: string;
    displayName: string;
    provider: 'gmail' | 'outlook' | 'proton' | 'yahoo' | 'custom-domain';
    liveAccessToken?: string;
    expiresInSeconds?: number;
  }) {
    const cleanEmail = params.email.trim().toLowerCase();
    const cleanName = params.displayName.trim() || cleanEmail.split('@')[0];
    const handle = `@${cleanEmail.split('@')[0].replace(/[^a-z0-9_]/gi, '_')}`;

    setIsSending(true);
    try {
      const newIdentity: UserIdentity = {
        email: cleanEmail,
        displayName: cleanName,
        handle,
        bio: `Signed in via ${params.provider.toUpperCase()} OAuth • ATME/1.0`,
        profileUpdatedAt: new Date().toISOString(),
        provider: params.provider,
        hasAppInstalled: true,
      };

      setUsers((prev) => {
        const exists = prev.some((u) => u.email.toLowerCase() === cleanEmail);
        const next = exists
          ? prev.map((u) =>
              u.email.toLowerCase() === cleanEmail ? newIdentity : u
            )
          : [newIdentity, ...prev];
        void saveUserIdentitiesToIdb(next);
        return next;
      });
      setActiveUserEmail(newIdentity.email);
      setProfileNameInput(newIdentity.displayName);
      setProfileHandleInput(newIdentity.handle || handle);
      setForceBroadcastProfileNext(true);
      setSimulatedOAuthProvider(null);

      // Ensure personal Notes (@me) vault channel exists for the newly signed-in user
      const vaultId = `vault_${cleanEmail}`;
      setChannels((prev) =>
        prev.some((c) => c.id === vaultId)
          ? prev
          : [
              ...prev,
              {
                id: vaultId,
                type: 'vault',
                name: 'Notes (@me)',
                participants: [cleanEmail],
                createdAt: new Date().toISOString(),
              },
            ]
      );

      if (params.liveAccessToken && params.provider === 'gmail') {
        const ttlMs = (params.expiresInSeconds || 3500) * 1000;
        saveGoogleOAuthSession({
          email: cleanEmail,
          accessToken: params.liveAccessToken,
          expiresAtMs: Date.now() + ttlMs,
        });
        void handleSyncLiveGmailPackets(params.liveAccessToken, cleanEmail);
      }

      // Lazily generate Curve25519 keys in background so encrypted ATME/1.0 peers can interop
      void generateDeviceKeyPair(cleanName, cleanEmail)
        .then((kp) => {
          setUsers((prev) => {
            const next = prev.map((u) =>
              u.email.toLowerCase() === cleanEmail && !u.pgpKeyPair
                ? { ...u, pgpKeyPair: kp }
                : u
            );
            void saveUserIdentitiesToIdb(next);
            return next;
          });
        })
        .catch(() => undefined);

      setConnectorStatusMsg(
        `Signed in as ${newIdentity.displayName} (${newIdentity.email}) • ATME/1.0 ready.`
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
      window.localStorage.removeItem('atme_simple_seed_v1');
      window.localStorage.removeItem('atme_simple_seed_v2');
      window.localStorage.removeItem('atme_simple_seed_v3');
      window.localStorage.removeItem('atme_simple_channels_v1');
      window.localStorage.removeItem('atme_simple_channels_v2');
      window.localStorage.removeItem('dontcall_seed_v5');
      window.localStorage.removeItem('dontcall_seed_v6');
      window.localStorage.removeItem('dontcall_seed_v7');
      window.localStorage.removeItem('dc_channels_v3');
      window.localStorage.removeItem('dc_channels_v4');
      window.localStorage.removeItem('dc_burn_read_started');
      window.localStorage.removeItem('atme_profile_onboarded');
      window.localStorage.removeItem('atme_blocked_emails');
      window.localStorage.removeItem('atme_whitelisted_emails');
      window.localStorage.removeItem('atme_whitelist_only');
      window.localStorage.removeItem('atme_google_oauth_session');
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
      className={`dc-root-viewport ${isIphoneFrame ? 'iphone-frame' : ''} messenger-viewport`}
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
          ANDROID / iMESSAGE TEXTING UI WITH FREE-FLOWING THREADS
         ===================================================================== */}
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
                      title="New Conversation"
                      aria-label="New Conversation"
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
                            setNewChatRecipientEmail('');
                            setSelectedGroupMemberEmails([]);
                            newChannelModalRef.current?.showModal();
                          }}
                          title="New Message"
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
                            setNewChatName('');
                            setSelectedGroupMemberEmails([]);
                            newChannelModalRef.current?.showModal();
                          }}
                          title="New Group"
                          aria-label="New Group"
                        >
                          <Users size={19} />
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
                          openMobileChat(ch.id);
                        }}
                      >
                        {!isGroup && !isVault ? (
                          renderUserAvatar(
                            peerUser,
                            ch.name,
                            'dc-thread-avatar'
                          )
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
                            ) : (
                              <Users size={18} />
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
                      const canManageParticipants =
                        activeChannel.type !== 'vault';

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
                          {activeChannel.type === 'vault' ? (
                            <div className="dc-header-avatar vault-avatar">
                              <Bookmark size={16} />
                            </div>
                          ) : activeChannel.type === 'dm' ? (
                            renderUserAvatar(
                              activeChannelPeerUser,
                              activeChannelDisplayTitle,
                              'dc-header-avatar'
                            )
                          ) : (
                            <div className="dc-header-avatar">
                              <Users size={17} />
                            </div>
                          )}
                          <div>
                            <h2>{activeChannelDisplayTitle}</h2>
                          </div>
                        </div>
                      );
                    })()}
                  </div>

                  <div className="dc-freeflow-header-actions">
                    {/* Top-Right 3-Line Dropdown Menu (People, Block, Settings) */}
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
                        aria-label="Open conversation menu"
                        title="Conversation Menu & Settings"
                      >
                        <Menu size={17} />
                      </button>

                      {isHeaderMenuOpen && (
                        <div
                          className="dc-header-dropdown-menu"
                          role="menu"
                          aria-label="Conversation actions and settings"
                        >
                          {((activeChannel.type !== 'vault' &&
                            activeChannel.type !== 'dm') ||
                            (activeChannel.type !== 'vault' &&
                              activeChannel.participants.length <= 2 &&
                              Boolean(activeChannelPeerUser))) && (
                            <>
                              <div
                                className="dc-header-menu-actions-row"
                                role="toolbar"
                                aria-label="Conversation actions"
                              >
                                {activeChannel.type !== 'dm' && (
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

                                {activeChannel.participants.length <= 2 &&
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
                            </>
                          )}

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
                  {activeChannel.type === 'vault' && <strong>📌 Notes</strong>}
                </div>
              )}

              {freeflowStream.map((msg) => {
                const isOwn =
                  msg.packet.sender.email.toLowerCase() ===
                  activeUser.email.toLowerCase();
                const isMsgUnread =
                  !isOwn &&
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
                              isMsgUnread ? 'is-unread-bubble' : ''
                            }`}
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
                            <p>{msg.packet.payload.text}</p>

                                {/* Client-Side Link Preview Card */}
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
                                                    <Mic size={13} /> Voice Note ({att.filename})
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
                                                      KB &bull; ATME/1.0 (cid:{att.cid})
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

                            {/* Bottom-Right Reactions Badge (Emoji only; hover lists reactor names) */}
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
                        </div>

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

              <div className="dc-imessage-input-row">
                {/* Collapsed Bottom-Left '+' Action Menu (Camera, Upload, Voice) */}
                <div
                  className="dc-composer-plus-wrap"
                  ref={actionMenuContainerRef}
                >
                  <button
                    type="button"
                    className={`dc-circle-icon-btn dc-composer-plus-btn ${
                      isPlusMenuOpen ? 'is-open' : ''
                    }`}
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
                  aria-label="Send message"
                >
                  <Send size={15} />
                </button>
              </div>
            </form>
              </>
            )}
          </section>
        </div>

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
                      className="dc-profile-avatar-large dc-avatar-img"
                    />
                  ) : (
                    <div className="dc-profile-avatar-large dc-boring-avatar-wrapper">
                      <Avatar
                        name={activeUser.email}
                        variant="beam"
                        size="100%"
                        title={true}
                      />
                    </div>
                  )}
                </div>
                <div className="dc-profile-avatar-buttons">
                  <span className="dc-avatar-section-label">
                    <User size={12} /> {activeUser.email}
                  </span>
                  <div className="dc-avatar-actions-row">
                    <button
                      type="button"
                      className="dc-pill-action-btn dc-google-pill-btn"
                      onClick={() => {
                        profileDialogRef.current?.close();
                        setConnectModalMode('easy');
                        connectWizardDialogRef.current?.showModal();
                        void handleOneClickOAuthPopup('google');
                      }}
                      title="Sign in with Google OAuth"
                    >
                      <svg
                        width="14"
                        height="14"
                        viewBox="0 0 24 24"
                        aria-hidden="true"
                      >
                        <path
                          fill="#EA4335"
                          d="M12 5c1.6 0 3 .6 4.1 1.7l3.1-3.1C17.3 1.8 14.8 1 12 1 7.4 1 3.5 3.6 1.6 7.4l3.7 2.8C6.2 7.2 8.9 5 12 5z"
                        />
                        <path
                          fill="#4285F4"
                          d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.5h6.5c-.3 1.5-1.1 2.8-2.4 3.6l3.7 2.9c2.2-2 3.7-5 3.7-8.7z"
                        />
                        <path
                          fill="#FBBC05"
                          d="M5.3 14.8c-.2-.8-.4-1.6-.4-2.5s.2-1.7.4-2.5L1.6 7C.6 9 0 11.2 0 13.5s.6 4.5 1.6 6.5l3.7-2.9z"
                        />
                        <path
                          fill="#34A853"
                          d="M12 23c3.2 0 6-1.1 8-3l-3.7-2.9c-1.1.7-2.5 1.2-4.3 1.2-3.1 0-5.8-2.1-6.7-5l-3.7 2.9C3.5 20.4 7.4 23 12 23z"
                        />
                      </svg>
                      Google Sign-In
                    </button>
                    <button
                      type="button"
                      className="dc-pill-action-btn dc-photo-icon-btn"
                      onClick={() => avatarUploadInputRef.current?.click()}
                      title="Upload custom image"
                      aria-label="Upload custom image"
                    >
                      <Camera size={15} /> Photo
                    </button>
                    {profileAvatarInput && (
                      <button
                        type="button"
                        className="dc-pill-action-btn dc-avatar-reset-btn"
                        onClick={() => {
                          setProfileAvatarInput('');
                        }}
                        title="Revert to default Boring Avatar"
                        aria-label="Revert to default Boring Avatar"
                      >
                        <RefreshCw size={13} />
                      </button>
                    )}
                  </div>
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
                      className="dc-qr-card-avatar dc-avatar-img"
                    />
                  ) : (
                    <div className="dc-qr-card-avatar dc-boring-avatar-wrapper">
                      <Avatar
                        name={activeUser.email}
                        variant="beam"
                        size="100%"
                        title={true}
                      />
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
                <label className="dc-pill-switch-row">
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
              {/* Primary 1-Click Google OAuth Sign-Up / Sign-In Hero Button */}
              <div className="dc-google-hero-box">
                <button
                  type="button"
                  className="dc-google-one-tap-btn"
                  onClick={() => handleOneClickOAuthPopup('google', easyEmailInput)}
                >
                  <span className="dc-google-g-badge" aria-hidden="true">
                    <svg width="20" height="20" viewBox="0 0 24 24">
                      <path
                        fill="#EA4335"
                        d="M12 5c1.6 0 3 .6 4.1 1.7l3.1-3.1C17.3 1.8 14.8 1 12 1 7.4 1 3.5 3.6 1.6 7.4l3.7 2.8C6.2 7.2 8.9 5 12 5z"
                      />
                      <path
                        fill="#4285F4"
                        d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.5h6.5c-.3 1.5-1.1 2.8-2.4 3.6l3.7 2.9c2.2-2 3.7-5 3.7-8.7z"
                      />
                      <path
                        fill="#FBBC05"
                        d="M5.3 14.8c-.2-.8-.4-1.6-.4-2.5s.2-1.7.4-2.5L1.6 7C.6 9 0 11.2 0 13.5s.6 4.5 1.6 6.5l3.7-2.9z"
                      />
                      <path
                        fill="#34A853"
                        d="M12 23c3.2 0 6-1.1 8-3l-3.7-2.9c-1.1.7-2.5 1.2-4.3 1.2-3.1 0-5.8-2.1-6.7-5l-3.7 2.9C3.5 20.4 7.4 23 12 23z"
                      />
                    </svg>
                  </span>
                  <div className="dc-google-btn-copy">
                    <strong>Continue with Google</strong>
                    <span>1-Click Gmail &amp; Workspace OAuth &bull; Zero Passwords</span>
                  </div>
                  <ChevronRight size={18} />
                </button>

                {gmailAccessToken && (
                  <div className="dc-live-gmail-sync-bar">
                    <span>🟢 Google OAuth Connected ({activeUser.email})</span>
                    <button
                      type="button"
                      className="dc-pill-action-btn"
                      disabled={isSyncingGmailInbox}
                      onClick={() => void handleSyncLiveGmailPackets()}
                    >
                      <RefreshCw size={13} />{' '}
                      {isSyncingGmailInbox ? 'Syncing…' : 'Sync Gmail'}
                    </button>
                  </div>
                )}
              </div>

              {/* Interactive Google Account Chooser (1-Tap Demo Accounts + Custom Gmail Input) */}
              {simulatedOAuthProvider && (
                <div className="dc-oauth-consent-card dc-google-chooser-card">
                  <div className="dc-oauth-consent-header">
                    <div className="dc-google-chooser-title">
                      <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true">
                        <path
                          fill="#EA4335"
                          d="M12 5c1.6 0 3 .6 4.1 1.7l3.1-3.1C17.3 1.8 14.8 1 12 1 7.4 1 3.5 3.6 1.6 7.4l3.7 2.8C6.2 7.2 8.9 5 12 5z"
                        />
                        <path
                          fill="#4285F4"
                          d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.5h6.5c-.3 1.5-1.1 2.8-2.4 3.6l3.7 2.9c2.2-2 3.7-5 3.7-8.7z"
                        />
                        <path
                          fill="#FBBC05"
                          d="M5.3 14.8c-.2-.8-.4-1.6-.4-2.5s.2-1.7.4-2.5L1.6 7C.6 9 0 11.2 0 13.5s.6 4.5 1.6 6.5l3.7-2.9z"
                        />
                        <path
                          fill="#34A853"
                          d="M12 23c3.2 0 6-1.1 8-3l-3.7-2.9c-1.1.7-2.5 1.2-4.3 1.2-3.1 0-5.8-2.1-6.7-5l-3.7 2.9C3.5 20.4 7.4 23 12 23z"
                        />
                      </svg>
                      <strong>
                        {simulatedOAuthProvider === 'google'
                          ? 'Choose a Google Account'
                          : 'Microsoft Account Sign-In'}
                      </strong>
                    </div>
                    <button
                      type="button"
                      className="dc-icon-btn"
                      onClick={() => setSimulatedOAuthProvider(null)}
                      aria-label="Close Google Chooser"
                    >
                      <X size={14} />
                    </button>
                  </div>

                  {simulatedOAuthProvider === 'google' && (
                    <div className="dc-google-quick-accounts">
                      {[
                        {
                          name: 'Alex',
                          email: 'alex.rivera@gmail.com',
                          tag: 'Current Squad',
                        },
                        {
                          name: 'Taylor',
                          email: 'taylor.reed@gmail.com',
                          tag: 'New Gmail',
                        },
                        {
                          name: 'Kai',
                          email: 'kai.chen@gmail.com',
                          tag: 'New Gmail',
                        },
                      ].map((acct) => (
                        <button
                          key={acct.email}
                          type="button"
                          className="dc-google-account-row"
                          disabled={isSending}
                          onClick={() =>
                            void handleCompletePortalSignIn({
                              email: acct.email,
                              displayName: acct.name,
                              provider: 'gmail',
                            })
                          }
                        >
                          <div className="dc-google-acct-avatar">
                            <Avatar
                              name={acct.email}
                              variant="beam"
                              size={34}
                              title={true}
                            />
                          </div>
                          <div className="dc-google-acct-meta">
                            <strong>{acct.name}</strong>
                            <span>{acct.email}</span>
                          </div>
                          <span className="dc-google-acct-pill">{acct.tag}</span>
                        </button>
                      ))}
                    </div>
                  )}

                  <div className="dc-form-row">
                    <div className="dc-form-group">
                      <label>Google Email</label>
                      <input
                        type="email"
                        value={simulatedOAuthEmail}
                        onChange={(e) => {
                          const val = e.target.value;
                          setSimulatedOAuthEmail(val);
                          const prefix = val.split('@')[0];
                          if (prefix) {
                            const guessed = prefix
                              .split(/[._-]/)
                              .filter(Boolean)
                              .map(
                                (w) => w.charAt(0).toUpperCase() + w.slice(1)
                              )
                              .join(' ');
                            if (guessed) setSimulatedOAuthName(guessed);
                          }
                        }}
                        placeholder="you@gmail.com"
                      />
                    </div>
                    <div className="dc-form-group">
                      <label>First Name</label>
                      <input
                        type="text"
                        value={simulatedOAuthName}
                        onChange={(e) => setSimulatedOAuthName(e.target.value)}
                        placeholder="Taylor"
                      />
                    </div>
                  </div>
                  <div className="dc-modal-actions">
                    <button
                      type="button"
                      className="dc-btn-send"
                      disabled={isSending || !simulatedOAuthEmail.includes('@')}
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
                      <CheckCircle2 size={14} /> Continue as{' '}
                      {simulatedOAuthName || 'User'}
                    </button>
                  </div>
                </div>
              )}

              <div className="dc-easy-divider">
                <span>or any email provider</span>
              </div>

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
                          One-click OAuth2 sign-in &bull; ATME/1.0 JSON + PGP
                          Interop
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
                          One-click OAuth2 PKCE sign-in &bull; ATME/1.0 Ready
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
                        {easyEmailInput.trim()} &amp; Sign In
                      </button>
                    </div>
                  )}
                </div>
              )}

              {connectorStatusMsg && (
                <div className="dc-profile-saved-alert">
                  <CheckCircle2 size={14} /> {connectorStatusMsg}
                </div>
              )}

              {/* Inline Google OAuth Client ID Inspector & Quick Editor */}
              {(showAdvancedOAuthConfig || Boolean(googleClientId)) && (
                <div className="dc-oauth-consent-card dc-google-chooser-card">
                  <div className="dc-oauth-consent-header">
                    <strong>🔑 Google Cloud OAuth Web Client ID</strong>
                    <button
                      type="button"
                      className="dc-icon-btn"
                      onClick={() => setShowAdvancedOAuthConfig(false)}
                      aria-label="Hide Client ID Box"
                    >
                      <X size={14} />
                    </button>
                  </div>
                  <div className="dc-form-group">
                    <label htmlFor="easy-google-client-id">
                      Paste your Client ID ending in{' '}
                      <code>.apps.googleusercontent.com</code> (not the{' '}
                      <code>GOCSPX-</code> secret)
                    </label>
                    <div className="dc-inline-input-btn">
                      <input
                        id="easy-google-client-id"
                        type="text"
                        value={googleClientId}
                        onChange={(e) => {
                          const raw = e.target.value;
                          setGoogleClientId(raw);
                          saveGoogleClientId(raw);
                        }}
                        placeholder="1234567890-abcdefg.apps.googleusercontent.com"
                      />
                      {googleClientId && (
                        <button
                          type="button"
                          className="dc-btn-ghost"
                          onClick={() => {
                            setGoogleClientId('');
                            saveGoogleClientId('');
                            setConnectorStatusMsg(
                              'Cleared saved Google Client ID. Using built-in 1-Tap Google Account Chooser.'
                            );
                          }}
                        >
                          Clear
                        </button>
                      )}
                    </div>
                    <small className="dc-form-hint">
                      Authorized JavaScript Origin to add in Google Cloud
                      Console:{' '}
                      <code>
                        {typeof window !== 'undefined'
                          ? window.location.origin
                          : 'http://localhost:5173'}
                      </code>
                      {typeof window !== 'undefined' &&
                        window.location.hostname === '127.0.0.1' && (
                          <>
                            {' '}
                            &mdash; Open on <code>http://localhost:5173</code>{' '}
                            instead of <code>127.0.0.1</code> for Google OAuth.
                          </>
                        )}
                    </small>
                    {(() => {
                      const check = validateGoogleClientId(googleClientId);
                      if (!check.sanitized) return null;
                      return check.valid ? (
                        <small className="dc-form-hint">
                          ✅ Valid Client ID format &mdash; <strong>Continue with Google</strong> uses live Google OAuth.
                        </small>
                      ) : (
                        <small className="dc-form-hint" style={{ color: '#ef4444' }}>
                          ⚠️ {check.reason}
                        </small>
                      );
                    })()}
                  </div>
                </div>
              )}

              {/* Bottom Bar with Advanced Button */}
              <div className="dc-connect-modal-footer">
                <button
                  type="button"
                  className="dc-btn-ghost"
                  onClick={() =>
                    setShowAdvancedOAuthConfig(!showAdvancedOAuthConfig)
                  }
                >
                  <KeyRound size={13} />{' '}
                  {googleClientId
                    ? 'Edit / Clear Google Client ID'
                    : 'Set Google OAuth Client ID'}
                </button>
                <button
                  type="button"
                  className="dc-btn-ghost"
                  onClick={() => {
                    setWizardProvider('gmail');
                    setConnectModalMode('advanced');
                  }}
                >
                  <Terminal size={13} /> Advanced &amp; Custom IMAP
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
                      Google Cloud OAuth2 Web Client ID (For Live{' '}
                      <code>accounts.google.com</code> Popup)
                    </label>
                    <div className="dc-inline-input-btn">
                      <input
                        id="google-client-id-input"
                        type="text"
                        value={googleClientId}
                        onChange={(e) => {
                          setGoogleClientId(e.target.value);
                          saveGoogleClientId(e.target.value);
                        }}
                        placeholder="123456789-abc.apps.googleusercontent.com"
                      />
                      <button
                        type="button"
                        className="dc-btn-send"
                        onClick={() => handleOneClickOAuthPopup('google')}
                      >
                        Test Google Popup
                      </button>
                    </div>
                    <small className="dc-form-hint">
                      <strong>30-Second Setup for Live Google Users:</strong> In{' '}
                      <strong>Google Cloud Console → APIs &amp; Services → Credentials</strong>,
                      create an <strong>OAuth 2.0 Web Client ID</strong> and add{' '}
                      <code>{typeof window !== 'undefined' ? window.location.origin : 'http://localhost:5173'}</code>{' '}
                      to <strong>Authorized JavaScript origins</strong>. Paste it
                      above (or in <code>.env</code> as{' '}
                      <code>VITE_GOOGLE_CLIENT_ID</code>) to enable 1-click
                      Google Identity Services sign-in!
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
                        SEARCH HEADER X-ATME-Protocol &quot;ATME/1.0&quot;
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
                  <Users size={15} /> Groups
                </h3>
                <div className="dc-menu-section-head-actions">
                  <button
                    type="button"
                    className="dc-pill-action-btn"
                    onClick={() => {
                      setNewChatType('workspace-channel');
                      newChannelModalRef.current?.showModal();
                    }}
                    title="New Group"
                    aria-label="New Group"
                  >
                    <Plus size={14} /> <Users size={14} />
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
                            }
                          </span>
                        </div>
                      </div>
                      <div className="dc-menu-item-actions">
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
                    className="dc-pill-action-btn"
                    onClick={() => {
                      setNewChatType('dm');
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
                          className="dc-btn-ghost"
                          onClick={() =>
                            handleStartOrOpenContactChat(contact.email)
                          }
                          title="Start chat"
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
                        className="dc-mode-chip is-active"
                        onClick={() => {
                          if (peerEmail) {
                            handleStartOrOpenContactChat(peerEmail);
                          }
                        }}
                      >
                        <MessageCircle size={15} /> Open Chat
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
          MODAL 6: Create New Group or DM (+ Add Friend from Contacts)
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
              {newChatType === 'workspace-channel' ? (
                <>
                  <Users size={17} /> New Group
                </>
              ) : (
                <>
                  <MessageCircle size={17} /> New Chat
                </>
              )}
            </h2>
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

          <form
            className="dc-modal-form"
            onSubmit={handleCreateNewChannelOrDm}
          >
            {newChatType === 'workspace-channel' ? (
              <div className="dc-form-group">
                <label htmlFor="new-channel-name">
                  <Users size={12} /> Group Name
                </label>
                <input
                  id="new-channel-name"
                  type="text"
                  value={newChatName}
                  onChange={(e) => setNewChatName(e.target.value)}
                  placeholder="squad-chat"
                  required={selectedGroupMemberEmails.length === 0}
                />
              </div>
            ) : (
              <div className="dc-form-group">
                <label htmlFor="new-dm-email">
                  <Mail size={12} /> Friend&apos;s Email
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

            {/* Add Friend from Contacts Quick Strip */}
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

            <div className="dc-modal-actions">
              <button type="submit" className="dc-btn-send">
                <Send size={15} /> Start
              </button>
            </div>
          </form>
        </div>
      </dialog>

      {/* =====================================================================
          MODAL 9: IN-APP CAMERA CAPTURE (Local DB only)
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
            <div className="dc-camera-viewport">
              {capturedPhotoDataUrl ? (
                <img
                  src={capturedPhotoDataUrl}
                  alt="Captured preview"
                  className="dc-camera-preview-img"
                  draggable={false}
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
                    </div>
                  )}
                </>
              )}
            </div>

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
                      void startCameraStream(cameraFacingMode);
                    }}
                    title="Retake photo"
                    aria-label="Retake photo"
                  >
                    <RefreshCw size={18} />
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
