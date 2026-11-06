/**
 * Burner Chat Cascade Timing Engine
 *
 * Implements sequential cascading deletion where:
 * 1. For RECIPIENTS: The timer for incoming messages activates ONLY when the receiving user
 *    views the message in the app.
 *    Each message burns for 20 seconds, and each subsequent message starts its timer only
 *    when the previous message is deleted:
 *    - 1 message viewed = 20 seconds total
 *    - 2 messages viewed = 40 seconds total
 *    - 3 messages viewed = 60 seconds total
 *
 * 2. MULTI-USER GROUP ISOLATION:
 *    In group chats with multiple recipients, each recipient has their own independent viewing
 *    timeline and cascade. If Elena views at 10:00, Elena's cascade burns from 10:00 to 10:01.
 *    If Sam views at 10:30, Sam's cascade burns from 10:30 to 10:31. Elena's deletion does NOT
 *    delete the message from Sam's view.
 *
 * 3. SENDER VIEW & DELETION:
 *    The sender's copy does not delete until ALL recipients in the channel have completed
 *    their burn cascade. The sender sees real-time per-recipient status (e.g.
 *    "⏳ Unread by Elena (burns 20s once viewed)" or "🔥 Elena (15s) • ⏳ Sam unread").
 */

export interface BurnerCascadeItem {
  messageId: string;
  viewedAtMs: number;
  cascadeStartMs: number;
  cascadeExpireMs: number;
  isActive: boolean;
  isQueued: boolean;
  isExpired: boolean;
  remainingSeconds: number;
}

export interface PeerRecipientBurnStatus {
  email: string;
  name: string;
  isViewed: boolean;
  viewedAtMs?: number;
  isActive: boolean;
  isQueued: boolean;
  isExpired: boolean;
  remainingSeconds: number;
}

export interface ViewerBurnerCascadeItem {
  messageId: string;
  isOwn: boolean;
  isViewed: boolean;
  viewedAtMs?: number;
  cascadeStartMs?: number;
  cascadeExpireMs?: number;
  isActive: boolean;
  isQueued: boolean;
  isExpired: boolean;
  remainingSeconds: number;
  allRecipientsExpired?: boolean;
  peerStatuses?: PeerRecipientBurnStatus[];
  summaryLabel: string;
}

export interface BurnerMessageInput {
  messageId: string;
  senderEmail: string;
  sentAtMs?: number;
}

/**
 * Basic cascade computation (kept for backward compatibility with existing tests and simple consumers)
 */
export function computeBurnerCascadeTimings(
  messages: Array<{ messageId: string; viewedAtMs?: number }>,
  nowMs: number,
  ttlSeconds: number = 20
): Map<string, BurnerCascadeItem> {
  const result = new Map<string, BurnerCascadeItem>();
  const ttlMs = ttlSeconds * 1000;
  let cascadePrevExpireMs = 0;

  for (const msg of messages) {
    const viewedAtMs = msg.viewedAtMs || nowMs;
    const cascadeStartMs = Math.max(viewedAtMs, cascadePrevExpireMs);
    const cascadeExpireMs = cascadeStartMs + ttlMs;
    cascadePrevExpireMs = cascadeExpireMs;

    const isExpired = nowMs >= cascadeExpireMs;
    const isActive = nowMs >= cascadeStartMs && nowMs < cascadeExpireMs;
    const isQueued = nowMs < cascadeStartMs;
    const remainingSeconds = isExpired
      ? 0
      : isActive
      ? Math.max(1, Math.ceil((cascadeExpireMs - nowMs) / 1000))
      : ttlSeconds;

    result.set(msg.messageId, {
      messageId: msg.messageId,
      viewedAtMs,
      cascadeStartMs,
      cascadeExpireMs,
      isActive,
      isQueued,
      isExpired,
      remainingSeconds,
    });
  }

  return result;
}

/**
 * Helper to look up a peer's view timestamp for a message from localViewMap or signed receipts
 */
export function resolveUserViewTimestamp(
  userEmail: string,
  messageId: string,
  receiptsByMessageId?:
    | Map<string, Array<{ senderEmail: string; readAtIso?: string; status?: string }>>
    | Record<string, Array<{ senderEmail: string; readAtIso?: string; status?: string }>>,
  localViewMap?: Record<string, number>
): number | undefined {
  const normUser = userEmail.toLowerCase().trim();

  // 1. Check local view map first (${userEmail}:${messageId})
  if (localViewMap) {
    const keyed = localViewMap[`${normUser}:${messageId}`];
    if (typeof keyed === 'number' && !isNaN(keyed) && keyed > 0) {
      return keyed;
    }
  }

  // 2. Check signed receipts (from network / email packet)
  if (receiptsByMessageId) {
    const receipts =
      receiptsByMessageId instanceof Map
        ? receiptsByMessageId.get(messageId)
        : receiptsByMessageId[messageId];

    if (receipts && Array.isArray(receipts)) {
      const match = receipts.find(
        (r) =>
          r.senderEmail.toLowerCase().trim() === normUser &&
          (r.status === 'read' || Boolean(r.readAtIso))
      );
      if (match?.readAtIso) {
        const ms = new Date(match.readAtIso).getTime();
        if (!isNaN(ms) && ms > 0) return ms;
      }
    }
  }

  return undefined;
}

/**
 * Computes the sequential cascade for a single recipient user over their incoming messages
 */
function computeSingleRecipientCascade(
  incomingMessages: BurnerMessageInput[],
  recipientEmail: string,
  receiptsByMessageId:
    | Map<string, Array<{ senderEmail: string; readAtIso?: string; status?: string }>>
    | Record<string, Array<{ senderEmail: string; readAtIso?: string; status?: string }>>
    | undefined,
  localViewMap: Record<string, number> | undefined,
  nowMs: number,
  ttlSeconds: number = 20
): Map<
  string,
  {
    isViewed: boolean;
    viewedAtMs?: number;
    cascadeStartMs?: number;
    cascadeExpireMs?: number;
    isActive: boolean;
    isQueued: boolean;
    isExpired: boolean;
    remainingSeconds: number;
  }
> {
  const result = new Map();
  const ttlMs = ttlSeconds * 1000;
  let cascadePrevExpireMs = 0;

  for (const msg of incomingMessages) {
    const viewedAtMs = resolveUserViewTimestamp(
      recipientEmail,
      msg.messageId,
      receiptsByMessageId,
      localViewMap
    );

    if (viewedAtMs === undefined) {
      // Not viewed yet by this recipient! Timer has NOT started.
      result.set(msg.messageId, {
        isViewed: false,
        isActive: false,
        isQueued: false,
        isExpired: false,
        remainingSeconds: ttlSeconds,
      });
      continue;
    }

    const cascadeStartMs = Math.max(viewedAtMs, cascadePrevExpireMs);
    const cascadeExpireMs = cascadeStartMs + ttlMs;
    cascadePrevExpireMs = cascadeExpireMs;

    const isExpired = nowMs >= cascadeExpireMs;
    const isActive = nowMs >= cascadeStartMs && nowMs < cascadeExpireMs;
    const isQueued = nowMs < cascadeStartMs;
    const remainingSeconds = isExpired
      ? 0
      : isActive
      ? Math.max(1, Math.ceil((cascadeExpireMs - nowMs) / 1000))
      : ttlSeconds;

    result.set(msg.messageId, {
      isViewed: true,
      viewedAtMs,
      cascadeStartMs,
      cascadeExpireMs,
      isActive,
      isQueued,
      isExpired,
      remainingSeconds,
    });
  }

  return result;
}

/**
 * Comprehensive Viewer Burner Cascade Engine
 *
 * Evaluates the status of all burner channel messages from the perspective of viewerEmail:
 * - Recipient messages: Start 20s burn only once viewed by viewerEmail in the app, cascading sequentially.
 * - Outgoing (own) messages: Track each recipient's cascade independently; deletes only once all
 *   recipients have completed their burn.
 */
export function computeViewerBurnerCascade(params: {
  messages: BurnerMessageInput[];
  viewerEmail: string;
  participants: string[];
  receiptsByMessageId?:
    | Map<string, Array<{ senderEmail: string; readAtIso?: string; status?: string }>>
    | Record<string, Array<{ senderEmail: string; readAtIso?: string; status?: string }>>;
  localViewMap?: Record<string, number>;
  nowMs: number;
  ttlSeconds?: number;
  userNameLookup?: (email: string) => string;
}): Map<string, ViewerBurnerCascadeItem> {
  const {
    messages,
    viewerEmail,
    participants,
    receiptsByMessageId,
    localViewMap,
    nowMs,
    ttlSeconds = 20,
    userNameLookup = (email: string) => {
      const prefix = email.split('@')[0] || email;
      return prefix.charAt(0).toUpperCase() + prefix.slice(1);
    },
  } = params;

  const result = new Map<string, ViewerBurnerCascadeItem>();
  const normViewer = viewerEmail.toLowerCase().trim();

  // 1. Pre-calculate cascade for viewer as a recipient over all incoming messages
  const incomingForViewer = messages.filter(
    (m) => m.senderEmail.toLowerCase().trim() !== normViewer
  );
  const viewerCascadeMap = computeSingleRecipientCascade(
    incomingForViewer,
    normViewer,
    receiptsByMessageId,
    localViewMap,
    nowMs,
    ttlSeconds
  );

  // 2. Pre-calculate cascades for all other participants as recipients
  const otherParticipants = participants.filter(
    (p) => p.toLowerCase().trim() !== normViewer
  );
  const peerCascades = new Map<string, ReturnType<typeof computeSingleRecipientCascade>>();

  for (const peerEmail of otherParticipants) {
    const normPeer = peerEmail.toLowerCase().trim();
    const incomingForPeer = messages.filter(
      (m) => m.senderEmail.toLowerCase().trim() !== normPeer
    );
    peerCascades.set(
      normPeer,
      computeSingleRecipientCascade(
        incomingForPeer,
        normPeer,
        receiptsByMessageId,
        localViewMap,
        nowMs,
        ttlSeconds
      )
    );
  }

  // 3. For each message in the channel, construct the ViewerBurnerCascadeItem
  for (const msg of messages) {
    const isOwn = msg.senderEmail.toLowerCase().trim() === normViewer;

    if (!isOwn) {
      // Recipient view
      const item = viewerCascadeMap.get(msg.messageId) || {
        isViewed: false,
        isActive: false,
        isQueued: false,
        isExpired: false,
        remainingSeconds: ttlSeconds,
      };

      const summaryLabel = item.isActive
        ? `${item.remainingSeconds}s`
        : item.isQueued
        ? `⏳ queued (${ttlSeconds}s)`
        : `⏳ burns ${ttlSeconds}s once viewed`;

      result.set(msg.messageId, {
        messageId: msg.messageId,
        isOwn: false,
        isViewed: item.isViewed,
        viewedAtMs: item.viewedAtMs,
        cascadeStartMs: item.cascadeStartMs,
        cascadeExpireMs: item.cascadeExpireMs,
        isActive: item.isActive,
        isQueued: item.isQueued,
        isExpired: item.isExpired,
        remainingSeconds: item.remainingSeconds,
        summaryLabel,
      });
    } else {
      // Sender view
      const targetPeers = otherParticipants.length > 0 ? otherParticipants : [];
      const peerStatuses: PeerRecipientBurnStatus[] = [];

      for (const peerEmail of targetPeers) {
        const normPeer = peerEmail.toLowerCase().trim();
        const peerMap = peerCascades.get(normPeer);
        const pItem = peerMap?.get(msg.messageId) || {
          isViewed: false,
          isActive: false,
          isQueued: false,
          isExpired: false,
          remainingSeconds: ttlSeconds,
        };

        peerStatuses.push({
          email: peerEmail,
          name: userNameLookup(peerEmail),
          isViewed: pItem.isViewed,
          viewedAtMs: pItem.viewedAtMs,
          isActive: pItem.isActive,
          isQueued: pItem.isQueued,
          isExpired: pItem.isExpired,
          remainingSeconds: pItem.remainingSeconds,
        });
      }

      const allRecipientsExpired =
        peerStatuses.length > 0 && peerStatuses.every((p) => p.isExpired);
      const anyRecipientActive = peerStatuses.some((p) => p.isActive);
      const anyRecipientQueued = peerStatuses.some((p) => p.isQueued);
      const anyRecipientViewed = peerStatuses.some((p) => p.isViewed);

      // Create human-friendly summary label
      let summaryLabel = '';
      if (!anyRecipientViewed) {
        const names = peerStatuses.map((p) => p.name).join(', ');
        summaryLabel = names
          ? `⏳ Unread by ${names} (burns ${ttlSeconds}s once viewed)`
          : `⏳ Burns ${ttlSeconds}s once viewed`;
      } else if (peerStatuses.length === 1) {
        const p = peerStatuses[0];
        if (p.isExpired) {
          summaryLabel = `🔥 Burned by ${p.name}`;
        } else if (p.isActive) {
          summaryLabel = `🔥 ${p.name} (${p.remainingSeconds}s)`;
        } else if (p.isQueued) {
          summaryLabel = `⏳ ${p.name} queued (${ttlSeconds}s)`;
        } else {
          summaryLabel = `⏳ Unread by ${p.name}`;
        }
      } else {
        const parts = peerStatuses.map((p) => {
          if (p.isExpired) return `Burned by ${p.name}`;
          if (p.isActive) return `${p.name} (${p.remainingSeconds}s)`;
          if (p.isQueued) return `${p.name} queued`;
          return `${p.name} unread`;
        });
        summaryLabel = parts.join(' • ');
      }

      result.set(msg.messageId, {
        messageId: msg.messageId,
        isOwn: true,
        isViewed: anyRecipientViewed,
        isActive: anyRecipientActive,
        isQueued: !anyRecipientActive && anyRecipientQueued,
        isExpired: allRecipientsExpired,
        remainingSeconds: anyRecipientActive
          ? Math.min(
              ...peerStatuses
                .filter((p) => p.isActive)
                .map((p) => p.remainingSeconds)
            )
          : ttlSeconds,
        allRecipientsExpired,
        peerStatuses,
        summaryLabel,
      });
    }
  }

  return result;
}
