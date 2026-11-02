/**
 * Burner Chat Cascade Timing Engine
 *
 * Implements sequential cascading deletion where each message deletes after 20 seconds,
 * and each message starts its timer ONLY when the previous message is deleted:
 * - 1 message viewed = 20 seconds total
 * - 2 messages viewed = 40 seconds total
 * - 3 messages viewed = 60 seconds total
 *
 * For sorted messages M_1, ..., M_n:
 * T_start(M_1) = T_viewed(M_1)
 * T_expire(M_1) = T_start(M_1) + 20_000ms
 * For i > 1:
 * T_start(M_i) = max(T_viewed(M_i), T_expire(M_{i-1}))
 * T_expire(M_i) = T_start(M_i) + 20_000ms
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
