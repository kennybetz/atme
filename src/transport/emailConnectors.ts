/**
 * Zero-Backend Email Transport Adapters
 *
 * Connects the user's device directly to:
 *   1. Gmail REST API v1 (via Google Identity Services OAuth2 token in browser)
 *   2. Microsoft Graph API v1.0 (via MSAL OAuth2 token in browser)
 *   3. Proton Mail Bridge / Standard IMAP Bridge (`127.0.0.1` or JMAP endpoint)
 *
 * All queries strictly filter for `[DontCall]` / `X-DontCall-Protocol: DCP/1.0`
 * so regular personal/work emails are never downloaded into the app.
 */

import { DCP_PROTOCOL_VERSION, DCP_SUBJECT_PREFIX, RawTransportEmail } from '../protocol/types';
import { parseRawMimeStructure } from '../protocol/mimeParser';

export interface ProviderConnectionConfig {
  provider: 'gmail' | 'outlook' | 'yahoo' | 'proton';
  accessToken?: string;
  bridgeEndpointUrl?: string;
  autoArchiveFromPrimaryInbox?: boolean;
}

/**
 * Encodes an RFC 5322 raw MIME string as URL-safe Base64 for Gmail API `messages.send`
 */
export function encodeBase64Url(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decodes URL-safe Base64 from Gmail API `format=raw` responses
 */
export function decodeBase64Url(input: string): string {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

/**
 * Direct Client-to-Gmail REST API v1 Adapter (Zero Developer Server)
 */
export class GmailDirectTransport {
  private accessToken: string;

  constructor(accessToken: string) {
    this.accessToken = accessToken;
  }

  /**
   * Queries Gmail strictly for @me (ATME/1.0) protocol messages, ignoring 100% of normal emails
   */
  static getStrictGmailSearchQuery(): string {
    return `subject:"${DCP_SUBJECT_PREFIX}" ("atme-packet.json" OR "atme-packet.pgp" OR "dontcall-packet.pgp")`;
  }

  /**
   * Sends a PGP-encrypted DCP/1.0 MIME email directly through the user's Gmail account
   */
  async sendRawMimeEmail(email: RawTransportEmail): Promise<{ providerMessageId: string }> {
    const rawBase64Url = encodeBase64Url(email.rawMime);
    const response = await fetch(
      'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ raw: rawBase64Url }),
      }
    );

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Gmail API send failed (${response.status}): ${errText}`);
    }

    const data = (await response.json()) as { id: string };
    return { providerMessageId: data.id };
  }

  /**
   * Creates a Gmail Inbox Filter (once per account) so `[DontCall]` / `[@me]` packets
   * skip the user's primary regular Inbox (`removeLabelIds: ['INBOX']`, archiving them).
   */
  async createAutoCleanInboxFilter(
    accountEmail?: string
  ): Promise<{ filterId: string; alreadyConfigured?: boolean }> {
    const cacheKey = accountEmail
      ? `atme_gmail_filter_created_${accountEmail.trim().toLowerCase()}`
      : 'atme_gmail_filter_created_default';

    try {
      if (typeof localStorage !== 'undefined' && localStorage.getItem(cacheKey) === 'true') {
        return { filterId: 'cached', alreadyConfigured: true };
      }
    } catch {
      // Ignore storage errors
    }

    const response = await fetch(
      'https://gmail.googleapis.com/gmail/v1/users/me/settings/filters',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          criteria: {
            subject: DCP_SUBJECT_PREFIX,
            hasAttachment: true,
          },
          action: {
            removeLabelIds: ['INBOX'],
          },
        }),
      }
    );

    if (!response.ok) {
      const errText = await response.text();
      if (response.status === 400 && /already exists/i.test(errText)) {
        try {
          if (typeof localStorage !== 'undefined') localStorage.setItem(cacheKey, 'true');
        } catch {
          // ignore
        }
        return { filterId: 'existing', alreadyConfigured: true };
      }
      throw new Error(`Gmail filter creation failed (${response.status}): ${errText}`);
    }

    const data = (await response.json()) as { id: string };
    try {
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem(cacheKey, 'true');
      }
    } catch {
      // ignore
    }
    return { filterId: data.id };
  }

  /**
   * Fetches all emails matching the strict ATME/1.0 search query across Gmail pages (`nextPageToken`)
   * so a new or existing device can hydrate and reconcile its entire ATME message history.
   */
  async fetchDontCallPackets(maxResults = 500): Promise<RawTransportEmail[]> {
    const q = encodeURIComponent(GmailDirectTransport.getStrictGmailSearchQuery());
    const collectedRefs: Array<{ id: string; threadId: string }> = [];
    const seenIds = new Set<string>();
    let pageToken: string | undefined;

    while (collectedRefs.length < maxResults) {
      const pageSize = Math.min(100, maxResults - collectedRefs.length);
      const tokenParam = pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : '';
      const listRes = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/messages?q=${q}&maxResults=${pageSize}${tokenParam}`,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );

      if (!listRes.ok) {
        throw new Error(`Gmail API list failed (${listRes.status})`);
      }

      const listData = (await listRes.json()) as {
        messages?: Array<{ id: string; threadId: string }>;
        nextPageToken?: string;
      };

      if (listData.messages && listData.messages.length > 0) {
        for (const msgRef of listData.messages) {
          if (!seenIds.has(msgRef.id)) {
            seenIds.add(msgRef.id);
            collectedRefs.push(msgRef);
          }
        }
      }

      if (!listData.nextPageToken) break;
      pageToken = listData.nextPageToken;
    }

    if (collectedRefs.length === 0) {
      return [];
    }

    const results: RawTransportEmail[] = [];
    for (const item of collectedRefs) {
      const msgRes = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/messages/${item.id}?format=raw`,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
      if (!msgRes.ok) continue;
      const msgData = (await msgRes.json()) as {
        id: string;
        threadId: string;
        raw: string;
      };
      const rawMime = decodeBase64Url(msgData.raw);
      const parsed = parseRawMimeStructure(rawMime);

      results.push({
        id: msgData.id,
        threadId: msgData.threadId,
        from: parsed.headers['From'] || '',
        to: (parsed.headers['To'] || '')
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        subject: parsed.headers['Subject'] || '',
        date: parsed.headers['Date'] || new Date().toISOString(),
        headers: parsed.headers,
        rawMime,
        encryptedPacketArmored: parsed.encryptedPacketArmored,
        cleartextPacketJson: parsed.cleartextPacketJson,
        attachedPublicKeyArmored: parsed.attachedPublicKeyArmored,
      });
    }

    return results;
  }
}

export interface EmailReconciliationResult {
  reconciledEmails: RawTransportEmail[];
  addedCount: number;
  updatedCount: number;
  removedCount: number;
  verifiedMatchCount: number;
}

function getCanonicalPacketKey(email: RawTransportEmail): string {
  const key =
    email.headers?.['X-ATME-Packet-Id'] ||
    email.headers?.['X-DontCall-Packet-Id'] ||
    email.headers?.['Message-ID'] ||
    email.id;
  return key.trim();
}

function headersMatch(
  a: Record<string, string>,
  b: Record<string, string>
): boolean {
  const aKeys = Object.keys(a);
  const bKeys = Object.keys(b);
  if (aKeys.length !== bKeys.length) return false;
  for (const k of aKeys) {
    if (a[k] !== b[k]) return false;
  }
  return true;
}

function emailRecordsMatch(a: RawTransportEmail, b: RawTransportEmail): boolean {
  return (
    a.id === b.id &&
    (a.threadId || '') === (b.threadId || '') &&
    a.from === b.from &&
    a.subject === b.subject &&
    a.rawMime === b.rawMime &&
    (a.cleartextPacketJson || '') === (b.cleartextPacketJson || '') &&
    (a.encryptedPacketArmored || '') === (b.encryptedPacketArmored || '') &&
    headersMatch(a.headers || {}, b.headers || {})
  );
}

/**
 * Reconciles device local storage against remote mailbox ATME/1.0 packets:
 * - Pulls all missing remote messages onto a new device
 * - Verifies already-loaded messages match remote email content & updates drifted records
 * - Prunes stale non-seed messages for `accountEmail` that no longer exist in the remote mailbox
 */
export function reconcileLocalEmailsWithRemoteMailbox(params: {
  localEmails: RawTransportEmail[];
  remoteEmails: RawTransportEmail[];
  accountEmail: string;
}): EmailReconciliationResult {
  const normAccount = params.accountEmail.trim().toLowerCase();
  const remoteByKey = new Map<string, RawTransportEmail>();

  for (const remote of params.remoteEmails) {
    remoteByKey.set(getCanonicalPacketKey(remote), remote);
  }

  const matchedKeys = new Set<string>();
  const kept: RawTransportEmail[] = [];
  let updatedCount = 0;
  let removedCount = 0;
  let verifiedMatchCount = 0;

  for (const local of params.localEmails) {
    const isDemoLocal = local.id.startsWith('seed_') || local.id.startsWith('reg_');
    const involvesAccount =
      !normAccount ||
      local.from.toLowerCase().includes(normAccount) ||
      local.to.some((t) => t.toLowerCase().includes(normAccount)) ||
      (local.bcc || []).some((b) => b.toLowerCase().includes(normAccount));

    if (isDemoLocal || !involvesAccount) {
      kept.push(local);
      continue;
    }

    const key = getCanonicalPacketKey(local);
    const remote = remoteByKey.get(key);
    if (!remote) {
      removedCount += 1;
      continue;
    }

    matchedKeys.add(key);
    if (emailRecordsMatch(local, remote)) {
      verifiedMatchCount += 1;
      kept.push(local);
    } else {
      updatedCount += 1;
      kept.push({
        ...remote,
        inviteKeyFragment: remote.inviteKeyFragment || local.inviteKeyFragment,
      });
    }
  }

  let addedCount = 0;
  for (const [key, remote] of remoteByKey.entries()) {
    if (!matchedKeys.has(key)) {
      addedCount += 1;
      kept.push(remote);
    }
  }

  const deduped = new Map<string, RawTransportEmail>();
  for (const email of kept) {
    deduped.set(email.id, email);
  }

  const reconciledEmails = Array.from(deduped.values()).sort(
    (a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()
  );

  return {
    reconciledEmails,
    addedCount,
    updatedCount,
    removedCount,
    verifiedMatchCount,
  };
}

/**
 * Direct Client-to-Microsoft Graph API v1.0 Adapter (Outlook / Hotmail / Microsoft 365)
 */
export class OutlookDirectTransport {
  private accessToken: string;

  constructor(accessToken: string) {
    this.accessToken = accessToken;
  }

  static getStrictGraphFilterQuery(): string {
    return `startsWith(subject, '${DCP_SUBJECT_PREFIX}')`;
  }

  /**
   * Sends raw RFC 5322 MIME packet directly via Microsoft Graph `/me/sendMail` (`text/plain` MIME mode)
   */
  async sendRawMimeEmail(email: RawTransportEmail): Promise<{ status: string }> {
    const base64Mime = btoa(
      Array.from(new TextEncoder().encode(email.rawMime), (b) =>
        String.fromCharCode(b)
      ).join('')
    );

    const response = await fetch('https://graph.microsoft.com/v1.0/me/sendMail', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
        'Content-Type': 'text/plain',
      },
      body: base64Mime,
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Microsoft Graph sendMail failed (${response.status}): ${errText}`);
    }

    return { status: 'sent' };
  }
}

/**
 * Returns the provider-specific technical filter specs displayed in the Protocol Inspector
 */
export function getProviderTechnicalSpecs() {
  return [
    {
      id: 'gmail',
      name: 'Google Gmail API (OAuth2 PKCE)',
      protocol: 'HTTPS REST v1 (Direct Browser-to-Google)',
      strictFilterQuery: GmailDirectTransport.getStrictGmailSearchQuery(),
      inboxIsolationRule:
        'Creates a Gmail filter matching subject:"[@me]" + hasAttachment:true that removes the INBOX label (archives to All Mail so Primary Inbox stays clean while ATME sync pulls full history).',
      e2eeSupport:
        'ATME/1.0 JSON + Optional OpenPGP (Curve25519) peer interop.',
    },
    {
      id: 'outlook',
      name: 'Microsoft Outlook / Graph API (OAuth2 PKCE)',
      protocol: 'HTTPS Graph v1.0 (/me/sendMail MIME)',
      strictFilterQuery: `$filter=startsWith(subject,'${DCP_SUBJECT_PREFIX}') and hasAttachments eq true`,
      inboxIsolationRule:
        'Auto-creates Graph Inbox Rule moving X-DontCall-Protocol: ' +
        DCP_PROTOCOL_VERSION +
        ' packets to hidden DontCall folder.',
      e2eeSupport:
        'On-Device OpenPGP (Curve25519). Microsoft servers only see encrypted ASCII armor.',
    },
    {
      id: 'yahoo',
      name: 'Yahoo / iCloud (IMAP IDLE + SMTP / JMAP)',
      protocol: 'IMAPv4 SEARCH HEADER + SMTP Submission',
      strictFilterQuery: `SEARCH HEADER X-DontCall-Protocol "${DCP_PROTOCOL_VERSION}"`,
      inboxIsolationRule:
        'Server-side IMAP HEADER search downloads exclusively DCP/1.0 packets; ignores all standard mail.',
      e2eeSupport: 'On-Device OpenPGP (Curve25519).',
    },
    {
      id: 'proton',
      name: 'Proton Mail (Native OpenPGP + Bridge Option)',
      protocol: 'Native OpenPGP Interop / Local Bridge IMAP (127.0.0.1:1143)',
      strictFilterQuery: `SEARCH HEADER X-DontCall-Protocol "${DCP_PROTOCOL_VERSION}"`,
      inboxIsolationRule:
        'Sieve filter (`header :contains "X-DontCall-Protocol" "DCP/1.0"`) routes directly to DontCall folder.',
      e2eeSupport:
        '100% Native OpenPGP compatibility between Gmail/Outlook app users and Proton Mail accounts.',
    },
  ];
}
