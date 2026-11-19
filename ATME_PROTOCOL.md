# `ATME/1.0` — `@me` Open Micro-Messaging Protocol Specification

> **Minimum Standard for Cross-Branch Interoperability**
> Every `@me` squad branch (`@me/core`, `@me/arcade-squad`, `@me/lunch-table`, `@me/band-room`, `@me/study-vault`, or your own custom fork) speaks **`ATME/1.0`** under the hood. As long as your AI coding assistant keeps the `ATME/1.0` envelope intact, your custom branch can send messages, reactions, IOUs, burners, and custom mods to any friend on any other `@me` branch.

---

## 1. Why `ATME/1.0` Exists

```
[Your Squad Branch: @me/arcade-squad]
         │
         ▼  1. Encrypt JSON + branchMod with OpenPGP (Curve25519)
[RFC 5322 Email + X-ATME-Protocol: ATME/1.0]
         │
         ▼  2. Rides free over Gmail / Outlook / Proton / iCloud ($0 Server)
[Friend's Branch: @me/core or @me/skate-spots]
         │
         ▼  3. Strict 3-Gate Inbox Filter ignores 100% of normal emails
[Decrypted Instant Chat Bubble + Mod Widget (or Fallback Text)]
```

---

## 2. The 5 Non-Negotiable Rules of `ATME/1.0`

When prompting an AI coding assistant to add features to your branch, tell it to follow `ATME_PROTOCOL.md`:

| # | Rule | Standard Value | Why It Matters |
| :--- | :--- | :--- | :--- |
| **1** | **Protocol Header** | `X-ATME-Protocol: ATME/1.0` | Allows the Strict Inbox Filter to accept `@me` packets and ignore 100% of regular spam/school/receipt emails. |
| **2** | **MIME Packet Part** | `application/vnd.atme.packet+pgp` | Holds the OpenPGP ASCII-armored ciphertext (`atme-packet.pgp`). |
| **3** | **Public Key Part** | `application/pgp-keys` | Attaches `sender-pubkey.asc` so friends automatically have your Curve25519 key on first contact. |
| **4** | **99-User Hard Cap** | `MAX_CHANNEL_AND_GROUP_USERS = 99` | Protects personal Gmail/Outlook/iCloud accounts from SMTP rate-limiting when sending group chats or BCC channel stories. |
| **5** | **Graceful Mod Fallback** | `payload.branchMod.fallbackBody` | If your branch invents a new mini-game or widget, friends on other branches still see a clean readable message. |

---

## 3. Required MIME Headers (`src/protocol/mimeBuilder.ts`)

Every outbound `ATME/1.0` email MUST include:

```http
MIME-Version: 1.0
Subject: [@me] Encrypted message (friday-hangout) [ch_product_launch]
X-ATME-Protocol: ATME/1.0
X-ATME-Branch: @me/core
X-ATME-Packet-Id: pkt_...
X-ATME-Packet-Type: chat.message
X-ATME-Channel-Id: ch_...
X-ATME-Channel-Type: dm | group | workspace-channel | broadcast-channel | vault
X-ATME-Encryption: openpgp-asymmetric | openpgp-invite-key
X-ATME-Sender-FP: <40-hex Curve25519 PGP Fingerprint>
```

> **Backward Compatibility:** `mimeParser.ts` also accepts legacy `X-DontCall-Protocol: DCP/1.0` and `application/vnd.dontcall.packet+pgp` so older packets never break.

---

## 4. Decrypted JSON Packet Schema (`src/protocol/types.ts`)

Inside the `-----BEGIN PGP MESSAGE-----` block is a UTF-8 JSON object matching `AtmePacket`:

```ts
export interface AtmePacket {
  protocol: 'ATME/1.0';
  packetId: string;
  type:
    | 'chat.message'
    | 'chat.reaction'
    | 'chat.receipt'
    | 'chat.iou'
    | 'chat.poll'
    | 'chat.poll-vote'
    | 'chat.member-update'
    | 'chat.shred-request'
    | 'chat.shred-ack'
    | 'chat.branch-mod';
  encryptionMode: 'openpgp-asymmetric' | 'openpgp-invite-key';
  channel: {
    id: string;
    type: 'dm' | 'group' | 'workspace-channel' | 'vault' | 'broadcast-channel';
    name: string;
    participants: string[]; // Hard capped at 99
    isBurner?: boolean;     // 20s sequential cascade burn after view
    ephemeralTimerSeconds?: 0 | 15 | 20 | 60 | 300 | 3600 | 86400;
  };
  sender: {
    email: string;
    displayName: string;
    handle?: string;        // Hardcoded '@' + letters/numbers/underscores
    provider: 'gmail' | 'outlook' | 'yahoo' | 'proton' | 'custom-domain';
    pgpFingerprint: string;
    publicKeyArmored: string;
    profileCard?: {
      displayName: string;
      handle: string;
      avatarDataUrl?: string; // Custom upload; if omitted, Boring Avatars Beam is generated from email
      bio?: string;
      updatedAt: string;
    };
  };
  payload: {
    messageId: string;
    text?: string;
    ephemeralTtlSeconds?: 0 | 15 | 20 | 60 | 300 | 3600 | 86400;
    iou?: {
      iouId: string;
      action: 'send-iou' | 'collect';
      amount: number;
      unit: string;
      note?: string;
      debtorEmail: string;
      creditorEmail: string;
    };
    branchMod?: {
      branchId: string;     // e.g. "@me/arcade-squad"
      modId: string;        // e.g. "pixel-duel"
      title: string;        // e.g. "Pixel Duel 1v1"
      fallbackBody: string; // Shown on branches that don't have this mod installed
      data: Record<string, unknown>;
    };
  };
  sentAt: string;
}
```

---

## 5. How to Add a Custom Feature on Your Squad's Branch

1. Open [`src/protocol/branchManifest.ts`](./src/protocol/branchManifest.ts) and set your `branchId` (e.g., `'@me/skate-spots'`).
2. When sending a custom widget or game state, use `type: 'chat.branch-mod'` (or attach `branchMod` to a `chat.message` packet) and always populate `fallbackBody` + `text`.
3. Run `npx vitest run` to verify all 12 `ATME/1.0` compliance and encryption tests pass!
