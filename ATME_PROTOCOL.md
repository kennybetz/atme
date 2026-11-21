# `ATME/1.0` — `@me` Open Micro-Messaging Protocol Specification (`@me/simple`)

> **Interoperable By Design (`@me/simple` ↔ Encrypted `@me` Branches)**
> Every `@me` branch—including **`@me/simple`**—speaks **`ATME/1.0`** MIME envelopes over standard email (`SMTP`/`IMAP`/Gmail API).
> On the `simple` branch, outbound messages use fast UTF-8 JSON (`cleartext-json`) for instant prototyping, while inbound parsing seamlessly accepts **both** cleartext JSON packets and Curve25519 OpenPGP packets sent by encrypted `@me` branches.

---

## 1. Dual-Mode Packet Flow (`cleartext-json` + OpenPGP Interop)

```
[@me/simple User]
       │  1a. Default Outbound: serialize UTF-8 JSON (<1ms)
       │      Content-Type: application/vnd.atme.packet+json (atme-packet.json)
       ▼
[Email Transport (Gmail / Outlook / IMAP)] ── Strict Gate ignores 100% of normal emails
       │
       ├──▶ [@me/simple Peer]: parses JSON directly (<1ms)
       └──▶ [Encrypted @me Peer]: verifies X-ATME-Protocol & ingests JSON seamlessly

[Encrypted @me Peer Replies with OpenPGP]
       │  Content-Type: application/vnd.atme.packet+pgp (atme-packet.pgp)
       ▼
[@me/simple User]: decrypts automatically using background-hydrated Curve25519 keys ✓
```

---

## 2. Core `ATME/1.0` Interop Contract

When asking an AI coding assistant to extend `@me/simple`, keep these rules intact:

| # | Contract Field | `@me/simple` Default | Encrypted `@me` Peer Interop |
| :--- | :--- | :--- | :--- |
| **1** | **`X-ATME-Protocol`** | `ATME/1.0` | Required so the Strict Filter separates chat packets from normal email. |
| **2** | **MIME Payload Part** | `application/vnd.atme.packet+json` (`atme-packet.json`) | Parser also accepts & decrypts `application/vnd.atme.packet+pgp` (`atme-packet.pgp`). |
| **3** | **`X-ATME-Encryption`** | `cleartext-json` | Also accepts `openpgp-asymmetric` and `openpgp-invite-key`. |
| **4** | **Public Key Part** | Omitted unless PGP encrypted | Background-hydrated Curve25519 keys unlock encrypted peer replies automatically. |
| **5** | **99-User Hard Cap** | `MAX_CHANNEL_AND_GROUP_USERS = 99` | Protects consumer Gmail/Outlook accounts from SMTP fanout limits. |
| **6** | **Extension Hook** | `payload.branchMod` + `fallbackBody` | Add custom features (Polls, IOUs, WebRTC rooms) without breaking other branches. |

---

## 3. Required MIME Headers (`src/protocol/mimeBuilder.ts`)

Every outbound `ATME/1.0` email MUST include:

```http
MIME-Version: 1.0
Subject: [@me] Message (simple-squad) [ch_simple_squad]
X-ATME-Protocol: ATME/1.0
X-ATME-Branch: @me/simple
X-ATME-Packet-Id: pkt_...
X-ATME-Packet-Type: chat.message
X-ATME-Channel-Id: ch_...
X-ATME-Channel-Type: dm | group | workspace-channel | vault
X-ATME-Encryption: cleartext-json | openpgp-asymmetric | openpgp-invite-key
```

> **Backward Compatibility:** `mimeParser.ts` also recognizes legacy `X-DontCall-Protocol: DCP/1.0` and `application/vnd.dontcall.packet+pgp`.

---

## 4. Packet Schema (`src/protocol/types.ts`)

```ts
export interface AtmePacket {
  protocol: 'ATME/1.0' | 'DCP/1.0';
  packetId: string;
  type:
    | 'chat.message'
    | 'chat.reaction'
    | 'chat.edit'
    | 'chat.member-update'
    | 'chat.branch-mod';
  encryptionMode: 'cleartext-json' | 'openpgp-asymmetric' | 'openpgp-invite-key';
  channel: {
    id: string;
    type: 'dm' | 'group' | 'workspace-channel' | 'vault';
    name: string;
    participants: string[]; // Hard capped at 99
  };
  sender: {
    email: string;
    displayName: string;
    handle?: string;        // '@' + letters/numbers/underscores
    provider: 'gmail' | 'outlook' | 'yahoo' | 'proton' | 'custom-domain';
    pgpFingerprint?: string;    // Optional in cleartext-json mode; required for OpenPGP
    publicKeyArmored?: string;  // Optional in cleartext-json mode; required for OpenPGP
    profileCard?: {
      displayName: string;
      handle: string;
      avatarDataUrl?: string;
      bio?: string;
      updatedAt: string;
    };
  };
  payload: {
    messageId: string;
    text?: string;
    branchMod?: {
      branchId: string;
      modId: string;
      title: string;
      fallbackBody: string;
      data: Record<string, unknown>;
    };
  };
  sentAt: string;
}
```

---

## 5. Adding Custom Features Safely

1. Create a feature branch (`git checkout -b feat/your-feature`).
2. Update [`src/protocol/branchManifest.ts`](./src/protocol/branchManifest.ts) with your branch ID and mod metadata.
3. Always provide `payload.text` and `payload.branchMod.fallbackBody` so friends running older or unmodded `@me` branches still see clean messages.
4. Run `npx vitest run` and `npm run build` before committing!
