# 🌿 Build `@me/simple` With AI & Git Version Control

> **Start Simple. Build Incrementally. Ship Safely.**
> **`@me/simple`** is the streamlined, barebones messaging scaffold of `@me`.
> Optional heavy features—outbound OpenPGP encryption locks, 20-second Burner Chats, In-Chat Polls, Honor IOUs, Camera Emoji Stickers, and unread thread dividers—have been cleanly removed so students, solo builders, and squads can study the core architecture and practice adding features back with **AI + Git best practices**.

---

## 🗺️ 1. What Makes `@me/simple` Different From `main`

| Capability | `main` (`@me/core`) | `simple` (`@me/simple`) |
| :--- | :--- | :--- |
| **Outbound MIME Packet** | OpenPGP encrypted (`atme-packet.pgp`) | **Cleartext JSON (`application/vnd.atme.packet+json`)** in `<1ms` |
| **Inbound Interoperability** | Decrypts `ATME/1.0` OpenPGP packets | **Decrypts BOTH JSON and OpenPGP `ATME/1.0` packets** |
| **Sign-In** | Google 1-Click OAuth / Demo Picker | **Hardened Google 1-Click OAuth** + Client ID pre-validator |
| **Core Chat Features** | DMs, Groups (up to 99), Broadcast Channels, Voice, Photos, Reactions, Read Receipts + Burners, IOUs, Polls, Stickers, Workbench | **Clean Core Only:** DMs, Groups (up to 99), Broadcast Channels, Voice Notes, Camera Photos, Emoji Reactions, Read Receipts |

---

## 🛠️ 2. Quickstart & Local Testing

```bash
npm install
npx vitest run          # Runs all 10 ATME/1.0 protocol & OAuth validation unit tests
npm run build           # Type-checks (tsc -b) + builds production dist/
npm run dev -- --host localhost --port 5173
```

Open:
- **Messenger UI:** `http://localhost:5173/`
- **Educational Site & AI Labs:** `http://localhost:5173/website/index.html`
- **Google OAuth Tester:** `http://localhost:5173/?view=google-oauth&no_onboarding=1`

> **Important for Live Google OAuth:** Always open the app on `http://localhost:5173` (not `127.0.0.1`), and paste ONLY a Cloud Web **Client ID** ending in `.apps.googleusercontent.com`—never a `GOCSPX-` Client Secret—to avoid `Error 401: invalid_client`.

---

## 🌿 3. The 5 AI + Git Best Practices

1. **Always Create a Feature Branch First:**
   ```bash
   git checkout simple && git pull
   git checkout -b feat/my-feature
   ```
   If an AI refactor goes sideways, `simple` stays untouched and you can reset safely.
2. **Keep Prompts Anchored to Architecture Files:**
   Point your AI assistant directly to [`ATME_PROTOCOL.md`](./ATME_PROTOCOL.md), [`src/protocol/types.ts`](./src/protocol/types.ts), and [`src/protocol/mimeParser.ts`](./src/protocol/mimeParser.ts) so new features reuse existing packet helpers rather than duplicating logic.
3. **Separate Pure Logic From UI:**
   When adding timers, ledgers, or vote counters (like Burners or IOUs), build pure TypeScript helper functions first so Vitest can test edge cases deterministically in milliseconds.
4. **Gate Every Change With Tests & Strict Types:**
   Require every feature branch to pass:
   ```bash
   npx tsc --noEmit --noUnusedLocals --noUnusedParameters
   npx vitest run
   npm run build
   ```
5. **Commit Small, Review Clean Diffs:**
   Inspect `git diff` to prune dead imports, debug `console.log`s, or commented-out code before committing and merging.

---

## 🧪 4. Copy-Paste AI Feature Labs (Simple → Full)

### Lab 1: Outbound OpenPGP End-to-End Encryption
```bash
git checkout -b feat/outbound-openpgp
```
> **Prompt for AI:**
> *"Read `ATME_PROTOCOL.md`, `src/crypto/openpgpService.ts`, `src/protocol/mimeBuilder.ts`, and `dispatchDcpEmailPacket` in `src/App.tsx`. Encrypt outbound `DcpPacket` JSON with `encryptDcpPayloadAsymmetric()` whenever peers have `publicKeyArmored`, keeping `cleartext-json` as fallback when keys are absent. Add a test in `src/protocol.test.ts` and run `npx vitest run`."*

### Lab 2: 20-Second Cascade Burner Chats
```bash
git checkout -b feat/cascade-burner-chats
```
> **Prompt for AI:**
> *"Create `src/protocol/burnerCascade.ts` exporting pure functions that expire viewed messages sequentially (20s each). Add Vitest tests asserting state at 0s, 20s, and 40s, then add an optional Burner toggle to the New Chat dialog and countdown badges in `src/App.tsx`."*

### Lab 3: Interactive In-Chat Polls (`chat.poll` / `chat.poll-vote`)
```bash
git checkout -b feat/in-chat-polls
```
> **Prompt for AI:**
> *"Add event-sourced Polls using `chat.poll` and `chat.poll-vote` packet types in `src/protocol/types.ts`. Deduplicate votes by sender email inside `freeflowStream`, add a `<dialog closedby="any">` poll creator in `src/App.tsx`, and render accessible percentage bars."*

### Lab 4: Peer-to-Peer Honor IOU Ledger (`chat.iou`)
```bash
git checkout -b feat/honor-iou-ledger
```
> **Prompt for AI:**
> *"Build `src/protocol/iouLedger.ts` to reduce signed `chat.iou` packets into per-peer whole-number balances (debtor issues `send-iou`, creditor confirms `collect`). Add Vitest tests and a clean split-column IOU wallet modal."*

### Lab 5: Camera Emoji Stickers (`<canvas>` Compositing)
```bash
git checkout -b feat/camera-emoji-stickers
```
> **Prompt for AI:**
> *"Inside `cameraCaptureDialogRef` in `src/App.tsx`, let users drop draggable/resizable emoji stickers (`{ id, emoji, xPct, yPct, sizePx }`) over captured photos using Pointer Events and composite them onto an offscreen `<canvas>` before sending."*

### Lab 6: Zero-Server P2P Live Audio & Video (WebRTC + Trystero)
```bash
git checkout -b feat/p2p-webrtc-calls
npm install trystero
```
> **Prompt for AI:**
> *"Read `ATME_PROTOCOL.md` and `src/App.tsx`. Add a header Video Call button that dispatches a `chat.branch-mod` packet (`modId: 'p2p-call'`) with a shared ephemeral room ID and opens a `<dialog>` connecting `getUserMedia()` streams over Trystero."*
