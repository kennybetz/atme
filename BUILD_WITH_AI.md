# 🌿 Build `@me` With AI — The Squad Branch Playbook

> **For 3–5 Best Friends & 10–15 Person Squads**
> Anthropological research (Dunbar's *Support Clique*) and Pew teen studies show **80%+ of all daily messages go to just 3 to 5 close friends**, with extended squads (lunch table, band, gaming crew, robotics team) topping out around **10 to 15 people**.
>
> Big Tech builds bloated apps for **2,000,000,000 strangers**. `@me` is a blueprint you can **branch with AI in 10 minutes**, customize for your 5 best friends, and run for **\$0/month** on recycled 1982 email tech (`SMTP`/`IMAP` + OpenPGP).

---

## 🗺️ 1. The 4-Step Visual Pipeline

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  1. FORK & CLONE │ ──▶ │  2. NEW BRANCH   │ ──▶ │   3. PROMPT AI   │ ──▶ │ 4. PUSH & QR SHARE│
│  Grab the @me    │     │  git checkout -b │     │  "Add a soundpad │     │ Cloudflare Pages │
│  blueprint repo  │     │  my-squad        │     │  or mini-game"   │     │ deploys in 45s   │
└──────────────────┘     └──────────────────┘     └──────────────────┘     └──────────────────┘
```

---

## 🧰 2. The \$0 Teen Builder Stack (What You Need)

| Icon | Tool | What It Does | Cost |
| :---: | :--- | :--- | :---: |
| 🐙 | **GitHub** | Holds your code in the cloud and tracks every squad branch. | **\$0** |
| 🌿 | **Git** | Your time machine. Creates save points (`commits`) and parallel universes (`branches`). | **\$0** |
| 🤖 | **AI Coding IDE** | Antigravity, Cursor, Windsurf, Claude, or Gemini — turns plain English into working React code. | **\$0 Tier** |
| ⚡ | **Node.js + Vite** | Runs the live `@me` phone preview on your laptop at `http://localhost:5173`. | **\$0** |
| ☁️ | **Cloudflare Pages** | Watches your GitHub branch and puts your app live on a real `https://` link automatically. | **\$0** |
| ✉️ | **Email + OpenPGP** | Recycled 40-year-old email servers act as your encrypted database. No backend servers to rent! | **\$0** |

---

## 🌿 3. Git & Version Control in 60 Seconds (Zero Jargon)

Think of **Git** like save files in a video game:

```
main trunk (@me/core — ATME/1.0 engine)
  ●─────────●─────────●─────────●
             \
              \  git checkout -b arcade-squad
               ●─────────●─────────●  (Your Squad's Custom Branch!)
```

- **`main` (The Trunk):** The core `@me` engine (`ATME/1.0` encryption, 20s burners, IOUs, BCC channels, Boring Avatars).
- **`branch` (Your Parallel Universe):** When you run `git checkout -b my-squad`, you get your own playground. If your AI prompt breaks something, `main` is still 100% safe.
- **`commit` (Save Point):** Saves a snapshot of your working code so you can rewind anytime.
- **`push` (Go Live):** Sends your save point to GitHub, which triggers Cloudflare Pages to update your friends' phones.

### Ask Your AI to Handle Git For You!
You don't even have to memorize terminal commands. Just tell your AI agent:
- 💬 *"Create a new git branch called `skate-crew` so I can test a new feature."*
- 💬 *"Run the tests (`npx vitest run`) and if everything passes, commit my changes with a clean summary."*
- 💬 *"Oops, that last change broke the layout—revert back to my previous commit."*

---

## 🎮 4. Follow-Along Tutorials: Copy-Paste AI Prompts

Open this folder in your AI coding tool and try any of these 4 starter builds:

### Build #1: Brand Your Squad Branch (2 Minutes)
> **Copy & Paste to AI:**
> *"Read `src/protocol/branchManifest.ts`. Change `branchId` to `'@me/night-owls'`, update `branchBadge` to `'ATME/1.0 • @me/night-owls'`, and add a new mod entry to `mods` for our squad."*

### Build #2: Add a 1-Tap "Roll the Dice / Coin Flip" Mod in Chat (5 Minutes)
> **Copy & Paste to AI:**
> *"Read `ATME_PROTOCOL.md` and `src/App.tsx`. Add a 🎲 button inside the chat `+` composer tray that sends an `ATME/1.0` message with a random 1–20 D&D dice roll or coin flip inside `payload.branchMod` (`modId: 'dice-roll'`), and render a cool neon badge for it inside the chat bubble!"*

### Build #3: Custom Boba / Pizza IOU Presets (5 Minutes)
> **Copy & Paste to AI:**
> *"In `src/App.tsx`, inside the Send IOU modal, add 3 quick-tap preset pills above the note input: `🧋 Boba (1)`, `🍕 Slice (2)`, and `🚗 Ride Home (3)` that auto-fill the IOU amount and note with one tap."*

### Build #4: Squad Soundboard / Vibe Check Status (10 Minutes)
> **Copy & Paste to AI:**
> *"Using the Web Audio API (zero external audio files needed), add 3 synth sound effects (8-bit Coin, Laser, Airhorn) that play when a friend sends a `chat.branch-mod` sound packet, while keeping `ATME/1.0` compatibility in `src/protocol.test.ts`."*

---

## 🚀 5. Ship It to Your 5 Friends' Phones

1. **Test Locally:**
   ```bash
   npm install
   npm run dev
   npx vitest run
   ```
2. **Push Your Branch to GitHub:**
   Ask your AI: *"Commit all my changes and push this branch to my GitHub repo."*
3. **Connect Cloudflare Pages (One-Time Setup, 60 Seconds):**
   - Log into [Cloudflare Dashboard](https://dash.cloudflare.com) $\rightarrow$ **Workers & Pages** $\rightarrow$ **Create** $\rightarrow$ **Pages** $\rightarrow$ **Connect to Git**.
   - Select your forked `@me` repository.
   - Build command: `npm run build` | Build output directory: `dist`.
   - Every branch you push automatically gets its own live preview URL (`https://<your-branch>.<your-project>.pages.dev`)!
4. **Add to Home Screen at the Lunch Table:**
   - Open your branch URL on your phone, tap the **QR Code** button in the top-right of `@me`, and let your 4 best friends scan it.
   - On iOS Safari: **Share $\rightarrow$ Add to Home Screen**. On Android Chrome: **Install App**.
