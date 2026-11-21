/**
 * @me Squad Branch Manifest (`ATME/1.0`)
 *
 * 👋 HEY AI BUILDER!
 * If you forked or branched `@me` for your friend group, this is the #1 file to edit first!
 *
 * Try prompting your AI coding assistant:
 *   "Update branchManifest.ts so our branch is called @me/skate-crew and add a custom squad mod!"
 *
 * Because every branch speaks the `ATME/1.0` standard under the hood, your friends on
 * other `@me` branches (including encrypted PGP branches) can still message you cleanly.
 */

export interface SquadModDescriptor {
  id: string;
  icon: string;
  name: string;
  shortDescription: string;
  enabled: boolean;
}

export interface AtmeBranchManifest {
  /** Protocol standard — keep as 'ATME/1.0' so your branch can talk to all other @me branches! */
  protocolStandard: 'ATME/1.0';
  /** Machine-readable branch identifier sent in `X-ATME-Branch` headers */
  branchId: string;
  /** Human-readable branch name (e.g. '@me/simple', '@me/arcade-squad') */
  branchName: string;
  /** Short badge shown in branch headers and docs */
  branchBadge: string;
  /** One-line description of this branch */
  tagline: string;
  /** Target micro-group size (Dunbar Support Clique: 3-5 core friends, Sympathy Squad: 10-15) */
  recommendedSquadSize: string;
  /** Hard email anti-spam ceiling across all ATME/1.0 branches */
  maxParticipantsCap: 99;
  /** Active starter capabilities enabled on this branch */
  activeMods: SquadModDescriptor[];
}

export const ACTIVE_BRANCH_MANIFEST: AtmeBranchManifest = {
  protocolStandard: 'ATME/1.0',
  branchId: 'atme-simple',
  branchName: '@me/simple',
  branchBadge: 'ATME/1.0 • @me/simple',
  tagline: 'Barebones AI Coding Scaffold • Clean Messaging Core over Recycled Email',
  recommendedSquadSize: '3–5 Core Friends (15 Squad / 99 Max)',
  maxParticipantsCap: 99,
  activeMods: [
    {
      id: 'google-oauth',
      icon: '🔑',
      name: '1-Click Google OAuth',
      shortDescription: 'Instant Gmail & school Google Workspace sign-in with GIS',
      enabled: true,
    },
    {
      id: 'atme-json-pgp-interop',
      icon: '⚡',
      name: 'ATME/1.0 JSON + PGP Interop',
      shortDescription:
        'Fast cleartext JSON outbound packets with automatic OpenPGP decryption for encrypted peers',
      enabled: true,
    },
    {
      id: 'groups-and-dms',
      icon: '💬',
      name: 'DMs & 99-User Groups',
      shortDescription: '1-to-1 DMs, 99-cap friend groups, voice notes, and camera photos',
      enabled: true,
    },
  ],
};
