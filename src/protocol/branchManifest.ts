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
 * other `@me` branches can still message you even when you add wild custom features here.
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
  /** Your custom branch name (e.g. '@me/core', '@me/arcade-squad', '@me/lunch-table') */
  branchId: string;
  /** Short badge shown in the app's Account & Protocol Inspector */
  branchBadge: string;
  /** Target micro-group size (Dunbar Support Clique: 3-5 core friends, Sympathy Squad: 10-15) */
  recommendedSquadSize: string;
  /** Hard email anti-spam ceiling across all ATME/1.0 branches */
  maxParticipantsCap: 99;
  /** Active custom mods enabled on this branch */
  mods: SquadModDescriptor[];
}

export const ACTIVE_BRANCH_MANIFEST: AtmeBranchManifest = {
  protocolStandard: 'ATME/1.0',
  branchId: '@me/core',
  branchBadge: 'ATME/1.0 • @me/core',
  recommendedSquadSize: '3–5 Core Friends (15 Squad / 99 Max)',
  maxParticipantsCap: 99,
  mods: [
    {
      id: 'burner-20s',
      icon: '🔥',
      name: '20s Cascade Burner',
      shortDescription: 'Sequential 20s self-destruct after viewing',
      enabled: true,
    },
    {
      id: 'honor-iou',
      icon: '🪙',
      name: 'Squad IOU Ledger',
      shortDescription: 'Peer-to-peer favor & boba tracker',
      enabled: true,
    },
    {
      id: 'bcc-channels',
      icon: '📡',
      name: 'Anon BCC Channels',
      shortDescription: 'Story broadcasts with anonymous reactions',
      enabled: true,
    },
    {
      id: 'face-stamps',
      icon: '🎨',
      name: 'Emoji Camera Stamps',
      shortDescription: 'Multi-emoji privacy stamps on camera snaps',
      enabled: true,
    },
  ],
};
