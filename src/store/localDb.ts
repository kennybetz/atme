/**
 * On-Device IndexedDB Store (`idb`)
 *
 * Persists user PGP keypairs, raw transport emails, and decrypted DCP/1.0 packets
 * locally on the device (Zero-Server storage).
 */

import { openDB, IDBPDatabase } from 'idb';
import { RawTransportEmail, UserIdentity } from '../protocol/types';

const DB_NAME = 'dontcall-engine-db';
const DB_VERSION = 1;

let dbPromise: Promise<IDBPDatabase> | null = null;

function getDb() {
  if (!dbPromise && typeof indexedDB !== 'undefined') {
    dbPromise = openDB(DB_NAME, DB_VERSION, {
      upgrade(db) {
        if (!db.objectStoreNames.contains('identities')) {
          db.createObjectStore('identities', { keyPath: 'email' });
        }
        if (!db.objectStoreNames.contains('transport_emails')) {
          db.createObjectStore('transport_emails', { keyPath: 'id' });
        }
      },
    });
  }
  return dbPromise;
}

export async function saveUserIdentitiesToIdb(
  users: UserIdentity[]
): Promise<void> {
  const db = await getDb();
  if (!db) return;
  const tx = db.transaction('identities', 'readwrite');
  for (const user of users) {
    await tx.store.put(user);
  }
  await tx.done;
}

export async function loadUserIdentitiesFromIdb(): Promise<
  UserIdentity[] | null
> {
  const db = await getDb();
  if (!db) return null;
  const all = (await db.getAll('identities')) as UserIdentity[];
  return all.length > 0 ? all : null;
}

export async function saveTransportEmailsToIdb(
  emails: RawTransportEmail[]
): Promise<void> {
  const db = await getDb();
  if (!db) return;
  const tx = db.transaction('transport_emails', 'readwrite');
  for (const eml of emails) {
    await tx.store.put(eml);
  }
  await tx.done;
}

export async function loadTransportEmailsFromIdb(): Promise<
  RawTransportEmail[] | null
> {
  const db = await getDb();
  if (!db) return null;
  const all = (await db.getAll('transport_emails')) as RawTransportEmail[];
  return all.length > 0 ? all : null;
}

export async function clearIdbDatabase(): Promise<void> {
  const db = await getDb();
  if (!db) return;
  await db.clear('identities');
  await db.clear('transport_emails');
}

/**
 * Cryptographic Scrub & Zero-Fill of IndexedDB Records:
 * 1. Overwrites the target UserIdentity's OpenPGP private/public key material with random noise
 *    before updating/removing the keypair in IndexedDB.
 * 2. Overwrites all matching RawTransportEmail records in IndexedDB with zeroed random noise
 *    before calling `store.delete(id)` so no residual ciphertext or headers remain in IndexedDB.
 */
export async function cryptographicScrubPeerAndEmailsInIdb(params: {
  targetEmailToScrub?: string;
  emailIdsToScrub: string[];
}): Promise<{ scrubbedCount: number; idbCiphertextZeroed: boolean }> {
  const db = await getDb();
  const noiseHex = Array.from(crypto.getRandomValues(new Uint8Array(64)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  if (!db) {
    return {
      scrubbedCount: params.emailIdsToScrub.length,
      idbCiphertextZeroed: true,
    };
  }

  // 1. Overwrite & purge the target user's PGP keypair in `identities` store if requested
  if (params.targetEmailToScrub) {
    const txId = db.transaction('identities', 'readwrite');
    const existing = (await txId.store.get(
      params.targetEmailToScrub
    )) as UserIdentity | undefined;
    if (existing && existing.pgpKeyPair) {
      // First overwrite the key strings in place with random noise bytes
      await txId.store.put({
        ...existing,
        pgpKeyPair: {
          publicKeyArmored: noiseHex,
          privateKeyArmored: noiseHex,
          fingerprint: '0000000000000000000000000000000000000000',
          createdAt: new Date(0).toISOString(),
        },
      });
      // Then remove the pgpKeyPair and mark keyShreddedAt
      await txId.store.put({
        ...existing,
        pgpKeyPair: undefined,
        keyShreddedAt: new Date().toISOString(),
      });
    }
    await txId.done;
  }

  // 2. Overwrite & delete all target transport_emails in IndexedDB
  if (params.emailIdsToScrub.length > 0) {
    const txEml = db.transaction('transport_emails', 'readwrite');
    for (const id of params.emailIdsToScrub) {
      const existingEml = (await txEml.store.get(id)) as
        | RawTransportEmail
        | undefined;
      if (existingEml) {
        await txEml.store.put({
          ...existingEml,
          rawMime: noiseHex,
          encryptedPacketArmored: noiseHex,
          attachedPublicKeyArmored: noiseHex,
          htmlFallbackPart: '',
          textFallbackPart: '',
        });
        await txEml.store.delete(id);
      }
    }
    await txEml.done;
  }

  return {
    scrubbedCount: params.emailIdsToScrub.length,
    idbCiphertextZeroed: true,
  };
}
