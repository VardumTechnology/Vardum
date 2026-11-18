/**
 * @veil/device — identity keyvault + storage-mode rules.
 *
 * Web behaviour ported (verified on the NaR battery, Sept 13):
 *  - 'device'   : keyvault + session keys persist across reloads.
 *  - 'hardware' : same persistence as 'device'; the identity keyvault entry
 *                 additionally requires a biometric/passcode prompt from the
 *                 OS keystore on every read (see secure-store.rn.ts) — a
 *                 stronger-than-'device', weaker-than-'memory' middle option.
 *  - 'memory'   : session keys (veil_rk_* / veil_gk_*) are wiped at flip and
 *                 at close; identity is recoverable ONLY via the 24-word
 *                 phrase. (Web P2 fix adopted natively: the keyvault itself
 *                 is wiped at close under memory mode — the web copy's
 *                 "nothing is stored anywhere, ever" finally becomes true.)
 */

import type { VeilStorage } from '../../crypto-core/src/index';
import { secureRemove, secureRemovePrefix } from './secure-wipe';

export type StorageMode = 'device' | 'hardware' | 'memory';

export const STORAGE_MODE_KEY = 'veil_storage_mode';
export const KEYVAULT_KEY = 'veil_keyvault_identity';
/**
 * b77m review (M1, VAR-63 follow-up): a one-bit Nothing-at-Rest marker kept OUTSIDE the sealed records
 * ('1' = Nothing-at-Rest on, '0' = off). The sealed mode and settings records live in the strict
 * WHEN_UNLOCKED keychain tier and under the container key; one keystore error (an iOS background launch:
 * "User interaction is not allowed", an Android keystore stall) made both unreadable at once, and the
 * fail-closed cold-boot wipe then erased a phone that was never in Nothing-at-Rest. The marker is stored
 * as it is (container-key raw set) in the AFTER_FIRST_UNLOCK tier (secure-store.rn.ts), so it is the
 * deciding signal when the sealed records can't be read. One bit, no secret: it says only that this
 * install uses Nothing-at-Rest (spec §8.2 #60). Absent = unknown (an install from before b77m, until its
 * first clean boot read backfills it).
 */
export const NAR_MARKER_KEY = 'veil_nar_marker';
export type NarMarker = 'on' | 'off' | 'unset' | 'unreadable';
/** read the marker; never throws */
export async function readNarMarker(storage: Pick<VeilStorage, 'get'>): Promise<NarMarker> {
  try {
    const v = await storage.get(NAR_MARKER_KEY);
    return v === '1' ? 'on' : v === '0' ? 'off' : 'unset';
  } catch { return 'unreadable'; }
}
/** write the marker for `mode` (best effort: false when the store refused it) */
export async function writeNarMarker(storage: Pick<VeilStorage, 'set'>, mode: StorageMode): Promise<boolean> {
  // KeychainStorage.set reports a refused write by returning false, not by throwing
  try { return (await storage.set(NAR_MARKER_KEY, mode === 'memory' ? '1' : '0')) !== false; } catch { return false; }
}

export interface KeyvaultIdentity {
  veilId: string;
  ikSeedB64: string;
  ikPubB64: string;
  spkPubB64: string;
  spkPrivB64: string;
  /** b75 (audit 2 V9): `sig.ts`, dated and labelled (crypto-core identity.ts); an older
   *  undated one is re-signed by ensurePqPrekeySigned() */
  spkSigB64: string;
  pqPubB64: string;
  pqPrivB64: string;
  /** b54: Ed25519(IK, label || pq_pub), published as pq_sig. Absent on
   *  pre-b54 keyvaults until ensurePqPrekeySigned() backfills it. b75 (V9): dated, as above. */
  pqSigB64?: string;
  createdAt: string;
  /** b70 (audit L-2): when the SPK + PQ prekeys last rotated (absent = createdAt) */
  prekeysRotatedAt?: string;
  /** b70 (L-2): rotated locally but not yet confirmed published on the relay */
  prekeysPending?: boolean;
}

export class IdentityVault {
  constructor(private storage: VeilStorage) {}

  async save(id: KeyvaultIdentity): Promise<void> {
    await this.storage.set(KEYVAULT_KEY, JSON.stringify(id));
  }

  async load(): Promise<KeyvaultIdentity | null> {
    const raw = await this.storage.get(KEYVAULT_KEY);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch { return null; }
  }

  async clear(): Promise<void> {
    // b93 P2: the keyvault is THE crown-jewel record (ik seed, spk priv, PQ
    // priv) — overwrite it in place before the delete.
    await secureRemove(this.storage, KEYVAULT_KEY);
  }

  async mode(): Promise<StorageMode> {
    return ((await this.storage.get(STORAGE_MODE_KEY)) as StorageMode) || 'device';
  }

  /** b77n (pre-audit LOW-1): the mode record as it really is, never defaulted. 'missing' = no record (a
   *  fresh install, one from before the record was written, or a deleted one: mode() reads all three as
   *  'device'); 'unreadable' = the read threw (a keystore error; a sealed record that fails its check or is
   *  missing while the presence list says it is there: veil_storage_mode is fail-closed since b77n) or the
   *  value is not a mode. The cold-boot Nothing-at-Rest check reads this, never mode(). Never throws. */
  async modeChecked(): Promise<{ mode: StorageMode; state: 'ok' } | { mode: null; state: 'missing' | 'unreadable' }> {
    let raw: string | null | undefined;
    try { raw = await this.storage.get(STORAGE_MODE_KEY); } catch { return { mode: null, state: 'unreadable' }; }
    if (raw === null || raw === undefined) return { mode: null, state: 'missing' };
    if (raw === 'device' || raw === 'hardware' || raw === 'memory') return { mode: raw, state: 'ok' };
    return { mode: null, state: 'unreadable' };
  }

  /** Flip the storage mode; wiping conversation keys as the web build does.
   *  b77k2 (re-review L3): `opts.wipeLater` — the Nothing-at-Rest dial flip: the flip wipe that runs
   *  right after reads the chats under its own write freeze and erases everything (this wipe would
   *  delete them before that read) */
  async setMode(mode: StorageMode, opts: { wipeLater?: boolean } = {}): Promise<number> {
    // b77m review (M1): the unsealed marker follows the mode. Turning Nothing-at-Rest ON writes it
    // first (a flip cut short still wipes at the next cold boot: fail closed); turning it OFF clears
    // it only once the mode record says so.
    // b77m confirmation review (L3): a refused marker write stops the flip ON, so the mode is never
    // 'memory' while the marker still says off. A save while already in memory mode (the post-flip
    // barrier refuses the write; the marker was set by the flip itself) stays best effort.
    if (mode === 'memory') {
      const already = await this.mode().catch(() => null) === 'memory';
      if (!(await writeNarMarker(this.storage, mode)) && !already) {
        throw new Error('Nothing-at-Rest could not be turned on: this phone refused to save its marker. Try again.');
      }
    }
    await this.storage.set(STORAGE_MODE_KEY, mode);
    if (mode !== 'memory') await writeNarMarker(this.storage, mode);
    if (mode === 'memory' && !opts.wipeLater) {
      const ks = await this.storage as unknown as { wipe?: (...p: string[]) => Promise<number> };
      if (typeof ks.wipe === 'function') return ks.wipe('veil_rk_', 'veil_gk_', 'veil_msgcache_');
      // b93 P2: conversation keys are overwritten in place, then deleted.
      await secureRemovePrefix(this.storage, 'veil_rk_');
      await secureRemovePrefix(this.storage, 'veil_gk_');
      // b92 F-S2 (settings sweep): the PLAINTEXT message cache is history
      // too — leaving it on disk broke the Nothing-at-Rest claim.
      await secureRemovePrefix(this.storage, 'veil_msgcache_');
    }
    return 0;
  }

  /**
   * Nothing-at-Rest wipe hook — the CONVERSATION layer of the b95 v2 design
   * (owner hardware verify, Sept 21: "lock the phone, unlock — absolutely
   * nothing happened"). Called by App.tsx's naRWipeStorage() on mode flip,
   * on ANY departure from the foreground ('inactive' = screen lock included,
   * 'background' = app switch), and at every cold boot while the mode is on.
   * Under memory mode NOTHING Veil-stored survives: conversation keys, the
   * plaintext history cache, and the identity keyvault itself — the identity
   * returns only via the 24-word recovery phrase. App.tsx extends this to
   * the full surface (notes, vaults, stego, saved media).
   */
  async onClose(): Promise<void> {
    if ((await this.mode()) === 'memory') {
      // b71 (audit): the identity goes FIRST — iOS can suspend the app part-way
      // through a close wipe, and the identity is what matters most
      await this.clear();
      // b76 (one-time prekeys): the one-time prekey private keys are identity key material
      // too — they go right after the identity (opk.ts)
      await secureRemovePrefix(this.storage, 'veil_opk_');
      await secureRemovePrefix(this.storage, 'veil_rk_');
      await secureRemovePrefix(this.storage, 'veil_gk_');
      // b92 F-S2: Nothing-at-Rest must include the plaintext history cache.
      await secureRemovePrefix(this.storage, 'veil_msgcache_');
    }
  }
}
