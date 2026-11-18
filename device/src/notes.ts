/**
 * @veil/device — private notes (web parity, extracted from the live bundle
 * index-CXHmaNHA.js + Notes-ZChV35c8.js on Sept 19 2026).
 *
 * Web contract:
 *   - a device-local AES-GCM-256 key (web: localStorage `veil_notes_key` JWK;
 *     native: raw key base64 in the secure keystore — never leaves the device);
 *   - note payload { title, body } JSON -> AES-256-GCM, fresh 12-byte IV ->
 *     { payload_ciphertext (b64), payload_iv (b64), byte_length };
 *   - VeilNote entity rows: { payload_ciphertext, payload_iv, byte_length };
 *     nothing but ciphertext server-side. Title lives inside the ciphertext.
 */
import { randomBytes, toB64, utf8, fromB64 } from '../../crypto-core/src/index';
import { aesGcmKey } from './kdf';
import { hkdf } from '../../crypto-core/src/kdf';


/**
 * b75 (audit VS-4): a note's ciphertext length (and the row's byte_length) showed the
 * relay each note's exact size. The JSON is now padded with spaces to a bucket: 256
 * bytes, then the next power of two up to 64 KiB, then whole 64 KiB steps. JSON.parse
 * ignores trailing whitespace, so older builds and older notes read the same way.
 */
export function noteBucket(n: number): number {
  if (n <= 256) return 256;
  if (n <= 65536) { let b = 512; while (b < n) b *= 2; return b; }
  return Math.ceil(n / 65536) * 65536;
}
export function padNotePlaintext(pt: Uint8Array): Uint8Array {
  const out = new Uint8Array(noteBucket(pt.length)).fill(0x20);
  out.set(pt);
  return out;
}

export const NOTES_KEY_STORAGE = 'veil_notes_key';
/** Batch C (B8): device-local newest-version-seen per note id */
export const NOTES_VERSIONS_STORAGE = 'veil_notes_versions';
/** b74 (review VAR-10): set once every note this identity can open is bound; from then on
 *  a row without note_nid / note_v is refused (a relay stripping the binding used to make
 *  the AAD and the rollback check silently switch off). */
export const NOTES_BOUND_ONLY_STORAGE = 'veil_notes_bound_only';
/** relay list page the migration reads (a longer list is never marked bound-only) */
const NOTES_PAGE = 100;

/**
 * b75 round 2 (audit D4): the rollback marks (newest version seen per note, and bound-only)
 * lived only on the device, and every wipe removed them; after a phrase restore (which
 * Nothing-at-Rest needs after every departure) the relay could serve an older version of a
 * note, or an unbound pre-binding copy that the migration then re-bound as a fresh note.
 * Now (1) Nothing-at-Rest keeps them (CK_KEPT_KEYS), and (2) they are also kept on the relay
 * as one more note row, the marks manifest: encrypted and bound like any note (AES-GCM with
 * AAD vardum-note-v2:<nid>:<version>) under the identity-derived notes key, at a note id
 * derived from that key (HKDF 'vardum-notes-manifest-v1', 16 bytes, hex), padded like every
 * note. A restore merges it before anything else (marks are only ever raised). The relay
 * can't forge or edit it; it can withhold it or serve an older copy of it (spec 8.2).
 */
export interface NotesMarks { versions: Record<string, number>; boundOnly: boolean }
const MANIFEST_LABEL = 'vardum-notes-manifest-v1';
export async function notesManifestNid(keyB64: string): Promise<string> {
  const k = await hkdf(fromB64(keyB64), new Uint8Array(), MANIFEST_LABEL, 16);
  return [...k].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function manifestPayload(m: NotesMarks): NotePayload {
  return { title: '', body: JSON.stringify({ vardumNotesManifest: 1, v: m.versions, bo: m.boundOnly ? 1 : 0 }) };
}
function parseManifest(p: NotePayload): NotesMarks | null {
  try {
    const o = JSON.parse(p.body) as { vardumNotesManifest?: unknown; v?: unknown; bo?: unknown };
    if (o?.vardumNotesManifest !== 1 || !o.v || typeof o.v !== 'object' || Array.isArray(o.v)) return null;
    return { versions: o.v as Record<string, number>, boundOnly: o.bo === 1 };
  } catch { return null; }
}

/** Batch C (B8): a note's binding — client-chosen id (32 hex) and version (1, 2, ...). */
export interface NoteMeta { nid: string; version: number }

export function newNoteId(): string {
  return [...randomBytes(16)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** meta stored on a relay row (note_nid, note_v), or null for a pre-Batch-C row */
export function noteMetaOf(row: { note_nid?: unknown; note_v?: unknown }): NoteMeta | null {
  return typeof row.note_nid === 'string' && Number.isInteger(row.note_v) ? { nid: row.note_nid, version: Number(row.note_v) } : null;
}

function noteAad(meta: NoteMeta): Uint8Array {
  return utf8(`vardum-note-v2:${meta.nid}:${meta.version}`);
}

export interface NotePayload {
  title: string;
  body: string;
}

export interface EncryptedNote {
  ciphertext: string; // base64 AES-GCM ct
  iv: string; // base64 12-byte IV
  byteLength: number;
}

export type NotesGet = (key: string) => Promise<string | null>;
export type NotesSet = (key: string, value: string) => Promise<unknown>;

/** b77t (audit 5 M-B, R4 F-02): a wipe (forget()) ran while a notes-key operation was waiting: it stops
 *  without touching the key in memory, the store or the relay */
export class NotesWipedError extends Error {
  constructor() { super('the notes key was forgotten (a wipe ran) while it was being set'); this.name = 'NotesWipedError'; }
}

export class NotesStore {
  constructor(private get: NotesGet, private set: NotesSet) {}

  /** b77t (audit 5 M-B): bumped by forget(). Work that began before a wipe captures it and checks it after
   *  every await, so it can't put the key back in memory (or write to the store / relay) after the wipe. */
  private gen = 0;
  generation(): number { return this.gen; }
  /** throws NotesWipedError if forget() ran since `gen` was captured */
  checkGeneration(gen: number): void { if (this.gen !== gen) throw new NotesWipedError(); }

  /** Device-local AES-GCM key — created once, stored raw (b64) in the keystore. */
  private key: CryptoKey | null = null;

  async getKey(): Promise<CryptoKey> {
    if (this.key) return this.key;
    const gen = this.gen; // b77t (audit 5 M-B): a key read before a wipe is never installed after it
    // b75 (audit DEV-I4): a read error is NOT "no key". It used to fall through to a
    // fresh random key, persisted over the identity-derived one (every note then failed to
    // open until a restore). The error goes to the caller; the next call reads again.
    const rawB64: string | null = await this.get(NOTES_KEY_STORAGE);
    if (rawB64) {
      let k: CryptoKey | null = null;
      try { k = await aesGcmKey(this.b64ToBytes(rawB64)); } catch { /* corrupted: below */ }
      if (k) {
        const nid = await notesManifestNid(rawB64).catch(() => null);
        this.checkGeneration(gen);
        if (this.key) return this.key; // another caller installed it meanwhile
        this.key = k;
        this.manifestNid = nid;
        return this.key;
      }
      /* corrupted key — replace it (old notes become unreadable, web parity: web also re-keys on bad JWK) */
    }
    this.checkGeneration(gen);
    const fresh = randomBytes(32);
    try {
      await this.set(NOTES_KEY_STORAGE, toB64(fresh));
    } catch {
      /* storage unavailable — keep the key in memory only (Nothing-at-Rest behaviour) */
    }
    const k = await aesGcmKey(fresh);
    this.checkGeneration(gen);
    if (this.key) return this.key;
    this.key = k;
    return this.key;
  }

    /**
   * b96: set (and persist) the notes key explicitly — used by the identity-
   * derived key path (see deriveNotesKeyB64 / adoptNotesIdentityKey). After
   * a Nothing-at-Rest wipe the phrase-restore reproduces the SAME key, so
   * every VeilNote row on the relay decrypts again ("the phrase restores
   * everything" — owner directive, Sept 21).
   */
  async setKey(rawB64: string, gen: number = this.gen): Promise<void> {
    // b77t (audit 5 M-B, R4 F-02): persist FIRST, install only if the write succeeded and no wipe ran
    // (`gen` is the caller's generation from before its own awaits). It used to install the RAM key
    // before the write and ignore a failed one, so an adoption racing a wipe put the key back.
    const key = await aesGcmKey(this.b64ToBytes(rawB64));
    const nid = await notesManifestNid(rawB64);
    this.checkGeneration(gen);
    const ok = await this.set(NOTES_KEY_STORAGE, rawB64); // a throw goes to the caller: nothing installed
    if (ok === false) throw new Error('the notes key could not be saved');
    this.checkGeneration(gen);
    this.key = key;
    this.manifestNid = nid;
  }

  /** b75 round 2 (audit D4): the note id of this key's marks manifest (null until a key is set) */
  private manifestNid: string | null = null;
  manifestId(): string | null { return this.manifestNid; }
  /** b75 round 2 (D4): is this relay row the marks manifest (never shown as a note) */
  isManifest(meta: NoteMeta | null | undefined): boolean {
    return !!meta && !!this.manifestNid && meta.nid === this.manifestNid;
  }

  /** b75 round 2 (D4): the rollback marks this device holds (the manifest's own entry left out) */
  async marks(): Promise<NotesMarks> {
    const v = { ...(await this.versions()) };
    if (this.manifestNid) delete v[this.manifestNid];
    return { versions: v, boundOnly: await this.boundOnly() };
  }

  /** b75 round 2 (D4): raise the local marks to at least `m` (never lowers one) */
  async mergeMarks(m: NotesMarks): Promise<void> {
    const v = await this.versions();
    let changed = false;
    for (const [nid, ver] of Object.entries(m.versions)) {
      if (!/^[0-9a-f]{32}$/.test(nid) || !Number.isInteger(ver) || ver < 1) continue;
      if ((v[nid] ?? 0) < ver) { v[nid] = ver; changed = true; }
    }
    if (changed) await this.set(NOTES_VERSIONS_STORAGE, JSON.stringify(v));
    if (m.boundOnly && !(await this.boundOnly())) await this.setBoundOnly();
  }

  /** b75 (audit DEV-L4): drop the key held in memory. Every wipe calls this (and
   *  "Remove identity"): the stored copy is gone, so this object must not keep opening
   *  notes for the rest of the run. */
  forget(): void {
    this.gen++; // b77t (audit 5 M-B): every operation that began before this stops at its next check
    this.key = null;
    this.manifestNid = null;
  }

  /** b96: activate a key in RAM without persisting (restore paths re-persist). */
  async useKey(rawB64: string): Promise<void> {
    this.key = await aesGcmKey(this.b64ToBytes(rawB64));
    this.manifestNid = await notesManifestNid(rawB64);
  }

/**
   * web Zd(): encrypt { title, body } -> VeilNote record fields.
   * Batch C (B8; reviews P2, P3 R6): with `meta`, the ciphertext is bound to a
   * client-chosen note id and a version number (AES-GCM associated data), so
   * the relay can't move a note's content to another note, and an older
   * version served back is refused by a device that has seen a newer one.
   */
  async encryptNote(note: NotePayload, meta?: NoteMeta): Promise<EncryptedNote> {
    const key = await this.getKey();
    const iv = randomBytes(12);
    const pt = padNotePlaintext(utf8(JSON.stringify(note))); // b75 (audit VS-4)
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv as unknown as BufferSource, ...(meta ? { additionalData: noteAad(meta) as unknown as BufferSource } : {}) },
        key, pt as unknown as BufferSource,
      ),
    );
    if (meta) await this.noteVersionSeen(meta);
    return { ciphertext: toB64(ct), iv: toB64(iv), byteLength: ct.length };
  }

  /** web Qd(): decrypt VeilNote payload fields -> { title, body }.
   *  Batch C (B8): rows carrying note_nid / note_v decrypt only with that
   *  binding and only if not older than the newest version this device saw.
   *  Pre-Batch-C rows (no meta) still open; they get the binding on their next save. */
  async decryptNote(ciphertext: string, iv: string, meta?: NoteMeta | null): Promise<NotePayload> {
    const key = await this.getKey();
    if (meta) {
      if (!/^[0-9a-f]{32}$/.test(meta.nid) || !Number.isInteger(meta.version) || meta.version < 1) throw new Error('Malformed note.');
      const seen = (await this.versions())[meta.nid] ?? 0;
      if (meta.version < seen) throw new Error('This note was rolled back to an older version.');
    } else if (await this.boundOnly() || Object.keys(await this.versions()).length > 0) {
      // b74 (VAR-10): the relay can't switch the binding off by dropping its fields. Once
      // this device has opened any bound note (or finished binding them all), an unbound
      // row is refused; the migration pass binds legacy rows with its own key handling.
      throw new Error('This note lost its binding on the server, so it was not opened.');
    }
    const pt = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: this.b64ToBytes(iv) as unknown as BufferSource, ...(meta ? { additionalData: noteAad(meta) as unknown as BufferSource } : {}) },
        key,
        this.b64ToBytes(ciphertext) as unknown as BufferSource,
      ),
    );
    if (meta) await this.noteVersionSeen(meta);
    return JSON.parse(new TextDecoder().decode(pt)) as NotePayload;
  }

  /** b74 (VAR-10): true once every note was bound (see adoptNotesIdentityKey).
   *  b75 round 3 (audit DV-8): fails closed: a record that can't be read (a fail-closed key:
   *  altered, planted, or deleted while the store's list says it is there) reads as
   *  bound-only, so an unbound copy is refused (it used to read as false and let one in) */
  async boundOnly(): Promise<boolean> {
    try { return (await this.get(NOTES_BOUND_ONLY_STORAGE)) === '1'; } catch { return true; }
  }

  async setBoundOnly(): Promise<void> {
    await this.set(NOTES_BOUND_ONLY_STORAGE, '1');
  }

  /** Batch C (B8): newest version seen per note id (device-local high-water marks).
   *  b75 round 3 (audit DV-8): a read or parse failure THROWS (it used to read as {}: every
   *  note then opened at any version, and the next note seen wrote back a map with one
   *  entry, erasing every other mark). Callers fail closed: a note is not opened and no map
   *  is written back while the marks can't be read. Only a missing record is "no marks". */
  private async versions(): Promise<Record<string, number>> {
    const raw = await this.get(NOTES_VERSIONS_STORAGE);
    if (raw === null || raw === undefined) return {};
    let v: unknown;
    try { v = JSON.parse(raw); } catch { throw new Error('The notes version record on this phone could not be read.'); }
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('The notes version record on this phone could not be read.');
    return v as Record<string, number>;
  }

  /** b75 round 2 (D4): the newest version this device saw of one note id (0 = none) */
  async seenVersion(nid: string): Promise<number> {
    return (await this.versions())[nid] ?? 0;
  }

  private async noteVersionSeen(meta: NoteMeta): Promise<void> {
    // b75 round 3 (DV-8): marks that can't be read are never replaced by a one-entry map
    let v: Record<string, number>;
    try { v = await this.versions(); } catch { return; }
    if ((v[meta.nid] ?? 0) >= meta.version) return;
    v[meta.nid] = meta.version;
    try { await this.set(NOTES_VERSIONS_STORAGE, JSON.stringify(v)); } catch { /* best-effort: RAM-only devices re-learn */ }
  }

  private b64ToBytes(b64: string): Uint8Array {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
}

/**
 * b96 (owner directive: "key phrase should restore everything"): the notes
 * key is now DERIVED from the identity — HKDF(ik seed, 'veil-notes-v1', 32B).
 * The ik seed itself derives from the 24-word phrase, so restoring the phrase
 * after a Nothing-at-Rest wipe reproduces the notes key exactly and every
 * relay-side VeilNote row decrypts again. Previously the key was a device-local
 * random value, meaning a NaR wipe made existing notes permanently unreadable.
 */
export async function deriveNotesKeyB64(ikSeedB64: string): Promise<string> {
  const k = await hkdf(fromB64(ikSeedB64), new Uint8Array(), 'veil-notes-v1', 32);
  return toB64(k);
}

export interface NotesMigrationDeps {
  get: NotesGet;
  set: NotesSet;
  /** list ALL VeilNote rows (relay): { id, payload_ciphertext, payload_iv, note_nid?, note_v? } */
  listRows: () => Promise<Array<{ id: string; payload_ciphertext: string; payload_iv: string; note_nid?: unknown; note_v?: unknown }>>;
  /** update one VeilNote row (relay): id + record fields */
  updateRow: (id: string, record: Record<string, unknown>) => Promise<unknown>;
  /** b75 round 2 (audit D4): create a VeilNote row (the marks manifest); without it the
   *  manifest is read but not written */
  createRow?: (record: Record<string, unknown>) => Promise<unknown>;
}

type NoteRowIn = { id: string; payload_ciphertext: string; payload_iv: string; note_nid?: unknown; note_v?: unknown };

/**
 * b75 round 2 (audit D4): bring the relay's marks manifest and this device's marks together:
 * the manifest's marks are merged in (only ever raised), then, when this device knows more,
 * a new manifest version is written. `rows` = a list just read (else listRows). Never throws.
 */
/** b75 round 3 (DV-9): above any version this device writes (one per manifest change) */
const MANIFEST_VERSION_CAP = 2 ** 40;

export async function syncNotesManifest(
  notes: NotesStore,
  deps: Pick<NotesMigrationDeps, 'listRows' | 'updateRow' | 'createRow'>,
  rows?: NoteRowIn[] | null,
): Promise<'written' | 'current' | 'skipped'> {
  try {
    const nid = notes.manifestId();
    if (!nid) return 'skipped';
    const list = rows ?? (await deps.listRows());
    const row = list.find((r) => noteMetaOf(r)?.nid === nid);
    let remote: NotesMarks | null = null;
    let remoteVersion = 0;
    if (row) {
      const meta = noteMetaOf(row)!;
      try { remote = parseManifest(await notes.decryptNote(row.payload_ciphertext, row.payload_iv, meta)); } catch { /* rolled back or not ours: rewritten below */ }
      // b75 round 3 (audit DV-9): the row's version counts only once it opened (it is then
      // bound into the ciphertext's associated data). Taken before, a huge relay-supplied
      // number pushed every later manifest version past the largest safe integer.
      if (remote && Number.isSafeInteger(meta.version) && meta.version < MANIFEST_VERSION_CAP) remoteVersion = meta.version;
      if (remote) await notes.mergeMarks(remote);
    }
    const local = await notes.marks();
    const covered = !!remote && (!local.boundOnly || remote.boundOnly)
      && Object.entries(local.versions).every(([k, v]) => (remote!.versions[k] ?? 0) >= v);
    if (covered) return 'current';
    if (!deps.createRow && !row) return 'skipped';
    const seen = (await notes.seenVersion(nid));
    const meta: NoteMeta = { nid, version: Math.max(remoteVersion, seen) + 1 };
    const rec = noteRecord(await notes.encryptNote(manifestPayload(local), meta), meta);
    if (row) await deps.updateRow(row.id, rec);
    else await deps.createRow!(rec);
    return 'written';
  } catch {
    return 'skipped';
  }
}

/**
 * Adopt the identity-derived notes key. Re-encrypts every existing VeilNote
 * row that decrypts under the OLD (device-local random) key, so existing
 * notes keep working instead of dying at the key change. Rows that don't
 * decrypt (foreign device's key, corrupted) are left untouched.
 * b74 (review VAR-10): every row this identity can open is (re)written BOUND —
 * a note id + version in the AES-GCM associated data and on the row — including
 * rows already under the identity key that predate the binding, and rows bound
 * under the old key (opened with their AAD; they used to fail the AAD-less try and
 * be stranded). Once a full pass leaves no unbound row this identity can open, the
 * store goes bound-only: a row without the binding is refused from then on.
 * Returns 'migrated' when rows were re-encrypted, 'ok' otherwise.
 */
export async function adoptNotesIdentityKey(
  notes: NotesStore,
  ikSeedB64: string,
  deps: NotesMigrationDeps,
): Promise<'ok' | 'migrated'> {
  // b77t (audit 5 M-B, R4 F-02): the generation before the first await. After every await, before any change
  // to memory, the store or the relay, a wipe (notes.forget()) that ran meanwhile stops the adoption.
  const gen = notes.generation();
  const live = () => notes.checkGeneration(gen);
  const newB64 = await deriveNotesKeyB64(ikSeedB64);
  const oldB64 = await deps.get(NOTES_KEY_STORAGE).catch(() => null);
  const newKey = await aesGcmKey(fromB64(newB64));
  const oldKey = oldB64 && oldB64 !== newB64 ? await aesGcmKey(fromB64(oldB64)) : null;
  const rows = await deps.listRows().catch(() => null);
  live();
  // b75 round 2 (audit D4): the marks manifest first (a restore has no local marks): its
  // bound-only flag and newest versions apply before any row is looked at
  const manifestNid = await notesManifestNid(newB64);
  const manifestRow = (rows ?? []).find((r) => noteMetaOf(r)?.nid === manifestNid);
  if (manifestRow) {
    const meta = noteMetaOf(manifestRow)!;
    try {
      const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromB64(manifestRow.payload_iv) as unknown as BufferSource, additionalData: noteAad(meta) as unknown as BufferSource },
        newKey, fromB64(manifestRow.payload_ciphertext) as unknown as BufferSource,
      );
      const m = parseManifest(JSON.parse(new TextDecoder().decode(pt)) as NotePayload);
      live();
      if (m) await notes.mergeMarks(m);
    } catch (e) { if (e instanceof NotesWipedError) throw e; /* not this key's manifest, or damaged: the local marks stand */ }
  }
  live();
  // re-audit N4: the unbound-to-bound pass runs once. After it, an unbound row the relay
  // serves is never bound (that would launder an old pre-binding copy into a "new" note)
  const boundOnly = await notes.boundOnly();
  let rewrote = 0;
  let unbound = 0;
  for (const r of rows ?? []) {
    const meta = noteMetaOf(r);
    if (meta?.nid === manifestNid) continue; // b75 round 2 (D4): the marks manifest
    if (meta && !oldKey) continue; // already bound under the identity key
    if (!meta && boundOnly) continue;
    const tryOpen = async (key: CryptoKey, m: NoteMeta | null): Promise<Uint8Array | null> => {
      try {
        return new Uint8Array(await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: fromB64(r.payload_iv) as unknown as BufferSource, ...(m ? { additionalData: noteAad(m) as unknown as BufferSource } : {}) },
          key, fromB64(r.payload_ciphertext) as unknown as BufferSource,
        ));
      } catch { return null; }
    };
    const pt = (oldKey ? await tryOpen(oldKey, meta) : null) ?? (meta ? null : await tryOpen(newKey, null));
    if (!pt) continue; // not this identity's note (or already done) — left as-is
    const bound: NoteMeta = meta ?? { nid: newNoteId(), version: 1 };
    const iv2 = randomBytes(12);
    const ct2 = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv2 as unknown as BufferSource, additionalData: noteAad(bound) as unknown as BufferSource },
      newKey, padNotePlaintext(pt) as unknown as BufferSource, // b75 (audit VS-4)
    ));
    live(); // b77t (M-B): no relay migration after a wipe
    try {
      await deps.updateRow(r.id, { payload_ciphertext: toB64(ct2), payload_iv: toB64(iv2), byte_length: ct2.length, note_nid: bound.nid, note_v: bound.version });
      rewrote += 1;
    } catch { unbound += 1; }
  }
  await notes.setKey(newB64, gen); // b77t (M-B): persisted first, installed only if no wipe ran
  // bound-only only after a complete pass: the list was read, it fit one page, and
  // every row this identity could open now carries its binding
  live();
  if (rows && rows.length < NOTES_PAGE && unbound === 0) await notes.setBoundOnly().catch(() => undefined);
  // b75 round 2 (audit D4): the marks (bound-only included) go to the relay's manifest
  live();
  if (rows && deps.createRow) await syncNotesManifest(notes, deps, rows);
  return rewrote ? 'migrated' : 'ok';
}

/** The VeilNote entity record (web parity field names; Batch C adds note_nid / note_v). */
export function noteRecord(enc: EncryptedNote, meta?: NoteMeta): Record<string, unknown> {
  return {
    payload_ciphertext: enc.ciphertext, payload_iv: enc.iv, byte_length: enc.byteLength,
    ...(meta ? { note_nid: meta.nid, note_v: meta.version } : {}),
  };
}
