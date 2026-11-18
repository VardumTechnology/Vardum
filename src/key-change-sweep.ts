/**
 * audit VAR-11 (b77m): opening a contact chat used to make a signed-in identity lookup naming that
 * contact, every time — the relay learned "account A is opening B's chat now", which it can line up
 * with the anonymous mailbox traffic that follows.
 *
 * Now the security-key-changed check runs on its own schedule, not on chat opens: about every
 * KEY_SWEEP_MS (jittered), ONE pass looks up EVERY pinned contact, in a shuffled order with a random
 * gap between lookups. Opening a chat makes no lookup; it reads the last pass's answer for that
 * contact from memory (`changed`).
 *
 * Pure (the clock, randomness and the lookup are passed in) so the repro tests drive it directly.
 *
 * b77m review (INFO): the default randomness (the pass interval's jitter, the shuffle and the gaps) is the
 * CSPRNG (cryptoRandomUnit), not Math.random: the timing and order are what the relay sees, so they must not
 * be predictable from the engine's PRNG state.
 *
 * b77q (audit 3 AQ-1): each pass handed the relay the WHOLE pinned list under the account's token (the
 * signed-in lookup), about four times a day. Now (owner decision: "check anonymously"):
 *  - the app's `check` uses the relay's no-login lookup (VeilRelay.identityLookupAnon: no Authorization
 *    header, no cookies), so no request names the account;
 *  - the lookups are spread out: a random gap (KEY_SWEEP_GAP_MS) before EVERY lookup, the first included,
 *    so a pass does not start the moment the app comes to the front (with the signed-in sync); a pass cut
 *    short (app in the background, locked) resumes with what it had left after about KEY_SWEEP_RESUME_MS,
 *    instead of being dropped until the next 6-hourly pass;
 *  - decoy lookups are mixed in: `decoyId` makes a random ID in the Vardum ID format, `lookupDecoy` asks
 *    for it the same way, and a random number of them (KEY_SWEEP_DECOYS_MIN + up to half the pinned count)
 *    is shuffled in with the real ones. Their answers are thrown away.
 * What the relay still sees (spec §8.2 #59): lookups of these IDs from a network address at these times, so it
 * can still guess that they belong together and, from other traffic on that address, whose they are. The decoys
 * hide the count and blur the set for anyone holding the requests alone; they are random IDs, so a relay that
 * checks them against its own identity table can tell them apart (they are never bound).
 *
 * b77q owner (1 Nov): ALSO a check when the user opens that contact's 1:1 chat (`checkOnOpen`), as b64 did, so a key
 * change shows at once instead of after the next pass (6 h ± 1 h, only while the app is open). Still anonymous (the
 * same no-login lookup), at most once per contact per KEY_OPEN_CHECK_MIN_MS (reopening a chat doesn't repeat it),
 * and never awaited by the chat opening. Its answer goes in the same table as the pass's: 'unknown' (an error, no
 * bundle, bad prekey signatures) keeps the last known answer and never raises a warning. The cost (owner's call):
 * the relay can again line a lookup of B up with a chat open from that network address (§8.2 #59).
 */
/** a uniform number in [0, 1) from crypto.getRandomValues (53 bits) */
export function cryptoRandomUnit(): number {
  const buf = new Uint32Array(2);
  crypto.getRandomValues(buf);
  return (buf[0] * 2 ** 21 + (buf[1] >>> 11)) / 2 ** 53;
}
export const KEY_SWEEP_MS = 6 * 3600_000;
/** the pass interval varies by up to this much either way */
export const KEY_SWEEP_JITTER_MS = 3600_000;
/** gap before each lookup inside a pass. b77q (audit 3 AQ-1): 2-20 s -> 15-120 s, and before the first one too */
export const KEY_SWEEP_GAP_MS: [number, number] = [15_000, 120_000];
/** b77q (audit 3 AQ-1): a pass cut short goes on with what it had left this long later (x0.5 to x1.5) */
export const KEY_SWEEP_RESUME_MS = 10 * 60_000;
/** b77q (audit 3 AQ-1): decoys per pass: at least this many, plus up to half the pinned count (random) */
export const KEY_SWEEP_DECOYS_MIN = 2;
/** b77q owner (1 Nov): the chat-open check runs at most once per contact in this long */
export const KEY_OPEN_CHECK_MIN_MS = 10 * 60_000;

/** b77u (audit 6 R4 #30): 'unverifiable' = the relay answered with a key bundle for this contact that does not check
 *  out (malformed, a bad signature). It used to count as 'unknown' (kept the last answer, never warned), so a relay
 *  that served a broken bundle silenced the check for good. It is its own answer now, kept and shown: the chat says
 *  this contact's key couldn't be checked. 'unknown' stays for no answer at all (a network error, no bundle). */
export type KeyCheck = 'ok' | 'changed' | 'unknown' | 'unverifiable';

export interface KeyChangeSweep {
  /** true when a pass should start now (none ran yet, the jittered interval is over, or a cut-short pass may resume) */
  due(now?: number): boolean;
  /** one pass over every pinned contact; resolves with the number of PINNED contacts checked (decoys are not
   *  counted). Never two at once. */
  run(deps: {
    listPinned: () => Promise<string[]>;
    check: (veilId: string) => Promise<KeyCheck>;
    sleep?: (ms: number) => Promise<void>;
    /** stops the pass early (locked, decoy mode, wiped); b77q: the rest of it resumes later */
    stillWanted?: () => boolean;
    /** b77q (audit 3 AQ-1): a random ID in the Vardum ID format (none: no decoys) */
    decoyId?: () => string;
    /** b77q (audit 3 AQ-1): looks a decoy up exactly as `check` looks a contact up; the answer is ignored */
    lookupDecoy?: (veilId: string) => Promise<unknown>;
  }): Promise<number>;
  /** b77q owner (1 Nov): one check of this contact now (the user opened its chat) — null when it was checked (by
   *  this) less than KEY_OPEN_CHECK_MIN_MS ago or one is under way; otherwise the answer, also kept for `changed`.
   *  Never throws ('unknown' on any error). */
  checkOnOpen(veilId: string, check: (veilId: string) => Promise<KeyCheck>): Promise<KeyCheck | null>;
  /** the last pass said this contact's published key no longer matches the pinned one */
  changed(veilId: string): boolean;
  /** b77u (R4 #30): the last answer for this contact was a bundle that did not check out */
  unverifiable(veilId: string): boolean;
  /** forget everything (wipe / sign-out) */
  reset(): void;
}

type SweepItem = { id: string; decoy?: true };

export function createKeyChangeSweep(o: { now?: () => number; rand?: () => number } = {}): KeyChangeSweep {
  const now = o.now ?? Date.now;
  const rand = o.rand ?? cryptoRandomUnit; // b77m review (INFO): was Math.random
  const results = new Map<string, KeyCheck>();
  let nextAt = 0;
  let running: Promise<number> | null = null;
  /** b77q (audit 3 AQ-1): what a cut-short pass had left (null: no pass under way) */
  let carry: SweepItem[] | null = null;
  let epoch = 0; // reset() during a pass: that pass's leftovers are dropped
  /** b77q owner (1 Nov): when each contact's chat-open check last started */
  const openChecked = new Map<string, number>();
  const shuffle = <T,>(a: T[]): T[] => { for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; };
  const scheduleFull = () => { nextAt = now() + KEY_SWEEP_MS + Math.round((rand() * 2 - 1) * KEY_SWEEP_JITTER_MS); };
  const scheduleResume = () => { nextAt = now() + Math.round(KEY_SWEEP_RESUME_MS * (0.5 + rand())); };
  return {
    due: (t = now()) => !running && t >= nextAt,
    run(deps) {
      if (running) return running;
      scheduleFull(); // (a pass cut short moves it to the resume time when it stops)
      const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
      const wanted = () => !deps.stillWanted || deps.stillWanted();
      const myEpoch = epoch;
      running = (async () => {
        let n = 0;
        let left: SweepItem[] | null = null;
        try {
          const pinned = [...(await deps.listPinned())];
          let queue: SweepItem[];
          if (carry) {
            // resume: what was left, minus contacts unpinned since (decoys kept)
            const still = new Set(pinned);
            queue = carry.filter((e) => e.decoy || still.has(e.id));
          } else {
            const decoys = deps.decoyId && deps.lookupDecoy ? KEY_SWEEP_DECOYS_MIN + Math.floor(rand() * (Math.ceil(pinned.length / 2) + 1)) : 0;
            const items: SweepItem[] = pinned.map((id) => ({ id }));
            for (let i = 0; i < decoys; i++) items.push({ id: deps.decoyId!(), decoy: true });
            queue = shuffle(items);
          }
          carry = null;
          for (let i = 0; i < queue.length; i++) {
            if (!wanted()) { left = queue.slice(i); break; }
            await sleep(KEY_SWEEP_GAP_MS[0] + Math.floor(rand() * (KEY_SWEEP_GAP_MS[1] - KEY_SWEEP_GAP_MS[0])));
            if (!wanted()) { left = queue.slice(i); break; }
            const { id, decoy } = queue[i];
            if (decoy) { try { await deps.lookupDecoy!(id); } catch { /* a decoy's answer never matters */ } continue; }
            let r: KeyCheck = 'unknown';
            try { r = await deps.check(id); } catch { r = 'unknown'; }
            // a failed lookup keeps the last known answer (a relay hiccup never clears a warning)
            if (r !== 'unknown' || !results.has(id)) results.set(id, r);
            n++;
          }
        } catch { /* no pin list: try again next time */ }
        if (myEpoch === epoch && left && left.length) { carry = left; scheduleResume(); }
        return n;
      })().finally(() => { running = null; });
      return running;
    },
    async checkOnOpen(veilId, check) {
      const t = now();
      const last = openChecked.get(veilId);
      if (last !== undefined && t - last < KEY_OPEN_CHECK_MIN_MS) return null;
      openChecked.set(veilId, t);
      const myEpoch = epoch;
      let r: KeyCheck = 'unknown';
      try { r = await check(veilId); } catch { r = 'unknown'; }
      if (myEpoch !== epoch) return null; // wiped meanwhile: the answer belongs to nobody now
      // as the pass: a failed lookup keeps the last known answer (never clears a warning, never raises one)
      if (r !== 'unknown' || !results.has(veilId)) results.set(veilId, r);
      return r;
    },
    changed: (veilId) => results.get(veilId) === 'changed',
    unverifiable: (veilId) => results.get(veilId) === 'unverifiable',
    reset: () => { results.clear(); openChecked.clear(); nextAt = 0; carry = null; epoch++; },
  };
}

/** b77u (audit 6 R4 #30): shown in a 1:1 chat whose contact's published keys did not check out */
export const KEY_UNVERIFIABLE_NOTE = 'Vardum couldn’t check this contact’s security key: the server sent keys that don’t check out. This chat still uses the keys you checked. If this keeps happening, compare safety codes with them again in person.';
