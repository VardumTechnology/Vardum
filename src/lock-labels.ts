/**
 * b77k2 (review M-A): the lock screen's status line and button label. A wipe that is still finishing
 * (wipe-busy: a duress wipe the duress code just started, a Nothing-at-Rest departure) shows exactly
 * what a normal password check shows — "Verifying…" — never "Finishing a wipe…", which told a
 * coercer the duress code had run (or an onlooker that Nothing-at-Rest is on). The screen stays inert
 * meanwhile (`verifying` is passed true while a wipe finishes). Pure module (no React Native imports).
 */
export interface LockLabelState {
  verifying?: boolean;
  /** accepted and deliberately unused in the text (see above) */
  wipeFinishing?: boolean;
  codeError?: string | null;
  lockedMins?: number | null;
}

export function lockStatusText(s: LockLabelState): string {
  return s.verifying || s.wipeFinishing ? 'Verifying — this takes a few seconds on this device.' : (s.codeError ?? '');
}

/** audit VAR-18 (b77m): lockouts now run up to a day — a wait of two hours or more reads in hours */
export function lockWaitText(mins: number): string {
  return mins >= 120 ? `${Math.ceil(mins / 60)} h` : `${mins} min`;
}

export function lockButtonText(s: LockLabelState): string {
  if (s.lockedMins != null) return `Locked · ${lockWaitText(s.lockedMins)}`;
  return s.verifying || s.wipeFinishing ? 'Verifying…' : 'Unlock';
}
