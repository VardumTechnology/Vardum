/**
 * b77u (audit 6 U-M13, app half / R4 #20): a wipe the owner asked for (wipe this phone, delete account, sign out)
 * that could not delete everything says so. The leftovers used to be counted and then dropped: the stored keys the
 * verify pass found, the files the sweep could not remove, the folders it could not list. Never shown after the
 * duress code, a Nothing-at-Rest departure or the self-destruct (nobody who should see it is there, and it would
 * tell).
 * b77u merge: one source of truth, the device's erase report (duress-wipe.ts EraseReport): files left 0/n/-1 and
 * whether veil_wipe_pending was kept, in which case the next launch runs the wipe again.
 */
import type { EraseReport } from './duress-wipe';

export const WIPE_LEFTOVER_TITLE = 'Not everything was deleted';

/** the text shown, or null when the wipe was complete. keysLeft: the verify pass's count (-1: the keys could not
 *  be listed); report: the erase's report */
export function wipeLeftoverNotice(keysLeft: number, report: Pick<EraseReport, 'filesLeft' | 'pendingNextLaunch'>): string | null {
  const files = report.filesLeft;
  if (keysLeft === 0 && files === 0) return null;
  const what: string[] = [];
  if (keysLeft > 0) what.push(keysLeft === 1 ? '1 stored item' : `${keysLeft} stored items`);
  else if (keysLeft < 0) what.push('some stored items (they could not be checked)');
  if (files > 0) what.push(files === 1 ? '1 file' : `${files} files`);
  else if (files < 0) what.push('some files (a folder could not be read)');
  const retry = report.pendingNextLaunch ? ' It tries again the next time Vardum starts.' : '';
  return `Vardum could not delete ${what.join(' and ')} from this phone.${retry} To be sure nothing is left, delete the Vardum app from this phone.`;
}
