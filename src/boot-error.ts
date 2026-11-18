/**
 * audit VAR-43 (1f51): what the boot error screen (index.ts) shows. Release builds show fixed text
 * and an opaque id, never the error message or its stack (file paths, internals, sometimes data);
 * development builds keep the full text. Same rule as the in-app crash screen (app-guards
 * crashScreenText, audit VAR-64). No imports: index.ts loads it before the polyfills.
 */
export function bootErrorText(e: unknown, dev: boolean, id: string): { hint: string; detail: string } {
  if (dev) {
    const err = e as Error;
    return {
      hint: 'Screenshot this whole screen and send it back — it names the exact problem.',
      detail: String((err && err.message) || e) + '\n\n' + String((err && err.stack) || '(no stack)'),
    };
  }
  return {
    hint: 'Close Vardum and open it again. If this keeps happening, contact support and quote the error code below.',
    detail: `Error ${id}`,
  };
}

/** a short random id (not derived from the error) */
export function bootErrorId(rand: () => number = Math.random): string {
  let s = '';
  for (let i = 0; i < 8; i++) s += Math.floor(rand() * 16).toString(16);
  return s;
}
