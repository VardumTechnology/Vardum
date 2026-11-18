/**
 * b77u (audit 6 U-M1 / R1 F-01): decrypted voice/video temp files belong to one generation.
 *
 * resolveMedia awaits the relay, the decrypt and the file system before it writes the plaintext temp file a
 * player needs. A cleanup that ran meanwhile (the lock, leaving the chat, Nothing-at-Rest's departure wipe,
 * an account switch, any wipe) was followed by a new plaintext file written after it, outside every sweep
 * that had already finished. Each load now takes a ticket; every cleanup moves the generation on; the load
 * checks the ticket after every await and before and after its write, and deletes what it wrote if a cleanup
 * came in between.
 */
export type MediaTicket = { readonly gen: number };

export class MediaWork {
  private gen = 0;

  constructor(private readonly extraLive: () => boolean = () => true) {}

  begin(): MediaTicket {
    return { gen: this.gen };
  }

  /** a cleanup: every load in flight is void */
  bump(): void {
    this.gen += 1;
  }

  current(t: MediaTicket, more?: () => boolean): boolean {
    return t.gen === this.gen && this.extraLive() && (more ? more() : true);
  }

  /**
   * Write a plaintext temp file only while the ticket holds; if it stops holding during the write, the file
   * is deleted again. true = written and still current.
   */
  async writeIfCurrent(t: MediaTicket, write: () => Promise<void>, remove: () => Promise<void>, more?: () => boolean): Promise<boolean> {
    if (!this.current(t, more)) return false;
    try {
      await write();
    } catch (e) {
      if (!this.current(t, more)) await remove().catch(() => undefined);
      throw e;
    }
    if (this.current(t, more)) return true;
    await remove().catch(() => undefined);
    return false;
  }
}
