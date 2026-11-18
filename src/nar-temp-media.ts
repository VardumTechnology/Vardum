/**
 * b77k2 (review L-4): under Nothing-at-Rest a received voice or video note is decrypted to a temp
 * file (expo-av can't play a data: URI). That path is reachable after the dial flip now that chats
 * keep working, so in memory mode every such file is tracked and deleted the moment its chat is left
 * (closed, another chat opened, the app leaves the screen), not only by the departure wipe's sweep.
 * Remaining exposure (protocol-spec.md): the file exists while its chat is open; a process death in
 * that window leaves it until the next launch's cold-boot wipe sweeps the temp folder.
 * Pure module (no React Native imports): App.tsx passes the delete.
 */
export class TempMediaTracker {
  private files = new Map<string, string>(); // uri -> message id
  note(uri: string, msgId: string): void { this.files.set(uri, msgId); }
  size(): number { return this.files.size; }
  /** delete every tracked file (best-effort, all at once); returns the message ids whose file went */
  async dropAll(del: (uri: string) => Promise<unknown>): Promise<string[]> {
    const all = [...this.files.entries()];
    this.files.clear();
    await Promise.all(all.map(([uri]) => Promise.resolve().then(() => del(uri)).catch(() => undefined)));
    return all.map(([, id]) => id);
  }
}
