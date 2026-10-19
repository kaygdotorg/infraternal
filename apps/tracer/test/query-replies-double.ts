/** Models the server's bounded output-position arbitration without terminal grammar [307]. */
export class QueryReplies {
  private next = 0n;
  private readonly outputRanges: { start: bigint; end: bigint; started: number }[] = [];
  private readonly claimed = new Map<bigint, number>();
  dropped = 0;
  attempts = 0;
  output(offset: bigint, bytes: Uint8Array): void {
    const start = offset > this.next ? offset : this.next;
    const end = offset + BigInt(bytes.length);
    if (start >= end) return;
    const now = performance.now();
    while (this.outputRanges.length && now - this.outputRanges[0]!.started >= 1000) this.outputRanges.shift();
    if (this.outputRanges.length === 64) this.outputRanges.shift();
    this.outputRanges.push({ start, end, started: now });
    this.next = end;
  }
  accept(sequence: bigint, bytes: Uint8Array): boolean {
    this.attempts++;
    const now = performance.now();
    const span = this.outputRanges.find((range) => range.start <= sequence && sequence < range.end);
    for (const [position, expiry] of this.claimed) if (now >= expiry) this.claimed.delete(position);
    if (!span || now - span.started >= 1000 || bytes.length === 0 || bytes.length > 1024 || this.claimed.has(sequence) || this.claimed.size === 64) {
      this.dropped++; return false;
    }
    this.claimed.set(sequence, span.started + 1000);
    return true;
  }
}
