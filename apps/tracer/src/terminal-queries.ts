/** Tracks query boundaries in bounded VT control strings, using absolute output offsets [307]. */
export class TerminalQueries {
  private state = 0;
  private sequence = 0n;
  private started = 0;
  private control = "";
  private escaped = false;
  private overflow = false;

  reset(): void { this.state = 0; this.control = ""; this.escaped = false; }

  /** Calls back at a recognised query's final byte; no query list or output copy is retained. */
  scan(bytes: Uint8Array, offset: bigint, query: (end: number, sequence: bigint, started: number, request: string) => void): void {
    // Plain output takes one native search. Control-rich output stays in JS,
    // avoiding a native-call boundary for every short styled text span.
    if (this.state === 0 && bytes.indexOf(27) < 0) return;
    for (let index = 0; index < bytes.length; index++) {
      const byte = bytes[index]!;
      if (this.state === 0) {
        if (byte === 27) { this.state = 1; this.sequence = offset + BigInt(index); this.started = performance.now(); this.control = "\u001b"; this.overflow = false; }
        continue;
      }
      if (byte === 24 || byte === 26) { this.reset(); continue; }
      if (this.state === 2 && byte === 27) { this.state = 1; this.sequence = offset + BigInt(index); this.started = performance.now(); this.control = "\u001b"; this.overflow = false; continue; }
      if (this.state === 1) {
        this.state = byte === 91 ? 2 : byte === 93 ? 3 : byte === 80 ? 4 : [88, 94, 95].includes(byte) ? 5 : 0;
        if (byte === 27) { this.state = 1; this.sequence = offset + BigInt(index); this.started = performance.now(); continue; }
        this.control += String.fromCharCode(byte); this.escaped = false; continue;
      }
      const kind = this.state;
      const end = this.state === 2 ? byte >= 0x40 && byte <= 0x7e : (this.state === 3 && byte === 7) || (this.escaped && byte === 92);
      if (this.control.length < 256) this.control += String.fromCharCode(byte);
      else { this.overflow = true; if (this.state === 2) this.state = 0; }
      this.escaped = byte === 27;
      if (!end) continue;
      this.state = 0;
      // Most CSI ends are drawing/style operations and can never request a reply.
      if (kind === 2 && byte !== 99 && byte !== 110 && byte !== 112 && byte !== 113 && byte !== 116 && byte !== 117) continue;
      if (!this.overflow && isTerminalQuery(this.control)) query(index + 1, this.sequence, this.started, this.control);
    }
  }
}

/** Shared with the test double's output observer; strings remain bounded by the scanner. */
export function isTerminalQuery(control: string): boolean {
  return /^\u001b\[(?:[>=]?0?c|[56]n|\?6n|>0?q|\?u|\??[0-9]{1,6}\$p|1[4689]t)$/.test(control)
    || (/^\u001b\](?:1[012]|4);[^\u001b\u0007]*(?:\u0007|\u001b\\)$/.test(control) && control.includes("?"))
    || /^\u001bP(?:\$q|\+q)[\x20-\x7e]*\u001b\\$/.test(control);
}
