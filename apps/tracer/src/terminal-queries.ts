/** Splits writes at every control boundary, without deciding which controls request answers [307]. */
export class TerminalQueries {
  // Ground, ESC/intermediates, CSI, OSC, other string, ESC inside a string.
  private state = 0;
  private sequence = 0n;
  private escapeSequence = 0n;

  reset(): void { this.state = 0; }

  /** The renderer alone decides which spans answer; retained state is constant even for huge strings. */
  scan(bytes: Uint8Array, offset: bigint, boundary: (end: number, sequence: bigint) => void): void {
    if (this.state === 0 && bytes.indexOf(27) < 0) return;
    for (let index = 0; index < bytes.length; index++) {
      const byte = bytes[index]!;
      if (byte === 24 || byte === 26) { this.reset(); continue; }
      if (this.state >= 5) {
        if (byte === 92) {
          this.state = 0; boundary(index + 1, this.sequence); continue;
        }
        // ESC followed by anything but ST ends the old string in the renderer.
        this.state = 1; this.sequence = this.escapeSequence;
      }
      if (byte === 27 && this.state >= 3) {
        this.state = 5; this.escapeSequence = offset + BigInt(index); continue;
      }
      if (byte === 27 && this.state < 3) {
        this.state = 1; this.sequence = offset + BigInt(index); continue;
      }
      let complete = false;
      if (this.state === 1) {
        if (byte === 91) this.state = 2;
        else if (byte === 93) { this.state = 3; }
        else if (byte === 80 || byte === 88 || byte === 94 || byte === 95) { this.state = 4; }
        else complete = byte >= 0x30 && byte <= 0x7e;
      } else if (this.state === 2) complete = byte >= 0x40 && byte <= 0x7e;
      else if (this.state >= 3) {
        complete = this.state === 3 && byte === 7;
      }
      if (!complete) continue;
      this.state = 0;
      boundary(index + 1, this.sequence);
    }
  }
}
