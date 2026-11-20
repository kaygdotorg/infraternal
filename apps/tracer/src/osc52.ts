/**
 * Finds clipboard writes (OSC 52) in a stream of terminal output, so the page can put the text on the clipboard.
 *
 * A program asks to copy by printing `ESC ] 52 ; <targets> ; <base64 text> BEL` (or ending with `ESC \`). That is how
 * a remote editor or a multiplexer copies from inside an SSH session. The renderer's VT parser ignores the sequence,
 * so this scanner reads it from the raw bytes, next to the other output scanners (`terminal-queries.ts`).
 *
 * Rules, chosen for safety and for cost:
 * - Writes only. A read request (`?` as the text) is never answered, and an empty text never clears the clipboard.
 * - The text is capped ({@link MAX_BASE64}: 1,048,576 base64 characters, which is 786,432 bytes of text). A longer copy is
 *   dropped whole, never cut in the middle, and the caller is told so it can say that nothing was copied.
 * - Chunks can split a sequence anywhere. The scanner keeps its place between calls, and keeps the text only while
 *   inside a clipboard sequence. Other output costs one `indexOf` per chunk, so floods stay fast.
 */

/** Most base64 characters of one copy: 1,048,576 (1 Mi characters), which decodes to 786,432 bytes (768 KiB) of text. A larger copy is dropped. */
export const MAX_BASE64 = 1_048_576;

/** The escape byte that starts every control sequence. */
const ESC = 0x1b;
/** The bell byte, which ends an OSC string in the short form. */
const BEL = 0x07;
/** The byte after ESC that makes the string terminator (`ESC \`). */
const BACKSLASH = 0x5c;
/** Reads the run of base64 characters; every character of a valid text is plain ASCII. */
const ASCII = new TextDecoder("latin1");
/** The introducer `ESC ] 5 2 ;`, after the ESC. */
const PREFIX = [0x5d, 0x35, 0x32, 0x3b];

/** Where the scanner is: outside a sequence, matching the introducer, reading targets or text, or after an ESC in either. */
enum Step { Ground, Prefix, Targets, Text, TargetsEscape, TextEscape, Skip }

/** Reads clipboard writes out of output chunks. Keep one per terminal stream and feed it every chunk in order. */
export class Osc52Scanner {
  private step: Step = Step.Ground;
  /** How many bytes of the introducer have matched. */
  private matched = 0;
  /** The targets field (for example `c`), as text. */
  private targets = "";
  /** The base64 text collected so far. */
  private text = "";
  /** The sequence began inside replayed output, so it is old news even if its end arrives live. */
  private replayed = false;

  /** Forgets any half-read sequence; call it when the stream restarts. */
  reset(): void { this.step = Step.Ground; this.text = ""; this.targets = ""; }

  /**
   * Reads one chunk. `onCopy` gets the decoded text of each finished clipboard write; pass `undefined` to keep the
   * scanner in step with bytes that must not act (a replay of old output). `onTooLarge` is called once for each live
   * copy that passes {@link MAX_BASE64} and is therefore dropped, so the person is not left pasting the old clipboard.
   */
  scan(bytes: Uint8Array, onCopy: ((text: string) => void) | undefined, onTooLarge?: () => void): void {
    let index = 0;
    const length = bytes.length;
    while (index < length) {
      if (this.step === Step.Ground) {
        index = bytes.indexOf(ESC, index);
        if (index < 0) return;
        this.step = Step.Prefix; this.matched = 0; index += 1; continue;
      }
      const byte = bytes[index++]!;
      if (byte === 0x18 || byte === 0x1a) { this.reset(); continue; }
      switch (this.step) {
        case Step.Prefix:
          if (byte === PREFIX[this.matched]) {
            this.matched += 1;
            if (this.matched === PREFIX.length) { this.step = Step.Targets; this.targets = ""; this.text = ""; this.replayed = !onCopy; }
          } else if (byte === ESC) this.matched = 0;
          else this.step = Step.Ground;
          break;
        case Step.Targets:
          if (byte === 0x3b) this.step = Step.Text;
          else if (byte === ESC) this.step = Step.TargetsEscape;
          else if (byte === BEL || this.targets.length > 8) this.step = Step.Ground;
          else this.targets += String.fromCharCode(byte);
          break;
        case Step.Text: {
          // Take the whole run up to the next terminator or ESC at once; text arrives in large chunks.
          if (byte === BEL) { this.finish(onCopy); break; }
          if (byte === ESC) { this.step = Step.TextEscape; break; }
          let end = index;
          while (end < length && bytes[end] !== BEL && bytes[end] !== ESC) end += 1;
          this.text += ASCII.decode(bytes.subarray(index - 1, end));
          if (this.text.length > MAX_BASE64) {
            this.text = ""; this.step = Step.Skip;
            if (onCopy && !this.replayed) onTooLarge?.();
          }
          index = end;
          break;
        }
        case Step.Skip:
          // Over the cap: wait for the end of the string without keeping anything.
          if (byte === BEL) this.step = Step.Ground;
          else if (byte === ESC) { this.step = Step.Prefix; this.matched = 0; }
          break;
        case Step.TargetsEscape:
        case Step.TextEscape:
          if (byte === BACKSLASH && this.step === Step.TextEscape) this.finish(onCopy);
          else if (byte === BACKSLASH) this.step = Step.Ground;
          else {
            // The ESC began a new sequence instead of ending this one: look at this byte as its first.
            this.step = Step.Prefix; this.matched = 0; this.text = ""; index -= 1;
          }
          break;
      }
    }
  }

  /** A clipboard sequence ended: hand over its decoded text when it is a valid write to the clipboard. */
  private finish(onCopy: ((text: string) => void) | undefined): void {
    const { targets, text } = this;
    this.step = Step.Ground; this.text = "";
    if (!onCopy || this.replayed || text === "" || text === "?") return;
    // Only the system clipboard and the primary selection; the numbered cut buffers have no browser equivalent.
    if (targets !== "" && !/[cps]/.test(targets)) return;
    const decoded = decodeBase64(text);
    if (decoded !== undefined && decoded !== "") onCopy(decoded);
  }
}

/** Decodes base64 text into a string, or `undefined` when it is not valid base64 or not valid UTF-8. */
export function decodeBase64(text: string): string | undefined {
  try {
    const binary = atob(text);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch { return undefined; }
}
