/**
 * Reads the numbered key tokens that the same-session flood spec's program draws on row 1 (#477, D381).
 *
 * A token reaches the test bridge in one of two shapes. Raw PTY output carries it as the program wrote it:
 * `ESC 7`, `ESC [1;1H`, `<K000042>`, `ESC 8`. A repaint (Snapshot) carries the screen as the infraternal agent
 * serialised it, which positions and styles every cell on its own: `ESC [1;1H ESC [0m < ESC [1;2H ESC [0m K ...`.
 * Under a flood the key's echo legitimately arrives only in that repaint, so matching the raw text alone timed
 * out while the key had in fact won. This reader drops terminal control sequences before matching, which keeps
 * the cells of one row in order and joins them back into the token.
 */

/** Control sequences the serialiser and the test program emit: CSI, OSC (BEL or ST), charset, single-character ESC, SI/SO. */
const CONTROL = /\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[ -~]|[\x0e\x0f]/g;
/** A token as the program prints it: `<K` and six digits. */
const TOKEN = /<K(\d{6})>/g;
/**
 * Raw text kept between scans. It must hold a token split across two frames, including control sequences around
 * it, so a later frame can complete it; the newest token is a maximum, so scanning the kept text twice is harmless.
 */
const TAIL = 256;

/** The newest token in `text` (at least `previous`), and the tail of `text` to keep for the next scan. */
export function scanTokens(text: string, previous: number): { newest: number; tail: string } {
  let newest = previous;
  for (const match of text.replace(CONTROL, "").matchAll(TOKEN)) newest = Math.max(newest, Number(match[1]));
  return { newest, tail: text.slice(-TAIL) };
}
