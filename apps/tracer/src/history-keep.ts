/**
 * Keeps a terminal's own scrollback across a host repaint (#569, D381, D130).
 *
 * A host repaint (a `Snapshot` frame) describes the screen the host holds now. The host sends at most 256 rows of
 * history with it, and the repaint starts with a full reset, so painting it onto the device's terminal would throw
 * away the 10,000 rows the device already holds. That is what happened after one key typed during a flood.
 *
 * The device must not lose what it already has, so this module reads the device's terminal before it is reset and
 * writes the same rows back as plain VT, ahead of the repaint:
 *
 * 1. every row of the existing scrollback, then
 * 2. when output was skipped, the screen as the device last showed it, then a one-row "skipped" marker,
 *
 * and finally scrolls all of that into the scrollback so the visible screen is blank for the repaint.
 * The repaint's own leading reset is removed (`withoutLeadingReset`): the terminal was just reset and then received
 * this text, so everything the reset protects (modes, margins, tab stops, palette) is still at its start value.
 *
 * What the copy keeps and what it does not: text, wide characters and grapheme clusters, bold, italic, underline,
 * strike, blink, inverse, invisible and faint, and the colour of every cell. The terminal reports a cell's colour
 * already resolved to RGB, so a palette colour comes back as the same RGB colour (it no longer follows a later theme
 * change) while a cell in the theme's default colours stays in the default colours. Hyperlinks and the soft-wrap flag
 * of scrollback rows are not reported by the terminal and are not kept; each kept row is its own row.
 */
import type { GhosttyCell } from "../vendor/ghostty-web";

/** The part of a Ghostty terminal this module reads. `GhosttyTerminal` satisfies it. */
export interface HistorySource {
  /** Brings the render state up to date before the viewport is read. */
  update(): unknown;
  /** Rows of history above the screen (0 on the alternate screen). */
  getScrollbackLength(): number;
  /** One history row, 0 = oldest. */
  getScrollbackLine(offset: number): GhosttyCell[] | null;
  /** The codepoints of a history cell's grapheme cluster. */
  getScrollbackGrapheme(offset: number, col: number): number[] | null;
  /** All cells of the visible screen, row after row. */
  getViewport(): GhosttyCell[];
  /** The codepoints of a visible cell's grapheme cluster. */
  getGrapheme(row: number, col: number): number[] | null;
  /** The theme's default colours: cells in them are written without a colour. */
  getColors(): { background: { r: number; g: number; b: number }; foreground: { r: number; g: number; b: number } };
  /** Whether the alternate screen is showing. */
  isAlternateScreen(): boolean;
  /** Feeds VT text to the terminal. Used once, to leave the alternate screen of a terminal that is about to be discarded. */
  write(data: string): void;
  /** Columns and rows of the screen. */
  getDimensions(): { cols: number; rows: number };
}

/** What the repaint should do with the existing terminal content. */
export interface KeepOptions {
  /** True when bytes between the device's position and the repaint's were dropped: the screen is kept and marked. */
  skipped: boolean;
  /**
   * The `screen` the previous call returned. A flood repaints again and again while the screen barely changes, and
   * copying the same screen into the history every time would fill it with copies, so a screen equal to this one is
   * neither copied nor marked a second time.
   */
  previousScreen?: string | undefined;
}

/** The text to write ahead of a repaint, and the copied screen to pass back as `previousScreen` next time. */
export interface KeptHistory {
  /** VT text for the repaint's terminal; see {@link keepHistoryVt}. */
  bytes: Uint8Array;
  /** The screen rows copied into the history by this call, as VT; `previousScreen` when it copied none. */
  screen: string | undefined;
}

/** The text of the marker row left where output was skipped. Plain words, dimmed. */
export const SKIPPED_OUTPUT_MARKER = "— output skipped here —";

/** The escape character that starts a control sequence. */
const ESC = "\x1b";
/** A cell's style flags, as the terminal reports them in `GhosttyCell.flags`: bold. */
const BOLD = 1;
/** Style flag: italic. */
const ITALIC = 2;
/** Style flag: underline. */
const UNDERLINE = 4;
/** Style flag: strike-through. */
const STRIKETHROUGH = 8;
/** Style flag: inverse video (foreground and background swapped when drawn). */
const INVERSE = 16;
/** Style flag: invisible text. */
const INVISIBLE = 32;
/** Style flag: blinking text. */
const BLINK = 64;
/** Style flag: faint (dim) text. */
const FAINT = 128;

/** Turns the finished VT text into bytes for the terminal. */
const encoder = new TextEncoder();

/** Whether the terminal holds anything worth keeping: history rows, or text on the visible screen. */
export function hasKeepableContent(source: HistorySource): boolean {
  // The history is invisible from the alternate screen, so there it may exist behind what the API reports.
  if (source.isAlternateScreen() || source.getScrollbackLength() > 0) return true;
  source.update();
  return source.getViewport().some((cell) => cell.codepoint > 32 || cell.grapheme_len > 0);
}

/**
 * Serialises the terminal's scrollback (and, with `skipped`, its screen and a marker row) as VT text that, written to
 * a freshly reset terminal of the same size, leaves all of it in the scrollback above a blank screen. Returns
 * `undefined` when there is nothing to keep, and then the caller repaints as before.
 */
export function keepHistoryVt(source: HistorySource, options: KeepOptions): KeptHistory | undefined {
  const { cols, rows } = source.getDimensions();
  // The history belongs to the primary screen, and the alternate screen cannot see it. The terminal is about to be
  // discarded, so leave the alternate screen (all three ways programs enter it) to reach the history. The host's
  // repaint restores whichever screen is showing.
  const wasAlternate = source.isAlternateScreen();
  if (wasAlternate) source.write("\x1b[?1049l\x1b[?1047l\x1b[?47l");
  // The default colours live in the render state, which is only current after an update.
  source.update();
  const defaults = source.getColors();
  const defaultFg = rgb(defaults.foreground.r, defaults.foreground.g, defaults.foreground.b);
  const defaultBg = rgb(defaults.background.r, defaults.background.g, defaults.background.b);
  const parts: string[] = [];
  let written = 0;

  const historyRows = source.getScrollbackLength();
  for (let offset = 0; offset < historyRows; offset += 1) {
    // A row the terminal cannot give is kept as an empty one, so the rows after it stay where they were.
    const cells = source.getScrollbackLine(offset) ?? [];
    parts.push(rowVt(cells, defaultFg, defaultBg, (col) => source.getScrollbackGrapheme(offset, col)), "\r\n");
    written += 1;
  }

  let screen = options.previousScreen;
  if (options.skipped) {
    // The host's repaint restores both screens, so the screen of a terminal that was on the alternate screen (a
    // program's own display, not output) is not copied into the history.
    let copied = "";
    let copiedRows = 0;
    if (!wasAlternate) {
      source.update();
      const viewport = source.getViewport();
      let last = rows - 1;
      while (last >= 0 && rowIsBlank(viewport, last * cols, cols, defaultBg)) last -= 1;
      for (let row = 0; row <= last; row += 1) {
        const cells = viewport.slice(row * cols, row * cols + cols);
        copied += `${rowVt(cells, defaultFg, defaultBg, (col) => source.getGrapheme(row, col))}\r\n`;
        copiedRows += 1;
      }
    }
    // The same screen as last time carries nothing new, and the marker before it already says output was skipped.
    if (copied !== options.previousScreen || copiedRows === 0) {
      parts.push(copied);
      written += copiedRows;
      if (copiedRows > 0) screen = copied;
      if (written > 0) {
        parts.push(`${ESC}[2m${SKIPPED_OUTPUT_MARKER}${ESC}[0m\r\n`);
        written += 1;
      }
    }
  }
  if (written === 0) return undefined;

  // Every row is in the terminal, but the last `rows - 1` are still on the screen. Line feeds from the bottom push
  // them into the scrollback one at a time, and only content scrolls out: the rows below it are blank. (Scroll-up
  // and clear-screen do not reach the scrollback here, so they cannot do this job.) Then home the cursor.
  parts.push("\n".repeat(rows - 1), `${ESC}[0m${ESC}[H`);
  return { bytes: encoder.encode(parts.join("")), screen };
}

/**
 * The repaint without its leading full reset (`ESC c`), or the bytes unchanged when they do not start with one.
 * Only call this after `keepHistoryVt` returned text: a full reset also erases the scrollback that text just built.
 */
export function withoutLeadingReset(bytes: Uint8Array): Uint8Array {
  return bytes.byteLength >= 2 && bytes[0] === 0x1b && bytes[1] === 0x63 ? bytes.subarray(2) : bytes;
}

/** Concatenates two byte ranges into a new array (the inputs are not touched, so the caller can wipe them). */
export function concatBytes(first: Uint8Array, second: Uint8Array): Uint8Array {
  const joined = new Uint8Array(first.byteLength + second.byteLength);
  joined.set(first, 0);
  joined.set(second, first.byteLength);
  return joined;
}

/** One colour as a single number (0xRRGGBB), so two colours compare with `===`. */
function rgb(r: number, g: number, b: number): number {
  return (r << 16) | (g << 8) | b;
}

/** Whether a screen row draws nothing at all, so trailing empty rows are not copied into the history. */
function rowIsBlank(viewport: GhosttyCell[], start: number, cols: number, defaultBg: number): boolean {
  for (let col = 0; col < cols; col += 1) {
    const cell = viewport[start + col];
    if (cell && !isPlainBlank(cell, defaultBg)) return false;
  }
  return true;
}

/** One row as VT text ending with a reset, without a line break. Trailing blank cells in default colours are cut. */
function rowVt(
  cells: GhosttyCell[],
  defaultFg: number,
  defaultBg: number,
  grapheme: (col: number) => number[] | null,
): string {
  // Everything after the last cell that draws anything is left to the terminal's own blank.
  let end = cells.length;
  while (end > 0 && isPlainBlank(cells[end - 1]!, defaultBg)) end -= 1;
  let out = "";
  let style = "";
  for (let col = 0; col < end; col += 1) {
    const cell = cells[col];
    if (!cell) continue;
    // The second half of a wide character: the first half already covers it.
    if (cell.width === 0) continue;
    const next = styleVt(cell, defaultFg, defaultBg);
    if (next !== style) {
      out += next;
      style = next;
    }
    if (cell.grapheme_len > 0) {
      const points = grapheme(col);
      out += points && points.length > 0 ? String.fromCodePoint(...points) : " ";
    } else {
      out += cell.codepoint > 31 && cell.codepoint !== 127 ? String.fromCodePoint(cell.codepoint) : " ";
    }
  }
  return `${out}${ESC}[0m`;
}

/** A cell that draws nothing: no text, no underline/strike/inverse, and the default background. */
function isPlainBlank(cell: GhosttyCell, defaultBg: number): boolean {
  if (cell.codepoint > 32 || cell.grapheme_len > 0) return false;
  if ((cell.flags & (INVERSE | UNDERLINE | STRIKETHROUGH)) !== 0) return false;
  return rgb(cell.bg_r, cell.bg_g, cell.bg_b) === defaultBg;
}

/** The complete SGR for a cell, starting from a reset so each run states its whole style. */
function styleVt(cell: GhosttyCell, defaultFg: number, defaultBg: number): string {
  const codes: string[] = ["0"];
  const flags = cell.flags;
  if (flags & BOLD) codes.push("1");
  if (flags & FAINT) codes.push("2");
  if (flags & ITALIC) codes.push("3");
  if (flags & UNDERLINE) codes.push("4");
  if (flags & BLINK) codes.push("5");
  if (flags & INVERSE) codes.push("7");
  if (flags & INVISIBLE) codes.push("8");
  if (flags & STRIKETHROUGH) codes.push("9");
  if (rgb(cell.fg_r, cell.fg_g, cell.fg_b) !== defaultFg) codes.push(`38;2;${cell.fg_r};${cell.fg_g};${cell.fg_b}`);
  if (rgb(cell.bg_r, cell.bg_g, cell.bg_b) !== defaultBg) codes.push(`48;2;${cell.bg_r};${cell.bg_g};${cell.bg_b}`);
  return `${ESC}[${codes.join(";")}m`;
}
