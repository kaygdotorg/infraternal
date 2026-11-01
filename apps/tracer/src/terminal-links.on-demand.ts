/** Finds and opens links in the visible terminal buffer; callers feed changed rows only after paint. */
import { hideTipAt as hideSharedTipAt, hoverTipAt, peekTipAt } from "../../../packages/ui/src/tooltip";
import { formatLinkTooltipText, linkTooltipLineCount } from "../../../packages/ui/src/tooltip-link-text";
import { isMacPlatform } from "../../../packages/ui/src/platform";
import { cssPx } from "../../../packages/ui/src/ui-scale";

interface TerminalLinkUnderlineRange {
  startX: number;
  startY: number;
  endX: number;
  endY: number;
}

export interface TerminalLinkRange {
  start: { x: number; y: number };
  end: { x: number; y: number };
}

export interface TerminalLink {
  kind: "url" | "osc8";
  target: string;
  visibleText: string;
  range: TerminalLinkRange;
  openable: boolean;
}

export interface TerminalLinkCell {
  text: string;
  target?: string;
}

export interface TerminalLinkRow {
  /** Absolute row in the active buffer, including scrollback. */
  y: number;
  /** Separates normal scrollback wrap fingerprints from alternate-screen rows at the same index. */
  bufferType?: "normal" | "alternate";
  /** Ghostty's flag says this row continues from the preceding row. */
  wrapped: boolean;
  /** Scrollback rows do not expose Ghostty's wrap bit through this buffer API. */
  wrapKnown?: boolean;
  cells: TerminalLinkCell[];
}

interface LinkCharacter {
  character: string;
  x: number;
  y: number;
  target?: string;
}

const URL_PATTERN = /(?<![\p{L}\p{N}_@])(?:https?:\/\/|mailto:|file:\/\/)[^\s<>"'`]+/giu;
const TRAILING_PUNCTUATION = /[.,;:!?]+$/u;
const BRACKETS = [["(", ")"], ["[", "]"], ["{", "}"]] as const;

/** Only web pages and mail links leave the terminal; local files are recognized for display. */
export function isOpenableTarget(target: string): boolean {
  if (!/^https?:\/\/|^mailto:/iu.test(target)) return false;
  try {
    const url = new URL(target);
    return url.protocol === "http:" || url.protocol === "https:" || (url.protocol === "mailto:" && url.pathname.length > 0);
  } catch {
    return false;
  }
}

/** Different OSC 8 labels need the actual destination visible before activation. */
export function shouldShowLinkTarget(link: TerminalLink): boolean {
  return link.kind === "osc8" && link.visibleText !== link.target;
}

/** Detects plain URLs and OSC 8 runs while preserving cell coordinates over soft wraps. */
export function detectTerminalLinks(rows: readonly TerminalLinkRow[]): TerminalLink[] {
  const ordered = [...rows].sort((left, right) => left.y - right.y);
  const output: TerminalLink[] = [];
  let group: TerminalLinkRow[] = [];

  const flush = (): void => {
    if (group.length > 0) output.push(...detectLogicalLine(group));
    group = [];
  };

  for (const row of ordered) {
    if (group.length > 0) {
      const previous = group[group.length - 1]!;
      if (row.y !== previous.y + 1 || !row.wrapped) flush();
    }
    group.push(row);
  }
  flush();
  return output.sort((left, right) => left.range.start.y - right.range.start.y || left.range.start.x - right.range.start.x);
}

function detectLogicalLine(rows: readonly TerminalLinkRow[]): TerminalLink[] {
  const cells = flattenRows(rows);
  if (cells.length === 0) return [];
  const text = cells.map((entry) => entry.character).join("");
  const links: TerminalLink[] = [];

  for (let start = 0; start < cells.length;) {
    const target = cells[start]!.target;
    if (!target) { start += 1; continue; }
    let end = start;
    while (end + 1 < cells.length && cells[end + 1]!.target === target) end += 1;
    const visibleText = text.slice(start, end + 1).trim();
    if (visibleText) links.push(makeLink("osc8", target, visibleText, cells[start]!, cells[end]!));
    start = end + 1;
  }

  URL_PATTERN.lastIndex = 0;
  for (const match of text.matchAll(URL_PATTERN)) {
    const raw = match[0];
    const offset = match.index ?? 0;
    const trimmed = trimUrl(raw);
    if (!trimmed) continue;
    const end = offset + trimmed.length - 1;
    if (cells.slice(offset, end + 1).some((entry) => entry.target !== undefined)) continue;
    links.push(makeLink("url", trimmed, trimmed, cells[offset]!, cells[end]!));
  }
  return links;
}

function flattenRows(rows: readonly TerminalLinkRow[]): LinkCharacter[] {
  const result: LinkCharacter[] = [];
  for (let rowIndex = 0; rowIndex < rows.length; rowIndex += 1) {
    const row = rows[rowIndex]!;
    const continues = rowIndex + 1 < rows.length && rows[rowIndex + 1]!.wrapped;
    let lastMeaningful = row.cells.length - 1;
    if (!continues) {
      while (lastMeaningful >= 0) {
        const cell = row.cells[lastMeaningful]!;
        if ((cell.text && cell.text !== " ") || cell.target !== undefined) break;
        lastMeaningful -= 1;
      }
    }
    for (let x = 0; x <= lastMeaningful; x += 1) {
      const cell = row.cells[x]!;
      const value = cell.text || " ";
      for (let offset = 0; offset < value.length; offset += 1) {
        result.push({
          character: value[offset]!,
          x,
          y: row.y,
          ...(cell.target === undefined ? {} : { target: cell.target }),
        });
      }
    }
  }
  return result;
}

function makeLink(kind: TerminalLink["kind"], target: string, visibleText: string, start: LinkCharacter, end: LinkCharacter): TerminalLink {
  return {
    kind,
    target,
    visibleText,
    range: { start: { x: start.x, y: start.y }, end: { x: end.x, y: end.y } },
    openable: isOpenableTarget(target),
  };
}

function trimUrl(value: string): string {
  let result = value.replace(TRAILING_PUNCTUATION, "");
  for (const [open, close] of BRACKETS) {
    const excess = count(result, close) - count(result, open);
    for (let removed = 0; removed < excess && result.endsWith(close); removed += 1) result = result.slice(0, -1);
  }
  return result;
}

function count(value: string, character: string): number {
  let total = 0;
  for (const current of value) if (current === character) total += 1;
  return total;
}

interface BufferRow {
  readonly isWrapped: boolean;
  readonly length: number;
  getCell(x: number): {
    getChars(): string;
    getHyperlinkId(): number;
  } | undefined;
}

interface LinkIndexOptions {
  host: HTMLElement;
  canvas: HTMLCanvasElement;
  getBufferLength(): number;
  getVisibleRange(): { first: number; last: number };
  getRow(y: number): TerminalLinkRow | undefined;
  getCellMetrics(): { width: number; height: number };
  paint(ranges: readonly TerminalLinkUnderlineRange[] | null): void;
  open(link: TerminalLink): void;
}

/** Incremental row cache and pointer bridge for a single live terminal. */
export interface TerminalLinkController {
  /** Queue changed buffer rows; actual parsing runs once in an idle slice. */
  updateRows(rows: readonly number[], force?: boolean): void;
  /** Queue the current viewport after scrolling or a full redraw. */
  updateVisibleRows(): void;
  /** Drop visible link state after resize or an active-buffer switch, preserving scrollback wrap fingerprints. */
  invalidateBuffer(): void;
  /** Links cached in the current viewport, for the keyboard palette. */
  linksOnScreen(): readonly TerminalLink[];
  /** Opens a cached, visible destination after validating it again. */
  openTarget(target: string): boolean;
  dispose(): void;
}

/** Creates the terminal-local link cache; no timer or scan runs until output or scrolling queues rows. */
export function createTerminalLinkController(options: LinkIndexOptions): TerminalLinkController {
  const macPlatform = isMacPlatform();
  const rowCache = new Map<string, { wrapped: boolean; fingerprint: string }>();
  const links = new Map<string, TerminalLink>();
  const pendingRows = new Set<number>();
  const forcedRows = new Set<number>();
  let idleHandle = 0;
  let focusedLink: TerminalLink | undefined;
  let openLinkModifierHeld = false;
  let paintedRanges: readonly TerminalLinkUnderlineRange[] | null = null;
  let refreshHover = false;
  let lastPoint: { x: number; y: number } | undefined;
  let down: { x: number; y: number; key?: string; dragged: boolean } | undefined;
  let released: { key?: string; dragged: boolean } | undefined;
  let touchOpenedKey: string | undefined;
  let touchOpenTimer = 0;
  let disposed = false;

  const linkKey = (link: TerminalLink): string => `${link.kind}:${link.range.start.y}:${link.range.start.x}:${link.range.end.y}:${link.range.end.x}:${link.target}`;

  const tooltipTextStyle = (): { fontSize: number; contentWidth: number; font: string } => {
    const style = getComputedStyle(options.host);
    const fontSize = cssPx(options.host, "--text-secondary", 12);
    const weight = style.getPropertyValue("--fw-label").trim() || "500";
    const family = style.getPropertyValue("--font-ui").trim() || "ui-monospace";
    return {
      fontSize,
      contentWidth: Math.max(1, Math.min(258, innerWidth - 38)),
      font: `${weight} ${fontSize}px ${family}`,
    };
  };

  const formatTarget = (target: string): string => {
    const style = tooltipTextStyle();
    return formatLinkTooltipText(target, style.contentWidth, style.font);
  };

  /** Multiline links span the terminal width so the shared tooltip can clear every wrapped row. */
  const tooltipPoint = (link: TerminalLink, label: string): { x: number; y: number; side: "top" | "bottom" } => {
    const canvas = options.canvas.getBoundingClientRect();
    const metrics = options.getCellMetrics();
    const visible = options.getVisibleRange();
    const first = Math.max(0, link.range.start.y - visible.first);
    const last = Math.min(visible.last - visible.first, link.range.end.y - visible.first);
    const multiline = link.range.start.y !== link.range.end.y;
    const left = multiline ? canvas.left : canvas.left + link.range.start.x * metrics.width;
    const right = multiline ? canvas.right : canvas.left + (link.range.end.x + 1) * metrics.width;
    const linkTop = canvas.top + first * metrics.height;
    const linkBottom = canvas.top + (last + 1) * metrics.height;
    const { fontSize, contentWidth, font } = tooltipTextStyle();
    const lineCount = linkTooltipLineCount(label, contentWidth, font);
    const tooltipHeight = Math.ceil(lineCount * fontSize * 1.2) + 14;
    const topFits = linkTop - 8 - tooltipHeight >= 8;
    const bottomFits = innerHeight - linkBottom - 8 - tooltipHeight >= 8;
    const side = topFits || (!bottomFits && linkTop - tooltipHeight >= innerHeight - linkBottom - tooltipHeight) ? "top" : "bottom";
    return { x: (left + right) / 2, y: side === "top" ? linkTop : linkBottom, side };
  };

  /** Sends link-only wrapping and placement to the shared tooltip for this call. */
  const showLinkTip = (label: string, point: { x: number; y: number; side: "top" | "bottom" }, hover: boolean): void => {
    if (hover) hoverTipAt(options.host, label, point.x, point.y, { lines: 2, side: point.side });
    else peekTipAt(options.host, label, point.x, point.y, 2600, { lines: 2, side: point.side });
  };

  const hideLinkTip = (): void => {
    hideSharedTipAt(options.host);
  };

  const paintHighlights = (): void => {
    const visible = options.getVisibleRange();
    const candidates = openLinkModifierHeld
      ? [...links.values()].filter((link) =>
        link.range.end.y >= visible.first && link.range.start.y <= visible.last && !touchesRows(link, pendingRows))
        .sort((left, right) => left.range.start.y - right.range.start.y || left.range.start.x - right.range.start.x)
      : focusedLink && focusedLink.range.end.y >= visible.first && focusedLink.range.start.y <= visible.last &&
        !touchesRows(focusedLink, pendingRows) ? [focusedLink] : [];
    const ranges = candidates.map((link) => ({
      startX: link.range.start.x,
      startY: Math.max(0, link.range.start.y - visible.first),
      endX: link.range.end.x,
      endY: Math.min(visible.last - visible.first, link.range.end.y - visible.first),
    }));
    const nextRanges = ranges.length > 0 ? ranges : null;
    if (sameUnderlineRanges(paintedRanges, nextRanges)) return;
    paintedRanges = nextRanges;
    options.paint(nextRanges);
  };

  const clearRevealedHighlights = (): void => {
    if (!focusedLink && !openLinkModifierHeld && paintedRanges === null) return;
    const hadFocus = focusedLink !== undefined;
    focusedLink = undefined;
    refreshHover = lastPoint !== undefined;
    if (hadFocus) {
      hideLinkTip();
      options.canvas.style.cursor = "text";
    }
    if (paintedRanges !== null) {
      paintedRanges = null;
      options.paint(null);
    }
  };

  const setOpenLinkModifierHeld = (held: boolean): void => {
    if (held === openLinkModifierHeld) return;
    openLinkModifierHeld = held;
    paintHighlights();
  };

  const rowsAt = (y: number, scannedRows: Map<number, TerminalLinkRow>, changedRows?: Set<number>): TerminalLinkRow | undefined => {
    const scanned = scannedRows.get(y);
    if (scanned) return scanned;
    const next = options.getRow(y);
    if (!next) return undefined;
    const fingerprint = rowFingerprint(next);
    const cacheKey = `${next.bufferType ?? "normal"}:${y}`;
    const previous = rowCache.get(cacheKey);
    // Scrollback drops Ghostty's wrap bit; retain it only while the exact row contents still match.
    const cached = Boolean(previous && previous.fingerprint === fingerprint);
    const changed = !previous || previous.fingerprint !== fingerprint ||
      (next.wrapKnown !== false && previous.wrapped !== next.wrapped);
    if (changed) changedRows?.add(y);
    // Missing wrap history is not an unwrapped boundary; preserve the buffer row's flag for this scan.
    const wrapped = next.wrapKnown === false && cached && previous
      ? previous.wrapped
      : next.wrapped;
    const row = next.wrapKnown === false
      ? { ...next, wrapped, wrapKnown: cached }
      : next;
    if (next.wrapKnown !== false || cached) rowCache.set(cacheKey, { wrapped, fingerprint });
    else rowCache.delete(cacheKey);
    scannedRows.set(y, row);
    return row;
  };

  const logicalGroup = (
    y: number,
    visible: { first: number; last: number },
    scannedRows: Map<number, TerminalLinkRow>,
    changedRows?: Set<number>,
  ): TerminalLinkRow[] => {
    const row = rowsAt(y, scannedRows, changedRows);
    if (!row) return [];
    let first = y;
    while (first > visible.first) {
      const current = rowsAt(first, scannedRows, changedRows);
      if (!current?.wrapped) break;
      first -= 1;
    }
    let last = y;
    while (last < visible.last) {
      const next = rowsAt(last + 1, scannedRows, changedRows);
      if (!next?.wrapped) break;
      last += 1;
    }
    const result: TerminalLinkRow[] = [];
    for (let current = first; current <= last; current += 1) {
      const item = rowsAt(current, scannedRows, changedRows);
      if (item) result.push(item);
    }
    return result;
  };

  const repaintHover = (link: TerminalLink | undefined, point?: { x: number; y: number }): void => {
    if (link === focusedLink) return;
    focusedLink = link;
    if (link) {
      if (!openLinkModifierHeld) paintHighlights();
      options.canvas.style.cursor = link.openable ? "pointer" : "text";
      if (shouldShowLinkTarget(link) && point) {
        const label = formatTarget(link.target);
        showLinkTip(label, tooltipPoint(link, label), true);
      }
      else hideLinkTip();
    } else {
      if (!openLinkModifierHeld) paintHighlights();
      options.canvas.style.cursor = "text";
      hideLinkTip();
    }
  };

  const hitTest = (clientX: number, clientY: number): TerminalLink | undefined => {
    const rect = options.canvas.getBoundingClientRect();
    const metrics = options.getCellMetrics();
    if (metrics.width <= 0 || metrics.height <= 0 || clientX < rect.left || clientY < rect.top || clientX >= rect.right || clientY >= rect.bottom) return undefined;
    const x = Math.floor((clientX - rect.left) / metrics.width);
    const screenY = Math.floor((clientY - rect.top) / metrics.height);
    const y = options.getVisibleRange().first + screenY;
    for (const link of links.values()) {
      if (touchesRows(link, pendingRows)) continue;
      if (y < link.range.start.y || y > link.range.end.y) continue;
      const within = y === link.range.start.y ? x >= link.range.start.x
        : y === link.range.end.y ? x <= link.range.end.x
          : true;
      if (within) return link;
    }
    return undefined;
  };

  const scanPending = (): void => {
    idleHandle = 0;
    if (disposed) return;
    const visible = options.getVisibleRange();
    const queued = [...pendingRows].filter((y) => y >= visible.first && y <= visible.last).sort((a, b) => a - b);
    const forced = new Set([...forcedRows].filter((y) => y >= visible.first && y <= visible.last));
    pendingRows.clear();
    forcedRows.clear();
    if (queued.length === 0) return;
    const scannedRows = new Map<number, TerminalLinkRow>();
    const groups = new Map<string, TerminalLinkRow[]>();
    const changedRows = new Set<number>();
    for (const y of queued) {
      const row = rowsAt(y, scannedRows, changedRows);
      if (!row || (!forced.has(y) && !changedRows.has(y))) continue;
      if (forced.has(y)) changedRows.add(y);
      const group = logicalGroup(y, visible, scannedRows, changedRows);
      if (group.length === 0) continue;
      const key = `${group[0]!.y}-${group.at(-1)!.y}`;
      groups.set(key, group);
    }
    for (const [key, link] of links) {
      if (touchesRows(link, changedRows)) links.delete(key);
    }
    if (focusedLink && touchesRows(focusedLink, changedRows)) {
      hideLinkTip();
      refreshHover = true;
    }
    for (const [key, link] of links) {
      if (link.range.end.y < visible.first || link.range.start.y > visible.last) links.delete(key);
    }
    for (const group of groups.values()) {
      const first = group[0]!.y;
      const last = group.at(-1)!.y;
      for (const [key, link] of links) {
        if (link.range.start.y <= last && link.range.end.y >= first) links.delete(key);
      }
      for (const link of detectTerminalLinks(group)) {
        if (isTruncatedPlainUrl(link, group, visible, options.getBufferLength())) continue;
        links.set(linkKey(link), link);
      }
    }
    if (lastPoint) {
      if (refreshHover) focusedLink = undefined;
      refreshHover = false;
      repaintHover(hitTest(lastPoint.x, lastPoint.y), lastPoint);
    }
    if (openLinkModifierHeld || focusedLink) paintHighlights();
  };

  const requestScan = (): void => {
    if (idleHandle || disposed || pendingRows.size === 0) return;
    const w = window as unknown as { requestIdleCallback?: (callback: () => void, options?: { timeout: number }) => number };
    if (w.requestIdleCallback) idleHandle = w.requestIdleCallback(scanPending, { timeout: 120 });
    else idleHandle = window.setTimeout(scanPending, 32);
  };

  const onPointerMove = (event: PointerEvent): void => {
    setOpenLinkModifierHeld(macPlatform ? event.metaKey : event.ctrlKey);
    lastPoint = { x: event.clientX, y: event.clientY };
    if (down && Math.hypot(event.clientX - down.x, event.clientY - down.y) > 6) {
      down.dragged = true;
      repaintHover(undefined);
      return;
    }
    if (event.pointerType === "touch") return;
    const link = hitTest(event.clientX, event.clientY);
    if (link !== focusedLink) repaintHover(link, lastPoint);
  };
  const onPointerDown = (event: PointerEvent): void => {
    const link = hitTest(event.clientX, event.clientY);
    down = { x: event.clientX, y: event.clientY, ...(link ? { key: linkKey(link) } : {}), dragged: false };
  };
  const onPointerUp = (event: PointerEvent): void => {
    if (!down) return;
    if (Math.hypot(event.clientX - down.x, event.clientY - down.y) > 6) down.dragged = true;
    const key = down.key;
    const dragged = down.dragged;
    released = { ...(key ? { key } : {}), dragged };
    down = undefined;
    window.setTimeout(() => { released = undefined; }, 50);
    const link = hitTest(event.clientX, event.clientY);
    if (event.pointerType === "touch" && key && !dragged && link?.openable && key === linkKey(link)) {
      // Some mobile browsers suppress click after terminal touch gestures; pointerup still carries tap activation.
      touchOpenedKey = key;
      window.clearTimeout(touchOpenTimer);
      touchOpenTimer = window.setTimeout(() => { touchOpenedKey = undefined; }, 700);
      if (shouldShowLinkTarget(link)) {
        const label = formatTarget(link.target);
        showLinkTip(label, tooltipPoint(link, label), false);
      }
      options.open(link);
    }
  };
  const onClick = (event: MouseEvent): void => {
    const link = hitTest(event.clientX, event.clientY);
    if (link && touchOpenedKey === linkKey(link)) {
      event.preventDefault();
      event.stopPropagation();
      touchOpenedKey = undefined;
      window.clearTimeout(touchOpenTimer);
      return;
    }
    const wasDragged = released?.dragged ?? false;
    const sameLink = released ? Boolean(link && released.key === linkKey(link)) : true;
    if (!link || !link.openable || wasDragged || !sameLink) return;
    event.preventDefault();
    event.stopPropagation();
    if (shouldShowLinkTarget(link)) {
      const label = formatTarget(link.target);
      showLinkTip(label, tooltipPoint(link, label), false);
    }
    options.open(link);
  };
  const onPointerLeave = (): void => {
    lastPoint = undefined;
    refreshHover = false;
    repaintHover(undefined);
  };

  const onModifierKey = (event: KeyboardEvent): void => {
    const modifierName = macPlatform ? "Meta" : "Control";
    const held = event.key === modifierName ? event.type === "keydown" : macPlatform ? event.metaKey : event.ctrlKey;
    setOpenLinkModifierHeld(held);
  };
  const onWindowBlur = (): void => setOpenLinkModifierHeld(false);

  options.host.addEventListener("pointermove", onPointerMove, { passive: true });
  options.host.addEventListener("pointerdown", onPointerDown, { capture: true, passive: true });
  options.host.addEventListener("pointerup", onPointerUp, { capture: true, passive: true });
  options.host.addEventListener("click", onClick, { capture: true });
  options.host.addEventListener("pointerleave", onPointerLeave);
  window.addEventListener("keydown", onModifierKey, { capture: true });
  window.addEventListener("keyup", onModifierKey, { capture: true });
  window.addEventListener("blur", onWindowBlur);

  return {
    updateRows(changedRows, force = true) {
      if (disposed) return;
      const dirtyRows = [...new Set(changedRows)];
      if (dirtyRows.length > 0) {
        let invalidatedFocus = false;
        for (const y of dirtyRows) pendingRows.add(y);
        if (force) for (const y of dirtyRows) forcedRows.add(y);
        const touchesDirtyGroup = (link: TerminalLink): boolean => dirtyRows.some((y) =>
          y >= link.range.start.y - 1 && y <= link.range.end.y + 1);
        if (force) {
          // Drop known dirty activation targets without reading terminal cells on the render or typing path.
          for (const [key, link] of links) {
            if (touchesDirtyGroup(link)) links.delete(key);
          }
        }
        if (focusedLink && touchesDirtyGroup(focusedLink)) {
          hideLinkTip();
          focusedLink = undefined;
          refreshHover = true;
          invalidatedFocus = true;
          options.canvas.style.cursor = "text";
        }
        if (openLinkModifierHeld || invalidatedFocus) paintHighlights();
      }
      requestScan();
    },
    updateVisibleRows() {
      if (disposed) return;
      // The terminal has already moved or repainted these screen-relative rows; remove old ink now.
      clearRevealedHighlights();
      const visible = options.getVisibleRange();
      const rows: number[] = [];
      for (let y = visible.first; y <= visible.last; y += 1) rows.push(y);
      this.updateRows(rows, true);
    },
    invalidateBuffer() {
      if (disposed) return;
      links.clear();
      pendingRows.clear();
      forcedRows.clear();
      repaintHover(undefined);
      if (openLinkModifierHeld) paintHighlights();
      this.updateVisibleRows();
    },
    linksOnScreen() {
      const visible = options.getVisibleRange();
      return [...links.values()]
        .filter((link) => link.openable && link.range.start.y <= visible.last && link.range.end.y >= visible.first && !touchesRows(link, pendingRows))
        .sort((left, right) => left.range.start.y - right.range.start.y || left.range.start.x - right.range.start.x);
    },
    openTarget(target) {
      const link = this.linksOnScreen().find((candidate) => candidate.target === target);
      if (!link || !isOpenableTarget(target)) return false;
      options.open(link);
      return true;
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      if (idleHandle) {
        const w = window as unknown as { cancelIdleCallback?: (id: number) => void };
        if (w.cancelIdleCallback) w.cancelIdleCallback(idleHandle);
        else window.clearTimeout(idleHandle);
      }
      window.clearTimeout(touchOpenTimer);
      options.host.removeEventListener("pointermove", onPointerMove);
      options.host.removeEventListener("pointerdown", onPointerDown, true);
      options.host.removeEventListener("pointerup", onPointerUp, true);
      options.host.removeEventListener("click", onClick, true);
      options.host.removeEventListener("pointerleave", onPointerLeave);
      window.removeEventListener("keydown", onModifierKey, true);
      window.removeEventListener("keyup", onModifierKey, true);
      window.removeEventListener("blur", onWindowBlur);
      openLinkModifierHeld = false;
      repaintHover(undefined);
      paintHighlights();
      rowCache.clear();
      links.clear();
      pendingRows.clear();
      forcedRows.clear();
    },
  };
}

function touchesRows(link: TerminalLink, rows: ReadonlySet<number>): boolean {
  for (const row of rows) {
    if (row >= link.range.start.y - 1 && row <= link.range.end.y + 1) return true;
  }
  return false;
}

/** Avoids terminal repaints when pointer and modifier events leave the visible underline set unchanged. */
function sameUnderlineRanges(
  left: readonly TerminalLinkUnderlineRange[] | null,
  right: readonly TerminalLinkUnderlineRange[] | null,
): boolean {
  if (left === right) return true;
  if (!left || !right || left.length !== right.length) return false;
  return left.every((range, index) => {
    const other = right[index];
    return other !== undefined && range.startX === other.startX && range.startY === other.startY &&
      range.endX === other.endX && range.endY === other.endY;
  });
}

function rowFingerprint(row: TerminalLinkRow): string {
  let text = `${row.cells.length}:`;
  let targets = "";
  let previousTarget: string | undefined;
  for (let x = 0; x < row.cells.length; x += 1) {
    const cell = row.cells[x]!;
    text += `${cell.text.length}:${cell.text}`;
    if (x === 0 || cell.target !== previousTarget) {
      const targetLength = cell.target === undefined ? -1 : cell.target.length;
      targets += `${x},${targetLength}:${cell.target ?? ""};`;
      previousTarget = cell.target;
    }
  }
  // Length prefixes make this an exact cell/target comparison without retaining a cell object per column.
  return `${text}|${targets}`;
}

/** A viewport edge can hide the rest of a soft-wrapped plain URL; wait instead of opening its visible prefix. */
function isTruncatedPlainUrl(
  link: TerminalLink,
  rows: readonly TerminalLinkRow[],
  visible: { first: number; last: number },
  bufferLength: number,
): boolean {
  if (link.kind !== "url" || rows.length === 0) return false;
  const first = rows[0]!;
  const last = rows[rows.length - 1]!;
  const startsAtClippedEdge = first.y === visible.first && link.range.start.y === first.y && link.range.start.x === 0 &&
    (first.wrapped || (first.y > 0 && first.wrapKnown === false));
  if (startsAtClippedEdge) return true;
  const endsAtClippedEdge = last.y === visible.last && link.range.end.y === last.y && link.range.end.x === last.cells.length - 1;
  // The next row may be below the viewport; skip a URL ending exactly at the edge until its boundary is visible.
  return endsAtClippedEdge && last.y < bufferLength - 1;
}
