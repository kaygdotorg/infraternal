/** Contracts for wrapped terminal links and untrusted OSC 8 targets. */
import { expect, test } from "bun:test";
import { createTerminalLinkController, detectTerminalLinks, isOpenableTarget, shouldShowLinkTarget } from "./terminal-links.on-demand";

type LinkCell = { text: string; target?: string };
type LinkRow = { y: number; wrapped: boolean; wrapKnown?: boolean; cells: LinkCell[] };

function row(text: string, y: number, wrapped = false, target?: string): LinkRow {
  return {
    y,
    wrapped,
    cells: Array.from(text, (character) => target === undefined ? { text: character } : { text: character, target }),
  };
}

function wrap(text: string, width: number, startY = 0): LinkRow[] {
  const rows: LinkRow[] = [];
  for (let offset = 0, y = startY; offset < text.length; offset += width, y += 1) {
    rows.push(row(text.slice(offset, offset + width), y, offset > 0));
  }
  return rows;
}

test("joins an OAuth URL across eight soft-wrapped rows", () => {
  const target = "https://[2001:db8::1]:8443/oauth/authorize?client_id=web-client&state=st_123&redirect_uri=https%3A%2F%2Fexample.test%2Fcallback&response_type=code&scope=openid%20profile&nonce=n_456";
  const rows = wrap(target, Math.ceil(target.length / 8), 40);

  expect(rows).toHaveLength(8);
  expect(detectTerminalLinks(rows)).toEqual([{
    kind: "url",
    target,
    visibleText: target,
    range: { start: { x: 0, y: 40 }, end: { x: rows.at(-1)!.cells.length - 1, y: 47 } },
    openable: true,
  }]);
});

test("trims trailing punctuation and only unbalanced closing brackets", () => {
  const text = "See (https://example.test/a(b)). and https://example.test/[keep]";
  const found = detectTerminalLinks([row(text, 3)]);

  expect(found.map((link) => link.target)).toEqual([
    "https://example.test/a(b)",
    "https://example.test/[keep]",
  ]);
});

test("keeps IPv6 brackets, ports, and query strings intact", () => {
  const target = "https://[2001:db8::7]:9443/search?q=one%20two&next=%2Fdone";
  expect(detectTerminalLinks([row(`${target},`, 9)]).map((link) => link.target)).toEqual([target]);
});

test("uses visible OSC 8 text with its real URI target across wrapped rows", () => {
  const target = "https://docs.example.test/manual";
  const rows = [row("Open doc", 11, false, target), row("umentation", 12, true, target)];

  expect(detectTerminalLinks(rows)).toEqual([{
    kind: "osc8",
    target,
    visibleText: "Open documentation",
    range: { start: { x: 0, y: 11 }, end: { x: 9, y: 12 } },
    openable: true,
  }]);
  expect(shouldShowLinkTarget(detectTerminalLinks(rows)[0]!)).toBe(true);
});

test("does not reinterpret an OSC 8 URL label as a second target", () => {
  const label = "https://lookalike.example.test/sign-in";
  const target = "https://real.example.test/account";
  const found = detectTerminalLinks([row(label, 0, false, target)]);

  expect(found.map((link) => link.target)).toEqual([target]);
  expect(shouldShowLinkTarget(found[0]!)).toBe(true);
});

test("opens only HTTP, HTTPS, and mailto targets", () => {
  expect(["http://example.test", "https://example.test:8443/a", "mailto:person@example.test"].map(isOpenableTarget)).toEqual([true, true, true]);
  expect(["file:///tmp/report", "javascript:alert(1)", "data:text/html,hi", "custom:thing"].map(isOpenableTarget)).toEqual([false, false, false, false]);
});

test("recognizes plain mailto links as openable terminal links", () => {
  expect(detectTerminalLinks([row("mailto:person@example.test", 0)])).toMatchObject([
    { kind: "url", target: "mailto:person@example.test", openable: true },
  ]);
});

test("shows file URLs locally without making them openable", () => {
  const target = "file:///home/user/report.txt";
  expect(detectTerminalLinks([row(target, 2)])).toMatchObject([{ kind: "url", target, openable: false }]);
});

test("re-detects a wrapped URL in scrollback using cached wrap flags", () => {
  const target = "https://scroll.example.test/a-long-path";
  const first = row(target.slice(0, 20), 0, false);
  const continuation = row(target.slice(20), 1, true);
  const visibleRows = [first, continuation, row("next", 2), row("away", 3), row("last", 4), row("more", 5)];
  const callbacks: Array<() => void> = [];
  const originalWindow = (globalThis as unknown as { window?: Window }).window;
  const fakeWindow = {
    requestIdleCallback(callback: () => void) { callbacks.push(callback); return callbacks.length; },
    cancelIdleCallback() {},
    setTimeout,
    clearTimeout,
  } as unknown as Window;
  (globalThis as unknown as { window?: Window }).window = fakeWindow;
  const host = {
    addEventListener() {},
    removeEventListener() {},
  } as unknown as HTMLElement;
  const canvas = {
    style: {},
    getBoundingClientRect: () => new DOMRect(0, 0, 80, 40),
  } as unknown as HTMLCanvasElement;
  let visible = { first: 0, last: 2 };
  const controller = createTerminalLinkController({
    host,
    canvas,
    getBufferLength: () => visibleRows.length,
    getVisibleRange: () => visible,
    getRow: (y) => visibleRows.find((candidate) => candidate.y === y),
    getCellMetrics: () => ({ width: 1, height: 1 }),
    paint: () => undefined,
    open: () => undefined,
  });
  const scan = (): void => callbacks.shift()?.();
  try {
    controller.updateVisibleRows();
    scan();
    expect(controller.linksOnScreen().map((link) => link.target)).toEqual([target]);

    visible = { first: 3, last: 5 };
    controller.updateVisibleRows();
    scan();
    expect(controller.linksOnScreen()).toEqual([]);

    visibleRows[0] = { ...first, wrapKnown: false, wrapped: false };
    visibleRows[1] = { ...continuation, wrapKnown: false, wrapped: false };
    visible = { first: 0, last: 2 };
    controller.updateVisibleRows();
    scan();
    expect(controller.linksOnScreen().map((link) => link.target)).toEqual([target]);
  } finally {
    controller.dispose();
    if (originalWindow === undefined) delete (globalThis as unknown as { window?: Window }).window;
    else (globalThis as unknown as { window?: Window }).window = originalWindow;
  }
});

test("does not expose a valid prefix when scrollback wrap history is unknown", () => {
  const target = "https://scroll.example.test/a-long-path";
  const first = { ...row(target.slice(0, 24), 0), wrapKnown: false };
  const continuation = { ...row(target.slice(24), 1, true), wrapKnown: false };
  const visibleRows = [first, continuation, row("next", 2), row("away", 3), row("last", 4)];
  const callbacks: Array<() => void> = [];
  const originalWindow = (globalThis as unknown as { window?: Window }).window;
  const fakeWindow = {
    requestIdleCallback(callback: () => void) { callbacks.push(callback); return callbacks.length; },
    cancelIdleCallback() {},
    setTimeout,
    clearTimeout,
  } as unknown as Window;
  (globalThis as unknown as { window?: Window }).window = fakeWindow;
  const host = { addEventListener() {}, removeEventListener() {} } as unknown as HTMLElement;
  const canvas = { style: {}, getBoundingClientRect: () => new DOMRect(0, 0, 80, 40) } as unknown as HTMLCanvasElement;
  const controller = createTerminalLinkController({
    host,
    canvas,
    getBufferLength: () => visibleRows.length,
    getVisibleRange: () => ({ first: 0, last: 2 }),
    getRow: (y) => visibleRows.find((candidate) => candidate.y === y),
    getCellMetrics: () => ({ width: 1, height: 1 }),
    paint: () => undefined,
    open: () => undefined,
  });
  try {
    controller.updateVisibleRows();
    callbacks.shift()?.();
    expect(controller.linksOnScreen().map((link) => link.target)).toEqual([target]);
  } finally {
    controller.dispose();
    if (originalWindow === undefined) delete (globalThis as unknown as { window?: Window }).window;
    else (globalThis as unknown as { window?: Window }).window = originalWindow;
  }
});

test("waits for a wrapped URL to leave the visible edge before offering it", () => {
  const target = "https://scroll.example.test/a-long-path";
  const visibleRows = [row(target.slice(0, 15), 0), row(target.slice(15, 30), 1, true), row(target.slice(30), 2, true)];
  const callbacks: Array<() => void> = [];
  const originalWindow = (globalThis as unknown as { window?: Window }).window;
  const fakeWindow = {
    requestIdleCallback(callback: () => void) { callbacks.push(callback); return callbacks.length; },
    cancelIdleCallback() {},
    setTimeout,
    clearTimeout,
  } as unknown as Window;
  (globalThis as unknown as { window?: Window }).window = fakeWindow;
  const host = { addEventListener() {}, removeEventListener() {} } as unknown as HTMLElement;
  const canvas = { style: {}, getBoundingClientRect: () => new DOMRect(0, 0, 80, 40) } as unknown as HTMLCanvasElement;
  let visible = { first: 0, last: 1 };
  const controller = createTerminalLinkController({
    host,
    canvas,
    getBufferLength: () => visibleRows.length,
    getVisibleRange: () => visible,
    getRow: (y) => visibleRows.find((candidate) => candidate.y === y),
    getCellMetrics: () => ({ width: 1, height: 1 }),
    paint: () => undefined,
    open: () => undefined,
  });
  const scan = (): void => callbacks.shift()?.();
  try {
    controller.updateVisibleRows();
    scan();
    expect(controller.linksOnScreen()).toEqual([]);

    visible = { first: 0, last: 2 };
    controller.updateVisibleRows();
    scan();
    expect(controller.linksOnScreen().map((link) => link.target)).toEqual([target]);
  } finally {
    controller.dispose();
    if (originalWindow === undefined) delete (globalThis as unknown as { window?: Window }).window;
    else (globalThis as unknown as { window?: Window }).window = originalWindow;
  }
});

test("drops a changed row's cached link before deferred detection runs", () => {
  const oldTarget = "https://old.example.test";
  const newTarget = "https://new.example.test";
  const visibleRows = [row(oldTarget, 0), row("next", 1)];
  const callbacks: Array<() => void> = [];
  const originalWindow = (globalThis as unknown as { window?: Window }).window;
  (globalThis as unknown as { window?: Window }).window = {
    requestIdleCallback(callback: () => void) { callbacks.push(callback); return callbacks.length; },
    cancelIdleCallback() {},
    setTimeout,
    clearTimeout,
  } as unknown as Window;
  const host = { addEventListener() {}, removeEventListener() {} } as unknown as HTMLElement;
  const canvas = { style: {}, getBoundingClientRect: () => new DOMRect(0, 0, 80, 40) } as unknown as HTMLCanvasElement;
  const controller = createTerminalLinkController({
    host,
    canvas,
    getBufferLength: () => visibleRows.length,
    getVisibleRange: () => ({ first: 0, last: 1 }),
    getRow: (y) => visibleRows.find((candidate) => candidate.y === y),
    getCellMetrics: () => ({ width: 1, height: 1 }),
    paint: () => undefined,
    open: () => undefined,
  });
  const scan = (): void => callbacks.shift()?.();
  try {
    controller.updateVisibleRows();
    scan();
    expect(controller.linksOnScreen().map((link) => link.target)).toEqual([oldTarget]);

    visibleRows[0] = row(newTarget, 0);
    controller.updateRows([0]);
    expect(controller.linksOnScreen()).toEqual([]);
    scan();
    expect(controller.linksOnScreen().map((link) => link.target)).toEqual([newTarget]);
  } finally {
    controller.dispose();
    if (originalWindow === undefined) delete (globalThis as unknown as { window?: Window }).window;
    else (globalThis as unknown as { window?: Window }).window = originalWindow;
  }
});

test("keeps unchanged candidate rows out of parsing while pending rows cannot activate", () => {
  const target = "https://scroll.example.test/unchanged";
  const visibleRows = [row(target, 0), row("next", 1)];
  const callbacks: Array<() => void> = [];
  const originalWindow = (globalThis as unknown as { window?: Window }).window;
  (globalThis as unknown as { window?: Window }).window = {
    requestIdleCallback(callback: () => void) { callbacks.push(callback); return callbacks.length; },
    cancelIdleCallback() {},
    setTimeout,
    clearTimeout,
  } as unknown as Window;
  const host = { addEventListener() {}, removeEventListener() {} } as unknown as HTMLElement;
  const canvas = { style: {}, getBoundingClientRect: () => new DOMRect(0, 0, 80, 40) } as unknown as HTMLCanvasElement;
  const controller = createTerminalLinkController({
    host,
    canvas,
    getBufferLength: () => visibleRows.length,
    getVisibleRange: () => ({ first: 0, last: 1 }),
    getRow: (y) => visibleRows.find((candidate) => candidate.y === y),
    getCellMetrics: () => ({ width: 1, height: 1 }),
    paint: () => undefined,
    open: () => undefined,
  });
  const scan = (): void => callbacks.shift()?.();
  try {
    controller.updateVisibleRows();
    scan();
    expect(controller.linksOnScreen().map((link) => link.target)).toEqual([target]);

    controller.updateRows([0], false);
    expect(controller.linksOnScreen()).toEqual([]);
    expect(controller.openTarget(target)).toBe(false);
    scan();
    expect(controller.linksOnScreen().map((link) => link.target)).toEqual([target]);

    const replacement = "https://scroll.example.test/replacement";
    visibleRows[0] = row(replacement, 0);
    controller.updateRows([0], false);
    expect(controller.linksOnScreen()).toEqual([]);
    expect(controller.openTarget(target)).toBe(false);
    scan();
    expect(controller.linksOnScreen().map((link) => link.target)).toEqual([replacement]);
  } finally {
    controller.dispose();
    if (originalWindow === undefined) delete (globalThis as unknown as { window?: Window }).window;
    else (globalThis as unknown as { window?: Window }).window = originalWindow;
  }
});
