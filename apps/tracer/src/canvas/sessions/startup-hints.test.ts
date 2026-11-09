/** Confirm, cancel and undo exercise the same notice controller used by real terminals [D315]. */
import { expect, test } from "bun:test";
import { createStartupHints, MULTIPLEXER_DOCS_URL, multiplexerName } from "./startup-hints";
import type { ToastMessage } from "../../../../../packages/ui/src/toast";
import type { ConfirmTipOptions } from "../../../../../packages/ui/src/tooltip";

const proposal = { file: ".zshrc", line: 0, original: "exec tmux", guard: '[ -n "$INFRATERNAL_SESSION" ] || exec tmux', fingerprint: "public-fixture", multiplexer: "tmux" };
const click = { currentTarget: {} } as MouseEvent;

function fixture() {
  let notice: ToastMessage | undefined;
  let confirmation: ConfirmTipOptions | undefined;
  let enabled = true;
  const writes: Record<string, unknown>[] = [];
  const hints = createStartupHints({ isWelcomed: false, onWelcome: () => () => {},
    async call(action, input) {
      expect(action).toBe("terminal.startup");
      if (input.op === "inspect") return { multiplexer: "tmux", proposal };
      if (input.op === "get") return { global_enabled: enabled, enabled, host_override: null };
      writes.push(input);
      if (input.op === "set") enabled = input.enabled as boolean;
      return { saved: true };
    },
  }, { show: (value) => { notice = value; return "t"; }, dismiss() {}, dispose() {}, focusAction: () => false, setEdge() {} }, (_anchor, options) => { confirmation = options; return { close() {} }; });
  return { hints, writes, notice: () => notice, confirmation: () => confirmation };
}

test("the offer asks in the owner's words and offers ✓, ✗ and ? with a name each", async () => {
  const f = fixture();
  await f.hints.inspect("01234567890123456789012345678901");
  expect(f.notice()?.message).toBe("tmux started automatically. Would you like to switch to the Infraternal Multiplexer instead?");
  expect(f.notice()?.action).toBeUndefined();
  expect(f.notice()?.iconActions?.map((choice) => choice.label)).toEqual([
    "Switch to the Infraternal Multiplexer", "Keep tmux, don't ask again on this host", "About the Infraternal Multiplexer",
  ]);
  expect(JSON.stringify(f.notice())).not.toMatch(/guard/i);
  f.hints.dispose();
});

test("each multiplexer is named as people know it", async () => {
  expect(multiplexerName("tmux")).toBe("tmux");
  expect(multiplexerName("zellij")).toBe("Zellij");
  expect(multiplexerName("other")).toBe("other");
});

test("discovery and cancelling confirmation never change startup; accepting offers a precise undo", async () => {
  const f = fixture();
  await f.hints.inspect("01234567890123456789012345678901");
  expect(f.writes).toEqual([]);
  f.notice()?.iconActions?.[0]?.onSelect(click);
  expect(f.confirmation()?.effect).toContain(proposal.guard);
  expect(f.confirmation()?.title).toBe("Switch to the Infraternal Multiplexer in .zshrc?");
  f.confirmation()?.onCancel?.();
  expect(f.writes).toEqual([]);
  expect(f.notice()?.iconActions).toHaveLength(3);
  f.notice()?.iconActions?.[0]?.onSelect(click);
  f.confirmation()?.onConfirm();
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(f.writes).toEqual([{ op: "apply", session: "01234567890123456789012345678901", proposal, confirmed: true }]);
  expect(f.notice()?.action?.label).toBe("Restore .zshrc");
  f.notice()?.action?.onSelect(click);
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(f.writes.at(-1)).toEqual({ op: "undo", session: "01234567890123456789012345678901", proposal, confirmed: true });
  expect(f.notice()?.message).toBe(".zshrc restored. tmux starts automatically again.");
  f.hints.dispose();
});

test("✗ changes nothing and ? opens the docs without closing the question", async () => {
  const opened: string[] = [];
  let notice: ToastMessage | undefined;
  const hints = createStartupHints({ isWelcomed: false, onWelcome: () => () => {}, async call(_action, input) { return input.op === "inspect" ? { multiplexer: "zellij", proposal: { ...proposal, multiplexer: "zellij" } } : { global_enabled: true }; } },
    { show: (value) => { notice = value; return "t"; }, dismiss() {}, dispose() {}, focusAction: () => false, setEdge() {} }, undefined, { openDocs: (url) => opened.push(url) });
  await hints.inspect("01234567890123456789012345678901");
  expect(notice?.message.startsWith("Zellij started automatically.")).toBe(true);
  const [, keep, help] = notice!.iconActions!;
  expect(help?.keepOpen).toBe(true);
  expect(keep?.keepOpen).toBeUndefined();
  help?.onSelect(click);
  expect(opened).toEqual([MULTIPLEXER_DOCS_URL]);
  keep?.onSelect(click);
  hints.dispose();
});

test("with no recognised startup line, ✓ copies the line instead of editing a file", async () => {
  let notice: ToastMessage | undefined;
  const copied: string[] = [];
  const saved = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { clipboard: { writeText: async (text: string) => { copied.push(text); } } } });
  try {
    const writes: Record<string, unknown>[] = [];
    const hints = createStartupHints({ isWelcomed: false, onWelcome: () => () => {}, async call(_action, input) { if (input.op === "inspect") return { multiplexer: "tmux" }; if (input.op !== "get") writes.push(input); return { global_enabled: true }; } },
      { show: (value) => { notice = value; return "t"; }, dismiss() {}, dispose() {}, focusAction: () => false, setEdge() {} });
    await hints.inspect("01234567890123456789012345678901");
    expect(notice?.iconActions?.[0]?.label).toBe("Copy the line that switches");
    notice?.iconActions?.[0]?.onSelect(click);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(copied).toEqual(['[ -n "$INFRATERNAL_SESSION" ] || tmux']);
    expect(writes).toEqual([]);
    hints.dispose();
  } finally {
    if (saved) Object.defineProperty(globalThis, "navigator", saved); else Reflect.deleteProperty(globalThis, "navigator");
  }
});

test("saving a hint switch never sends a startup-file edit", async () => {
  const f = fixture();
  await f.hints.set(false);
  expect(f.hints.enabled()).toBe(false);
  expect(f.writes).toEqual([{ op: "set", global: true, enabled: false }]);
  await f.hints.set(true);
  expect(f.hints.enabled()).toBe(true);
  f.hints.dispose();
});

test("disposing a pending detection never shows its late notice", async () => {
  let answer!: (value: Record<string, unknown>) => void;
  let shown = 0;
  const hints = createStartupHints({ isWelcomed: false, onWelcome: () => () => {}, call: () => new Promise((resolve) => { answer = resolve; }) },
    { show: () => { shown++; return "t"; }, dismiss() {}, dispose() {}, focusAction: () => false, setEdge() {} });
  const pending = hints.inspect("01234567890123456789012345678901");
  hints.dispose();
  answer({ multiplexer: "tmux", proposal });
  await pending;
  expect(shown).toBe(0);
});


test("a newly seen host reads its saved override before showing its switch", async () => {
  const hints = createStartupHints({ isWelcomed: false, onWelcome: () => () => {},
    async call(_action, input) {
      return input.op === "get" ? { global_enabled: true, host_override: false } : {};
    },
  }, { show: () => "t", dismiss() {}, dispose() {}, focusAction: () => false, setEdge() {} });
  await hints.inspect("01234567890123456789012345678901", undefined, "Local host");
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(hints.switches()[1]?.get()).toBe(false);
  hints.dispose();
});
