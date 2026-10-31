/** Confirm, cancel and undo exercise the same notice controller used by real terminals [D315]. */
import { expect, test } from "bun:test";
import { createStartupHints } from "./startup-hints";
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
  }, { show: (value) => { notice = value; }, dismiss() {}, dispose() {}, focusAction: () => false }, (_anchor, options) => { confirmation = options; return { close() {} }; });
  return { hints, writes, notice: () => notice, confirmation: () => confirmation };
}

test("discovery and cancelling confirmation never change startup; accepting offers a precise undo", async () => {
  const f = fixture();
  await f.hints.inspect("01234567890123456789012345678901");
  expect(f.notice()?.message).toContain("tmux");
  expect(f.writes).toEqual([]);
  f.notice()?.action?.onSelect(click);
  expect(f.confirmation()?.effect).toContain(proposal.guard);
  f.confirmation()?.onCancel?.();
  expect(f.writes).toEqual([]);
  f.confirmation()?.onConfirm();
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(f.writes).toEqual([{ op: "apply", session: "01234567890123456789012345678901", proposal, confirmed: true }]);
  expect(f.notice()?.action?.label).toBe("Remove guard");
  f.notice()?.action?.onSelect(click);
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(f.writes.at(-1)).toEqual({ op: "undo", session: "01234567890123456789012345678901", proposal, confirmed: true });
  f.hints.dispose();
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
    { show: () => { shown++; }, dismiss() {}, dispose() {}, focusAction: () => false });
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
  }, { show() {}, dismiss() {}, dispose() {}, focusAction: () => false });
  await hints.inspect("01234567890123456789012345678901", undefined, "Local host");
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(hints.switches()[1]?.get()).toBe(false);
  hints.dispose();
});
