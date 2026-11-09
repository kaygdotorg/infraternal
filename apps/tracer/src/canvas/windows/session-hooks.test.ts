/** The idle warm-up of the on-demand session UI is silent when it fails; a load the person asked for is not (#249). */
import { afterAll, beforeEach, expect, mock, test } from "bun:test";

let idle: (() => void) | undefined;
let importFails = true;
const created: unknown[] = [];
const originalOnDemand = await import("../../on-demand");
const originalOnDemandExports = {
  onDemand: originalOnDemand.onDemand,
  whenIdle: originalOnDemand.whenIdle,
};
mock.module("../../on-demand", () => ({
  whenIdle: (run: () => void) => { idle = run; },
  onDemand: <T>(load: () => Promise<T>) => (importFails ? Promise.reject(new Error("chunk")) : load()),
}));
const part = { toggleManager: mock(() => {}), paint() {}, render() {}, closeManager() {}, arrived() {}, refused: () => false, dispose() {} };
mock.module("./session-ui.on-demand", () => ({ createSessionUi: () => { created.push(part); return part; } }));

const previousMatchMedia = globalThis.matchMedia;
globalThis.matchMedia = (() => ({ matches: false })) as unknown as typeof matchMedia;
const { createSessionHooks } = await import("./session-hooks");
if (previousMatchMedia) globalThis.matchMedia = previousMatchMedia;

afterAll(() => {
  // Bun retains module mocks on this worker; restore the helper's saved exports for later files.
  mock.module("../../on-demand", () => originalOnDemandExports);
});

const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 5));
const toasts: string[] = [];
const online: Array<() => void> = [];

function setup() {
  const ac = new AbortController();
  const cx = {
    signal: ac.signal,
    toast: { show: (o: { message: string }) => { toasts.push(o.message); } },
    adapters: { inventory: { onChange: () => () => {}, get: () => undefined, sizedFor: () => false } },
    views: new Map(),
  };
  const rec = { model: { kind: "terminal", noAccess: false }, owner: { view: { team: false } }, card: { pill: { isConnected: true }, root: { isConnected: true } } };
  return { ui: createSessionHooks(cx as never), rec: rec as never };
}

beforeEach(() => {
  toasts.length = 0; online.length = 0; created.length = 0; idle = undefined; importFails = true; part.toggleManager.mockClear();
  (globalThis as { window?: unknown }).window = { addEventListener: (_: string, fn: () => void) => { online.push(fn); } };
});

test("a failed idle warm-up shows no toast and retries when the browser is back online", async () => {
  setup();
  idle!(); await flush();
  expect(toasts).toEqual([]);
  expect(online.length).toBe(1);
  importFails = false;
  online[0]!(); await flush();
  expect(created.length).toBe(1);
});

test("a failed open shows the toast, and opening again after the network returns succeeds", async () => {
  const { ui, rec } = setup();
  ui.toggleManager(rec, null); await flush();
  expect(toasts).toEqual(["Could not load the session list. Try again."]);
  importFails = false;
  ui.toggleManager(rec, null); await flush();
  expect(toasts.length).toBe(1);
  expect(part.toggleManager).toHaveBeenCalledTimes(1);
});

test("an open that joins a failing idle warm-up still shows the toast", async () => {
  const { ui, rec } = setup();
  idle!();
  ui.toggleManager(rec, null); await flush();
  expect(toasts.length).toBe(1);
});
