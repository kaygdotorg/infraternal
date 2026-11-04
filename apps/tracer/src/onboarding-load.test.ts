/** A failed fetch of the first-run setup code shows a retry card instead of a blank screen (#247, #249). */
import { afterAll, beforeEach, expect, mock, test } from "bun:test";

let importFails = true;
const mounted: unknown[] = [];
mock.module("./on-demand", () => ({
  whenIdle: () => {},
  onDemand: <T>(load: () => Promise<T>) => (importFails ? Promise.reject(new Error("chunk")) : load()),
}));
mock.module("./onboarding-setup.on-demand", () => ({ mountSetup: (host: unknown) => { mounted.push(host); } }));
// Bun's module mocks are process-wide and outlive this file. Keep the real `./auth` exports (above all its AuthError
// class, which later files compare errors against with instanceof), stub only the passkey prompt, and hand the real
// module back afterwards (#263: a stand-in AuthError here broke join-review's error mapping in the gate's batch).
const realAuth = { ...(await import("./auth")) };
mock.module("./auth", () => ({ ...realAuth, loginWithPasskey: async () => "u" }));
afterAll(() => { mock.module("./auth", () => realAuth); });
mock.module("./auth-motion", () => ({ swapCard: () => {} }));
mock.module("./recovery-ui", () => ({ recoveryUiEnabled: () => false }));
mock.module("../../../packages/ui/src/countup", () => ({ loading: () => ({ done() {} }) }));

const { loadSetup, SETUP_LOAD_FAILED } = await import("./onboarding");

const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 5));
const online: Array<() => void> = [];
let reloads = 0;
let click: (() => void) | undefined;
const messageLine = { textContent: "" };

function fakeHost() {
  return {
    innerHTML: "",
    querySelector: (selector: string) => selector === "#auth-error" ? messageLine : { addEventListener: (_: string, fn: () => void) => { click = fn; } },
  } as unknown as HTMLElement;
}

beforeEach(() => {
  importFails = true; mounted.length = 0; online.length = 0; click = undefined; reloads = 0; messageLine.textContent = "";
  (globalThis as { location?: unknown }).location = { reload: () => { reloads++; } };
  (globalThis as { window?: unknown }).window = { addEventListener: (_: string, fn: () => void) => { online.push(fn); } };
});

test("a failed load says so in the error line, offers Try again, and mounts nothing", async () => {
  const host = fakeHost();
  loadSetup(host, "", () => {}); await flush();
  expect(messageLine.textContent).toBe(SETUP_LOAD_FAILED);
  expect((host as unknown as { innerHTML: string }).innerHTML).toContain("Try again");
  expect(mounted.length).toBe(0);
});

test("the Try again button reloads the page: a failed import stays failed in the module map", async () => {
  loadSetup(fakeHost(), "", () => {}); await flush();
  click!();
  expect(reloads).toBe(1);
});

test("the online event retries by itself", async () => {
  loadSetup(fakeHost(), "", () => {}); await flush();
  expect(online.length).toBe(1);
  online[0]!();
  expect(reloads).toBe(1);
});
