/**
 * The lock control's order of events around a successful unlock (D168, D234).
 *
 * The person is told "Host connections unlocked" the moment the ceremony succeeds. From that moment the palette must
 * no longer offer "Unlock host connections": the status refresh that follows is a network call, and the answer to
 * "is it unlocked?" is already known. The status call is held open here, so the test needs no timing.
 */
import { afterEach, expect, test } from "bun:test";
import type { CoreScreen } from "../../core-screen";
import { makeAuthorityControl } from "./authority-control.on-demand";
import type { AuthorityStatus, ProvisioningService } from "./service";

/** The browser globals the control touches, as inert stand-ins (the unit suite has no DOM). */
function stubBrowser(): void {
  const target = { addEventListener() {}, removeEventListener() {}, dispatchEvent: () => true };
  Object.assign(globalThis, {
    window: { ...target, setTimeout: globalThis.setTimeout, clearTimeout: globalThis.clearTimeout },
    document: { ...target, visibilityState: "visible" },
  });
}

afterEach(() => {
  delete (globalThis as { window?: unknown }).window;
  delete (globalThis as { document?: unknown }).document;
});

test("the palette stops offering Unlock when the unlocked toast appears, before the status refresh answers", async () => {
  stubBrowser();
  const status = (locked: boolean): AuthorityStatus => ({ initialized: true, locked, roots: [] }) as unknown as AuthorityStatus;
  let ceremonyDone = false;
  let releaseRefresh!: () => void;
  const refreshHeld = new Promise<void>((resolve) => { releaseRefresh = resolve; });
  const service = {
    unlockAuthority: async () => { ceremonyDone = true; },
    authorityStatus: async () => {
      if (!ceremonyDone) return status(true);
      await refreshHeld;
      return status(false);
    },
  } as unknown as ProvisioningService;

  let provider!: () => Array<{ label: string }>;
  let toldUnlocked!: () => void;
  const unlockedToast = new Promise<void>((resolve) => { toldUnlocked = resolve; });
  const core = {
    inboxMount: undefined,
    addPaletteProvider: (fn: typeof provider) => { provider = fn; return () => {}; },
    toast: {
      show: (options: { message: string }) => { if (options.message === "Host connections unlocked") toldUnlocked(); return "t"; },
      dismiss: () => {},
    },
  } as unknown as CoreScreen;

  const control = makeAuthorityControl(core, { service: async () => service }, 0);
  await control.refresh();
  expect(control.state()).toBe("locked");
  expect(provider().map((row) => row.label)).toContain("Unlock host connections");

  const unlocking = control.unlock();
  await unlockedToast;
  expect(provider().map((row) => row.label)).not.toContain("Unlock host connections");
  releaseRefresh();
  await unlocking;
  expect(control.state()).toBe("unlocked");
  control.dispose();
});
