/** Exercises flow lifetime, CA authority and explicit root consent before private SSH work. */
import { expect, test } from "bun:test";
const previous = globalThis.matchMedia;
globalThis.matchMedia = (() => ({ matches: false })) as unknown as typeof matchMedia;
const { Wizard } = await import("./wizard");
if (previous) globalThis.matchMedia = previous;
else Reflect.deleteProperty(globalThis, "matchMedia");

test("a saved-key prompt completing after close never starts an SSH attempt", async () => {
  let finish: (text: string) => void = () => {};
  const unwrapped = new Promise<string>((resolve) => { finish = resolve; });
  let minted = 0, retried = 0;
  const wizard = Object.assign(Object.create(Wizard.prototype) as { alive: boolean; closing: boolean; busy: boolean; submitMethod(): Promise<void> }, {
    alive: true, closing: false, busy: false,
    fixing: { target: "one", entry: {} }, chosen: "saved",
    savedKey: { unwrap: () => unwrapped },
    deps: { service: { mintCredential: async () => { minted++; return "reference"; } } },
    setBusy() {}, addressText: () => "one", retryJob() { retried++; },
    showError() { throw new Error("unexpected fixture refusal"); },
  });
  const work = wizard.submitMethod();
  wizard.alive = false;
  wizard.closing = true;
  finish("fixture-key-input");
  await work;
  expect(minted).toBe(0);
  expect(retried).toBe(0);
});


function authorityWizard(service: object) {
  const observed: { page?: string; batches: boolean[] } = { batches: [] };
  const wizard = Object.assign(Object.create(Wizard.prototype) as {
    alive: boolean; closing: boolean; authorityInitialized: boolean; authorityRoot: boolean;
    prepareAuthority(root: boolean): Promise<void>; unlockAuthority(): Promise<void>;
  }, {
    alive: true, closing: false, busy: false, deps: { service },
    setBusy() {}, go(page: string) { observed.page = page; },
    beginBatch(root: boolean) { observed.batches.push(root); },
    showError() { throw new Error("unexpected authority refusal"); },
  });
  return { wizard, observed };
}

test("fresh CA requires setup before any SSH attempt and preserves root consent", async () => {
  const { wizard, observed } = authorityWizard({ authorityStatus: async () => ({ initialized: false, locked: true }) });
  await wizard.prepareAuthority(true);
  expect(observed.page).toBe("authority");
  expect(wizard.authorityInitialized).toBe(false);
  expect(wizard.authorityRoot).toBe(true);
  expect(observed.batches).toEqual([]);
});

test("ready CA begins the requested installation mode without another prompt", async () => {
  const { wizard, observed } = authorityWizard({ authorityStatus: async () => ({ initialized: true, locked: false }) });
  await wizard.prepareAuthority(false);
  expect(observed.batches).toEqual([false]);
});

test("closing during CA confirmation never starts an SSH attempt", async () => {
  let finish: () => void = () => {};
  const confirmation = new Promise<void>((resolve) => { finish = resolve; });
  const { wizard, observed } = authorityWizard({ unlockAuthority: () => confirmation });
  const work = wizard.unlockAuthority();
  wizard.alive = false;
  wizard.closing = true;
  finish();
  await work;
  expect(observed.batches).toEqual([]);
});


test("a typed root login requires explicit consent before any installation", () => {
  const pages: string[] = [], batches: boolean[] = [];
  const wizard = Object.assign(Object.create(Wizard.prototype) as { proceed(): void }, {
    selected: [{ id: "manual", label: "machine", user: "root", address: "machine" }],
    go(page: string) { pages.push(page); },
    startBatch(root: boolean) { batches.push(root); },
  });
  wizard.proceed();
  expect(pages).toEqual(["root"]);
  expect(batches).toEqual([]);
});
