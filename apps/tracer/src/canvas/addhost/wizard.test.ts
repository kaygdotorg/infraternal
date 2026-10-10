/** Closing the flow cancels private-input work even when a passkey prompt finishes later. */
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
