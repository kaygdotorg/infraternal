/** Opt-in red target-address regressions for #169; no product behavior is changed. */
import { expect, test } from "bun:test";
import { parseTarget } from "./model";
const previous = globalThis.matchMedia;
globalThis.matchMedia = (() => ({ matches: false })) as unknown as typeof matchMedia;
const { Wizard } = await import("./wizard");
if (previous) globalThis.matchMedia = previous;
else Reflect.deleteProperty(globalThis, "matchMedia");
const red = process.env.ADDHOST_BREAKIT2_RED === "1" ? test : test.skip;

red("breakit2 an explicit port on a listed host survives chip resolution", () => {
  type Entry = { id: string; user?: string; address: string; port?: number };
  const known: Entry = { id: "lab", user: "target", address: "lab" };
  const wizard = Object.assign(Object.create(Wizard.prototype) as {
    resolve(token: string, delimited: boolean): Entry;
  }, {
    typed: [], matchOf: () => ({ host: known, prefixed: false }),
    chipFor: (entry: Entry) => entry,
  });
  const chip = wizard.resolve("target@lab:2222", true);
  expect(chip.port).toBe(2222);
});

red("breakit2 malformed bracketed IPv6 waits for correction", () => {
  for (const input of ["target@[:::]", "target@[abcd]", "target@[1:2:3]"]) {
    expect(parseTarget(input)).toBeUndefined();
  }
});
