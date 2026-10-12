/** Guards destination selection and malformed IPv6 correction during host provisioning (#169). */
import { expect, test } from "bun:test";
import { parseTarget } from "./model";
const previous = globalThis.matchMedia;
globalThis.matchMedia = (() => ({ matches: false })) as unknown as typeof matchMedia;
const { Wizard } = await import("./wizard");
if (previous) globalThis.matchMedia = previous;
else Reflect.deleteProperty(globalThis, "matchMedia");

test("breakit2 an explicit port on a listed host survives chip resolution", () => {
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

test("breakit2 malformed bracketed IPv6 waits for correction", () => {
  for (const input of ["target@[:::]", "target@[abcd]", "target@[1:2:3]"]) {
    expect(parseTarget(input)).toBeUndefined();
  }
});

test("listed host plus port retains its saved user in the serialized destination", () => {
  type Entry = { id: string; user?: string; address: string; port?: number };
  const known: Entry = { id: "lab", user: "target", address: "lab" };
  const wizard = Object.assign(Object.create(Wizard.prototype) as {
    resolve(token: string, delimited: boolean): Entry;
    addressOf(entry: Entry): { kind: string; value: string };
  }, {
    typed: [], matchOf: () => ({ host: known, prefixed: false }),
    chipFor: (entry: Entry) => entry,
  });
  const chip = wizard.resolve("lab:2222", true);
  expect(wizard.addressOf(chip)).toEqual({ kind: "manual", value: "target@lab:2222" });
});

test("review listed inventory name plus port retains its resolved address", () => {
  type Entry = { id: string; label: string; user?: string; address: string; port?: number };
  const known: Entry = { id: "lab", label: "lab", user: "target", address: "203.0.113.7" };
  const wizard = Object.assign(Object.create(Wizard.prototype) as {
    resolve(token: string, delimited: boolean): Entry;
    addressOf(entry: Entry): { kind: string; value: string };
  }, {
    typed: [], listed: () => [{ entry: known, added: false }],
    chipFor: (entry: Entry) => entry,
  });
  // Inventory ids need not resolve in DNS. An explicit port changes the port
  // of the matched inventory destination, preserving its address and user.
  const chip = wizard.resolve("lab:2222", true);
  expect(wizard.addressOf(chip)).toEqual({ kind: "manual", value: "target@203.0.113.7:2222" });
});
