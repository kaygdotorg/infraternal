/** D312 replaces cached identity/offline drawing with public-shell warming and zero private writes. */
import { expect, test } from "bun:test";
import { warmOfflineShell } from "./offline-cache";
test("warming the shell never accesses private browser storage", () => {
  const prior = Object.getOwnPropertyDescriptor(globalThis, "localStorage"); let accesses = 0;
  Object.defineProperty(globalThis, "localStorage", { configurable: true, get() { accesses++; throw Error("blocked"); } });
  try { warmOfflineShell(); expect(accesses).toBe(0); }
  finally { if (prior) Object.defineProperty(globalThis, "localStorage", prior); else Reflect.deleteProperty(globalThis, "localStorage"); }
});
