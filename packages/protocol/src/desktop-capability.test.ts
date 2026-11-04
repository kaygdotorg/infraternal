/**
 * The desktop-video capability is one bit, and every side of the Hello must name the same one (contracts/wire.md §9,
 * #146). The Rust server and agent define it as `CAPABILITY = 1 << 4` (leg A, the browser) and `NATIVE_CAPABILITY = 1 << 8`
 * (leg B, the agent's native lane). The browser advertises leg A's bit in its Hello and reads it back from the server's
 * Hello to decide whether app windows exist at all; a constant that names another bit would silently turn them off.
 */
import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { DESKTOP_VIDEO } from "./desktop";
import { DESKTOP_VIDEO_CAP } from "../../../apps/tracer/src/connection";

/** Reads `pub const <name>: u64 = 1 << N;` from the Rust protocol crate, so the test follows the source of truth. */
function rustBit(name: string): bigint {
  const source = readFileSync(new URL("../../../crates/infraternal-protocol/src/desktop.rs", import.meta.url), "utf8");
  const match = source.match(new RegExp(`pub const ${name}: u64 = 1 << (\\d+);`));
  if (!match) throw new Error(`desktop.rs no longer defines ${name} as a shifted bit`);
  return 1n << BigInt(match[1]!);
}

test("the protocol package names the same leg-A capability bit as the Rust server and agent", () => {
  expect(DESKTOP_VIDEO).toBe(rustBit("CAPABILITY"));
  // The contract's words: "caps bit 4", counting from zero (RESUME_NEXT is bit 0).
  expect(DESKTOP_VIDEO).toBe(16n);
});

test("the browser negotiates with that same bit, not a second copy of it", () => {
  expect(DESKTOP_VIDEO_CAP).toBe(DESKTOP_VIDEO);
});

test("leg B's native lane is a different bit from leg A's and from the core transport bits 0 to 7", () => {
  const native = rustBit("NATIVE_CAPABILITY");
  expect(native).toBe(256n);
  expect(native & DESKTOP_VIDEO).toBe(0n);
  expect(native & 0xffn).toBe(0n);
});
