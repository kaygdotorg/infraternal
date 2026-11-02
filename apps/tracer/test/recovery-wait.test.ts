/** Validates honest server wait durations without using the browser wall clock as authority. */
import { expect, test } from "bun:test";
import { startRecovery, getRecoveryStatus } from "../src/recovery-auth";
const words = Array(23).fill("abandon").concat("art").join(" ");
for (const delay of [0, 86400, 90000, 172800]) {
  test(`server remaining wait ${delay}s is accepted through the capability policy maximum`, async () => {
    const original = globalThis.fetch;
    globalThis.fetch = (async () => new Response(JSON.stringify({token:"public-fixture",ready_at:1800000000,delay_seconds:delay}))) as unknown as typeof fetch;
    try { expect((await startRecovery("fixture_owner", words)).delay_seconds).toBe(delay); }
    finally { globalThis.fetch = original; }
  });
}
for (const delay of [-1, 0.5, 172801, Number.MAX_SAFE_INTEGER + 1, "90000"]) {
  test(`malformed or excessive remaining wait ${delay} is denied`, async () => {
    const original = globalThis.fetch;
    globalThis.fetch = (async () => new Response(JSON.stringify({token:"public-fixture",ready_at:1800000000,delay_seconds:delay}))) as unknown as typeof fetch;
    try { await expect(startRecovery("fixture_owner", words)).rejects.toThrow("could not be used"); }
    finally { globalThis.fetch = original; }
  });
}

for (const [ready, delay, valid] of [[false,60,true],[true,0,true],[false,0,false],[true,1,false],["true",0,false]] as const) {
  test(`status readiness ${ready} with delay ${delay} is ${valid ? "accepted" : "denied"}`, async () => {
    const original = globalThis.fetch;
    globalThis.fetch = (async () => new Response(JSON.stringify({ready,ready_at:1800000000,delay_seconds:delay}))) as unknown as typeof fetch;
    try {
      const result = getRecoveryStatus("public-fixture");
      if (valid) expect((await result).ready).toBe(ready);
      else await expect(result).rejects.toThrow("could not be used");
    } finally { globalThis.fetch = original; }
  });
}
