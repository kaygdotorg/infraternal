/** Role: verify measurement readiness stays on the hosts authorized for a run (#146). */
import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";

// Execute only readiness: importing the controller would build and launch a real
// server and contact a Mac before this host-boundary test could intercept it.
const source = readFileSync(process.env.APP_WINDOW_CONTROLLER_SOURCE ?? new URL("measure.ts", import.meta.url), "utf8");
const body = source.slice(source.indexOf(" const prepare=async()=>{"), source.indexOf(" mac.stdin!.on('error'"));
const javascript = new Bun.Transpiler({ loader: "ts" }).transformSync(body + "return prepare();");

test("Mac-only readiness never starts a guest command", async () => {
  const replies: unknown[] = [];
  const starts: unknown[] = [];
  const prepare = new Function("macOnly", "startRealServer", "mac", "ROOT", "port", "pipelineDiagnostics", "console", "spawn", `
    let vmIdle=[];let readinessPhase='vm';let server;const label='test';const probeTrace=false;
    ${javascript}
  `);
  await prepare(true, async (options: unknown) => {
    starts.push(options);
    return { pid: 123, origin: "https://localhost:4746", token: "fixture-only" };
  }, { stdin: { write: (row: string) => replies.push(JSON.parse(row)) } }, "fixture-root", 4746, false,
  { log: () => {} }, () => { throw Error("unexpected guest access"); });
  expect(starts).toHaveLength(1);
  expect(starts[0]).toMatchObject({ address: "10.69.69.125", port: 4746 });
  expect(replies).toEqual([{ ready: true, idle: [], origin: "https://localhost:4746", token: "fixture-only" }]);
});

test("the 80-input cohort cannot silently replace another requested phase", () => {
  const configuration = source.slice(source.indexOf("const resourcesOnly="), source.indexOf("const port="));
  const validate = new Function("process", new Bun.Transpiler({ loader: "ts" }).transformSync(configuration + "return inputOnly;"));
  expect(validate({ env: {} })).toBe(false);
  expect(validate({ env: { APP_WINDOW_INPUT_ONLY: "1" } })).toBe(true);
  for (const phase of ["APP_WINDOW_RESOURCES_ONLY", "APP_WINDOW_DEMO_ONLY", "APP_WINDOW_SOAK", "APP_WINDOW_OWNER_PREVIEW"]) {
    expect(() => validate({ env: { APP_WINDOW_INPUT_ONLY: "1", [phase]: "1" } })).toThrow("input-only mode cannot include another measurement phase");
  }
});
