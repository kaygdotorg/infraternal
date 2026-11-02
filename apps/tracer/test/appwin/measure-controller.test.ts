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

test("the ten-window first-picture check and soak cohorts have fixed shapes", () => {
  const configuration = source.slice(source.indexOf("const resourcesOnly="), source.indexOf("const port="));
  const validate = new Function("process", new Bun.Transpiler({ loader: "ts" }).transformSync(configuration + "return {tenWindowIdle,firstPictureIdle,flood,fixtureWindowCount,pipelineDiagnostics,helperBinary};"));
  expect(validate({ env: {} })).toEqual({ tenWindowIdle: false, firstPictureIdle: false, flood: false, fixtureWindowCount: 1, pipelineDiagnostics: true, helperBinary: undefined });
  expect(validate({ env: { APP_WINDOW_TEN_WINDOW_IDLE: "1" } })).toEqual({ tenWindowIdle: true, firstPictureIdle: false, flood: false, fixtureWindowCount: 10, pipelineDiagnostics: true, helperBinary: undefined });
  const helperBinary = "/Users/kayg/infraternal-bench/app-windows-first-picture/target/release/infraternal-desktop-helper";
  expect(validate({ env: { APP_WINDOW_FIRST_PICTURE_IDLE: "1", APP_WINDOW_HELPER_BINARY: helperBinary } })).toEqual({ tenWindowIdle: false, firstPictureIdle: true, flood: false, fixtureWindowCount: 10, pipelineDiagnostics: true, helperBinary });
  expect(() => validate({ env: { APP_WINDOW_FIRST_PICTURE_IDLE: "1" } })).toThrow("first-picture idle check requires a Mac helper binary");
  expect(() => validate({ env: { APP_WINDOW_HELPER_BINARY: "relative/helper" } })).toThrow("Mac helper binary path must be absolute");
  expect(validate({ env: { APP_WINDOW_FLOOD: "1" } })).toEqual({ tenWindowIdle: false, firstPictureIdle: false, flood: true, fixtureWindowCount: 1, pipelineDiagnostics: true, helperBinary: undefined });
  expect(() => validate({ env: { APP_WINDOW_TEN_WINDOW_IDLE: "1", APP_WINDOW_FLOOD: "1" } })).toThrow("idle and flood cohorts cannot run together");
  expect(() => validate({ env: { APP_WINDOW_TEN_WINDOW_IDLE: "1", APP_WINDOW_FIRST_PICTURE_IDLE: "1" } })).toThrow("ten-window idle modes cannot run together");
  expect(() => validate({ env: { APP_WINDOW_FIRST_PICTURE_IDLE: "1", APP_WINDOW_PROBE_TRACE: "1" } })).toThrow("first-picture idle check cannot include another phase");
  expect(() => validate({ env: { APP_WINDOW_TEN_WINDOW_IDLE: "1", APP_WINDOW_STABILITY_SECONDS: "180" } })).toThrow("soak cohorts require exactly ten minutes");
  expect(() => validate({ env: { APP_WINDOW_FLOOD: "1", APP_WINDOW_INPUT_ONLY: "1" } })).toThrow("flood cohort cannot include another phase");
});

test("a signed helper variant always carries a checked shipped-bundle restoration", () => {
  const configuration = source.slice(source.indexOf("const variantArchive="), source.indexOf("const job="));
  const validate = new Function("process", "native", "nativeHash", new Bun.Transpiler({ loader: "ts" }).transformSync(configuration + "return {helperVariant,helperRestore};"));
  expect(validate({ env: {} }, undefined, undefined)).toEqual({ helperVariant: undefined, helperRestore: undefined });
  const env = {
    APP_WINDOW_VARIANT_ARCHIVE: "/Users/kayg/infraternal-bench/job/r7.zip",
    APP_WINDOW_VARIANT_ARCHIVE_SHA256: "b".repeat(64),
    APP_WINDOW_RESTORE_HELPER_ARCHIVE: "/Users/kayg/infraternal-bench/job/shipped.zip",
    APP_WINDOW_RESTORE_HELPER_ARCHIVE_SHA256: "c".repeat(64),
    APP_WINDOW_RESTORE_HELPER_EXECUTABLE_SHA256: "d".repeat(64),
    APP_WINDOW_HELPER_LEAF_SHA1: "e".repeat(40),
  };
  expect(validate({ env }, "/Users/kayg/infraternal-bench/native-diagnostic/InfraternalCaptureHelper.app/Contents/MacOS/InfraternalCaptureHelper", "a".repeat(64))).toEqual({
    helperVariant: { archive: env.APP_WINDOW_VARIANT_ARCHIVE, archive_sha256: env.APP_WINDOW_VARIANT_ARCHIVE_SHA256, executable_sha256: "a".repeat(64), leaf_sha1: env.APP_WINDOW_HELPER_LEAF_SHA1 },
    helperRestore: { archive: env.APP_WINDOW_RESTORE_HELPER_ARCHIVE, archive_sha256: env.APP_WINDOW_RESTORE_HELPER_ARCHIVE_SHA256, executable_sha256: env.APP_WINDOW_RESTORE_HELPER_EXECUTABLE_SHA256, leaf_sha1: env.APP_WINDOW_HELPER_LEAF_SHA1 },
  });
  expect(() => validate({ env: { APP_WINDOW_VARIANT_ARCHIVE: env.APP_WINDOW_VARIANT_ARCHIVE } }, undefined, undefined)).toThrow("helper variant and restoration archives must be supplied together");
});


test("concurrent opening is explicit and requires ten fixture windows", () => {
  const configuration = source.slice(source.indexOf("const resourcesOnly="), source.indexOf("const port="));
  const validate = new Function("process", new Bun.Transpiler({ loader: "ts" }).transformSync(configuration + "return openMode;"));
  expect(validate({ env: {} })).toBe("serial");
  expect(validate({ env: { APP_WINDOW_TEN_WINDOW_IDLE: "1", APP_WINDOW_OPEN_MODE: "concurrent" } })).toBe("concurrent");
  expect(() => validate({ env: { APP_WINDOW_OPEN_MODE: "concurrent" } })).toThrow("concurrent opening requires ten fixture windows");
  expect(() => validate({ env: { APP_WINDOW_OPEN_MODE: "invalid" } })).toThrow("invalid fixture open mode");
});
