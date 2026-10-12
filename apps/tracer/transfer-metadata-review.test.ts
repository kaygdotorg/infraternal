/** Checks #194's production transfer budget with fixed public build metadata, without changing the bundler or limits (D188). */
import { expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

test("the reviewed production source meets transfer budgets for fixed build metadata", async () => {
  const root = join(homedir(), ".cache/codex-scratch/hosts-from-server-review");
  await mkdir(root, { recursive: true });
  const scratch = await mkdtemp(join(root, "transfer-"));
  try {
    const preload = join(scratch, "public-metadata.js");
    // Content-hashed imports depend on these public defines. Fix them so the regression is reproducible.
    await writeFile(preload, `// Reproducible public metadata for the independent production bundle check.\n
const original = Bun.spawnSync;
Bun.spawnSync = (...args) => {
  const result = original(...args);
  if (Array.isArray(args[0]) && args[0].join(" ") === "git rev-parse HEAD") return { ...result, stdout: Buffer.from("fa2f3f2d358cff843ec35aa994a95b679b4177f5\\n") };
  return result;
};
Date.prototype.toISOString = () => "2026-10-13T00:00:00.000Z";
`);
    const env = { ...process.env, TRACER_DIST: join(scratch, "dist"), INFRATERNAL_CLUSTERS_PREVIEW: "0", INFRATERNAL_RECOVERY_UI: "off" };
    const build = Bun.spawn([process.execPath, `--preload=${preload}`, "build.ts"], { cwd: import.meta.dir, env, stdout: "pipe", stderr: "pipe" });
    const buildOutput = await new Response(build.stdout).text();
    const buildErrors = await new Response(build.stderr).text();
    await writeFile(join(root, "transfer-metadata-build.log"), buildOutput + buildErrors);
    expect(await build.exited).toBe(0);
    // Use the repository's gate rather than duplicating its classification, compression or budgets.
    const gate = Bun.spawn([process.execPath, "run", "transfer-budget.ts"], { cwd: import.meta.dir, env, stdout: "pipe", stderr: "pipe" });
    const output = await new Response(gate.stdout).text();
    const errors = await new Response(gate.stderr).text();
    await writeFile(join(root, "transfer-metadata-gate.log"), output + errors);
    expect(await gate.exited).toBe(0);
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}, 120_000);
