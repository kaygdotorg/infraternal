/** Exercises production preview exclusions and the pinned renderer's optional Node file loader. */
import { expect, test } from "bun:test";
import { browserFileLoader } from "./browser-build";
import { mkdir, mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

test("the browser renderer has no unresolved Vite Node-file shim request", async () => {
  const result = await Bun.build({
    entrypoints: ["vendor/ghostty-web/dist/ghostty-web.js"],
    target: "browser",
    splitting: true,
    plugins: [browserFileLoader],
  });
  expect(result.success).toBe(true);
  const outputs = await Promise.all(result.outputs.map((output) => output.text()));
  expect(outputs.join("\n")).not.toContain("__vite-browser-external-2447137e.js");
  expect(outputs.join("\n")).toContain("Node filesystem unavailable in browser");
});

test("layout review fixtures ship only in explicitly enabled preview builds", async () => {
  const parent = resolve(process.env.CARGO_TARGET_DIR ?? join(homedir(), ".cache", "codex-scratch", "tracer-build-tests"));
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(join(parent, "layout-bundle-"));
  try {
    for (const preview of [false, true]) {
      const dist = join(root, preview ? "preview" : "production");
      const child = Bun.spawn([process.execPath, "run", "build.ts"], {
        env: { ...process.env, TRACER_DIST: dist, INFRATERNAL_CLUSTERS_PREVIEW: preview ? "1" : "0" },
        stdout: "pipe", stderr: "pipe",
      });
      const [code, stdout, stderr] = await Promise.all([child.exited, new Response(child.stdout).text(), new Response(child.stderr).text()]);
      expect({ code, diagnostics: code === 0 ? "" : stdout + stderr }).toEqual({ code: 0, diagnostics: "" });
      const scripts = await Promise.all((await readdir(dist)).filter((name) => name.endsWith(".js")).map((name) => readFile(join(dist, name), "utf8")));
      // This controlled peer edit exists only in the review transport, never in the shipped product.
      expect(scripts.some((script) => script.includes("Skipped peer edit"))).toBe(preview);
    }
  } finally { await rm(root, { recursive: true, force: true }); }
}, 120_000);
