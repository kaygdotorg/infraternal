/** Bundles the tracer and workers, copies licensed fonts, and writes static compressed encodings. */
import { cp, mkdir, rm } from "node:fs/promises";
import { precompress } from "./precompress";
import { browserFileLoader } from "./browser-build";
import { classifyChunks, type MetaOutput } from "./chunk-classes";

// TRACER_DIST builds elsewhere (a build next to a running preview server must not replace its files).
const dist = process.env.TRACER_DIST ?? "dist";

await rm(dist, { recursive: true, force: true });
await mkdir(`${dist}/fonts`, { recursive: true });
const recoveryUiMode = process.env.INFRATERNAL_RECOVERY_UI ?? "off";
if (!["off", "preview", "1"].includes(recoveryUiMode)) {
  throw new Error("INFRATERNAL_RECOVERY_UI must be off, preview, or 1");
}
// The clusters concept mockup (#89) is preview-only (D162): the production bundle leaves it out
// unless the build asks for it, so it never counts against the transfer budget or ships.
const clustersPreview = process.env.INFRATERNAL_CLUSTERS_PREVIEW === "1";
// The commit the bundle was built from, shown (and copied) from Settings, About. A tree
// without git history reports nothing, and the UI then says "dev". Reproducible
// package builds supply the source revision and timestamp explicitly.
const commit = process.env.INFRATERNAL_BUILD_COMMIT ?? Bun.spawnSync(["git", "rev-parse", "HEAD"], { stderr: "ignore" }).stdout.toString().trim();
const build = await Bun.build({
  entrypoints: ["src/main.ts", "src/offline.worker.ts", "../../packages/ui/src/backdrop.worker.ts", "../../packages/ui/src/faulty-terminal.worker.ts"],
  outdir: dist,
  naming: { entry: "[name].js" },
  // TRACER_NO_MINIFY=1 or TRACER_BUILD_READABLE=1 keeps function names, so a CPU profile can be read.
  minify: process.env.TRACER_NO_MINIFY === undefined && process.env.TRACER_BUILD_READABLE !== "1",
  target: "browser",
  splitting: true, // the terminal chunk loads after sign-in (see src/main.ts)
  define: { __CLUSTERS_PREVIEW__: JSON.stringify(clustersPreview), __RECOVERY_UI_MODE__: JSON.stringify(recoveryUiMode), __BUILD_DATE__: JSON.stringify(process.env.INFRATERNAL_BUILD_DATE ?? new Date().toISOString()), __BUILD_COMMIT__: JSON.stringify(/^[0-9a-f]{40}$/.test(commit) ? commit : "") },
  metafile: true,
  plugins: clustersPreview ? [browserFileLoader] : [browserFileLoader, {
    // Without the preview flag the mockups resolve to empty modules (their calls are unreachable: the define is false).
    name: "leave-out-mockups",
    setup(builder) {
      builder.onResolve({ filter: /^\.\/(canvas\/mock(\/windows-proto\/canvas)?|canvas\/model\/layout-review-double|add-host-prototype|perf-hud\.on-demand)$/ }, (args) => ({ path: args.path, namespace: "left-out" }));
      builder.onLoad({ filter: /.*/, namespace: "left-out" }, () => ({ contents: "export const mountMockup = undefined; export const mountAddHostPrototype = undefined; export const mountCanvas = undefined; export const mountPerfHud = undefined; export const createLayoutReviewDouble = undefined;", loader: "js" }));
    },
  }],
});
if (!build.success) {
  throw new Error(build.logs.map((log) => log.message).join("\n"));
}
await Promise.all([
  cp("index.html", `${dist}/index.html`),
  cp("style.css", `${dist}/style.css`),
  cp("auth.css", `${dist}/auth.css`),
  cp("canvas.css", `${dist}/canvas.css`),
  cp("clusters.css", `${dist}/clusters.css`),
  cp("mesh.css", `${dist}/mesh.css`),
  cp("sessions.css", `${dist}/sessions.css`),
  cp("addhost.css", `${dist}/addhost.css`),
  cp("version.css", `${dist}/version.css`),
  // The person's card (D283) loads its own styles when it is first wanted, so they are not part of the first screen (D188).
  cp("account.css", `${dist}/account.css`),
  // The mockups' dev-only data toggle: in the preview build only.
  ...(clustersPreview ? [cp("data-toggle.css", `${dist}/data-toggle.css`)] : []),
  cp("../../packages/ui/styles.css", `${dist}/ui.css`),
  cp("fonts", `${dist}/fonts`, { recursive: true, filter: (source) => !source.endsWith(".sh") && !source.endsWith(".py") }),
  cp("node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", `${dist}/fonts/Geist-Variable.woff2`),
]);
// The budget gate reads this: which chunks the first screen needs and which load later (D188).
const meta = (build as unknown as { metafile: { outputs: Record<string, MetaOutput> } }).metafile;
await Bun.write(`${dist}/chunks.json`, JSON.stringify(classifyChunks(meta.outputs), null, 1));
await precompress(dist);
console.log(`built ${build.outputs.map((output) => output.path.split("/").at(-1)).join(", ")}`);
