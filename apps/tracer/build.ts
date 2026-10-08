/** Bundles the tracer and workers, copies licensed fonts, and writes static compressed encodings. */
import { cp, mkdir, rm } from "node:fs/promises";
import { precompress } from "./precompress";
import { browserFileLoader } from "./browser-build";

await rm("dist", { recursive: true, force: true });
await mkdir("dist/fonts", { recursive: true });
const recoveryUiMode = process.env.INFRATERNAL_RECOVERY_UI ?? "off";
if (!["off", "preview", "1"].includes(recoveryUiMode)) {
  throw new Error("INFRATERNAL_RECOVERY_UI must be off, preview, or 1");
}
// The clusters concept mockup (#89) is preview-only (D162): the production bundle leaves it out
// unless the build asks for it, so it never counts against the transfer budget or ships.
const clustersPreview = process.env.INFRATERNAL_CLUSTERS_PREVIEW === "1";
// The commit the bundle was built from, shown (and copied) from Settings, About. A tree
// without git history reports nothing, and the UI then says "dev".
const commit = Bun.spawnSync(["git", "rev-parse", "HEAD"], { stderr: "ignore" }).stdout.toString().trim();
const build = await Bun.build({
  entrypoints: ["src/main.ts", "../../packages/ui/src/backdrop.worker.ts", "../../packages/ui/src/faulty-terminal.worker.ts"],
  outdir: "dist",
  naming: { entry: "[name].js" },
  // TRACER_NO_MINIFY=1 or TRACER_BUILD_READABLE=1 keeps function names, so a CPU profile can be read.
  minify: process.env.TRACER_NO_MINIFY === undefined && process.env.TRACER_BUILD_READABLE !== "1",
  target: "browser",
  splitting: true, // the terminal chunk loads after sign-in (see src/main.ts)
  define: { __CLUSTERS_PREVIEW__: JSON.stringify(clustersPreview), __RECOVERY_UI_MODE__: JSON.stringify(recoveryUiMode), __BUILD_DATE__: JSON.stringify(new Date().toISOString()), __BUILD_COMMIT__: JSON.stringify(/^[0-9a-f]{40}$/.test(commit) ? commit : "") },
  plugins: clustersPreview ? [browserFileLoader] : [browserFileLoader, {
    // Without the preview flag the mockup resolves to an empty module (its call is unreachable: the define is false).
    name: "leave-out-clusters-preview",
    setup(builder) {
      builder.onResolve({ filter: /^\.\/canvas\/mock$/ }, () => ({ path: "clusters-left-out", namespace: "left-out" }));
      builder.onLoad({ filter: /.*/, namespace: "left-out" }, () => ({ contents: "export const mountMockup = undefined;", loader: "js" }));
    },
  }],
});
if (!build.success) {
  throw new Error(build.logs.map((log) => log.message).join("\n"));
}
await Promise.all([
  cp("index.html", "dist/index.html"),
  cp("style.css", "dist/style.css"),
  cp("auth.css", "dist/auth.css"),
  cp("canvas.css", "dist/canvas.css"),
  cp("clusters.css", "dist/clusters.css"),
  cp("addhost.css", "dist/addhost.css"),
  cp("../../packages/ui/styles.css", "dist/ui.css"),
  cp("fonts", "dist/fonts", { recursive: true, filter: (source) => !source.endsWith(".sh") && !source.endsWith(".py") }),
  cp("node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", "dist/fonts/Geist-Variable.woff2"),
]);
await precompress("dist");
console.log(`built ${build.outputs.map((output) => output.path.split("/").at(-1)).join(", ")}`);
