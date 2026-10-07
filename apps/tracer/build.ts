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
const build = await Bun.build({
  entrypoints: ["src/main.ts", "../../packages/ui/src/backdrop.worker.ts", "../../packages/ui/src/faulty-terminal.worker.ts"],
  outdir: "dist",
  naming: { entry: "[name].js" },
  minify: true,
  target: "browser",
  splitting: true, // the terminal chunk loads after sign-in (see src/main.ts)
  define: { __RECOVERY_UI_MODE__: JSON.stringify(recoveryUiMode) },
  plugins: [browserFileLoader],
});
if (!build.success) {
  throw new Error(build.logs.map((log) => log.message).join("\n"));
}
await Promise.all([
  cp("index.html", "dist/index.html"),
  cp("style.css", "dist/style.css"),
  cp("auth.css", "dist/auth.css"),
  cp("addhost.css", "dist/addhost.css"),
  cp("../../packages/ui/styles.css", "dist/ui.css"),
  cp("node_modules/geist/dist/fonts/geist-mono/GeistMono-Variable.woff2", "dist/fonts/GeistMono-Variable.woff2"),
  cp("node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", "dist/fonts/Geist-Variable.woff2"),
]);
await precompress("dist");
console.log(`built ${build.outputs.map((output) => output.path.split("/").at(-1)).join(", ")}`);
