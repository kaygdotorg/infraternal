/** Bundles the static tracer app and copies its licensed terminal font into dist/. */
import { cp, mkdir, rm } from "node:fs/promises";

await rm("dist", { recursive: true, force: true });
await mkdir("dist/fonts", { recursive: true });
const build = await Bun.build({
  entrypoints: ["src/main.ts"],
  outdir: "dist",
  minify: true,
  target: "browser",
  splitting: true, // the terminal chunk loads after sign-in (see src/main.ts)
});
if (!build.success) {
  throw new Error(build.logs.map((log) => log.message).join("\n"));
}
await Promise.all([
  cp("index.html", "dist/index.html"),
  cp("style.css", "dist/style.css"),
  cp("node_modules/geist/dist/fonts/geist-mono/GeistMono-Variable.woff2", "dist/fonts/GeistMono-Variable.woff2"),
]);
console.log(`built ${build.outputs.map((output) => output.path.split("/").at(-1)).join(", ")}`);
