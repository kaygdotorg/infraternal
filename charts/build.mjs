import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const here = dirname(fileURLToPath(import.meta.url));
const vendorRoot = resolve(here, "src/vendor/bklit");
const distRoot = resolve(here, "../web");

mkdirSync(distRoot, { recursive: true });

const bklitAlias = {
  name: "bklit-source-alias",
  setup(buildOptions) {
    buildOptions.onResolve({ filter: /^@\// }, ({ path }) => {
      const target = resolve(vendorRoot, path.slice(2));
      return { path: existsSync(target) ? target : `${target}.ts` };
    });
  },
};

await build({
  alias: {},
  banner: {
    js: "/* Bklit UI chart components (MIT); source/license in charts/src/vendor. */",
  },
  bundle: true,
  define: { "process.env.NODE_ENV": '"production"' },
  entryPoints: [resolve(here, "src/bklit-charts.tsx")],
  format: "esm",
  jsx: "automatic",
  legalComments: "eof",
  minify: true,
  outfile: resolve(distRoot, "bklit-charts.js"),
  platform: "browser",
  plugins: [bklitAlias],
  sourcemap: false,
  target: ["es2020"],
  treeShaking: true,
});

copyFileSync(
  resolve(here, "src/bklit-charts.css"),
  resolve(distRoot, "bklit-charts.css")
);
copyFileSync(
  resolve(here, "src/vendor/BKLIT-MIT-LICENSE.txt"),
  resolve(distRoot, "bklit-LICENSE.txt")
);

console.log("Built web/bklit-charts.js, web/bklit-charts.css, and web/bklit-LICENSE.txt");
