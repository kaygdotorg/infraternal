/** Exercises browser bundling of the pinned renderer's optional Node file loader. */
import { expect, test } from "bun:test";
import { browserFileLoader } from "./browser-build";

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
