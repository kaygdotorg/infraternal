import { expect, test } from "bun:test";
import { mkdtemp, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { FINGERPRINTED_NAME, contentHash, fingerprintAssets, hashedName, withHashedReferences } from "./fingerprint";

/** A small output folder: one sheet with a font, one plain sheet, the entry and the font. */
async function folder(sheet = '@font-face { src: url("./fonts/a/f.woff2") format("woff2"); }'): Promise<string> {
  const dist = await mkdtemp(`${tmpdir()}/fingerprint-`);
  await mkdir(`${dist}/fonts/a`, { recursive: true });
  await writeFile(`${dist}/style.css`, sheet);
  await writeFile(`${dist}/ui.css`, "body{margin:0}");
  await writeFile(`${dist}/main.js`, "console.log(1)");
  await writeFile(`${dist}/fonts/a/f.woff2`, "font bytes");
  return dist;
}

test("the hash goes before the extension and matches the shape the server accepts", () => {
  expect(hashedName("fonts/a/roman.latin.woff2", "0123456789")).toBe("fonts/a/roman.latin.0123456789.woff2");
  expect(FINGERPRINTED_NAME.test(hashedName("ui.css", contentHash("x")))).toBe(true);
  expect(FINGERPRINTED_NAME.test("ui.css")).toBe(false);
  expect(() => hashedName("LICENSE", "0123456789")).toThrow("no extension");
});

test("sheets and the entry are moved, fonts are copied, and the sheet follows its font's new name", async () => {
  const dist = await folder();
  const names = await fingerprintAssets(dist, ["style.css", "ui.css"], "main.js");
  const files = (await readdir(dist, { recursive: true })).sort();
  expect(files).not.toContain("style.css");
  expect(files).not.toContain("main.js");
  expect(files).toContain("fonts/a/f.woff2");
  const font = names.get("fonts/a/f.woff2")!;
  expect(files).toContain(font);
  const sheet = await readFile(`${dist}/${names.get("style.css")}`, "utf8");
  expect(sheet).toContain(`url("./${font}")`);
  expect(names.get("main.js")).toBe(hashedName("main.js", contentHash("console.log(1)")));
});

test("a sheet's name changes when only its font changes", async () => {
  const one = await fingerprintAssets(await folder(), ["style.css"], "main.js");
  const dist = await folder();
  await writeFile(`${dist}/fonts/a/f.woff2`, "other font bytes");
  const two = await fingerprintAssets(dist, ["style.css"], "main.js");
  expect(two.get("style.css")).not.toBe(one.get("style.css"));
});

test("the page follows the renames and refuses a preloaded font that no sheet uses", async () => {
  const names = await fingerprintAssets(await folder(), ["style.css", "ui.css"], "main.js");
  const page = withHashedReferences('<link href="./style.css" /><link href="./icons/x.svg" /><script src="./main.js"></script>', names, ["fonts/a/f.woff2"]);
  expect(page).toContain(`href="./${names.get("style.css")}"`);
  expect(page).toContain(`src="./${names.get("main.js")}"`);
  expect(page).toContain('href="./icons/x.svg"');
  expect(() => withHashedReferences("", names, ["fonts/a/missing.woff2"])).toThrow("not renamed");
});
