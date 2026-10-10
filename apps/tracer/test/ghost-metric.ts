/**
 * The ghost-text metric shared by the glass audits: how much of the text behind a glass surface still shows through it,
 * and a page of dense, high-contrast text to put behind the surface (TASTE: glass shows colour, never legible text).
 */
import type { Page } from "playwright/test";

/**
 * How much of the text behind survives in the surface: the normalised cross-correlation (mean removed) between the
 * luminance of the surface crop and of the same crop without the surface. 1 = the text passes untouched, 0 = no
 * trace of it. (Laplacian variance falls to nothing for any blur at all, so it cannot tell a smear from a
 * clean blur; correlation with the text itself can, and it is what "legible" means.)
 */
export async function ghost(page: Page, through: Buffer, bare: Buffer): Promise<number> {
  return page.evaluate(async ([a64, b64]) => {
    const load = async (b64: string) => {
      const img = new Image(); img.src = `data:image/png;base64,${b64}`; await img.decode();
      const c = document.createElement("canvas"); c.width = img.width; c.height = img.height;
      const g = c.getContext("2d", { willReadFrequently: true })!; g.drawImage(img, 0, 0);
      const { data, width, height } = g.getImageData(0, 0, c.width, c.height);
      const lum = new Float32Array(width * height);
      for (let i = 0; i < lum.length; i++) lum[i] = 0.2126 * data[i * 4]! + 0.7152 * data[i * 4 + 1]! + 0.0722 * data[i * 4 + 2]!;
      return lum;
    };
    const x = await load(a64!), y = await load(b64!);
    const n = Math.min(x.length, y.length);
    let mx = 0, my = 0;
    for (let i = 0; i < n; i++) { mx += x[i]!; my += y[i]!; }
    mx /= n; my /= n;
    let sxy = 0, sxx = 0, syy = 0;
    for (let i = 0; i < n; i++) { const dx = x[i]! - mx, dy = y[i]! - my; sxy += dx * dy; sxx += dx * dx; syy += dy * dy; }
    // The regression slope of the surface on the text: the fraction of the text's contrast that still shows. (The
    // plain correlation is scale free, so a surface that is 90 % tint would score like a clear one.)
    return syy > 0 ? Math.abs(sxy) / syy : 0;
  }, [through.toString("base64"), bare.toString("base64")] as const);
}

/** A page of dense, high-contrast text under every surface (colour from the theme, so ink and paper both bite). */
export async function denseText(page: Page): Promise<void> {
  await page.evaluate(() => {
    document.getElementById("ghost-text")?.remove();
    const d = document.createElement("div");
    d.id = "ghost-text";
    // Pseudo-random words (a fixed seed), so the page has no period a blur could leave behind as stripes.
    let seed = 7;
    const rnd = (): number => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
    const words = ["fn", "let", "ghost", "read_line()", "println!", "if", "match", "legible", "text", "never", "show", "{", "}", "=>", "&mut", "self", "0x1f", "//", "return", "Ok(())"];
    d.textContent = Array.from({ length: 140 }, () => Array.from({ length: 70 }, () => words[Math.floor(rnd() * words.length)]).join(" ")).join("\n");
    d.style.cssText = "position:fixed;inset:0;z-index:1;overflow:hidden;white-space:pre;font:700 13px/16px ui-monospace,monospace;color:var(--fg);background:var(--bg);pointer-events:none";
    document.querySelector("#terminal-screen")!.append(d);
  });
}

