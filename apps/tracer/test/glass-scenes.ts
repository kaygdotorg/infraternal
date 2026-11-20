/**
 * Real product surfaces and picture backdrops for the glass contrast specs (D365, #448).
 *
 * The specs used to open #146 mockup scenes, so on a branch without the mockup they skipped and nothing gated D365. This
 * file opens only what the product ships: the clusters scene of the mock page (`/?mock=1&proto=clusters&scene=1`), whose
 * windows carry a ⋯ menu and a pill the confirm card anchors to, the command palette, the shared toast and a real terminal.
 * Each {@link Surface} says how to open one glass surface and which element to measure. {@link putPicture} lays a picture of a
 * known worst case under every surface (as a stream's canvas or a video would be), and {@link watchFirstFrame} records what the
 * surface looked like in the first frame a person could see it.
 */
import { expect, type Page } from "playwright/test";
import { glassReady } from "./glass-settled";

/** The two sizes of the review: a desktop and an iPhone. */
export const SIZES = [
  { id: "1440x900", width: 1440, height: 900, phone: false },
  { id: "393x852", width: 393, height: 852, phone: true },
] as const;
/** One size of {@link SIZES}. */
export type Size = (typeof SIZES)[number];
/** The pictures that put the most strain on text: both extremes, the middle grey that fights dark and light text alike, and a split. */
export const PICTURES = ["white", "black", "grey", "split"] as const;
/** One picture of {@link PICTURES}. */
export type Picture = (typeof PICTURES)[number];
/** The line every text run must reach (D365). */
export const LINE = 4.5;

/** A glass surface of the product: how it is opened over the page and which element carries its text. */
export interface Surface {
  /** Short name used in test titles and file names. */
  id: string;
  /** The element the surface is, and the one whose text is measured. */
  selector: string;
  /** Where its backdrop picture goes: over the whole screen, or inside the window the surface opens in (a window's own menu mounts there). */
  host: "screen" | "window";
  /** Whether it exists on a phone-sized screen (the ⋯ menu does not: a phone window has only its close control). */
  phone: boolean;
  /** Opens the surface on a page that already has its picture; resolves when it is on screen. */
  open(page: Page): Promise<void>;
  /** Closes it again, so the next picture can be laid and the surface opened afresh over it. */
  close(page: Page): Promise<void>;
}

/** Closes whatever the Escape key closes (the palette, the confirmation card, a menu). */
const escape = async (page: Page): Promise<void> => { await page.keyboard.press("Escape"); };
/** Closes every toast. */
const dismissToasts = async (page: Page): Promise<void> => {
  // By id: a bare dismiss leaves an error up, which is how the product keeps a failure from being lost.
  await page.evaluate(() => { for (const id of (globalThis as { __glassToasts?: string[] }).__glassToasts ?? []) window.__toast!.dismiss(id); });
};

/** The shared toast's probe in preview builds (`core-screen.ts`). */
type ToastProbe = { dismiss(...id: [string?]): void; show(value: Record<string, unknown>): string };
declare global {
  interface Window { __toast?: ToastProbe; __removalCard?: (anchor: HTMLElement) => void }
}

/** The command palette, opened with its keyboard shortcut. */
const palette: Surface = {
  id: "palette", phone: true, selector: "#palette", host: "screen",
  async open(page) { await page.keyboard.press("Control+Shift+K"); },
  close: escape,
};
/** A plain notice. */
const toast: Surface = {
  id: "toast", phone: true, host: "screen", selector: '.ui-toast[data-hidden="false"]',
  async open(page) {
    await page.evaluate(() => { (globalThis as { __glassToasts?: string[] }).__glassToasts = [window.__toast!.show({ message: "Screenshot saved to your downloads", duration: 0 })]; });
  },
  close: dismissToasts,
};
/** An error notice with an action: the danger colour and a button, the hardest text a toast carries. */
const toastError: Surface = {
  id: "toast-error", phone: true, host: "screen", selector: '.ui-toast[data-hidden="false"]',
  async open(page) {
    await page.evaluate(() => { (globalThis as { __glassToasts?: string[] }).__glassToasts = [window.__toast!.show({ message: "Could not open a shell on this host.", tone: "error", duration: 0, action: { label: "Try again" } })]; });
  },
  close: dismissToasts,
};
/** The glass confirmation card, anchored on a window's pill (the product's own host-removal question). */
const confirm: Surface = {
  id: "confirm", phone: true, host: "screen", selector: '.ui-confirm-tip[data-open="true"]',
  async open(page) {
    await page.evaluate(() => { window.__removalCard!(document.querySelector<HTMLElement>(".ui-window .ui-window-pill")!); });
  },
  close: escape,
};
/** A window's ⋯ menu (split, sessions, close): the popover every window carries. Pressed by a DOM click, as the picture covers the page. */
const menu: Surface = {
  id: "menu", phone: false, selector: ".ui-window-menu", host: "window",
  async open(page) {
    await page.locator(".ui-window .ui-window-more").first().evaluate((b) => { (b as HTMLElement).click(); });
  },
  close: escape,
};

/** Every glass surface the specs measure. */
export const SURFACES: readonly Surface[] = [palette, toast, toastError, confirm, menu];

/** The surfaces that exist at `size`. */
export const surfacesFor = (size: Size): readonly Surface[] => SURFACES.filter((s) => s.phone || !size.phone);

/** The page of the review: the clusters scene (windows, ⋯ menus, a pill to anchor the card to) in a named theme and card level. */
export async function openScene(page: Page, scheme: "ink" | "paper", card: number): Promise<void> {
  // `theme=` is explicit: without it the page picks a theme from the colour scheme, not Ink or Paper.
  await page.goto(`/?mock=1&proto=clusters&scene=1&fps=0&removal=1&bg=none&theme=${scheme}&card=${card}`);
  await expect(page.locator(".ui-window").first()).toBeVisible({ timeout: 30_000 });
  await glassReady(page);
  await page.waitForFunction(() => Boolean(window.__toast && window.__removalCard), null, { timeout: 30_000 });
  // The scene opens zoomed out, with windows the size of thumbnails; a menu or card on one of those is not what a person uses. Fly to the Console view.
  await page.waitForFunction(() => Boolean((window as unknown as { __tracerClusters?: unknown }).__tracerClusters), null, { timeout: 30_000 });
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(v: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForFunction(() => { const w = document.querySelector(".ui-window"); return w !== null && w.getBoundingClientRect().width > 280; }, null, { timeout: 30_000 });
  // The mock welcomes with its own notices; start from none.
  await page.evaluate(() => window.__toast!.dismiss());
  await page.evaluate(() => document.fonts.ready);
}

/** Takes the picture laid by {@link putPicture} away. */
export async function removePicture(page: Page): Promise<void> {
  await page.evaluate(() => { document.querySelectorAll("img[data-test-picture]").forEach((i) => { i.remove(); }); });
}

/**
 * Lays a full-window picture of `picture` over the page, below every glass surface (inside the terminal screen they mount in) and above the windows, as a decoded `<img>`.
 * `fit: "fill"` is a picture the glass can sample (the adaptive path); `"cover"` is one it cannot, so a surface over it stays
 * on the static floor, which is also exactly how every surface looks in the first frame it is shown.
 */
export async function putPicture(page: Page, picture: Picture, fit: "fill" | "cover" = "fill", host: Surface["host"] = "screen"): Promise<void> {
  await page.evaluate(async ({ picture, fit, host }) => {
    const c = document.createElement("canvas");
    c.width = 64; c.height = 64;
    const g = c.getContext("2d")!;
    const fill = (x: string, from: number, to: number): void => { g.fillStyle = x; g.fillRect(from, 0, to - from, 64); };
    if (picture === "split") { fill("#fff", 0, 32); fill("#000", 32, 64); }
    else fill(picture === "white" ? "#fff" : picture === "black" ? "#000" : "#777", 0, 64);
    const img = document.createElement("img");
    img.dataset.testPicture = picture;
    img.src = c.toDataURL("image/png");
    const inWindow = host === "window" ? document.querySelector<HTMLElement>(".ui-window") : null;
    img.style.cssText = `${inWindow ? "position:absolute;inset:0;width:100%;height:100%;z-index:0" : "position:fixed;inset:0;width:100vw;height:100vh;z-index:20"};object-fit:${fit};image-rendering:pixelated`;
    // The terminal screen is the stacking context every glass surface mounts in, so the picture is under them as a stream is.
    (inWindow ?? document.querySelector("#terminal-screen") ?? document.body).append(img);
    await img.decode();
  }, { picture, fit, host });
}

/** One frame of the page as a person would see it, logged by {@link watchFirstFrame}. */
export interface Frame { shown: boolean; under: string | null; overlay: string }

/** Starts logging, every frame, whether `selector` is visible, what it is marked as being over, and its tint. Read it with {@link frames}. */
export async function watchFirstFrame(page: Page, selector: string): Promise<void> {
  await page.evaluate((sel) => {
    const log: Array<{ shown: boolean; under: string | null; overlay: string }> = [];
    (globalThis as { __frames?: typeof log }).__frames = log;
    const tick = (): void => {
      const p = document.querySelector<HTMLElement>(sel);
      if (p) log.push({ shown: !p.hidden && getComputedStyle(p).visibility !== "hidden" && Number(getComputedStyle(p).opacity) > 0, under: p.dataset.glassUnder ?? null, overlay: getComputedStyle(p).getPropertyValue("--overlay") });
      if (log.length < 240) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, selector);
}

/** The frames {@link watchFirstFrame} logged so far. */
export function frames(page: Page): Promise<Frame[]> {
  return page.evaluate(() => (globalThis as { __frames?: Frame[] }).__frames ?? []);
}
