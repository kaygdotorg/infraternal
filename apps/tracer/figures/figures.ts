// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The figures of the user docs (#302): which screen of the product each picture shows, how to get the product there, and which
 * part of the screen is the picture. `capture.ts` runs every entry, in ink and paper, at the desktop and the phone size, against a
 * production build of the mock world with the demo dataset (docs-dataset.ts); the files it writes are what the pages show.
 *
 * Adding a figure: add an entry here, then write `![alt](figure:name "caption")` in a page. Nothing else. Changing the product's
 * look: run `bun run docs:figures` again, and the pictures follow.
 *
 * Every entry reaches its state through the product's own UI (clicks, keys), the way a person would. A state that cannot be reached
 * that way does not belong in a figure.
 */
import { expect, type Locator, type Page } from "playwright/test";

export type Scheme = "ink" | "paper";
export type SizeName = "desktop" | "phone";

/** A capture size: the browser window, and how sharp the pictures are (desktop 2x, phone 3x). */
export interface CaptureSize { width: number; height: number; scale: number; touch: boolean }
export const SIZES: Record<SizeName, CaptureSize> = {
  desktop: { width: 1440, height: 900, scale: 2, touch: false },
  phone: { width: 393, height: 852, scale: 3, touch: true },
};

/** What a figure shows of the screen: the whole window, or the box of an element with some air around it (CSS px). */
export type Crop = { whole: true } | { around: (page: Page) => Locator; air: number; minWidth?: number };

/** The steps of a clip: what a person does from the prepared state, each followed by a pause long enough to read the result. */
export type Flow = (page: Page, pause: (ms: number) => Promise<void>) => Promise<void>;

export interface Figure {
  name: string;
  /** The page to open (the same address the product's own mockups use, plus the scheme). */
  address(scheme: Scheme, size: SizeName): string;
  /** The window size for this figure at this size name; a clip's window is its picture, so a clip figure sets its own. */
  viewport?: Partial<Record<SizeName, { width: number; height: number }>>;
  /** Gets the product into the state the picture shows. */
  prepare(page: Page, size: SizeName): Promise<void>;
  crop: Partial<Record<SizeName, Crop>> | Crop;
  /** When present the figure also has a clip: this flow is played from the prepared state and recorded. */
  clip?: Flow;
}

const QUESTION = "tmux started automatically. Would you like to switch to the Infraternal Multiplexer instead?";
const choice = (page: Page, name: string): Locator => page.locator(".ui-toast-icons").getByRole("button", { name, exact: true });
const inWizard = (page: Page, name: string): Locator => page.locator(".ah-float").getByRole("button", { name, exact: true });

export const FIGURES: Figure[] = [
  {
    // The startup question of the multiplexer page, and the clip of answering it. The window is the picture (a clip cannot be cropped).
    name: "multiplexer-switch",
    address: (scheme) => `/?mock=1&proto=clusters&startup-demo=1&fixture=none&bg=none&fps=0&theme=${scheme}`,
    viewport: { desktop: { width: 760, height: 480 } },
    async prepare(page) {
      await expect(page.locator(".ui-toast-message")).toHaveText(QUESTION, { timeout: 60_000 });
      await page.waitForTimeout(600);
    },
    crop: { whole: true },
    async clip(page, pause) {
      await pause(1600);
      await choice(page, "Switch to the Infraternal Multiplexer").click();
      await expect(page.locator(".ui-confirm-tip")).toBeVisible();
      await pause(2400);
      await page.locator(".ui-confirm-yes").click();
      await expect(page.locator(".ui-toast-message")).toContainText("Switched.");
      await pause(2200);
      await page.getByRole("button", { name: "Restore .zshrc", exact: true }).click();
      await expect(page.locator(".ui-toast-message")).toContainText("restored");
      await pause(1800);
    },
  },
  {
    // Sessions are windows on the canvas: no prefix key, no status bar.
    name: "sessions-windows",
    address: (scheme) => `/?mock=1&proto=clusters&scene=3&bg=none&fps=0&theme=${scheme}`,
    viewport: { desktop: { width: 820, height: 520 } },
    async prepare(page) {
      await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
      await page.waitForTimeout(1200);
    },
    crop: { whole: true },
  },
  {
    // The person's card: passkeys and the recovery key, which the keys page explains.
    name: "account-card",
    address: (scheme) => `/?mock=1&proto=clusters&scene=3&account=1&bg=none&fps=0&theme=${scheme}&data=demo`,
    async prepare(page) {
      await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
      await page.waitForTimeout(1200);
      await page.locator("#sidebar-toggle").click();
      await page.locator(".ui-sidebar-user").click();
      await expect(page.locator('.ac[data-open="true"]')).toBeVisible({ timeout: 8000 });
      await page.waitForTimeout(700);
    },
    crop: { around: (page) => page.locator(".ac[data-open='true']"), air: 12 },
  },
  {
    // Adding a machine: the join token the keys page describes is made by this flow.
    name: "add-machine",
    address: (scheme) => `/?mock=1&proto=clusters&scene=3&bg=none&fps=0&theme=${scheme}`,
    viewport: { desktop: { width: 760, height: 700 } },
    async prepare(page) {
      await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
      await page.waitForTimeout(800);
      await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
      await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible();
      await expect(page.locator(".ah-row[data-host='raspberry-pi']")).toBeVisible();
      await page.waitForTimeout(500);
    },
    crop: { whole: true },
    async clip(page, pause) {
      await pause(1400);
      await page.locator(".ah-row[data-host='raspberry-pi']").click();
      await pause(1200);
      await inWizard(page, "Continue").click();
      // A machine that can be added as root asks first; the clip chooses the safer answer, a user install.
      await inWizard(page, "Install as user").click();
      await expect(page.locator(".ah-stage-row").first()).toBeVisible({ timeout: 40_000 });
      await pause(2600);
      await page.locator(".ah-summary").waitFor({ timeout: 40_000 }).catch(() => undefined);
      await pause(1800);
    },
  },
];
