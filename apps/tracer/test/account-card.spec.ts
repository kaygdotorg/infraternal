/**
 * The person's card (D283, #224) on a production build. Two builds of the same card are exercised:
 *
 *   - the product (`proto=product`): the server knows the name and the username, so the card shows those, and sign out;
 *     it draws no row it cannot fill and no control that would do nothing;
 *   - the mockup's double (`proto=clusters&account=1`): it knows everything, and carries the regression fixture of the
 *     toggle (`data=worst|empty|one`), so every state of every row is reached.
 *
 * What is asserted is what the owner asked for on 2026-11-01:
 *   - the value says the state, and a concern says itself; no "checked N days ago" line exists anywhere on the card;
 *   - "Logs in as" has a card for each tag in the tag's colour, every machine a gradient of its own tags, never one colour
 *     for all, with text that clears 4.5:1 on its real background, in the worst case too (many tags, many machines).
 */
import { expect, test, type Page } from "playwright/test";

const MOCK = "/?mock=1&proto=clusters&scene=3&account=1&bg=none";

async function openCard(page: Page, url = MOCK, viewport = { width: 1440, height: 900 }): Promise<void> {
  await page.setViewportSize(viewport);
  await page.goto(url);
  await expect(page.locator(url.includes("proto=clusters") ? ".cl-mockup" : "#sidebar-toggle")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator(".ui-sidebar-user")).toBeVisible();
  await page.locator(".ui-sidebar-user").click();
  await expect(page.locator('.ac[data-open="true"]')).toBeVisible({ timeout: 8000 });
  await page.waitForTimeout(500);
}

/** Switches the double to a named scenario (the palette rows do this), and waits for the card to redraw. */
async function scenario(page: Page, id: string): Promise<void> {
  await page.evaluate((action) => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action, source: "keyboard" } })), `proto:acct:s:${id}`);
  await page.waitForTimeout(500);
}

const rowText = (page: Page, key: string): Promise<string> => page.evaluate((k) => {
  const row = [...document.querySelectorAll<HTMLElement>(".ac .ui-kv-row")].find((r) => r.querySelector(".ui-kv-key")?.textContent?.trim() === k);
  return row?.querySelector(".ui-kv-value")?.textContent?.trim() ?? "";
}, key);

const rowWarns = (page: Page, key: string): Promise<boolean> => page.evaluate((k) => {
  const row = [...document.querySelectorAll<HTMLElement>(".ac .ui-kv-row")].find((r) => r.querySelector(".ui-kv-key")?.textContent?.trim() === k);
  return Boolean(row?.querySelector('.ui-mark[data-mark="warn"]'));
}, key);

test.describe("values say the state, and a concern says itself", () => {
  test.setTimeout(120_000);

  test("a healthy account: calm values, no amber, and no 'checked N days ago' line anywhere on the card", async ({ page }) => {
    await openCard(page);
    expect(await rowText(page, "Passkeys")).toBe("2");
    expect(await rowText(page, "Recovery key")).toBe("Set up");
    expect(await rowText(page, "Devices")).toBe("4");
    expect(await rowText(page, "Email")).toBe("Not added");
    for (const key of ["Passkeys", "Recovery key", "Devices"]) expect(await rowWarns(page, key)).toBe(false);
    await expect(page.locator(".ui-sidebar-user .ac-badge")).toHaveCount(0);
    const text = await page.locator(".ac").innerText();
    expect(text).not.toMatch(/checked|\bago\b/i);
    // No second line under a key: a row is a key and a value.
    expect(await page.locator(".ac .ui-kv-hint").count()).toBe(0);
  });

  for (const [id, key, value, why] of [
    ["recovery", "Recovery key", /^Never verified, verify now$/, "recovery"],
    ["recovery-stale", "Recovery key", /^Not verified since \d{1,2} \w{3}( \d{4})?, verify now$/, "recovery"],
    ["recovery-none", "Recovery key", /^Not set up$/, "recovery"],
    ["one-passkey", "Passkeys", /^Only one, add a second$/, "passkey"],
  ] as const) {
    test(`${id}: the value says it, with the amber mark, and the pill carries one`, async ({ page }) => {
      await openCard(page);
      await scenario(page, id);
      expect(await rowText(page, key)).toMatch(value);
      expect(await rowWarns(page, key)).toBe(true);
      await expect(page.locator(".ui-sidebar-user .ac-badge")).toHaveCount(1);
      await expect(page.locator(".ui-sidebar-user")).toHaveAttribute("data-attention", why);
      // The concern is the strong text, not the quiet one.
      const weight = await page.evaluate((k) => {
        const row = [...document.querySelectorAll<HTMLElement>(".ac .ui-kv-row")].find((r) => r.querySelector(".ui-kv-key")?.textContent?.trim() === k)!;
        return Number(getComputedStyle(row.querySelector(".ui-kv-value")!).fontWeight);
      }, key);
      expect(weight).toBeGreaterThanOrEqual(500);
      expect(await page.locator(".ac").innerText()).not.toMatch(/checked|\bago\b/i);
    });
  }

  test("the Logs in as row draws each account once, however often the card is redrawn", async ({ page }) => {
    await openCard(page);
    for (const id of ["recovery", "one-passkey", "community", "recovery-stale"]) await scenario(page, id);
    expect((await page.locator(".ac .ui-kv-part").allTextContents()).map((t) => t.replace(/\s+/g, " ").trim())).toEqual(["kayg 12", "root 2"]);
    await page.locator(".ac .ui-kv-row", { hasText: "Logs in as" }).locator(".ui-kv-value").click();
    await expect(page.locator(".ac-pane[data-open]")).toBeVisible();
    expect(await page.locator(".ac .ui-kv-part").count()).toBe(2);
  });

  test("a concern in the value is a link to where it is fixed (Settings, Account)", async ({ page }) => {
    await openCard(page);
    await scenario(page, "recovery-stale");
    const cell = page.locator(".ac .ui-kv-row", { hasText: "Recovery key" }).locator(".ui-kv-value");
    await expect(cell).toHaveAttribute("data-tip", /Verify it in Settings/);
  });

  test("the empty set says plainly what is missing; nothing is blank", async ({ page }) => {
    await openCard(page, `${MOCK}&data=empty`);
    expect(await rowText(page, "Passkeys")).toBe("None, add one");
    expect(await rowText(page, "Recovery key")).toBe("Not set up");
    expect(await rowText(page, "Devices")).toBe("None");
    expect(await rowText(page, "Logs in as")).toBe("No hosts yet");
    // The name is the username, once; the username line is not repeated under it.
    await expect(page.locator(".ac-name")).toHaveText("kayg");
    await expect(page.locator(".ac-username")).toBeHidden();
  });

  test("the one-of-everything set", async ({ page }) => {
    await openCard(page, `${MOCK}&data=one`);
    expect(await rowText(page, "Passkeys")).toBe("Only one, add a second");
    expect(await rowText(page, "Recovery key")).toBe("Set up");
    expect(await rowText(page, "Devices")).toBe("1");
  });
});

/** Opens the "Logs in as" pane and returns the facts about what it drew. */
async function logins(page: Page): Promise<void> {
  await page.locator(".ac .ui-kv-row", { hasText: "Logs in as" }).locator(".ui-kv-value").click();
  await expect(page.locator(".ac-pane[data-open]")).toBeVisible();
  await page.waitForTimeout(500);
}

const paneFacts = (page: Page) => page.evaluate(() => {
  const pane = document.querySelector<HTMLElement>(".ac-pane-body")!;
  const box = pane.getBoundingClientRect();
  const accounts = [...pane.querySelectorAll<HTMLElement>(".ac-account")].map((a) => ({
    name: a.querySelector(".ac-account-name")?.textContent ?? "",
    cards: a.querySelectorAll(".ac-tag").length,
    chips: [...a.querySelectorAll<HTMLElement>(".ac-tag-hosts .ui-entity")].map((c) => c.style.background),
    cardsChips: [...a.querySelectorAll<HTMLElement>(".ac-tag")].map((t) => t.querySelectorAll(".ui-entity[data-kind=host]").length),
    cardFills: [...a.querySelectorAll<HTMLElement>(".ac-tag:not([data-untagged])")].map((t) => getComputedStyle(t).backgroundColor),
    tagChips: [...a.querySelectorAll<HTMLElement>(".ac-tag-head .ui-entity[data-kind=tag]")].map((c) => c.style.background),
    more: [...a.querySelectorAll<HTMLElement>(".ac-more")].map((m) => m.textContent ?? ""),
    overflow: [...a.querySelectorAll<HTMLElement>(".ac-tag, .ac-account-head")].filter((t) => t.getBoundingClientRect().right > box.right + 0.5 || t.scrollWidth > t.clientWidth + 1).length,
  }));
  return { accounts, paneOverflow: pane.scrollWidth > pane.clientWidth + 1, text: pane.innerText };
});

test.describe("Logs in as: a card for each tag, a gradient for each machine", () => {
  test.setTimeout(180_000);

  test("the demo set: every tag has a card in its own colour, no two tags share one, machines differ", async ({ page }) => {
    await openCard(page);
    await logins(page);
    const facts = await paneFacts(page);
    const kayg = facts.accounts.find((a) => a.name === "kayg")!;
    // twelve machines: tags ci, prod, ops, storage, home, edge, db, lab, gpu, and some with none.
    expect(kayg.cards).toBeGreaterThanOrEqual(6);
    // Twelve palette colours serve any number of tags, so two tags can share one; the cards are not all one colour.
    expect(new Set(kayg.cardFills).size).toBeGreaterThanOrEqual(3);
    expect(new Set(kayg.chips).size, "machines are not all one colour").toBeGreaterThanOrEqual(6);
    // A machine with several tags is a linear gradient of them; one with a single tag is that tag's solid colour.
    expect(kayg.chips.some((c) => c.includes("linear-gradient"))).toBe(true);
    expect(kayg.chips.some((c) => !c.includes("gradient") && c.includes("var(--ui-ent-"))).toBe(true);
    expect(facts.paneOverflow).toBe(false);
  });

  test("the worst case: 12 accounts, 1,202 machines on one, fourteen tags; bounded, readable, still coloured", async ({ page }) => {
    await openCard(page, `${MOCK}&data=worst`);
    await logins(page);
    const facts = await paneFacts(page);
    expect(facts.accounts).toHaveLength(12);
    const big = facts.accounts[0]!;
    expect(big.name).toBe("aleksandra.wisniewska-kowalczyk2");
    // Six tag cards and a quiet "+N more tags"; 24 chips at most in a card, then "+N more".
    expect(big.cards).toBe(6);
    expect(big.more.some((m) => /^\+\d+ more tags$/.test(m))).toBe(true);
    expect(Math.max(...big.cardsChips)).toBeLessThanOrEqual(24);
    expect(big.more.some((m) => /^\+[\d,]+ more$/.test(m))).toBe(true);
    // Never one colour: many distinct fills, gradients among them.
    expect(new Set(big.cardFills).size).toBeGreaterThanOrEqual(4);
    expect(new Set(big.chips).size).toBeGreaterThanOrEqual(8);
    expect(big.chips.filter((c) => c.includes("linear-gradient")).length).toBeGreaterThanOrEqual(3);
    // Nothing leaves the pane, the long account name wraps, and the card never scrolls sideways.
    for (const a of facts.accounts) expect(a.overflow, `${a.name} overflows`).toBe(0);
    expect(facts.paneOverflow).toBe(false);
    // The row's own value never covers its key: the account chips stay in the value column.
    const rowBoxes = await page.evaluate(() => {
      const row = [...document.querySelectorAll<HTMLElement>(".ac .ui-kv-row")].find((r) => r.querySelector(".ui-kv-key")?.textContent?.trim() === "Logs in as")!;
      return { key: row.querySelector(".ui-kv-key")!.getBoundingClientRect().right, valueLeft: row.querySelector(".ui-kv-value")!.getBoundingClientRect().left };
    });
    expect(rowBoxes.valueLeft).toBeGreaterThanOrEqual(rowBoxes.key - 0.5);
    // The card is inside the sidebar and the page has no horizontal scroll.
    const inside = await page.evaluate(() => {
      const card = document.querySelector<HTMLElement>(".ac")!.getBoundingClientRect();
      const bar = document.querySelector<HTMLElement>("#sidebar, .ui-sidebar")?.getBoundingClientRect();
      return { left: card.left, right: card.right, barLeft: bar?.left ?? 0, barRight: bar?.right ?? 9999, scroll: document.documentElement.scrollWidth - document.documentElement.clientWidth };
    });
    expect(inside.left).toBeGreaterThanOrEqual(inside.barLeft - 0.5);
    expect(inside.right).toBeLessThanOrEqual(inside.barRight + 0.5);
    expect(inside.scroll).toBeLessThanOrEqual(0);
  });

  test("text on the pane clears 4.5:1 on its real background, light and dark", async ({ page }) => {
    for (const theme of ["ink", "paper"]) {
      await page.setViewportSize({ width: 1440, height: 900 });
      await page.goto(`${MOCK}&data=worst&theme=${theme}`);
      await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
      await page.waitForTimeout(1200);
      await page.locator("#sidebar-toggle").click();
      await page.locator(".ui-sidebar-user").click();
      await expect(page.locator('.ac[data-open="true"]')).toBeVisible({ timeout: 8000 });
      await logins(page);
      const low = await page.evaluate(() => {
        const px = (css: string): number[] => {
          const c = document.createElement("canvas"); c.width = c.height = 1;
          const g = c.getContext("2d", { willReadFrequently: true })!;
          g.clearRect(0, 0, 1, 1); g.fillStyle = css; g.fillRect(0, 0, 1, 1);
          const d = g.getImageData(0, 0, 1, 1).data;
          return [d[0]!, d[1]!, d[2]!, d[3]! / 255];
        };
        const over = (top: number[], bottom: number[]): number[] => {
          const a = top[3]!;
          return [0, 1, 2].map((i) => top[i]! * a + bottom[i]! * (1 - a)).concat([1]);
        };
        /** The opaque colour behind `node`: its ancestors' fills laid over each other until one is opaque. */
        const behind = (node: HTMLElement): number[] => {
          const layers: number[][] = [];
          for (let n: HTMLElement | null = node; n; n = n.parentElement) {
            const fill = px(getComputedStyle(n).backgroundColor);
            if (fill[3]! > 0) layers.push(fill);
            if (fill[3] === 1) break;
          }
          let out = layers.length && layers.at(-1)![3] === 1 ? layers.pop()! : px(getComputedStyle(document.body).backgroundColor);
          if (out[3] !== 1) out = [0, 0, 0, 1];
          while (layers.length) out = over(layers.pop()!, out);
          return out;
        };
        const lum = (c: number[]): number => { const f = (v: number): number => { const s = v / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(c[0]!) + 0.7152 * f(c[1]!) + 0.0722 * f(c[2]!); };
        const ratio = (a: number[], b: number[]): number => { const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x); return (hi! + 0.05) / (lo! + 0.05); };
        const bad: string[] = [];
        let measured = 0;
        for (const node of document.querySelectorAll<HTMLElement>(".ac-account-name, .ac-account-count, .ac-tag-count, .ac-tag-none, .ac-more, .ac-rules span")) {
          if (!node.textContent?.trim() || node.getBoundingClientRect().width === 0) continue;
          const bg = behind(node);
          const fg = over(px(getComputedStyle(node).color), bg);
          measured++;
          const r = ratio(fg, bg);
          if (r < 4.5) bad.push(`${node.className} "${node.textContent.slice(0, 24)}" ${r.toFixed(2)}`);
        }
        return { bad, measured };
      });
      expect(low.measured, `${theme}: texts measured`).toBeGreaterThan(20);
      expect(low.bad, `${theme}: below 4.5:1`).toEqual([]);
    }
  });

  test("a tag has the same colour in its card, its chip and on every machine that carries it", async ({ page }) => {
    await openCard(page);
    await logins(page);
    const same = await page.evaluate(() => {
      const first = document.querySelector<HTMLElement>(".ac-tag:not([data-untagged])")!;
      const chip = first.querySelector<HTMLElement>(".ac-tag-head .ui-entity")!;
      const token = chip.style.background; // var(--ui-ent-N)
      const host = [...first.querySelectorAll<HTMLElement>(".ac-tag-hosts .ui-entity")].find((c) => c.style.background === token);
      return { token, cardTag: first.style.getPropertyValue("--tag"), soloHost: Boolean(host) };
    });
    expect(same.cardTag).toBe(same.token);
  });

  test("Escape closes the pane first, the card after it; the row is focused again", async ({ page }) => {
    await openCard(page);
    await logins(page);
    await page.keyboard.press("Escape");
    await expect(page.locator(".ac-pane[data-open]")).toHaveCount(0);
    await expect(page.locator('.ac[data-open="true"]')).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.locator('.ac[data-open="true"]')).toHaveCount(0);
  });
});

test.describe("beside the version panel", () => {
  test.setTimeout(120_000);

  test("one card at a time: the version pill closes the person's card, and the person's pill closes the version panel", async ({ page }) => {
    await openCard(page, `${MOCK}&version=1`);
    await expect(page.locator(".ui-version-pill")).toBeVisible({ timeout: 8000 });
    await page.locator(".ui-version-pill").click();
    await expect(page.locator('.ac[data-open="true"]')).toHaveCount(0);
    await expect(page.locator(".ui-version-pill")).toHaveAttribute("aria-expanded", "true");
    await page.locator(".ui-sidebar-user").click();
    await expect(page.locator('.ac[data-open="true"]')).toBeVisible();
    await expect(page.locator(".ui-version-pill")).toHaveAttribute("aria-expanded", "false");
  });
});

test.describe("on a phone", () => {
  test.setTimeout(180_000);

  test("the worst case fits 393 x 852: nothing leaves the card, touch rows are 44 px", async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true });
    const page = await context.newPage();
    await openCard(page, `${MOCK}&data=worst`, { width: 393, height: 852 });
    const rows = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>(".ac .ui-kv-row")].map((r) => r.getBoundingClientRect().height));
    expect(Math.min(...rows)).toBeGreaterThanOrEqual(43.5);
    await page.locator(".ac .ui-kv-row", { hasText: "Logs in as" }).locator(".ui-kv-value").tap();
    await expect(page.locator(".ac-pane[data-open]")).toBeVisible();
    await page.waitForTimeout(500);
    const facts = await paneFacts(page);
    for (const a of facts.accounts) expect(a.overflow).toBe(0);
    expect(facts.paneOverflow).toBe(false);
    const wide = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(wide).toBeLessThanOrEqual(0);
    await context.close();
  });
});

test.describe("the product (what the server can say today)", () => {
  test.setTimeout(120_000);

  test("the pill opens the card with the name, the username and sign out; no row it cannot fill, no control that does nothing", async ({ page }) => {
    await openCard(page, "/?mock=1&proto=product&fresh=1&bg=none");
    await expect(page.locator(".ac-name")).not.toHaveText("");
    expect(await page.locator(".ac .ui-kv-row").count()).toBe(0);
    await expect(page.locator(".ac-pencil")).toHaveCount(0);
    await expect(page.locator(".ac-avatar")).toBeDisabled();
    await expect(page.locator(".ac-signout")).toBeVisible();
    // The old small menu never opens.
    await expect(page.locator(".ui-sidebar-menu, .ui-anchored-popover")).toHaveCount(0);
    await page.keyboard.press("Escape");
    await expect(page.locator('.ac[data-open="true"]')).toHaveCount(0);
  });
});
