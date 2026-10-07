/** Exercises the mock-only add-host canvas window and its SSH outcome states. */
import { expect, test, type Browser, type BrowserContext, type Page } from "playwright/test";

const port = Number(process.env.TRACER_TEST_PORT ?? "4173");
const origin = `http://localhost:${port}`;

async function openAddHost(context: BrowserContext, page: Page, query = "?mock=1&proto=addhost&theme=ink&bg=none"): Promise<void> {
  await context.request.post("/__mock/open-terminal");
  await page.goto(`${origin}/${query}`);
  await expect(page.locator(".addhost-window")).toBeVisible({ timeout: 10_000 });
}

async function makePage(browser: Browser, width = 393, height = 852): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ baseURL: origin, viewport: { width, height } });
  return { context, page: await context.newPage() };
}

async function closeContext(context: BrowserContext): Promise<void> {
  await context.close().catch(() => undefined);
}

async function expectSuccessSurfacesVisible(page: Page): Promise<void> {
  const audit = await page.evaluate(() => {
    const window = document.querySelector<HTMLElement>(".addhost-window")!.getBoundingClientRect();
    const toast = document.querySelector<HTMLElement>(".ui-toast")!.getBoundingClientRect();
    const surfaces = [...document.querySelectorAll<HTMLElement>(".addhost-window-group, .addhost-result-group")]
      .filter((element) => element.getClientRects().length > 0)
      .map((element) => {
        const rect = element.getBoundingClientRect();
        const intersects = rect.left < innerWidth && rect.right > 0 && rect.top < innerHeight && rect.bottom > 0;
        const fullyVisible = rect.left >= 0 && rect.top >= 0 && rect.right <= innerWidth && rect.bottom <= innerHeight;
        return { label: element.getAttribute("aria-label"), intersects, fullyVisible, left: rect.left, right: rect.right, marginInlineStart: getComputedStyle(element).marginInlineStart };
      });
    const controls = [...document.querySelectorAll<HTMLElement>(".addhost-window button, .addhost-result-window button")]
      .filter((element) => element.getClientRects().length > 0 && !element.closest(".ui-toast"));
    return {
      window: { left: window.left, top: window.top, right: window.right, bottom: window.bottom },
      viewport: { width: innerWidth, height: innerHeight },
      clippedSurfaces: surfaces.filter((surface) => surface.intersects && !surface.fullyVisible),
      toastPosition: getComputedStyle(document.querySelector<HTMLElement>(".ui-toast")!).position,
      toastOverlaps: controls.filter((element) => {
        const rect = element.getBoundingClientRect();
        return rect.left < toast.right && rect.right > toast.left && rect.top < toast.bottom && rect.bottom > toast.top;
      }).map((element) => element.getAttribute("aria-label") ?? element.textContent),
    };
  });
  expect(audit.window.left).toBeGreaterThanOrEqual(0);
  expect(audit.window.top).toBeGreaterThanOrEqual(0);
  expect(audit.window.right).toBeLessThanOrEqual(audit.viewport.width);
  expect(audit.window.bottom).toBeLessThanOrEqual(audit.viewport.height);
  expect(audit.clippedSurfaces).toEqual([]);
  expect(audit.toastPosition).toBe("fixed");
  expect(audit.toastOverlaps).toEqual([]);
}

test("add-host preview opens in a canvas window with quiet, deduplicated discovery", async ({ browser }) => {
  const { context, page } = await makePage(browser);
  try {
    await openAddHost(context, page);
    await expect(page.locator(".addhost-window")).toHaveAttribute("data-step", "discovery");
    await expect(page.getByRole("heading", { name: "Add hosts" })).toBeVisible();
    await expect(page.locator(".addhost-host-list [data-host-row]")).toHaveCount(6);
    await expect(page.locator(".addhost-host-list [data-host-row][data-host-id='build-01']")).toHaveCount(1);
    await expect(page.locator("[data-host-id='build-01'] [data-source-icon='netbird']")).toBeVisible();
    await expect(page.locator("[data-host-id='build-01'] [data-source-icon='ssh-config']")).toBeVisible();
    await expect(page.locator("[data-host-id='edge-arm'] [data-ssh-status]")).toContainText("SSH ready");
    await expect(page.locator("[data-host-id='pve01'] [data-ssh-status]")).toContainText("mesh policy");
    await expect(page.locator("[data-host-id='archive-01'] [data-ssh-status]")).toContainText("No SSH response");
    await expect(page.locator("[data-host-id='build-01'] [data-ssh-status]")).toHaveText("Already added");
    await expect(page.locator("[data-host-id='build-01'] [data-source-icon='already-added']")).toHaveCount(0);
    await page.getByRole("searchbox", { name: "Find a host" }).fill("edge-arm");
    await expect(page.locator(".addhost-host-list [data-host-row]")).toHaveCount(1);
    await expect(page.locator("[data-host-row][data-host-id='edge-arm']")).toBeVisible();
  } finally {
    await closeContext(context);
  }
});

test("discovered rows stay legible across the desktop and phone layouts", async ({ browser }) => {
  for (const viewport of [{ width: 1440, height: 900 }, { width: 393, height: 852 }]) {
    const context = await browser.newContext({ baseURL: origin, viewport });
    const page = await context.newPage();
    try {
      await openAddHost(context, page);
      const row = page.locator("[data-host-row][data-host-id='build-01']");
      const audit = await row.evaluate((element) => {
        const style = getComputedStyle(element);
        const columns = style.gridTemplateColumns.split(" ").length;
        const box = element.getBoundingClientRect();
        const name = element.querySelector<HTMLElement>(".addhost-host-name")!;
        const source = element.querySelector<HTMLElement>(".addhost-source-chip")!;
        const description = document.querySelector<HTMLElement>(".addhost-heading p")!;
        const range = document.createRange();
        range.selectNodeContents(description);
        return {
          columns,
          height: box.height,
          nameWrap: getComputedStyle(name).overflowWrap,
          nameSize: Number.parseFloat(getComputedStyle(name).fontSize),
          bodySize: Number.parseFloat(getComputedStyle(description).fontSize),
          headingSize: Number.parseFloat(getComputedStyle(document.querySelector<HTMLElement>(".addhost-heading h1")!).fontSize),
          secondarySize: Number.parseFloat(getComputedStyle(element.querySelector<HTMLElement>(".addhost-host-system") ?? name).fontSize),
          secondaryText: element.querySelector<HTMLElement>(".addhost-host-secondary")?.textContent ?? "",
          sourcesShareSecondary: Boolean(source.closest(".addhost-host-secondary")),
          introLines: range.getClientRects().length,
          headerPillVisible: Boolean(document.querySelector(".addhost-window-header .window-host-pill:not([hidden])")),
        };
      });
      expect(audit.columns).toBe(3);
      expect(audit.nameWrap).toBe("normal");
      expect(audit.secondaryText).toContain("Ubuntu 24.04 · x86_64");
      expect(audit.secondaryText).toContain("NetBird");
      expect(audit.secondaryText).toContain("SSH config");
      expect(audit.sourcesShareSecondary).toBe(true);
      expect(audit.headerPillVisible).toBe(false);
      expect(audit.nameSize).toBe(viewport.width > 600 ? 13 : 16);
      expect(audit.bodySize).toBe(viewport.width > 600 ? 13 : 16);
      expect(audit.headingSize).toBe(viewport.width > 600 ? 20 : 22);
      expect(audit.secondarySize).toBe(viewport.width > 600 ? 12 : 15);
      if (viewport.width > 600) {
        expect(audit.height).toBeGreaterThanOrEqual(52);
        expect(audit.height).toBeLessThanOrEqual(56);
        expect(audit.introLines).toBe(1);
      }
    } finally {
      await closeContext(context);
    }
  }
});

test("the test-double badge stays in the corner and hides behind a window or overlay", async ({ browser }) => {
  const { context, page } = await makePage(browser);
  try {
    await openAddHost(context, page, "?mock=1&proto=addhost&empty=1&theme=ink&bg=none");
    await page.getByRole("button", { name: "Close add hosts" }).click();
    const badge = page.locator("#test-double-badge");
    await expect(badge).toBeVisible();
    const barePosition = await badge.evaluate((element) => {
      const rect = element.getBoundingClientRect();
      return {
        left: rect.left,
        bottomGap: innerHeight - rect.bottom,
        rightGap: innerWidth - rect.right,
        viewportWidth: innerWidth,
      };
    });
    expect(barePosition.left).toBeLessThanOrEqual(16);
    expect(barePosition.bottomGap).toBeLessThanOrEqual(16);
    expect(barePosition.rightGap).toBeGreaterThan(barePosition.viewportWidth / 2);
    await page.locator("#sidebar-toggle").click();
    await expect(badge).toBeHidden();
    await page.locator("#sidebar").getByRole("button", { name: "Add hosts" }).click();
    await expect(page.locator(".addhost-window")).toBeVisible();
    await expect(badge).toBeHidden();
  } finally {
    await closeContext(context);
  }
});

test("sidebar and command palette open the same add-host window", async ({ browser }) => {
  const { context, page } = await makePage(browser);
  try {
    await openAddHost(context, page);
    await page.getByRole("button", { name: "Close add hosts" }).click();
    await page.locator("#sidebar-toggle").click();
    await page.locator("#sidebar").getByRole("button", { name: "Add hosts" }).click();
    await expect(page.locator(".addhost-window")).toBeVisible();
    await expect(page.locator("#sidebar")).toBeHidden();
    await page.getByRole("button", { name: "Close add hosts" }).click();
    await page.keyboard.press("Control+k");
    await expect(page.locator("#palette")).toBeVisible();
    await page.locator("#palette-input").fill("Add hosts");
    const addHostsAction = page.getByRole("option", { name: /Add hosts/ });
    await expect(addHostsAction).toBeVisible();
    await addHostsAction.click();
    await expect(page.locator(".addhost-window")).toBeVisible();
  } finally {
    await closeContext(context);
  }
});

test("the calm empty state opens the same discovery flow", async ({ browser }) => {
  const { context, page } = await makePage(browser);
  try {
    await openAddHost(context, page, "?mock=1&proto=addhost&empty=1&theme=ink&bg=none");
    await expect(page.locator(".addhost-empty-state")).toBeVisible();
    await page.locator(".addhost-empty-state").getByRole("button", { name: "Add hosts", exact: true }).click();
    await expect(page.locator(".addhost-window")).toHaveAttribute("data-step", "discovery");
  } finally {
    await closeContext(context);
  }
});

test("root consent uses the visible shared checkbox in both themes", async ({ browser }) => {
  for (const theme of ["ink", "paper"]) {
    const { context, page } = await makePage(browser);
    try {
      await openAddHost(context, page, `?mock=1&proto=addhost&theme=${theme}&bg=none`);
      await page.locator("[data-host-id='edge-arm'] .addhost-host-select").click();
      await page.getByRole("button", { name: "Continue" }).click();
      const checkbox = page.getByRole("checkbox", { name: /trust .* root access/i });
      await expect(checkbox).not.toBeChecked();
      const hitArea = await page.locator(".addhost-consent-label").first().evaluate((label) => {
        const mark = label.querySelector<HTMLElement>(".tick")!;
        const style = getComputedStyle(mark);
        return {
          height: label.getBoundingClientRect().height,
          borderWidth: style.getPropertyValue("--ui-tick-border-width").trim(),
          borderColor: style.getPropertyValue("--ui-tick-border-color").trim(),
          themeBorderColor: getComputedStyle(document.querySelector<HTMLElement>(".terminal-screen")!).getPropertyValue("--fg-2").trim(),
        };
      });
      expect(hitArea.height).toBeGreaterThanOrEqual(44);
      expect(hitArea.borderWidth).toBe("1.5px");
      expect(hitArea.borderColor).toBe(hitArea.themeBorderColor);
      await expect(page.getByRole("button", { name: "Install as root" })).toBeDisabled();
    } finally {
      await closeContext(context);
    }
  }
});

test("source switches filter the single list and host names reveal IPs on tap", async ({ browser }) => {
  const { context, page } = await makePage(browser);
  try {
    await openAddHost(context, page);
    const sourceDisclosure = page.getByRole("button", { name: "Discovery sources" });
    await sourceDisclosure.scrollIntoViewIfNeeded();
    await sourceDisclosure.click();
    const netbirdSwitch = page.getByRole("switch", { name: "NetBird" });
    await netbirdSwitch.scrollIntoViewIfNeeded();
    await netbirdSwitch.uncheck();
    await expect(page.locator("[data-host-id='pve01']")).toHaveCount(0);
    await expect(page.locator("[data-host-row][data-host-id='build-01']")).toHaveCount(1);
    await page.getByRole("button", { name: "Show IP for edge-arm" }).scrollIntoViewIfNeeded();
    await page.getByRole("button", { name: "Show IP for edge-arm" }).click();
    await expect(page.locator("[data-host-id='edge-arm'] [data-host-ip]")).toHaveText("10.69.69.72");
  } finally {
    await closeContext(context);
  }
});

test("manual entry gives separate unreachable, authentication, and mesh-policy explanations", async ({ browser }) => {
  const scenarios = [
    {
      value: "ops@10.69.69.254",
      heading: "Host unreachable",
      happened: "SSH to 10.69.69.254 got no response on TCP 22.",
      next: "Check that the host is online and SSH is listening, then retry.",
    },
    {
      value: "kayg@nix-cache",
      heading: "SSH key refused",
      happened: "SSH to nix-cache reached the host, but the selected identity was refused.",
      next: "Choose another SSH identity or correct its access, then retry.",
    },
    {
      value: "root@pve01",
      heading: "SSH blocked by mesh policy",
      happened: "SSH to pve01 is blocked by the mesh access policy (TCP 22).",
      next: "Ask a mesh admin to allow TCP 22 from this server, then retry.",
    },
  ];
  for (const scenario of scenarios) {
    const { context, page } = await makePage(browser);
    try {
      await openAddHost(context, page);
      await page.getByRole("tab", { name: "Manual" }).click();
      await page.getByRole("textbox", { name: "Host" }).fill(scenario.value);
      await page.getByRole("button", { name: "Add host", exact: true }).click();
      if (scenario.value === "kayg@nix-cache") {
        await expect(page.getByRole("textbox", { name: "SSH key or password for nix-cache" })).toBeVisible();
        await page.getByRole("button", { name: "Continue" }).click();
      }
      await expect(page.getByRole("heading", { name: scenario.heading })).toBeVisible();
      await expect(page.getByText(scenario.happened, { exact: true })).toBeVisible();
      await expect(page.getByText(scenario.next, { exact: true })).toBeVisible();
      await expect(page.locator(".addhost-error > p")).toHaveCount(2);
      await expect(page.getByRole("button", { name: "Retry", exact: true })).toBeVisible();
      await expect(page.getByRole("button", { name: "Back to hosts", exact: true })).toBeVisible();
      if (scenario.value === "root@pve01") {
        await expect(page.locator(".addhost-window-header .window-host-pill")).toContainText("root@pve01");
      }
    } finally {
        await closeContext(context);
    }
  }
});

test("mixed selections keep every failed host visible while ready hosts continue", async ({ browser }) => {
  const { context, page } = await makePage(browser);
  try {
    await openAddHost(context, page);
    await page.locator("[data-host-id='edge-arm'] .addhost-host-select").click();
    await page.locator("[data-host-id='nix-cache'] .addhost-host-select").click();
    await page.locator("[data-host-id='archive-01'] .addhost-host-select").click();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("textbox", { name: "SSH key or password for nix-cache" }).fill("preview-only");
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Install as a user" }).click();
    await expect(page.locator(".addhost-policy-evidence")).toContainText(["archive-01", "nix-cache"]);
    await expect(page.getByRole("heading", { name: "edge-arm is ready" })).toBeVisible({ timeout: 8_000 });
    await expect(page.locator(".addhost-policy-evidence")).toContainText(["archive-01", "nix-cache"]);
  } finally {
    await closeContext(context);
  }
});

test("root installation needs a separate consent and ready hosts offer their window", async ({ browser }) => {
  const { context, page } = await makePage(browser);
  try {
    await openAddHost(context, page);
    await page.locator("[data-host-id='edge-arm'] .addhost-host-select").click();
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.getByRole("heading", { name: "Root access" })).toBeVisible();
    const consent = page.getByRole("checkbox", { name: /trust .* root access/i });
    await expect(consent).not.toBeChecked();
    await expect(page.getByRole("button", { name: "Install as root" })).toBeDisabled();
    await page.locator(".addhost-consent-label").first().click();
    await page.getByRole("button", { name: "Install as root" }).click();
    await expect(page.locator(".addhost-window")).toHaveAttribute("data-step", "bootstrap");
    await expect(page.locator("[data-bootstrap-step='install']")).toBeVisible();
    await expect(page.locator("[data-bootstrap-step='facts']")).toBeVisible();
    await expect(page.locator("[data-bootstrap-step='connect']")).toBeVisible();
    await expect(page.locator(".addhost-progress-steps input")).toHaveCount(0);
    await expect(page.locator(".addhost-progress-mark[data-state='running'] .ui-spinner")).toBeVisible();
    await expect(page.locator(".addhost-progress-mark[data-state='pending'] .ui-step-status-pending").first()).toBeVisible();
    const failedStep = page.locator("[data-bootstrap-step='connect']");
    const failedMark = failedStep.locator(".addhost-progress-mark");
    await failedMark.evaluate((element) => { (element as HTMLElement).dataset.state = "failed"; });
    await expect(failedMark.locator(".ui-step-status-failed")).toBeVisible();
    const failedColor = await failedMark.locator(".ui-step-status-failed").evaluate((element) => getComputedStyle(element).stroke);
    expect(failedColor).not.toBe("rgb(0, 0, 0)");
    await expect(page.getByRole("heading", { name: "edge-arm is ready" })).toBeVisible({ timeout: 8_000 });
    await expect(page.locator(".ui-toast")).toContainText("edge-arm is ready");
    await expect(page.locator(".ui-toast").getByRole("button", { name: "Go to window" })).toBeVisible();
    await expectSuccessSurfacesVisible(page);
    await page.locator(".ui-toast").getByRole("button", { name: "Go to window" }).click();
    await expect(page.locator(".addhost-window-group")).toBeHidden();
    const hostBounds = await page.locator(".addhost-result-group").evaluate((group) => {
      const rect = group.getBoundingClientRect();
      return { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom, width: innerWidth, height: innerHeight };
    });
    expect(hostBounds.left).toBeGreaterThanOrEqual(0);
    expect(hostBounds.top).toBeGreaterThanOrEqual(0);
    expect(hostBounds.right).toBeLessThanOrEqual(hostBounds.width);
    expect(hostBounds.bottom).toBeLessThanOrEqual(hostBounds.height);
  } finally {
    await closeContext(context);
  }
});

test("a rootless install exposes an anchored Root available confirmation", async ({ browser }) => {
  const { context, page } = await makePage(browser);
  try {
    await openAddHost(context, page);
    await page.locator("[data-host-id='edge-arm'] .addhost-host-select").click();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Install as a user" }).click();
    await expect(page.getByRole("heading", { name: "edge-arm is ready" })).toBeVisible({ timeout: 8_000 });
    await expect(page.locator(".ui-toast")).toContainText("edge-arm is ready");
    await expectSuccessSurfacesVisible(page);
    await page.getByRole("button", { name: "Root available" }).click();
    const confirmation = page.getByRole("dialog", { name: "Root access confirmation" });
    await expect(confirmation).toBeVisible();
    await expect(confirmation.getByRole("button", { name: "Yes" })).toBeVisible();
    await expect(confirmation.getByRole("button", { name: "No" })).toBeVisible();
    await confirmation.getByRole("button", { name: "No" }).click();
    await expect(confirmation).toBeHidden();
  } finally {
    await closeContext(context);
  }
});

test("desktop success keeps canvas windows wholly inside or outside the viewport", async ({ browser }) => {
  const { context, page } = await makePage(browser, 1440, 900);
  try {
    await openAddHost(context, page);
    await page.locator("[data-host-id='edge-arm'] .addhost-host-select").click();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Install as a user" }).click();
    await expect(page.getByRole("heading", { name: "edge-arm is ready" })).toBeVisible({ timeout: 8_000 });
    await expectSuccessSurfacesVisible(page);
  } finally {
    await closeContext(context);
  }
});

test("add-host text stays monospace and touch targets stay at least 44 pixels", async ({ browser }) => {
  const { context, page } = await makePage(browser);
  try {
    await openAddHost(context, page);
    const audit = await page.locator(".addhost-window").evaluate((root) => {
      const textElements = [...root.querySelectorAll<HTMLElement>("h1,h2,h3,p,label,button,input,summary,[data-text]")]
        .filter((element) => element.getClientRects().length > 0 && (element.innerText || element.getAttribute("aria-label")));
      const fontFamilies = textElements.map((element) => getComputedStyle(element).fontFamily);
      const fontSizes = textElements.map((element) => Number.parseFloat(getComputedStyle(element).fontSize));
      const targets = [...root.querySelectorAll<HTMLElement>("button,.addhost-host-select,.addhost-consent-label,input.ui-switch")]
        .filter((element) => element.getClientRects().length > 0)
        .map((element) => ({
          label: element.innerText || element.getAttribute("aria-label") || element.className,
          width: element.getBoundingClientRect().width,
          height: element.getBoundingClientRect().height,
        }));
      return {
        rootFont: getComputedStyle(document.documentElement).fontFamily,
        fontFamilies,
        fontSizes,
        targets,
        ellipsis: textElements.filter((element) => !element.matches(".addhost-host-name") && getComputedStyle(element).textOverflow === "ellipsis").map((element) => element.textContent),
      };
    });
    expect(audit.rootFont).toContain("Geist Mono");
    expect(audit.fontFamilies.every((family) => family.includes("Geist Mono"))).toBe(true);
    expect(audit.fontSizes.every((size) => size >= 13)).toBe(true);
    expect(audit.targets.filter((target) => target.width < 44 || target.height < 44)).toEqual([]);
    expect(audit.ellipsis).toEqual([]);
    await page.evaluate(() => document.documentElement.setAttribute("data-ui-font", "sans"));
    await expect.poll(() => page.locator(".addhost-window").evaluate((window) => getComputedStyle(window).fontFamily))
      .toContain("Geist Mono");
  } finally {
    await closeContext(context);
  }
});
