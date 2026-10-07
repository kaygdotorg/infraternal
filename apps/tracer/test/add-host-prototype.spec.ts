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
    await expect(page.locator("[data-host-id='build-01'] [data-source-icon='already-added']")).toBeVisible();
    await page.getByRole("searchbox", { name: "Find a host" }).fill("edge-arm");
    await expect(page.locator(".addhost-host-list [data-host-row]")).toHaveCount(1);
    await expect(page.locator("[data-host-row][data-host-id='edge-arm']")).toBeVisible();
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
    { value: "ops@10.69.69.254", heading: "Host unreachable", message: "No SSH response on port 22." },
    { value: "kayg@nix-cache", heading: "SSH key refused", message: "The host answered, but it did not accept this key." },
    { value: "root@pve01", heading: "SSH blocked by mesh policy", message: "The host is reachable on the mesh, but its access policy blocks SSH on port 22." },
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
      await expect(page.getByText(scenario.message)).toBeVisible();
      const logs = page.locator(".addhost-error details");
      await expect(logs).not.toHaveAttribute("open", "");
      await logs.locator("summary").click();
      await expect(logs).toHaveAttribute("open", "");
      await expect(logs.locator("pre")).toBeVisible();
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
    await expect(page.getByRole("heading", { name: "edge-arm is ready" })).toBeVisible({ timeout: 8_000 });
    await expect(page.locator(".ui-toast")).toContainText("edge-arm is ready");
    await expect(page.locator(".ui-toast").getByRole("button", { name: "Go to window" })).toBeVisible();
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
        ellipsis: textElements.filter((element) => getComputedStyle(element).textOverflow === "ellipsis").map((element) => element.textContent),
      };
    });
    expect(audit.rootFont).toContain("Geist Mono");
    expect(audit.fontFamilies.every((family) => family.includes("Geist Mono"))).toBe(true);
    expect(audit.fontSizes.every((size) => size >= 13)).toBe(true);
    expect(audit.targets.filter((target) => target.width < 44 || target.height < 44)).toEqual([]);
    expect(audit.ellipsis).toEqual([]);
  } finally {
    await closeContext(context);
  }
});
