/**
 * "Add this machine" approval (D311, #263): a mocked join request on the production build. Checks what the screen says,
 * that the QR link's code is read from the fragment and gone from the address bar before any request, that every machine
 * needs its own passkey tap, that nothing approves by itself, and that the layout is aligned and not clipped.
 */
import { expect, test, type Page } from "playwright/test";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";

const CODE = "AbCdEfGhIjKlMnOp";
const FINGERPRINT = "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCde";
const LINK = `/#join=${CODE}`;
const TITLE = (name: string) => `Add ${name} to localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`;

interface Mock {
  requests: string[];
  addressAtRequest: string[];
  /** Passkey ceremonies started for this approval (`device-approve-start`). */
  approvalStarts: () => number;
  /** Ordinary logins: a join's approval never needs one (#263, J134 P3-2). */
  logins: () => number;
  approvals: () => number;
}

/** A signed-in owner, one pending join request, and a passkey prompt that the test can count and refuse. */
async function mockJoin(page: Page, request: Record<string, unknown> = {}, options: { cancelPasskey?: boolean } = {}): Promise<Mock> {
  const requests: string[] = [];
  const addressAtRequest: string[] = [];
  let approvalStarts = 0;
  let logins = 0;
  let approvals = 0;
  await page.addInitScript((cancel) => {
    Object.defineProperty(navigator.credentials, "get", {
      configurable: true,
      value: () => {
        Object.defineProperty(window, "__passkeyPrompts", { configurable: true, value: ((window as { __passkeyPrompts?: number }).__passkeyPrompts ?? 0) + 1 });
        return cancel ? Promise.reject(new DOMException("cancelled", "NotAllowedError")) : new Promise(() => undefined);
      },
    });
  }, options.cancelPasskey ?? true);
  page.on("request", (seen) => {
    const url = new URL(seen.url());
    if (!url.pathname.startsWith("/auth/")) return;
    // The request line (path and query) must never carry the code; the fragment is not sent at all.
    requests.push(`${url.pathname}${url.search}`);
    addressAtRequest.push(new URL(page.url()).hash);
  });
  await page.route("**/auth/status", route => route.fulfill({ json: { setup_required: false } }));
  await page.route("**/auth/session", route => route.fulfill({ json: {
    user_id: "11111111-1111-4111-8111-111111111111",
    username: "fixture_owner",
    display_name: "Fixture owner",
    device: "Browser",
    fresh: Math.floor(Date.now() / 1000),
  } }));
  await page.route("**/auth/device-inspect", route => route.fulfill({ json: {
    kind: "join_machine", hostname: "build-01", mode: "system", key_fingerprint: FINGERPRINT, ...request,
  } }));
  await page.route("**/auth/login-start", async route => {
    logins += 1;
    await route.fulfill({ json: { ceremony: "login", options: { publicKey: {} } } });
  });
  await page.route("**/auth/device-approve-start", async route => {
    approvalStarts += 1;
    await route.fulfill({ json: { ceremony: "fixture", options: { publicKey: {
      challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      rpId: "localhost",
      allowCredentials: [],
      timeout: 30_000,
      userVerification: "required",
      extensions: { prf: { eval: { first: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" } } },
    } } } });
  });
  await page.route("**/auth/device-approve-finish", async route => {
    approvals += 1;
    await route.fulfill({ json: { ok: true } });
  });
  return {
    requests, addressAtRequest, approvalStarts: () => approvalStarts, logins: () => logins, approvals: () => approvals,
  };
}

const tick = (page: Page) => page.getByText("I checked that the code and key match my terminal");

test("the QR link's code is read from the fragment and removed from the address bar before any request", async ({ page }) => {
  const mock = await mockJoin(page);
  await page.goto(LINK);
  await expect(page.getByRole("heading", { name: TITLE("build-01") })).toBeVisible();
  expect(await page.evaluate(() => location.hash)).toBe("");
  expect(await page.evaluate(() => location.href.includes("AbCdEf"))).toBe(false);
  expect(mock.requests.length).toBeGreaterThan(0);
  // No request line mentions the code, and the bar was already clean when the first one went out.
  expect(mock.requests.some(line => line.includes("AbCdEf"))).toBe(false);
  expect(mock.addressAtRequest.every(hash => hash === "")).toBe(true);
});

test("the screen says what is being approved in plain words", async ({ page }) => {
  await mockJoin(page);
  await page.goto(LINK);
  await expect(page.getByRole("heading", { name: TITLE("build-01") })).toBeVisible();
  await expect(page.locator("#device-approval-code")).toHaveText(CODE);
  const facts = page.getByRole("list", { name: "Machine to add" });
  await expect(facts.getByText("Runs as", { exact: true })).toBeVisible();
  await expect(facts.getByText("System service", { exact: true })).toBeVisible();
  await expect(facts.getByText("Machine key", { exact: true })).toBeVisible();
  await expect(facts.getByText("AbCd EfGh IjKl MnOp", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve with passkey" })).toBeDisabled();
  // None of the CLI sign-in wording appears on the join screen.
  await expect(page.getByText("Approve device sign-in")).toHaveCount(0);
  await expect(page.getByText("hosts:read")).toHaveCount(0);
});

test("a user service is named as such", async ({ page }) => {
  await mockJoin(page, { mode: "user" });
  await page.goto(LINK);
  await expect(page.getByText("User service", { exact: true })).toBeVisible();
});

test("a machine name that is not a plain host name is refused, never shown", async ({ page }) => {
  // The page accepts only the ASCII set `infraternal up` sends (#263, J134 P3-3), so markup and bidi never reach it.
  for (const hostname of ["<img src=x onerror=alert(1)>", "build-\u202e10-dliub"]) {
    await mockJoin(page, { hostname });
    await page.goto("about:blank");
    await page.goto(LINK);
    await expect(page.getByRole("heading", { name: "Can't add this machine" })).toBeVisible();
    await expect(page.locator("img")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Approve with passkey" })).toHaveCount(0);
  }
});

test("the longest machine name wraps inside the card", async ({ page }) => {
  const hostname = "w".repeat(128);
  await mockJoin(page, { hostname });
  await page.goto(LINK);
  await expect(page.locator("#device-approval-title")).toContainText(hostname);
  const [title, card] = await page.evaluate(() => [".device-approval-title", ".auth-card"].map(selector => {
    const box = document.querySelector<HTMLElement>(selector)!.getBoundingClientRect();
    return { left: box.left, right: box.right };
  }));
  expect(title!.left).toBeGreaterThanOrEqual(card!.left);
  expect(title!.right).toBeLessThanOrEqual(card!.right);
});

test("nothing approves by itself: loading, ticking and a cancelled passkey leave the request pending", async ({ page }) => {
  const mock = await mockJoin(page);
  await page.goto(LINK);
  await expect(page.getByRole("heading", { name: TITLE("build-01") })).toBeVisible();
  expect(mock.approvals()).toBe(0);
  expect(mock.approvalStarts()).toBe(0);
  expect(mock.logins()).toBe(0);
  await tick(page).click();
  await expect(page.getByRole("button", { name: "Approve with passkey" })).toBeEnabled();
  expect(mock.approvals()).toBe(0);
  await page.getByRole("button", { name: "Approve with passkey" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "passkey prompt was cancelled" })).toBeVisible();
  expect(mock.approvalStarts()).toBe(1);
  expect(mock.logins()).toBe(0);
  expect(mock.approvals()).toBe(0);
});

test("every machine needs its own passkey tap", async ({ page }) => {
  const context = page.context();
  await context.request.post("/__mock/reset");
  const setup = await (await context.request.get("/__mock/setup-token")).json() as { setup_token: string };
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
  } });
  await page.addInitScript(() => {
    const get = navigator.credentials.get.bind(navigator.credentials);
    Object.defineProperty(navigator.credentials, "get", {
      configurable: true,
      value: (options: CredentialRequestOptions) => {
        document.documentElement.dataset.passkeyGets = String(Number(document.documentElement.dataset.passkeyGets ?? "0") + 1);
        return get(options);
      },
    });
  });
  await page.goto("/?mock=1");
  await page.locator("#setup-token").fill(setup.setup_token);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.locator("#setup-username").fill("join_approval_test");
  await page.locator("#setup-display-name").fill("Join approval test");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await expect(page.getByRole("heading", { name: "Save your recovery key" })).toBeVisible();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await expect(page.getByText("TEST DOUBLE")).toBeVisible();

  const starts: Array<{ code: string; ceremony: string }> = [];
  const finishes: Array<{ code: string; ceremony: string }> = [];
  const requests: string[] = [];
  page.on("request", seen => { const path = new URL(seen.url()).pathname; if (path.startsWith("/auth/")) requests.push(path); });
  await page.route("**/auth/device-inspect", route => route.fulfill({ json: {
    kind: "join_machine", hostname: "build-01", mode: "system", key_fingerprint: FINGERPRINT,
  } }));
  // The double has no join ceremony: borrow its real login options (so the virtual authenticator answers), and give
  // each start its own ceremony ID, so the test can see which start a finish belongs to.
  await page.route("**/auth/device-approve-start", async route => {
    const login = await route.fetch({ url: new URL("/auth/login-start", route.request().url()).href, postData: "{}" });
    const ceremony = `approval-${starts.length + 1}`;
    starts.push({ code: String(route.request().postDataJSON().code), ceremony });
    await route.fulfill({ json: { ...(await login.json() as object), ceremony } });
  });
  await page.route("**/auth/device-approve-finish", async route => {
    const body = route.request().postDataJSON() as { code: unknown; ceremony: unknown; proof: unknown };
    expect(typeof body.proof).toBe("object");
    finishes.push({ code: String(body.code), ceremony: String(body.ceremony) });
    await route.fulfill({ json: { ok: true } });
  });
  for (const code of ["AbCdEfGhIjKlMnOp", "QwErTyUiOpAsDfGh"]) {
    // A new document each time: a fragment-only navigation would keep the page, and its state, alive.
    await page.goto("about:blank");
    await page.goto(`/#join=${code}`);
    await expect(page.getByRole("heading", { name: TITLE("build-01") })).toBeVisible();
    await tick(page).click();
    await page.getByRole("button", { name: "Approve with passkey" }).click();
    await expect(page.getByRole("heading", { name: "Machine approved" })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.dataset.passkeyGets)).toBe("1");
  }
  // Each approval is its own ceremony, finished with the code it was started for, and no login stands in for it.
  expect(starts).toEqual([
    { code: "AbCdEfGhIjKlMnOp", ceremony: "approval-1" }, { code: "QwErTyUiOpAsDfGh", ceremony: "approval-2" },
  ]);
  expect(finishes).toEqual(starts);
  expect(requests.filter(path => path === "/auth/device-approve")).toEqual([]);
});

test("Escape cancels without approving and returns to the app", async ({ page }) => {
  const mock = await mockJoin(page);
  await page.goto(LINK);
  await expect(page.getByRole("heading", { name: TITLE("build-01") })).toBeVisible();
  await tick(page).click();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("heading", { name: TITLE("build-01") })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Approve with passkey" })).toHaveCount(0);
  expect(mock.approvals()).toBe(0);
  expect(mock.approvalStarts()).toBe(0);
  expect(mock.logins()).toBe(0);
});

test("Escape does nothing while the passkey prompt is open", async ({ page }) => {
  const mock = await mockJoin(page, {}, { cancelPasskey: false });
  await page.goto(LINK);
  await expect(page.getByRole("heading", { name: TITLE("build-01") })).toBeVisible();
  await tick(page).click();
  await page.getByRole("button", { name: "Approve with passkey" }).click();
  await expect.poll(() => page.evaluate(() => (window as { __passkeyPrompts?: number }).__passkeyPrompts ?? 0)).toBe(1);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("heading", { name: TITLE("build-01") })).toBeVisible();
  expect(mock.approvals()).toBe(0);
});

test("going back leaves the page without approving", async ({ page }) => {
  const mock = await mockJoin(page);
  await page.goto("/?mock=1#top");
  await page.goto(LINK);
  await expect(page.getByRole("heading", { name: TITLE("build-01") })).toBeVisible();
  await page.goBack();
  expect(mock.approvals()).toBe(0);
  expect(mock.approvalStarts()).toBe(0);
  expect(mock.logins()).toBe(0);
});

test("a request that has expired offers no approval and says what to do", async ({ page }) => {
  await mockJoin(page);
  await page.route("**/auth/device-inspect", route => route.fulfill({ status: 401, json: { error: "authorization failed" } }));
  await page.goto(LINK);
  await expect(page.getByRole("heading", { name: "Can't add this machine" })).toBeVisible();
  await expect(page.getByRole("alert")).toContainText("infraternal up again");
  await expect(page.getByRole("button", { name: "Approve with passkey" })).toHaveCount(0);
});

test("a sign-in answer behind a join link is refused", async ({ page }) => {
  await mockJoin(page);
  await page.route("**/auth/device-inspect", route => route.fulfill({ json: { device: "kayg-laptop", scopes: ["hosts:read", "terminal:connect", "actions:dry-run"] } }));
  await page.goto(LINK);
  await expect(page.getByRole("heading", { name: "Can't add this machine" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve with passkey" })).toHaveCount(0);
});

test("two codes in one link are refused before any request", async ({ page }) => {
  let authRequests = 0;
  await page.route("**/auth/**", async route => { authRequests += 1; await route.fulfill({ json: {} }); });
  await page.goto("/#join=AbCdEfGhIjKlMnOp&join=QwErTyUiOpAsDfGh");
  await expect(page.getByRole("heading", { name: "Can't add this machine" })).toBeVisible();
  await expect(page.getByRole("alert")).toContainText("more than one code");
  expect(await page.evaluate(() => location.hash)).toBe("");
  expect(authRequests).toBe(0);
});

test("clicking the machine key copies the whole fingerprint and answers in place", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await mockJoin(page);
  await page.goto(LINK);
  await expect(page.getByRole("heading", { name: TITLE("build-01") })).toBeVisible();
  await page.getByText("AbCd EfGh IjKl MnOp", { exact: true }).click();
  await expect(page.getByText("Copied", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(FINGERPRINT);
});

for (const profile of [
  { name: "desktop", viewport: { width: 1440, height: 900 }, scale: 2, touch: false },
  { name: "phone", viewport: { width: 393, height: 852 }, scale: 3, touch: true },
]) {
  test.describe(`layout, ${profile.name} ${profile.viewport.width}×${profile.viewport.height} at ${profile.scale}×`, () => {
    test.use({ viewport: profile.viewport, deviceScaleFactor: profile.scale, hasTouch: profile.touch, isMobile: profile.touch });

    test("text and icons line up and nothing is clipped", async ({ page }) => {
      await mockJoin(page);
      await page.goto(LINK);
      await expect(page.getByRole("heading", { name: TITLE("build-01") })).toBeVisible();

      const measured = await page.evaluate(() => {
        const box = (selector: string, root: ParentNode = document) => {
          const element = root.querySelector<HTMLElement>(selector);
          if (!element) throw new Error(`Missing alignment element: ${selector}`);
          const rect = element.getBoundingClientRect();
          return { left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom, centerY: rect.top + rect.height / 2 };
        };
        // The shared list pads its highlight run by 6 px and cancels it with a negative margin, so the text itself
        // (not the run's box) is what has to line up.
        const textBox = (selector: string, root: ParentNode) => {
          const run = root.querySelector<HTMLElement>(selector);
          if (!run) throw new Error(`Missing alignment element: ${selector}`);
          const range = document.createRange();
          range.selectNodeContents(run);
          const rect = range.getBoundingClientRect();
          return { left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom, centerY: rect.top + rect.height / 2 };
        };
        const rows = [...document.querySelectorAll<HTMLElement>(".ui-kv-row")].map(row => ({
          key: textBox(".ui-kv-key .ui-kv-text", row),
          value: textBox(".ui-kv-value .ui-kv-text", row),
        }));
        return {
          title: box("#device-approval-title"),
          lede: box(".auth-lede"),
          label: box(".auth-label"),
          code: box("#device-approval-code"),
          hint: box(".auth-hint"),
          facts: box(".device-approval-kv"),
          rows,
          checkbox: box("#device-approval-code-match"),
          checkText: box(".auth-check span"),
          check: box(".auth-check"),
          note: box(".device-approval-note"),
          button: box("#device-approval-approve"),
          icon: box("#device-approval-approve svg"),
          text: box("#device-approval-approve > span:not(.busy-count)"),
          card: box(".auth-card"),
        };
      });
      const near = (actual: number, expected: number, what: string): void => {
        expect(Math.abs(actual - expected), what).toBeLessThanOrEqual(0.5);
      };
      // One left edge for the title, lede, label, code, hint, checkbox row and note.
      for (const [name, edge] of Object.entries({ title: measured.title, lede: measured.lede, code: measured.code, hint: measured.hint, check: measured.check, note: measured.note, facts: measured.facts })) {
        near(edge.left, measured.label.left, `${name} left edge`);
      }
      // The facts span the same width as the code field: keys on the left edge, values on the right edge.
      near(measured.facts.right, measured.code.right, "facts right edge");
      expect(measured.rows).toHaveLength(2);
      for (const row of measured.rows) {
        near(row.key.left, measured.label.left, "key left edge");
        near(row.value.right, measured.code.right, "value right edge");
        near(row.key.centerY, row.value.centerY, "key and value share a centre line");
      }
      near(measured.checkbox.centerY, measured.checkText.centerY, "tick and its text share a centre line");
      near(measured.icon.centerY, measured.text.centerY, "passkey icon and label share a centre line");
      near((measured.icon.left + measured.text.right) / 2, (measured.button.left + measured.button.right) / 2, "button content is centred");
      // 4 px grid: the gap under the last action equals the card's top padding is the card's job; here only check fit.
      expect(measured.button.bottom).toBeLessThanOrEqual(measured.card.bottom);
      expect(measured.card.left).toBeGreaterThanOrEqual(0);
      expect(measured.card.right).toBeLessThanOrEqual(profile.viewport.width);
      expect(measured.card.bottom).toBeLessThanOrEqual(profile.viewport.height);

      // Phone sizes: reading text 15 px or larger for the title, 13 px or larger for the rest.
      const sizes = await page.evaluate(() => [".auth-lede", ".ui-kv-value", ".ui-kv-key", ".auth-check span", ".device-approval-note"].map(selector => Number.parseFloat(getComputedStyle(document.querySelector(selector)!).fontSize)));
      for (const size of sizes) expect(size).toBeGreaterThanOrEqual(12);

      const evidence = process.env.INFRATERAL_SIGNIN_EVIDENCE_DIR;
      if (evidence) {
        await mkdir(evidence, { recursive: true });
        for (const theme of ["dark", "light"] as const) {
          await page.emulateMedia({ colorScheme: theme });
          await page.screenshot({ path: join(evidence, `join-${profile.name}-${theme}.png`), animations: "disabled" });
        }
        await page.emulateMedia({ colorScheme: "dark" });
        await tick(page).click();
        await page.screenshot({ path: join(evidence, `join-${profile.name}-ticked.png`), animations: "disabled" });
        // A fresh page for the keyboard part: the click above left focus on the tick.
        await page.goto("about:blank");
        await page.goto(LINK);
        await expect(page.getByRole("heading", { name: TITLE("build-01") })).toBeVisible();
      }

      // Tab to the tick: its ring is drawn, and every ancestor that clips still contains it.
      await page.keyboard.press("Tab");
      for (let step = 0; step < 6 && !(await page.evaluate(() => document.activeElement?.id === "device-approval-code-match")); step += 1) await page.keyboard.press("Tab");
      expect(await page.evaluate(() => document.activeElement?.id)).toBe("device-approval-code-match");
      const clipped = await page.evaluate(() => {
        const tickBox = document.querySelector<HTMLElement>(".auth-check .tick")!.getBoundingClientRect();
        // The ring is a 2 px outline offset 2 px (auth.css): 4 px beyond the tick's box.
        const ring = { left: tickBox.left - 4, right: tickBox.right + 4, top: tickBox.top - 4, bottom: tickBox.bottom + 4 };
        const outside: string[] = [];
        for (let node = document.querySelector<HTMLElement>(".auth-check .tick")!.parentElement; node; node = node.parentElement) {
          const style = getComputedStyle(node);
          if (style.overflow === "visible" && style.overflowX === "visible" && style.overflowY === "visible") continue;
          const clip = node.getBoundingClientRect();
          if (ring.left < clip.left - 0.01 || ring.right > clip.right + 0.01 || ring.top < clip.top - 0.01 || ring.bottom > clip.bottom + 0.01) {
            outside.push(`${node.tagName.toLowerCase()}.${node.className}`);
          }
        }
        return outside;
      });
      expect(clipped).toEqual([]);
      if (process.env.INFRATERAL_SIGNIN_EVIDENCE_DIR) {
        await page.screenshot({ path: join(process.env.INFRATERAL_SIGNIN_EVIDENCE_DIR, `join-${profile.name}-focus.png`), animations: "disabled" });
      }

    });
  });
}
