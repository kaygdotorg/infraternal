/** Checks that a device approval URL opens its passkey-scoped review screen. */
import { expect, test } from "playwright/test";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";

test("device approval link reviews the exact laptop and scopes before approval", async ({ page }) => {
  let codeInAddressAtStatus: string | null = null;
  let loginStarts = 0;
  let approvals = 0;
  await page.addInitScript(() => {
    Object.defineProperty(navigator.credentials, "get", {
      configurable: true,
      value: () => {
        Object.defineProperty(window, "__deviceApprovalPasskeyPrompted", { configurable: true, value: true });
        return Promise.reject(new DOMException("cancelled", "NotAllowedError"));
      },
    });
  });
  await page.route("**/auth/status", async route => {
    codeInAddressAtStatus = new URL(page.url()).searchParams.get("device_code");
    await route.fulfill({ json: { setup_required: false } });
  });
  await page.route("**/auth/session", route => route.fulfill({ json: {
    user_id: "11111111-1111-4111-8111-111111111111",
    username: "fixture_owner",
    display_name: "Fixture owner",
    device: "Browser",
    fresh: Math.floor(Date.now() / 1000),
  } }));
  await page.route("**/auth/device-inspect", route => route.fulfill({ json: {
    device: "kayg-laptop",
    scopes: ["hosts:read", "terminal:connect", "actions:dry-run"],
  } }));
  await page.route("**/auth/login-start", async route => {
    loginStarts += 1;
    await route.fulfill({ json: { ceremony: "fixture", options: { publicKey: {
      challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      rpId: "localhost",
      allowCredentials: [],
      timeout: 30_000,
      userVerification: "required",
      extensions: { prf: { eval: { first: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" } } },
    } } } });
  });
  await page.route("**/auth/device-approve", async route => {
    approvals += 1;
    await route.fulfill({ json: { ok: true } });
  });
  await page.goto("/?device_code=AbCdEfGhIjKlMnOp");

  await expect.poll(() => page.evaluate(() => location.search)).toBe("");
  expect(codeInAddressAtStatus).toBeNull();
  await expect(page.getByRole("heading", { name: "Approve device sign-in" })).toBeVisible();
  await expect(page.getByText("kayg-laptop", { exact: true })).toBeVisible();
  await expect(page.getByText("hosts:read", { exact: true })).toBeVisible();
  await expect(page.getByText("terminal:connect", { exact: true })).toBeVisible();
  await expect(page.getByText("actions:dry-run", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve with passkey" })).toBeVisible();

  const expectApprovalAlignment = async (): Promise<void> => {
    const alignment = await page.evaluate(() => {
      const rect = (selector: string) => {
        const element = document.querySelector<HTMLElement>(selector);
        if (!element) throw new Error(`Missing approval alignment element: ${selector}`);
        const bounds = element.getBoundingClientRect();
        return { left: bounds.left, centerY: bounds.top + bounds.height / 2 };
      };
      return {
        label: rect(".auth-label"),
        code: rect("#device-approval-code"),
        hint: rect(".auth-hint"),
        confirmation: rect(".auth-check"),
        checkbox: rect("#device-approval-code-match"),
        confirmationText: rect(".auth-check span"),
        approveIcon: rect("#device-approval-approve svg"),
        approveText: rect("#device-approval-approve > span:not(.busy-count)"),
      };
    });
    const withinHalfPixel = (actual: number, expected: number): void => {
      expect(Math.abs(actual - expected)).toBeLessThanOrEqual(0.5);
    };
    withinHalfPixel(alignment.code.left, alignment.label.left);
    withinHalfPixel(alignment.hint.left, alignment.label.left);
    withinHalfPixel(alignment.confirmation.left, alignment.label.left);
    withinHalfPixel(alignment.checkbox.centerY, alignment.confirmationText.centerY);
    withinHalfPixel(alignment.approveIcon.centerY, alignment.approveText.centerY);
  };

  const evidenceDirectory = process.env.INFRATERAL_SIGNIN_EVIDENCE_DIR;
  if (evidenceDirectory) {
    await mkdir(evidenceDirectory, { recursive: true });
    for (const theme of ["dark", "light"] as const) {
      await page.emulateMedia({ colorScheme: theme });
      for (const viewport of [
        { name: "desktop", width: 1440, height: 900 },
        { name: "phone", width: 393, height: 852 },
        { name: "phone-small", width: 375, height: 667 },
      ]) {
        await page.setViewportSize({ width: viewport.width, height: viewport.height });
        if (theme !== "dark" || viewport.name !== "desktop") {
          await page.goto("/?device_code=AbCdEfGhIjKlMnOp");
          await expect(page.getByRole("heading", { name: "Approve device sign-in" })).toBeVisible();
        }
        await expectApprovalAlignment();
        await page.screenshot({
          path: join(evidenceDirectory, `${theme}-${viewport.name}.png`),
          animations: "disabled",
        });
      }
    }
  }

  await page.getByText("I checked that this code matches the code in my terminal").click();
  await page.getByRole("button", { name: "Approve with passkey" }).click();
  await expect(page.getByRole("alert")).toContainText("passkey prompt was cancelled");
  expect(loginStarts).toBe(1);
  expect(approvals).toBe(0);
  expect(await page.evaluate(() => Reflect.get(window, "__deviceApprovalPasskeyPrompted"))).toBe(true);
});

test("approval page shows the code so a person can match it with the CLI", async ({ page }) => {
  const code = "AbCdEfGhIjKlMnOp";
  await page.route("**/auth/status", route => route.fulfill({ json: { setup_required: false } }));
  await page.route("**/auth/session", route => route.fulfill({ json: {
    user_id: "11111111-1111-4111-8111-111111111111",
    username: "fixture_owner",
    display_name: "Fixture owner",
    device: "Browser",
    fresh: Math.floor(Date.now() / 1000),
  } }));
  await page.route("**/auth/device-inspect", route => route.fulfill({ json: {
    device: "kayg-laptop",
    scopes: ["hosts:read", "terminal:connect", "actions:dry-run"],
  } }));

  await page.goto(`/?device_code=${code}`);
  await expect(page.getByRole("heading", { name: "Approve device sign-in" })).toBeVisible();
  // The terminal prints the same one-time code; comparing it prevents approving a different request's link.
  await expect(page.getByText(code, { exact: true })).toBeVisible();
  const codeMatch = page.getByRole("checkbox", { name: "I checked that this code matches the code in my terminal" });
  await expect(codeMatch).toBeVisible();
  const approve = page.getByRole("button", { name: "Approve with passkey" });
  await expect(approve).toBeDisabled();
  await page.getByText("I checked that this code matches the code in my terminal").click();
  await expect(approve).toBeEnabled();
});

test("a fresh virtual passkey tap approves the reviewed device request", async ({ page }) => {
  test.setTimeout(90_000);
  const context = page.context();
  await context.request.post("/__mock/reset");
  const setup = await (await context.request.get("/__mock/setup-token")).json() as { setup_token: string };
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      hasPrf: true,
    },
  });
  await page.addInitScript(() => {
    const get = navigator.credentials.get.bind(navigator.credentials);
    Object.defineProperty(navigator.credentials, "get", {
      configurable: true,
      value: (options: CredentialRequestOptions) => {
        document.documentElement.dataset.deviceApprovalPasskeyGets = String(
          Number(document.documentElement.dataset.deviceApprovalPasskeyGets ?? "0") + 1,
        );
        return get(options);
      },
    });
  });

  await page.goto("/?mock=1");
  await expect(page.locator("#setup-card")).toBeVisible();
  await page.locator("#setup-token").fill(setup.setup_token);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.locator("#setup-username").fill("device_approval_test");
  await page.locator("#setup-display-name").fill("Device approval test");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await expect(page.getByRole("heading", { name: "Save your recovery key" })).toBeVisible();
  expect(await page.locator("#recovery-words li").count()).toBe(24);
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await expect(page.getByText("TEST DOUBLE")).toBeVisible();

  const requests: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith("/auth/")) requests.push(path);
  });
  await page.route("**/auth/device-inspect", (route) => route.fulfill({ json: {
    device: "new-developer-workstation",
    scopes: ["hosts:read", "terminal:connect", "actions:dry-run"],
  } }));
  let approvals = 0;
  await page.route("**/auth/device-approve", async (route) => {
    approvals += 1;
    await route.fulfill({ json: { ok: true } });
  });

  await page.goto("/?device_code=AbCdEfGhIjKlMnOp");
  await expect(page.getByRole("heading", { name: "Approve device sign-in" })).toBeVisible();
  await page.getByText("I checked that this code matches the code in my terminal").click();
  await page.getByRole("button", { name: "Approve with passkey" }).click();
  await expect(page.getByRole("heading", { name: "Device approved" })).toBeVisible();
  expect(approvals).toBe(1);
  expect(await page.evaluate(() => document.documentElement.dataset.deviceApprovalPasskeyGets)).toBe("1");
  expect(requests.indexOf("/auth/login-finish")).toBeGreaterThanOrEqual(0);
  expect(requests.indexOf("/auth/login-finish")).toBeLessThan(requests.indexOf("/auth/device-approve"));
});

test("a signed-out browser must sign in before it can inspect a device request", async ({ page }) => {
  let inspections = 0;
  let approvals = 0;
  let loginStarts = 0;
  await page.addInitScript(() => {
    Object.defineProperty(navigator.credentials, "get", {
      configurable: true,
      value: () => Promise.reject(new DOMException("cancelled", "NotAllowedError")),
    });
  });
  await page.route("**/auth/status", route => route.fulfill({ json: { setup_required: false } }));
  await page.route("**/auth/session", route => route.fulfill({ status: 401, json: { error: "signed out" } }));
  await page.route("**/auth/device-inspect", async route => {
    inspections += 1;
    await route.fulfill({ json: { device: "kayg-laptop", scopes: ["hosts:read", "terminal:connect", "actions:dry-run"] } });
  });
  await page.route("**/auth/login-start", async route => {
    loginStarts += 1;
    await route.fulfill({ json: { ceremony: "fixture", options: { publicKey: {
      challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      rpId: "localhost",
      allowCredentials: [],
      timeout: 30_000,
      userVerification: "required",
      extensions: { prf: { eval: { first: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" } } },
    } } } });
  });
  await page.route("**/auth/device-approve", async route => {
    approvals += 1;
    await route.fulfill({ json: { ok: true } });
  });

  await page.goto("/?device_code=AbCdEfGhIjKlMnOp");
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  expect(inspections).toBe(0);
  await page.getByRole("button", { name: "Continue with passkey" }).click();
  await expect(page.getByRole("alert")).toContainText("passkey prompt was cancelled");
  expect(loginStarts).toBe(1);
  expect(inspections).toBe(0);
  expect(approvals).toBe(0);
});

test("an expired device request gives a next step without offering approval", async ({ page }) => {
  await page.route("**/auth/status", route => route.fulfill({ json: { setup_required: false } }));
  await page.route("**/auth/session", route => route.fulfill({ json: {
    user_id: "11111111-1111-4111-8111-111111111111",
    username: "fixture_owner",
    display_name: "Fixture owner",
    device: "Browser",
    fresh: Math.floor(Date.now() / 1000),
  } }));
  await page.route("**/auth/device-inspect", route => route.fulfill({ status: 401, json: { error: "authorization failed" } }));

  await page.goto("/?device_code=AbCdEfGhIjKlMnOp");
  await expect(page.getByRole("heading", { name: "Device sign-in unavailable" })).toBeVisible();
  await expect(page.getByRole("alert")).toContainText("expired or was already used");
  await expect(page.getByRole("alert")).toContainText("run infraternal sign-in again");
  await expect(page.getByRole("button", { name: "Approve with passkey" })).toHaveCount(0);
});

test("every duplicate device code is removed before showing the link error", async ({ page }) => {
  let authRequests = 0;
  await page.route("**/auth/**", async route => {
    authRequests += 1;
    await route.fulfill({ json: {} });
  });
  await page.goto("/?device_code=AbCdEfGhIjKlMnOp&device_code=QwErTyUiOpAsDfGh");
  await expect(page.getByRole("heading", { name: "Device sign-in unavailable" })).toBeVisible();
  await expect(page.getByRole("alert")).toContainText("more than one code");
  expect(await page.evaluate(() => location.search)).toBe("");
  expect(authRequests).toBe(0);
});

test("device names are rendered as text, never as server-provided markup", async ({ page }) => {
  const device = "<img src=x onerror=alert(1)>";
  await page.route("**/auth/status", route => route.fulfill({ json: { setup_required: false } }));
  await page.route("**/auth/session", route => route.fulfill({ json: {
    user_id: "11111111-1111-4111-8111-111111111111",
    username: "fixture_owner",
    display_name: "Fixture owner",
    device: "Browser",
    fresh: Math.floor(Date.now() / 1000),
  } }));
  await page.route("**/auth/device-inspect", route => route.fulfill({ json: {
    device,
    scopes: ["hosts:read", "terminal:connect", "actions:dry-run"],
  } }));

  await page.goto("/?device_code=AbCdEfGhIjKlMnOp");
  await expect(page.getByRole("heading", { name: "Approve device sign-in" })).toBeVisible();
  await expect(page.getByText(device, { exact: true })).toBeVisible();
  await expect(page.locator("img")).toHaveCount(0);
});
