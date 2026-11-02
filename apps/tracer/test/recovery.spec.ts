/** Verifies the production recovery entry point without recording account secrets. */
import { expect, test, type Page, type TestInfo } from "playwright/test";
import { entropyToMnemonic, mnemonicToEntropy } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

test.skip(!["preview", "1"].includes(process.env.INFRATERNAL_RECOVERY_UI ?? "off"), "Recovery presentation requires an explicit build flag");

// Public, deterministic fixture material only; screenshots never contain an account's real words.
const phrase = entropyToMnemonic(new Uint8Array(32).fill(1), wordlist);
const rotated = entropyToMnemonic(new Uint8Array(32).fill(2), wordlist);
const userId = "11111111-1111-4111-8111-111111111111";
const dek = new Uint8Array(32).fill(7);
const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");

async function fixtureWrap(): Promise<{ salt: string; nonce: string; ciphertext: string }> {
  const salt = new Uint8Array(32).fill(3), nonce = new Uint8Array(12).fill(4);
  const aad = new TextEncoder().encode(`infraternal/keywrap/v1|${userId}|recovery`);
  const key = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: aad },
    await crypto.subtle.importKey("raw", mnemonicToEntropy(phrase, wordlist), "HKDF", false, ["deriveKey"]),
    { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  return { salt: b64(salt), nonce: b64(nonce), ciphertext: b64(new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, dek))) };
}

async function capture(page: Page, info: TestInfo, name: string): Promise<void> {
  for (const [width, height] of [[393, 852], [1440, 900]] as const) {
    await page.setViewportSize({ width, height });
    // The inactive sign-in card stays mounted; only the active card owns this recovery step's animation.
    const activeCard = page.locator(".auth-card:not([inert])");
    if (await activeCard.count()) await activeCard.evaluate(async card => {
      // Measure steady-state targets after the approved 240 ms entrance scale.
      await Promise.all(card.getAnimations().map(animation => animation.finished));
    });
    await expect.poll(() => page.locator("#recovery-card button, #recovery-card .auth-word-inputs input, #recovery-card .auth-check").evaluateAll(elements =>
      elements.map(element => element.getBoundingClientRect()).filter(rect => rect.width && rect.height).every(rect => rect.width >= 44 && rect.height >= 44))).toBe(true);
    const path = info.outputPath(`${name}-${width}x${height}.png`);
    await page.screenshot({ path, animations: "disabled" });
    await info.attach(`${name}-${width}`, { path, contentType: "image/png" });
  }
}

async function paste(page: Page, text: string): Promise<void> {
  await page.getByRole("textbox", { name: "Word 1", exact: true }).evaluate((input, value) => {
    const clipboardData = new DataTransfer(); clipboardData.setData("text/plain", value);
    input.dispatchEvent(new ClipboardEvent("paste", { clipboardData, bubbles: true, cancelable: true }));
  }, text);
}

test("sign-in exposes recovery key entry with per-word errors", async ({ page }) => {
  await page.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: false } }));
  await page.route("**/auth/session", (route) => route.fulfill({ status: 401, json: {} }));
  await page.goto("/?mock=1&proto=recovery");
  await expect.poll(async () => (await page.locator("#use-recovery").boundingBox())?.height ?? 0).toBeGreaterThanOrEqual(44);
  await page.getByRole("button", { name: "use recovery key", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Use your recovery key" })).toBeVisible();
  await page.getByRole("textbox", { name: "Word 1", exact: true }).fill("notaword");
  await expect(page.locator("#recovery-word-error")).toHaveText("Word 1 is not in the recovery word list.");
  await expect(page.getByRole("button", { name: "Start recovery" })).toBeDisabled();
  await page.route("**/auth/recovery-resume", route => route.fulfill({ status: 401, json: {} }));
  await page.locator("#recovery-username").fill("fixture_owner");
  await paste(page, phrase);
  await page.getByRole("button", { name: "Start recovery" }).click();
  await expect(page.locator("#auth-error")).toContainText("username and recovery key");
});

for (const delay of [0, 86400]) {
  test(`recovery ${delay === 0 ? "immediate" : "delayed"} steps and original DEK`, async ({ page }, info) => {
    test.setTimeout(60_000);
    await page.context().request.post("/__mock/reset");
    let finished = false, ready = delay === 0, starts = 0, finishes = 0;
    let releaseStart: (() => void) | undefined;
    const readyAt = Math.floor(Date.now() / 1000) + delay;
    const oldWrap = await fixtureWrap();
    // Every explicit word screenshot uses public deterministic client entropy.
    await page.addInitScript(() => {
      const random = crypto.getRandomValues.bind(crypto);
      crypto.getRandomValues = <T extends ArrayBufferView | null>(value: T): T => {
        if (value instanceof Uint8Array && value.length === 32) { value.fill(2); return value; }
        return random(value);
      };
    });
    await page.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: false } }));
    await page.route("**/auth/session", (route) => finished
      ? route.fulfill({ json: { user_id: userId, username: "fixture_owner", display_name: "Fixture owner", hostname: "fixture-host" } })
      : route.fulfill({ status: 401, json: {} }));
    await page.route("**/auth/recovery-resume", async route => {
      starts++;
      const body = route.request().postDataJSON() as { username: string; verifier: string; words?: unknown };
      // Keep failures boolean so no phrase can appear in assertion output.
      expect(body.username === "fixture_owner" && typeof body.verifier === "string" && body.words === undefined).toBe(true);
      await new Promise<void>((resolve) => { releaseStart = resolve; });
      await route.fulfill({ json: { token: "public-recovery-fixture", delay_seconds: delay, ready_at: readyAt } });
    });
    await page.route("**/auth/recovery-status", route => route.fulfill({ json: {
      ready: true, delay_seconds: 0, ready_at: readyAt,
    } }));
    await page.route("**/auth/recovery-ready", route => ready ? route.fulfill({ json: {
      ceremony: "public-recovery-ceremony", user_id: userId, recovery_words: rotated, old_recovery_wrap: oldWrap,
      options: { publicKey: { challenge: b64(new Uint8Array(32).fill(5)), rp: { id: "localhost", name: "Fixture" },
        user: { id: b64(new Uint8Array(16).fill(1)), name: "fixture_owner", displayName: "Fixture owner" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }], timeout: 300000,
        authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
        extensions: { credProps: true, prf: { eval: { first: b64(new Uint8Array(32).fill(6)) } } },
      } },
    } }) : route.fulfill({ status: 401, json: {} }));
    await page.route("**/auth/registration-finish", async route => {
      finishes++;
      const body = route.request().postDataJSON() as { proof: { extensions?: { prf?: unknown } }; recovery_wrap: { salt: string; nonce: string; ciphertext: string } };
      expect(body.proof.extensions?.prf === undefined).toBe(true);
      const wrap = body.recovery_wrap;
      const aad = new TextEncoder().encode(`infraternal/keywrap/v1|${userId}|recovery`);
      const key = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: Buffer.from(wrap.salt, "base64url"), info: aad },
        await crypto.subtle.importKey("raw", await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new ArrayBuffer(0), info: new TextEncoder().encode("infraternal/recovery/wrap/v2") }, await crypto.subtle.importKey("raw", mnemonicToEntropy(rotated, wordlist), "HKDF", false, ["deriveBits"]), 256), "HKDF", false, ["deriveKey"]),
        { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
      const clear = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(wrap.nonce, "base64url"), additionalData: aad }, key, Buffer.from(wrap.ciphertext, "base64url")));
      expect(clear.every((value, i) => value === dek[i])).toBe(true);
      if (delay === 0 && finishes === 1) {
        await route.fulfill({ status: 401, json: {} });
        return;
      }
      finished = true;
      await page.context().request.post("/__mock/open-terminal");
      await route.fulfill({ json: {} });
    });
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
      protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
    } });
    if (delay !== 0) await page.clock.install();
    await page.goto("/?mock=1&proto=recovery");
    await page.getByRole("button", { name: "use recovery key", exact: true }).click();
    await capture(page, info, "enter-words-empty");
    await page.locator("#recovery-username").fill("fixture_owner");
    await paste(page, phrase.split(" ").map((word, i) => `${i + 1}. ${word}`).join("\n"));
    await expect(page.getByRole("button", { name: "Start recovery" })).toBeEnabled();
    await capture(page, info, "enter-words-public-fixture");
    await page.getByRole("button", { name: "Start recovery" }).click();
    await expect(page.locator(".busy-count")).toBeVisible();
    releaseStart!();
    await expect(page.getByRole("heading", { name: "Recovery started" })).toBeVisible();
    await expect(page.locator("#recovery-ready-time")).toContainText(delay === 0 ? "Ready now" : "Available");
    await capture(page, info, delay === 0 ? "ready-now" : "wait-24h");
    if (delay !== 0) {
      await expect(page.getByRole("button", { name: "Continue recovery" })).toBeDisabled();
      await page.clock.fastForward(86400_000);
    }
    await page.getByRole("button", { name: "Continue recovery" }).click();
    await capture(page, info, "create-passkey");
    if (delay !== 0) {
      await page.getByRole("button", { name: "Create passkey" }).click();
      await expect(page.locator("#auth-error")).toContainText("Recovery is not ready");
      expect(finishes).toBe(0);
      ready = true; // UI double only; native verification advances the real SQLite fixture.
    } else {
      await page.evaluate(() => {
        const create = navigator.credentials.create.bind(navigator.credentials);
        let first = true;
        navigator.credentials.create = async options => {
          if (first) { first = false; throw new DOMException("Fixture already has an excluded credential", "InvalidStateError"); }
          return create(options);
        };
      });
      await page.getByRole("button", { name: "Create passkey" }).click();
      await expect(page.locator("#auth-error")).toContainText("another passkey provider");
    }
    await page.getByRole("button", { name: "Create passkey" }).click();
    await expect(page.getByRole("heading", { name: "Save your new recovery key" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Open infraternal" })).toBeDisabled();
    await capture(page, info, "save-rotated-public-fixture");
    await page.locator(".auth-check").click();
    await page.getByRole("button", { name: "Open infraternal" }).click();
    if (delay === 0) {
      await expect(page.getByRole("heading", { name: "Create a new passkey" })).toBeVisible();
      await expect(page.locator("#welcome-title")).toHaveCount(0);
      await page.getByRole("button", { name: "Create passkey" }).click();
      await expect(page.getByRole("heading", { name: "Save your new recovery key" })).toBeVisible();
      await expect(page.getByRole("button", { name: "Open infraternal" })).toBeDisabled();
      await page.locator(".auth-check").click();
      await page.getByRole("button", { name: "Open infraternal" }).click();
    }
    await expect(page.getByRole("heading", { name: "Welcome to infraternal" })).toBeVisible();
    await capture(page, info, "welcome");
    expect(starts).toBe(1); expect(finishes).toBe(delay === 0 ? 2 : 1);
    expect(await page.evaluate(() => document.scrollingElement?.scrollTop)).toBe(0);
    await expect(page.locator("#terminal-screen")).toBeVisible();
  });
}

test("a signed-in device can open recovery without revoking its session", async ({ page }) => {
  await page.context().request.post("/__mock/reset");
  await page.context().request.post("/__mock/open-terminal");
  await page.goto("/?mock=1&proto=recovery");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected())).toBe(true);
  await page.locator("#capsule").click();
  await page.locator("#palette-input").fill("recovery");
  await page.getByRole("option", { name: /Use recovery key/ }).click();
  await expect(page.getByRole("heading", { name: "Use your recovery key" })).toBeVisible();
  const status = await page.evaluate(async () => (await fetch("/auth/session", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
  })).status);
  expect(status).toBe(200);
});

test("pointer recovery step changes glide the fitted pane", async ({ page }) => {
  await page.route("**/auth/status", route => route.fulfill({ json: { setup_required: false } }));
  await page.route("**/auth/session", route => route.fulfill({ status: 401, json: {} }));
  await page.route("**/auth/recovery-resume", route => route.fulfill({ json: {
    token: "public-motion-fixture", delay_seconds: 0, ready_at: Math.floor(Date.now() / 1000),
  } }));
  await page.goto("/?mock=1&proto=recovery");
  await page.getByRole("button", { name: "use recovery key", exact: true }).click();
  await page.locator("#recovery-username").fill("fixture_owner");
  await paste(page, phrase);
  await page.getByRole("button", { name: "Start recovery" }).click();
  await expect(page.getByRole("heading", { name: "Recovery started" })).toBeVisible();
  await page.waitForTimeout(300);
  await page.locator("#recovery-next").evaluate(button => {
    button.addEventListener("click", () => {
      const samples: number[] = [];
      Object.assign(window, { __recoveryHeights: samples });
      const begin = performance.now();
      const sample = (): void => {
        samples.push(document.querySelector("#recovery-card .auth-viewport")!.getBoundingClientRect().height);
        if (performance.now() - begin < 300) requestAnimationFrame(sample);
      };
      requestAnimationFrame(sample);
    }, { once: true, capture: true });
  });
  await page.getByRole("button", { name: "Continue recovery" }).click();
  await page.waitForTimeout(350);
  const heights = await page.evaluate(() => (window as Window & { __recoveryHeights?: number[] }).__recoveryHeights ?? []);
  expect(Math.max(...heights) - Math.min(...heights)).toBeGreaterThan(8);
});

test("discarded waiting page resumes the original deadline", async ({ page }) => {
  const readyAt = Math.floor(Date.now() / 1000) + 3600;
  let attempts = 0;
  await page.route("**/auth/status", route => route.fulfill({ json: { setup_required: false } }));
  await page.route("**/auth/session", route => route.fulfill({ status: 401, json: {} }));
  await page.route("**/auth/recovery-resume", route => {
    attempts++;
    return route.fulfill({ json: { token: "public-resume-fixture", ready_at: readyAt, delay_seconds: 3600 } });
  });
  for (let attempt = 0; attempt < 2; attempt++) {
    await page.goto("/?mock=1&proto=recovery");
    await page.getByRole("button", { name: "use recovery key", exact: true }).click();
    await page.locator("#recovery-username").fill("fixture_owner");
    await paste(page, phrase);
    await page.getByRole("button", { name: "Start recovery" }).click();
    await expect(page.locator("#recovery-ready-time")).toContainText("60 minutes remaining");
    await expect(page.getByRole("button", { name: "Continue recovery" })).toBeDisabled();
    await expect(page.locator(".auth-lede")).toContainText("original deadline stays the same");
    // Reload drops every in-memory capability and word reference.
    await page.reload();
  }
  expect(attempts).toBe(2);
});

test("signed-in device shows a persistent notice and can cancel recovery", async ({ page }, info) => {
  await page.context().request.post("/__mock/reset");
  await page.context().request.post("/__mock/open-terminal");
  let pending = true, cancels = 0;
  const readyAt = Math.floor(Date.now() / 1000) + 3600;
  await page.route("**/auth/session", route => route.fulfill({ json: {
    user_id: userId, username: "fixture_owner", display_name: "Fixture owner", hostname: "fixture-host",
    recovery_pending: pending ? { ready_at: readyAt } : null,
  } }));
  await page.route("**/auth/recovery-cancel", route => {
    cancels++; pending = false;
    return route.fulfill({ json: { ok: true } });
  });
  await page.goto("/?mock=1&proto=recovery");
  await expect(page.locator("#recovery-notice")).toBeVisible();
  await expect(page.locator(".ui-toast")).toContainText("Recovery requested");
  await capture(page, info, "pending-recovery-notice");
  await page.getByRole("button", { name: "Cancel recovery", exact: true }).click();
  await expect(page.locator("#recovery-notice")).toBeHidden();
  expect(cancels).toBe(1);
});

test("remaining recovery wait uses server duration with a skewed browser clock", async ({ page }) => {
  const serverNow = Date.now();
  await page.clock.install({ time: new Date(serverNow + 7 * 86400_000) });
  await page.route("**/auth/status", route => route.fulfill({ json: { setup_required: false } }));
  await page.route("**/auth/session", route => route.fulfill({ status: 401, json: {} }));
  await page.route("**/auth/recovery-resume", route => route.fulfill({ json: {
    token: "public-clock-fixture", ready_at: Math.floor(serverNow / 1000) + 3600, delay_seconds: 3600,
  } }));
  await page.goto("/?mock=1&proto=recovery");
  await page.getByRole("button", { name: "use recovery key", exact: true }).click();
  await page.locator("#recovery-username").fill("fixture_owner");
  await paste(page, phrase);
  await page.getByRole("button", { name: "Start recovery" }).click();
  await expect(page.getByRole("button", { name: "Continue recovery" })).toBeDisabled();
  await expect(page.locator("#recovery-ready-time")).toContainText("60 minutes remaining");
});

test("terminal startup reuses its authenticated recovery snapshot", async ({ page }) => {
  await page.context().request.post("/__mock/reset");
  await page.context().request.post("/__mock/open-terminal");
  let sessionReads = 0;
  await page.route("**/auth/session", route => {
    sessionReads++;
    return route.fulfill(sessionReads === 1 ? { json: {
      user_id: userId, username: "fixture_owner", display_name: "Fixture owner", hostname: "fixture-host",
      recovery_pending: { ready_at: Math.floor(Date.now() / 1000) + 3600 },
    } } : { status: 503, json: { error: "unavailable" } });
  });
  await page.goto("/?mock=1&proto=recovery");
  await expect(page.locator("#recovery-notice")).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected())).toBe(true);
  expect(sessionReads).toBe(1);
});
