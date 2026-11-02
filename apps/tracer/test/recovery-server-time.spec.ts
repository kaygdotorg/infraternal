/** Recovery readiness is confirmed by the server, including after its elapsed clock restarts (#309). */
import { expect, test } from "playwright/test";
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

test.skip(!["preview", "1"].includes(process.env.INFRATERNAL_RECOVERY_UI ?? "off"), "Recovery presentation requires an explicit build flag");

test("countdown zero, minute polling and visibility use server readiness, never a page-local deadline", async ({ page }, info) => {
  let calls = 0, starts = 0, ready = false, available = true;
  let delay = 60;
  await page.route("**/auth/status", route => route.fulfill({json:{setup_required:false}}));
  await page.route("**/auth/session", route => route.fulfill({status:401,json:{}}));
  await page.route("**/auth/recovery-resume", route => {
    starts++;
    return route.fulfill({json:{token:"public-wait-fixture",ready_at:1900000000,delay_seconds:60}});
  });
  await page.route("**/auth/recovery-status", async route => {
    calls++;
    expect(route.request().postDataJSON()).toEqual({token:"public-wait-fixture"});
    await route.fulfill({status:available?200:503,json:available?{ready,delay_seconds:ready?0:delay,ready_at:1900000000}:{}});
  });
  await page.clock.install();
  await page.goto("/?mock=1&proto=recovery");
  await page.locator("#use-recovery").click();
  await page.locator("#recovery-username").fill("fixture_owner");
  const phrase = entropyToMnemonic(new Uint8Array(32).fill(1),wordlist);
  await page.getByRole("textbox",{name:"Word 1",exact:true}).evaluate((input,value)=>{
    const clipboardData=new DataTransfer();clipboardData.setData("text/plain",value);
    input.dispatchEvent(new ClipboardEvent("paste",{clipboardData,bubbles:true,cancelable:true}));
  },phrase);
  await page.getByRole("button",{name:"Start recovery",exact:true}).click();
  const next=page.getByRole("button",{name:"Continue recovery",exact:true});
  await expect(next).toBeDisabled();
  await page.clock.fastForward(60_000);
  await expect(next).toBeDisabled();
  await expect.poll(()=>calls).toBe(1);
  await expect(page.locator("#recovery-ready-time")).not.toHaveText("Ready now");
  delay=300;
  await page.clock.fastForward(60_000);
  await expect.poll(()=>calls).toBe(2);
  await expect(next).toBeDisabled();
  await page.evaluate(()=>document.dispatchEvent(new Event("visibilitychange")));
  await expect.poll(()=>calls).toBe(3);
  ready=true;
  await page.clock.fastForward(60_000);
  await expect(page.locator("#recovery-ready-time")).toHaveText("Ready now");
  await expect(next).toBeEnabled();
  available=false;
  await page.evaluate(()=>document.dispatchEvent(new Event("visibilitychange")));
  await expect(next).toBeDisabled();
  await expect(page.locator("#recovery-ready-time")).not.toHaveText("Ready now");
  expect(starts).toBe(1);
  const alignment = await page.evaluate(() => {
    const status = document.querySelector("#recovery-ready-time")!.getBoundingClientRect();
    const lede = document.querySelector(".auth-pane .auth-lede")!.getBoundingClientRect();
    return Math.abs(status.left - lede.left);
  });
  expect(alignment).toBeLessThanOrEqual(0.5);
  await page.screenshot({path:info.outputPath("server-status-unavailable.png"),animations:"disabled"});
});
