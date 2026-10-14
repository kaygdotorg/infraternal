/** Runs an instrumented production renderer against the live ignored fixture; stdin authority and protocol bodies are never logged (#189). */
import { chromium } from "playwright";

const input = await Bun.stdin.text();
const { cookie, target } = JSON.parse(input);
const browser = await chromium.launch({ headless: true, args: ["--host-resolver-rules=MAP addhost-breakit2.test 172.17.0.1", "--no-proxy-server"] });
let timelinePage;
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const origin = "https://addhost-breakit2.test:4929";
  await context.addCookies([{ name: "__Host-infraternal", value: cookie, url: origin, secure: true, httpOnly: true, sameSite: "Strict" }]);
  const page = await context.newPage();
  timelinePage = page;
  const cdp = await context.newCDPSession(page);
  await cdp.send("Network.enable");
  // Record only URL paths, clock values and resource timing; never headers,
  // WebSocket frame contents or request/response bodies.
  const requests = new Map();
  const publicPath = (url) => { const parsed = new URL(url); return parsed.protocol === "http:" || parsed.protocol === "https:" || parsed.protocol === "wss:" ? parsed.pathname : "<embedded>"; };
  let clockOffset = 0;
  cdp.on("Network.requestWillBeSent", (event) => {
    const path = publicPath(event.request.url);
    clockOffset = (event.wallTime - event.timestamp) * 1000;
    requests.set(event.requestId, path);
    console.log(JSON.stringify({ source: "browser", step: "request", path, epoch_ms: event.wallTime * 1000 }));
  });
  cdp.on("Network.webSocketCreated", (event) => requests.set(event.requestId, publicPath(event.url)));
  cdp.on("Network.webSocketWillSendHandshakeRequest", (event) => {
    clockOffset = (event.wallTime - event.timestamp) * 1000;
    console.log(JSON.stringify({ source: "browser", step: "ws_upgrade_sent", path: requests.get(event.requestId), epoch_ms: event.wallTime * 1000 }));
  });
  cdp.on("Network.webSocketHandshakeResponseReceived", (event) => console.log(JSON.stringify({ source: "browser", step: "ws_upgrade_received", path: requests.get(event.requestId), epoch_ms: event.timestamp * 1000 + clockOffset })));
  cdp.on("Network.responseReceived", (event) => {
    const timing = event.response.timing;
    if (timing) console.log(JSON.stringify({ source: "browser", step: "response_timing", path: requests.get(event.requestId), timing }));
  });
  await page.goto(`${origin}/timeline.html${process.env.ADDHOST_BROWSER_PREPARE === "1" ? "?prepare=1" : ""}`);
  const records = await page.evaluate((address) => window.addhostTimeline(address), target);
  for (const record of records) console.log(JSON.stringify({ source: "browser", ...record }));
  const click = records.find((record) => record.step === "sign_in_click");
  const prompt = records.find((record) => record.step === "first_prompt_painted");
  const proof = records.find((record) => record.step === "integrity_confirmed");
  if (!click || !prompt || proof?.bytes !== 59) throw new Error("timeline integrity assertion");
  console.log(`METRIC addhost_browser click_to_prompt_ms=${(prompt.epoch_ms - click.epoch_ms).toFixed(3)} input_acked_bytes=${proof.bytes}`);
} catch {
  const retained = await timelinePage?.evaluate(() => window.addhostTimelineRecords?.()).catch(() => undefined);
  for (const record of retained ?? []) console.log(JSON.stringify({ source: "browser", ...record }));
  // An exception may include a request or cookie: emit only a fixed refusal.
  console.error("Production-browser timeline failed; no private diagnostics emitted.");
  process.exitCode = 1;
} finally { await browser.close(); }
