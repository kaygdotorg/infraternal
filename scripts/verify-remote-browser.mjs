/** Proves production Ghostty rendering over a real enrolled host; fixture authority arrives only on private stdin (#78). */
import { chromium, devices } from '../apps/tracer/node_modules/playwright/index.mjs';
import { mkdir } from 'node:fs/promises';

// No traces, storage-state files, or request logging: the cookie stays in memory.
let input = '';
for await (const chunk of process.stdin) {
  input += chunk;
  if (input.length > 8192) throw new Error('oversized private fixture input');
}
const fixture = JSON.parse(input);
input = '';
async function focusTerminal(page) {
  await page.locator('#terminal-host').evaluate(host => {
    (host.querySelector("textarea, input, [contenteditable='true']") ?? host).focus({ preventScroll: true });
  });
}

const launchArgs = ['--disable-renderer-backgrounding'];
if (fixture.resolver_address) launchArgs.push(`--host-resolver-rules=MAP localhost ${fixture.resolver_address}`);
const browser = await chromium.launch({ args: launchArgs });
let stage = 'launch';
try {
  for (const [name, device] of [['desktop', { viewport: { width: 1440, height: 900 } }], ['iphone', devices['iPhone 15']]]) {
    // Only the memory-only fixture CA is untrusted by Chromium's system store.
    stage = `${name}:context`;
    const context = await browser.newContext({ ...device, ignoreHTTPSErrors: true });
    try {
      stage = `${name}:cookie`;
      await context.addCookies([{ name: '__Host-infraternal', value: fixture.cookie,
        url: 'https://localhost:4701/', secure: true, httpOnly: true, sameSite: 'Strict' }]);
      const page = await context.newPage();
      // mock=1 exposes existing renderer inspection hooks. There is no HTTP or
      // WebSocket mock: the real server, host daemon, and PTY remain in the path.
      stage = `${name}:navigate`;
      await page.goto(`https://localhost:4701/?mock=1&probe=1&n=25&bg=none&theme=ink&host=${fixture.host}&session=${fixture.session}`);
      stage = `${name}:connect`;
      await page.waitForFunction(() => window.__tracerTestDouble?.isConnected(), null, { timeout: 15000 });
      stage = `${name}:prompt`;
      await page.waitForFunction(() => window.__tracerTestDouble?.screenText().includes('shim-test'), null, { timeout: 15000 });
      await focusTerminal(page);
      const marker = `BROWSER_${name.toUpperCase()}_OK`;
      await page.keyboard.type(`printf 'BROWSER_${name.toUpperCase()}_%s\\n' OK`);
      const started = performance.now();
      await page.keyboard.press('Enter');
      stage = `${name}:glyph`;
      await page.waitForFunction(value => window.__tracerTestDouble?.screenText().includes(value), marker, { timeout: 15000 });
      const roundtrip = performance.now() - started;
      await mkdir('evidence/remote-agents/screenshots', { recursive: true });
      await page.screenshot({ path: `evidence/remote-agents/screenshots/${fixture.screenshot_prefix ?? 'run7-real-remote'}-${name}.png` });
      console.log(`remote_browser viewport=${name} real_server=true real_host_daemon=true production_renderer=true enter_to_glyph_ms=${roundtrip.toFixed(3)}`);
      stage = `${name}:probe`;
      await page.locator('#probe-run').click();
      await page.waitForFunction(() => document.querySelector('#probe-results')?.textContent?.includes('Painted echoes: 25 / 25'), null, { timeout: 20000 });
      const report = await page.locator('#probe-results').textContent();
      const p50 = report.match(/p50: ([0-9.]+) ms/)[1];
      const p99 = report.match(/p99: ([0-9.]+) ms/)[1];
      console.log(`remote_browser_probe viewport=${name} n=25 keydown_to_glyph_p50_ms=${p50} p99_ms=${p99}`);
      const beforeClear = await page.evaluate(() => window.__tracerTestDouble.rendererMetrics().outputSequence);
      await focusTerminal(page);
      await page.keyboard.press('Control+u');
      await page.waitForFunction(sequence => BigInt(window.__tracerTestDouble.rendererMetrics().outputSequence) > BigInt(sequence), beforeClear);
    } finally {
      await context.close();
    }
  }
} catch (error) {
  // Playwright exceptions can include request details; retain only a safe status.
  const code = String(error?.message).match(/net::ERR_[A-Z_]+/)?.[0] ?? 'unclassified';
  console.error(`real remote browser fixture failed stage=${stage} code=${code}`);
  process.exitCode = 1;
} finally {
  await browser.close();
}
