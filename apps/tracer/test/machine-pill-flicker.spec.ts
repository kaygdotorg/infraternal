/** Records the machine pill state while a redraw workload crosses the mock terminal stream. */
import { expect, test } from "playwright/test";

const testDoubleOrigin = `http://localhost:${Number(process.env.TRACER_TEST_PORT ?? "4621") + 1}`;

test("machine pill state stays tied to the session connection during terminal redraws", async ({ page }) => {
  await page.context().request.post("/__mock/reset");
  await page.context().request.post("/__mock/open-terminal");
  await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
  const windowCard = page.locator(".ui-window").first();
  await expect(windowCard).toBeVisible({ timeout: 20_000 });
  await expect.poll(() => page.evaluate(() => window.__tracerProductTestDouble?.isConnected() ?? false), { timeout: 30_000 }).toBe(true);
  await expect(windowCard).toHaveAttribute("data-status", "live");

  await page.evaluate(() => {
    const root = document.querySelector<HTMLElement>(".ui-window");
    const dot = root?.querySelector<HTMLElement>(".ui-window-conn");
    if (!root || !dot) throw new Error("machine pill is missing");
    const trace = {
      mutations: [] as Array<{ at: number; attribute: string; old: string | null; next: string | null }>,
      frames: [] as Array<{ at: number; state: string | undefined; color: string; classes: string }>,
    };
    const observer = new MutationObserver((records) => {
      const relevant = records.filter((record) =>
        (record.target === root && record.attributeName === "data-status")
        || (record.target === dot && record.attributeName === "class"));
      for (let index = 0; index < relevant.length; index += 1) {
        const record = relevant[index];
        if (!record) continue;
        const nextRecord = relevant.slice(index + 1).find((next) => next.target === record.target && next.attributeName === record.attributeName);
        const next = nextRecord?.oldValue ?? (record.target as Element).getAttribute(record.attributeName ?? "");
        if (record.oldValue !== next) trace.mutations.push({ at: performance.now(), attribute: record.attributeName ?? "", old: record.oldValue, next });
      }
    });
    observer.observe(root, { attributes: true, attributeOldValue: true, subtree: true });
    const startedAt = performance.now();
    const sample = (): void => {
      trace.frames.push({ at: performance.now() - startedAt, state: root.dataset.status, color: getComputedStyle(dot).backgroundColor, classes: dot.className });
      if (performance.now() - startedAt < 2_500) requestAnimationFrame(sample);
      else observer.disconnect();
    };
    requestAnimationFrame(sample);
    (window as unknown as { __machinePillTrace: typeof trace }).__machinePillTrace = trace;
  });

  const response: number[] = [];
  const esc = "\u001b";
  await page.request.post(`${testDoubleOrigin}/__mock/live-query-output`, { data: { text: `${esc}[?1049h${esc}[?25l${esc}[?2004h${esc}[?1004h` } });
  for (let frame = 0; frame < 19; frame += 1) {
    const rows = Array.from({ length: 24 }, (_, row) => `${esc}[${row + 1};1H${`terminal sign-in frame ${frame} row ${row + 1}`.padEnd(80)}`).join("");
    const text = `${esc}[?2026h${esc}[H${esc}[2J${rows}${esc}]0;sign-in-${frame}\u0007${esc}[?2026l`;
    const result = await page.request.post(`${testDoubleOrigin}/__mock/live-query-output`, { data: { text } });
    response.push(result.status());
    await page.waitForTimeout(111);
  }
  await page.request.post(`${testDoubleOrigin}/__mock/live-query-output`, { data: { text: "\u001b[?2026l\u001b[?25h\u001b[?1049l\u001b[?2004l\u001b[?1004l" } });
  await page.waitForTimeout(350);
  expect(response).toHaveLength(19);
  expect(response.every((status) => status === 200)).toBe(true);

  const trace = await page.evaluate(() => (window as unknown as { __machinePillTrace: { mutations: Array<{ at: number; attribute: string; old: string | null; next: string | null }>; frames: Array<{ at: number; state: string | undefined; color: string; classes: string }> } }).__machinePillTrace);
  console.log(`PILL_TRACE mock mutations=${JSON.stringify(trace.mutations)} frames=${JSON.stringify(trace.frames)}`);
  expect(trace.mutations.filter((mutation) => mutation.attribute === "data-status")).toHaveLength(0);
  expect(await page.evaluate(() => window.__tracerProductTestDouble?.isConnected() ?? false)).toBe(true);
  expect(await windowCard.getAttribute("data-status")).toBe("live");
});

test("machine pill stays steady through repeated immediate server closes", async ({ page }) => {
  await page.context().request.post("/__mock/reset");
  await page.context().request.post("/__mock/open-terminal");
  await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
  const windowCard = page.locator(".ui-window").first();
  await expect(windowCard).toBeVisible({ timeout: 20_000 });
  await expect.poll(() => page.evaluate(() => window.__tracerProductTestDouble?.isConnected() ?? false), { timeout: 30_000 }).toBe(true);
  await expect(windowCard).toHaveAttribute("data-status", "live");

  const traceDuration = 2_500;
  await page.evaluate((durationMs) => {
    const root = document.querySelector<HTMLElement>(".ui-window");
    const dot = root?.querySelector<HTMLElement>(".ui-window-conn");
    if (!root || !dot) throw new Error("machine pill is missing");
    const trace = {
      startedAt: performance.now(),
      mutations: [] as Array<{ at: number; attribute: string; old: string | null; next: string | null }>,
      frames: [] as Array<{ at: number; state: string | undefined; color: string; classes: string }>,
    };
    const observer = new MutationObserver((records) => {
      const relevant = records.filter((record) =>
        (record.target === root && record.attributeName === "data-status")
        || (record.target === dot && record.attributeName === "class"));
      for (let index = 0; index < relevant.length; index += 1) {
        const record = relevant[index];
        if (!record) continue;
        const nextRecord = relevant.slice(index + 1).find((next) => next.target === record.target && next.attributeName === record.attributeName);
        const next = nextRecord?.oldValue ?? (record.target as Element).getAttribute(record.attributeName ?? "");
        if (record.oldValue !== next) trace.mutations.push({ at: performance.now() - trace.startedAt, attribute: record.attributeName ?? "", old: record.oldValue, next });
      }
    });
    observer.observe(root, { attributes: true, attributeOldValue: true, subtree: true });
    const sample = (): void => {
      trace.frames.push({ at: performance.now() - trace.startedAt, state: root.dataset.status, color: getComputedStyle(dot).backgroundColor, classes: dot.className });
      if (performance.now() - trace.startedAt < durationMs) requestAnimationFrame(sample);
      else observer.disconnect();
    };
    requestAnimationFrame(sample);
    (window as unknown as { __pillReconnectTrace: typeof trace }).__pillReconnectTrace = trace;
  }, traceDuration);

  await page.request.post(`${testDoubleOrigin}/__mock/close-after-attach`, { data: { delay_ms: 110 } });
  try {
    await page.request.post(`${testDoubleOrigin}/__mock/drop-sockets`);
    const esc = "\u001b";
    for (let frame = 0; frame < 19; frame += 1) {
      const rows = Array.from({ length: 24 }, (_, row) => `${esc}[${row + 1};1H${`terminal sign-in frame ${frame} row ${row + 1}`.padEnd(80)}`).join("");
      const text = `${esc}[?2026h${esc}[H${esc}[2J${rows}${esc}]0;sign-in-${frame}\u0007${esc}[?2026l`;
      await page.request.post(`${testDoubleOrigin}/__mock/live-query-output`, { data: { text } });
      await page.waitForTimeout(111);
    }
    await page.waitForTimeout(400);
    const trace = await page.evaluate(() => (window as unknown as { __pillReconnectTrace: { mutations: Array<{ at: number; attribute: string; old: string | null; next: string | null }>; frames: Array<{ at: number; state: string | undefined }> } }).__pillReconnectTrace);
    const liveTransitions = trace.mutations.filter((mutation) => mutation.attribute === "data-status" && mutation.next === "live");
    const disconnects = trace.mutations.filter((mutation) => mutation.attribute === "data-status" && mutation.next === "connecting");
    const stateFlips = trace.mutations.filter((mutation) => mutation.attribute === "data-status").length;
    const reconnects = disconnects.length;
    const firstDisconnectAt = disconnects[0]?.at ?? 0;
    const liveFrames = trace.frames.filter((frame) => frame.at >= firstDisconnectAt && frame.state === "live").length;
    const state = await page.context().request.get("/__mock/state").then((response) => response.json()) as { socket_open_count: number; attach_count: number };
    console.log(`PILL_RECONNECT sockets=${state.socket_open_count} attaches=${state.attach_count} connectingTransitions=${reconnects} liveTransitions=${liveTransitions.length} stateFlips=${stateFlips} liveFrames=${liveFrames} mutations=${JSON.stringify(trace.mutations)}`);
    expect(state.socket_open_count).toBeGreaterThanOrEqual(2);
    expect(state.attach_count).toBeGreaterThanOrEqual(2);
    expect(reconnects).toBeGreaterThan(0);
    expect(stateFlips).toBeLessThanOrEqual(1);
    expect(liveTransitions).toHaveLength(0);
    expect(liveFrames).toBe(0);
    await expect(windowCard).toHaveAttribute("data-status", "connecting");
    const toast = page.locator(".ui-toast");
    await expect.poll(async () => {
      const visible = await toast.isVisible();
      const message = await toast.locator(".ui-toast-message").textContent();
      return visible && message?.includes("connection to the server ended") === true;
    }).toBe(true);
  } finally {
    await page.request.post(`${testDoubleOrigin}/__mock/close-after-attach`, { data: { delay_ms: null } });
  }
  await expect(windowCard).toHaveAttribute("data-status", "live", { timeout: 10_000 });
});
