/** Regresses query replies during output replay and terminal-state restoration. */
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { expect, test, type APIRequestContext, type Page } from "playwright/test";

const QUERY_OUTPUT = [
  "\u001b[c",                 // DA1
  "\u001b[>c",                // DA2
  "\u001b[5n",                // DSR operating status
  "\u001b[6n",                // DSR cursor position
  "\u001b[?2004$p",           // DECRQM
  "\u001b[>q",                // XTVERSION
  "\u001b]10;?\u0007",        // OSC foreground color
  "\u001b]11;?\u0007",        // OSC background color
  "\u001b]12;?\u0007",        // OSC cursor color
  "\u001b]4;0;?\u0007",       // OSC palette color
  "\u001bP$qm\u001b\\",      // DECRQSS rendition
  "\u001b[18t",               // window cell dimensions
].join("");

type MockState = {
  accepted_input_bytes: number;
  output_sequence: string;
  snapshot_count: number;
  input_bytes?: number[];
  attach_history?: Array<{ last_out_seq: string; output_sequence: string }>;
};

const scratch = resolve(process.env.HOME ?? ".", ".cache/codex-scratch/terminal-fidelity");
const testDoublePort = Number(process.env.TRACER_BACKEND_PORT ?? String(Number(process.env.TRACER_TEST_PORT ?? "4621") + 1));
const testDoubleOrigin = `http://localhost:${testDoublePort}`;
const mockUrl = (path: string): string => new URL(path, testDoubleOrigin).toString();
const mockState = async (request: APIRequestContext, includeInput = false): Promise<MockState> =>
  (await (await request.get(mockUrl(`/__mock/state${includeInput ? "?input_bytes=1" : ""}`))).json()) as MockState;

async function openProduct(page: Page): Promise<void> {
  const request = page.context().request;
  expect((await request.post(mockUrl("/__mock/reset"))).ok()).toBe(true);
  expect((await request.post(mockUrl("/__mock/open-terminal"))).ok()).toBe(true);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("/?mock=1&theme=ink&bg=none");
  await expect(page.getByText("TEST DOUBLE")).toBeVisible({ timeout: 30_000 });
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
}

async function waitForOutputToSettle(page: Page, request: APIRequestContext): Promise<void> {
  await expect.poll(async () => {
    const state = await mockState(request);
    const sequence = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0");
    return BigInt(sequence) >= BigInt(state.output_sequence);
  }, { timeout: 30_000 }).toBe(true);
}

async function writeEvidence(name: string, bytes: Uint8Array): Promise<void> {
  await mkdir(scratch, { recursive: true });
  await writeFile(resolve(scratch, name), bytes);
}

test("live terminal queries answer once; reattach and reload replay reaches no extra input", async ({ page }) => {
  test.setTimeout(120_000);
  const request = page.context().request;
  await openProduct(page);
  await writeEvidence("query-fixture.bin", new TextEncoder().encode(QUERY_OUTPUT));

  const sent = await request.post(mockUrl("/__mock/text-output"), { data: { text: QUERY_OUTPUT, echo_input: false } });
  expect(sent.ok()).toBe(true);
  await expect.poll(async () => (await mockState(request)).accepted_input_bytes, { timeout: 15_000 }).toBeGreaterThan(0);
  await waitForOutputToSettle(page, request);
  const live = await mockState(request, true);
  expect(live.accepted_input_bytes).toBeGreaterThan(0);
  const liveAnswerBytes = live.accepted_input_bytes;
  await writeEvidence("query-live-input.bin", Uint8Array.from(live.input_bytes ?? []));

  // A transport detach keeps the renderer cursor, so reattach must not resend
  // already-painted query answers.
  const beforeReattach = await mockState(request);
  const detached = await request.post(mockUrl("/__mock/transient-terminal-close"));
  expect((await detached.json()).closed).toBe(1);
  await expect.poll(async () => (await mockState(request)).attach_history?.length ?? 0, { timeout: 30_000 })
    .toBeGreaterThan(beforeReattach.attach_history?.length ?? 0);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await waitForOutputToSettle(page, request);
  const reattached = await mockState(request, true);
  expect(reattached.accepted_input_bytes).toBe(liveAnswerBytes);
  let lastAttachCount = reattached.attach_history?.length ?? 0;
  const queryLength = String(new TextEncoder().encode(QUERY_OUTPUT).byteLength);
  expect(reattached.attach_history?.at(-1)).toEqual({ last_out_seq: queryLength, output_sequence: queryLength });

  // A full reload starts the renderer at output sequence zero. Each attach
  // replays the old PTY bytes, but those bytes must not answer again.
  for (let reopen = 0; reopen < 3; reopen += 1) {
    await page.reload();
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
    await expect.poll(async () => (await mockState(request)).attach_history?.length ?? 0).toBeGreaterThan(lastAttachCount);
    await waitForOutputToSettle(page, request);
    const reopened = await mockState(request);
    const lastAttach = reopened.attach_history?.at(-1);
    expect(lastAttach).toEqual({ last_out_seq: "0", output_sequence: queryLength });
    expect(reopened.accepted_input_bytes, `reopen ${reopen + 1} added input`).toBe(liveAnswerBytes);
    lastAttachCount = reopened.attach_history?.length ?? lastAttachCount;
  }
});

test("terminal Snapshot repaint never answers VT queries", async ({ page }) => {
  test.setTimeout(60_000);
  const context = page.context();
  const request = context.request;
  await openProduct(page);
  await writeEvidence("query-snapshot-fixture.bin", new TextEncoder().encode(QUERY_OUTPUT));
  await context.setOffline(true);
  await page.evaluate(() => window.__tracerTestDouble?.dropConnection());
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(false);
  const seeded = await request.post(mockUrl("/__mock/query-snapshot"), { data: { text: QUERY_OUTPUT } });
  expect(seeded.ok()).toBe(true);

  await context.setOffline(false);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);
  await waitForOutputToSettle(page, request);
  const restored = await mockState(request);
  expect(restored.snapshot_count).toBe(1);
  expect(restored.accepted_input_bytes).toBe(0);
});
