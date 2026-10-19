/** Regresses duplicate and late VT replies across attached terminal viewers. */
import { expect, test, type APIRequestContext, type BrowserContext, type Page } from "playwright/test";

type ViewerInput = { client_id: number; viewer_label: string | null; attached: boolean; accepted_input_bytes: number };
type MockState = {
  attach_count: number;
  reply_attempts: number;
  dropped_replies: number;
  accepted_input_bytes: number;
  output_sequence: string;
  session_id: string;
  viewer_input_bytes: ViewerInput[];
};

const testDoublePort = Number(process.env.TRACER_BACKEND_PORT ?? String(Number(process.env.TRACER_TEST_PORT ?? "4621") + 1));
const testDoubleOrigin = `http://localhost:${testDoublePort}`;
const mockUrl = (path: string): string => new URL(path, testDoubleOrigin).toString();
const QUERY_OUTPUT = [
  "\u001b[c", "\u001b[6n", "\u001b]11;?\u0007", "\u001b[?2004$p", "\u001b[>q", "\u001b[?u",
].join("");

const mockState = async (request: APIRequestContext): Promise<MockState> =>
  (await (await request.get(mockUrl("/__mock/state"))).json()) as MockState;

async function waitForOutput(page: Page, request: APIRequestContext): Promise<void> {
  await expect.poll(async () => {
    const state = await mockState(request);
    const sequence = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0");
    return BigInt(sequence) >= BigInt(state.output_sequence);
  }, { timeout: 30_000 }).toBe(true);
}

async function openFirstViewer(page: Page): Promise<{ request: APIRequestContext; state: MockState }> {
  const request = page.context().request;
  expect((await request.post(mockUrl("/__mock/reset"))).ok()).toBe(true);
  expect((await request.post(mockUrl("/__mock/open-terminal"))).ok()).toBe(true);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("/?mock=1&fixture=none&theme=ink&bg=none");
  await expect(page.getByText("TEST DOUBLE")).toBeVisible({ timeout: 30_000 });
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(async () => (await mockState(request)).viewer_input_bytes.filter((viewer) => viewer.attached).length, { timeout: 15_000 }).toBe(1);
  return { request, state: await mockState(request) };
}

async function attachViewer(context: BrowserContext, request: APIRequestContext, sessionId: string, knownIds: Set<number>): Promise<{ page: Page; clientId: number }> {
  const page = await context.newPage();
  const label = `viewer-${knownIds.size}`;
  // Socket IDs change on reconnect; attribute this page with a fixture-only URL label.
  await page.addInitScript((viewerLabel) => {
    const NativeSocket = window.WebSocket;
    window.WebSocket = class extends NativeSocket {
      constructor(url: string | URL, protocols?: string | string[]) {
        const address = new URL(url, location.href);
        if (address.pathname === "/v1/ws") address.searchParams.set("fixture_viewer", viewerLabel);
        super(address, protocols);
      }
    };
  }, label);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto(`/?mock=1&session=${encodeURIComponent(sessionId)}&fixture=none&theme=ink&bg=none`);
  await expect(page.getByText("TEST DOUBLE")).toBeVisible({ timeout: 30_000 });
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(async () => (await mockState(request)).viewer_input_bytes.filter((viewer) => viewer.attached && viewer.viewer_label === label).length, { timeout: 15_000 }).toBe(1);
  await waitForOutput(page, request);
  const viewer = (await mockState(request)).viewer_input_bytes.find((candidate) => candidate.attached && candidate.viewer_label === label);
  if (!viewer) throw new Error("the new terminal viewer did not attach to the shared session");
  return { page, clientId: viewer.client_id };
}

async function sendLiveOutput(request: APIRequestContext, text: string): Promise<void> {
  const response = await request.post(mockUrl("/__mock/live-query-output"), { data: { text } });
  expect(response.ok(), `query fixture HTTP ${response.status()}`).toBe(true);
}

function inputCount(state: MockState, clientId: number): number {
  return state.viewer_input_bytes.find((viewer) => viewer.client_id === clientId)?.accepted_input_bytes ?? 0;
}

test("three attached viewers deliver one copy of live query replies", async ({ page }) => {
  test.setTimeout(120_000);
  const viewers: Page[] = [];
  try {
    const { request, state: initial } = await openFirstViewer(page);
    const firstId = initial.viewer_input_bytes.find((viewer) => viewer.attached)?.client_id;
    if (firstId === undefined) throw new Error("first terminal viewer did not attach");

    const beforeReference = await mockState(request);
    await sendLiveOutput(request, QUERY_OUTPUT);
    await waitForOutput(page, request);
    await expect.poll(async () => inputCount(await mockState(request), firstId), { timeout: 15_000 }).toBeGreaterThan(inputCount(beforeReference, firstId));
    const afterReference = await mockState(request);
    const oneViewerReplyBytes = inputCount(afterReference, firstId) - inputCount(beforeReference, firstId);
    expect(oneViewerReplyBytes).toBeGreaterThan(0);

    const knownIds = new Set([firstId]);
    const second = await attachViewer(page.context(), request, initial.session_id, knownIds);
    knownIds.add(second.clientId);
    viewers.push(second.page);
    const third = await attachViewer(page.context(), request, initial.session_id, knownIds);
    knownIds.add(third.clientId);
    viewers.push(third.page);

    await third.page.keyboard.type("last-typist");
    await expect.poll(async () => (await mockState(request)).accepted_input_bytes, { timeout: 15_000 }).toBeGreaterThan(afterReference.accepted_input_bytes);
    const beforeQuery = await mockState(request);
    await Promise.all([page, second.page, third.page].map((viewer) => waitForOutput(viewer, request)));
    await sendLiveOutput(request, QUERY_OUTPUT);
    await Promise.all([page, second.page, third.page].map((viewer) => waitForOutput(viewer, request)));
    await expect.poll(async () => (await mockState(request)).accepted_input_bytes, { timeout: 15_000 }).toBeGreaterThan(beforeQuery.accepted_input_bytes);

    await expect.poll(async () => (await mockState(request)).reply_attempts - beforeQuery.reply_attempts).toBe(3 * (afterReference.reply_attempts - beforeReference.reply_attempts));
    const afterQuery = await mockState(request);
    const perViewer = [firstId, second.clientId, third.clientId].map((id) => inputCount(afterQuery, id) - inputCount(beforeQuery, id));
    expect(perViewer.reduce((sum, count) => sum + count, 0), "the server admits exactly one response per query across all viewers (D307)").toBe(oneViewerReplyBytes);
  } finally {
    await Promise.all(viewers.map((viewer) => viewer.close().catch(() => undefined)));
  }
});

test("a reconnect preserves query expiry and the next query answers once", async ({ page }) => {
  test.setTimeout(120_000);
  const viewers: Page[] = [];
  try {
    const { request, state: initial } = await openFirstViewer(page);
    const firstId = initial.viewer_input_bytes.find((viewer) => viewer.attached)?.client_id;
    if (firstId === undefined) throw new Error("first terminal viewer did not attach");

    const knownIds = new Set([firstId]);
    const second = await attachViewer(page.context(), request, initial.session_id, knownIds);
    knownIds.add(second.clientId);
    viewers.push(second.page);
    const third = await attachViewer(page.context(), request, initial.session_id, knownIds);
    viewers.push(third.page);
    await third.page.keyboard.type("last-typist");
    await expect.poll(async () => (await mockState(request)).accepted_input_bytes).toBe(11);
    const beforeQuery = await mockState(request);

    await sendLiveOutput(request, "\u001b[6");
    await Promise.all([page, second.page, third.page].map((viewer) => waitForOutput(viewer, request)));
    const beforeReconnect = await mockState(request);
    const attachedBeforeReconnect = beforeReconnect.viewer_input_bytes.filter((viewer) => viewer.attached).length;
    expect(attachedBeforeReconnect).toBe(3);

    expect((await request.post(mockUrl("/__mock/drop-sockets"))).ok()).toBe(true);
    await expect.poll(async () => (await mockState(request)).attach_count, { timeout: 30_000 }).toBeGreaterThanOrEqual(beforeReconnect.attach_count + 3);
    await expect.poll(async () => (await mockState(request)).viewer_input_bytes.filter((viewer) => viewer.attached).length, { timeout: 30_000 }).toBe(3);
    await Promise.all([page, second.page, third.page].map((viewer) => waitForOutput(viewer, request)));

    // Reconnection may outlive the one-second response window. Make expiry
    // explicit so this functional test never depends on reconnect timing.
    await page.waitForTimeout(1_100);
    const beforeCompletion = await mockState(request);
    await sendLiveOutput(request, "n");
    await Promise.all([page, second.page, third.page].map((viewer) => waitForOutput(viewer, request)));
    await expect.poll(async () => (await mockState(request)).reply_attempts - beforeCompletion.reply_attempts).toBe(3);
    const afterCompletion = await mockState(request);
    expect(afterCompletion.accepted_input_bytes).toBe(beforeQuery.accepted_input_bytes);
    await sendLiveOutput(request, "\u001b[6n");
    await Promise.all([page, second.page, third.page].map((viewer) => waitForOutput(viewer, request)));
    await expect.poll(async () => (await mockState(request)).reply_attempts - afterCompletion.reply_attempts).toBe(3);
    const afterNext = await mockState(request);
    expect(afterNext.dropped_replies - afterCompletion.dropped_replies, "two of three answers are duplicates").toBe(2);
    expect(afterNext.accepted_input_bytes - afterCompletion.accepted_input_bytes).toBeGreaterThan(0);
  } finally {
    await Promise.all(viewers.map((viewer) => viewer.close().catch(() => undefined)));
  }
});

test("a query completed after its response window sends no late reply", async ({ page }) => {
  test.setTimeout(60_000);
  const { request } = await openFirstViewer(page);
  await sendLiveOutput(request, "\u001b[6");
  await waitForOutput(page, request);

  // The split models a reply that cannot be produced until the delayed final byte arrives.
  await page.waitForTimeout(1_100);
  const timedOut = await mockState(request);
  await sendLiveOutput(request, "n");
  await waitForOutput(page, request);
  await expect.poll(async () => (await mockState(request)).reply_attempts).toBeGreaterThan(timedOut.reply_attempts);
  const afterLateCompletion = await mockState(request);
  expect(afterLateCompletion.accepted_input_bytes, "a timed-out query must not leak a late parser reply to the PTY").toBe(timedOut.accepted_input_bytes);
});

test("typing continues while another viewer answers a terminal query", async ({ page }) => {
  const { request, state } = await openFirstViewer(page);
  const first = state.viewer_input_bytes.find((viewer) => viewer.attached)!;
  const other = await attachViewer(page.context(), request, state.session_id, new Set([first.client_id]));
  try {
    const before = await mockState(request);
    await Promise.all([page.keyboard.type("typed"), sendLiveOutput(request, "\u001b[6n")]);
    await Promise.all([page, other.page].map((viewer) => waitForOutput(viewer, request)));
    await expect.poll(async () => (await mockState(request)).accepted_input_bytes - before.accepted_input_bytes).toBe(11);
    await page.keyboard.type("after");
    await expect.poll(async () => (await mockState(request)).accepted_input_bytes - before.accepted_input_bytes).toBe(16);
  } finally { await other.page.close(); }
});

for (const [name, query] of [
  ["DECID", "\u001bZ"],
  ["zero-padded CPR", "\u001b[06n"],
  ["CPR with an ignored NUL", "\u001b[\u00006n"],
] as const) {
  test(`review: renderer-supported ${name} retains its live response`, async ({ page }) => {
    const { request } = await openFirstViewer(page);
    const before = await mockState(request);
    await sendLiveOutput(request, query);
    await waitForOutput(page, request);
    // Each form already produces a response in the shipping VT engine. The
    // new identity scanner must preserve that response rather than suppress it.
    await expect.poll(async () => (await mockState(request)).accepted_input_bytes,
      { timeout: 5_000 }).toBeGreaterThan(before.accepted_input_bytes);
  });
}
