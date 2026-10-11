/** Independent #158 review: a transient terminal-stream failure must retry without replacing a healthy shared socket. */
import { expect, test } from "playwright/test";

type State = { attach_count: number; socket_open_count: number; socket_close_count: number; session_id: string };

test("a transient terminal close retries while the shared socket stays open", async ({ page }) => {
  test.setTimeout(45_000);
  const request = page.context().request;
  const retry = <T>(call: () => Promise<T>): Promise<T> => call().catch(() => call());
  const state = async (): Promise<State> => (await (await retry(() => request.get("/__mock/state"))).json()) as State;
  await retry(() => request.post("/__mock/reset"));
  await retry(() => request.post("/__mock/open-terminal"));
  await page.goto("/?theme=ink&bg=none");
  await expect.poll(async () => (await state()).attach_count, { timeout: 20_000 }).toBeGreaterThan(0);
  // The prompt finishes painting before the failure, so a crossed initial Credit cannot drop the socket.
  await page.waitForTimeout(1_000);
  const before = await state();
  const closed = await (await retry(() => request.post("/__mock/transient-terminal-close"))).json() as { closed: number };
  expect(closed.closed).toBe(1);
  try {
    await expect.poll(async () => (await state()).attach_count, {
      timeout: 10_000, message: "a transient stream close never retried its still-live session",
    }).toBeGreaterThan(before.attach_count);
  } finally {
    const after = await state();
    console.info("transient-close fixture", { before, after });
    expect(after.session_id).toBe(before.session_id);
    expect(after.socket_open_count).toBe(before.socket_open_count);
    expect(after.socket_close_count).toBe(before.socket_close_count);
  }
});
