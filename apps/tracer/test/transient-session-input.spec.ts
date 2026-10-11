/** Keeps acknowledged input on the same durable writer across a transient shared-stream retry (#158). */
import { expect, test } from "playwright/test";

type State = { attach_count: number; socket_open_count: number; socket_close_count: number; session_id: string; echoed_text: string; written_input: string; attached_stream_ids: number[] };

test("shared terminal retry preserves acknowledged input without replaying it", async ({ page }) => {
  test.setTimeout(45_000);
  const request = page.context().request;
  const state = async (): Promise<State> => (await (await request.get("/__mock/state")).json()) as State;
  await request.post("/__mock/reset");
  await request.post("/__mock/open-terminal");
  await page.goto("/?theme=ink&bg=none");
  await expect.poll(async () => (await state()).attach_count, { timeout: 20_000 }).toBe(1);
  await page.locator(".ui-window .terminal-host").first().click();
  await page.keyboard.type("before");
  await expect.poll(async () => (await state()).written_input).toBe("6");
  const before = await state();
  await request.post("/__mock/transient-terminal-close");
  await expect.poll(async () => (await state()).attach_count, { timeout: 10_000 }).toBe(2);
  await page.keyboard.type("after");
  await expect.poll(async () => (await state()).echoed_text).toBe("beforeafter");
  const after = await state();
  expect(after.written_input).toBe("11");
  expect(after.session_id).toBe(before.session_id);
  expect(after.attached_stream_ids).toEqual(before.attached_stream_ids);
  expect(after.socket_open_count).toBe(before.socket_open_count);
  expect(after.socket_close_count).toBe(before.socket_close_count);
});
