/**
 * The test double must not drop a kept-alive HTTP connection while a spec is busy elsewhere (#438).
 *
 * Specs reach the double with Playwright's `context.request`, which keeps its connection open between calls, through the
 * test link with its added delay. A server that closes idle connections after its own timeout can close one while the
 * next request is already on the delayed link, and the spec fails with `socket hang up (ECONNRESET)` although neither
 * the product nor the spec did anything wrong. `predictive-echo.spec.ts` hit this at its first state poll, 5.7 s
 * after its previous request. This spec asks again after a range of pauses around that window and expects every
 * answer.
 */
import { expect, test } from "playwright/test";

/**
 * The pauses (seconds) between a context's two requests. With the default idle limit of a Node HTTP server (5 s) and
 * the test link's delay, a request is reset only when it follows the previous response by about 5.7 - 5.8 s. The window
 * moves a little with the host's speed, so the pauses cover 5.55 - 5.91 s, and every context waits for its own one at
 * the same time, which keeps the whole check near 7 s.
 */
const PAUSES_S = Array.from({ length: 13 }, (_, step) => 5.55 + step * 0.03);

test("a request after an idle pause is answered, not reset", async ({ playwright, baseURL }) => {
  if (baseURL === undefined) throw new Error("the Playwright config sets no baseURL");
  const contexts = await Promise.all(PAUSES_S.map(() => playwright.request.newContext({ baseURL })));
  try {
    await Promise.all(contexts.map(async (context) => expect((await context.get("/health")).ok()).toBe(true)));
    const answers = await Promise.all(contexts.map(async (context, index) => {
      // sleep: each context stays idle for its own pause, which is the condition under test.
      await new Promise((done) => setTimeout(done, PAUSES_S[index]! * 1000));
      return context.get("/health").then((response) => response.ok(), (error: Error) => error.message.split("\n")[0]);
    }));
    expect(answers).toEqual(PAUSES_S.map(() => true));
  } finally {
    await Promise.all(contexts.map((context) => context.dispose()));
  }
});
