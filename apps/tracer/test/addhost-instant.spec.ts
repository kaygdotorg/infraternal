/** Functional production-build checks for retained D255 setup after wizard closure; no timing budgets. */
import { expect, test } from "playwright/test";

test("published setup outlives the wizard and retries without replacing its session", async ({ page }) => {
  await page.goto("/?mock=1&proto=clusters&scene=3");
  const result = await page.evaluate(async () => {
    const root = location.origin.replace("http", "ws");
    const wizard = new WebSocket(`${root}/v1/bootstrap/ws`);
    const done = await new Promise<{ host_id: string; session_id: string }>((resolve, reject) => {
      wizard.onopen = () => wizard.send(JSON.stringify({ action: "start", targets: [{ id: "early", address: { kind: "manual", value: "instant-fail.lab" }, mode: "rootless" }] }));
      wizard.onerror = () => reject(new Error("wizard failed"));
      wizard.onmessage = (message) => {
        const value = JSON.parse(String(message.data)) as { step?: string; host_id?: string; session_id?: string };
        if (value.step === "done" && value.host_id && value.session_id) resolve({ host_id: value.host_id, session_id: value.session_id });
      };
    });
    wizard.close();
    const status = new WebSocket(`${root}/v1/bootstrap/setup/ws`);
    const events: Array<{ host_id: string; session_id: string; window_id: string; attempt: number; sequence: number; stage: string; state: string }> = [];
    await new Promise<void>((resolve, reject) => {
      status.onopen = () => status.send(JSON.stringify({ action: "subscribe", host_id: done.host_id, window_id: "original-window", after: 0 }));
      status.onerror = () => reject(new Error("status failed"));
      status.onmessage = (message) => {
        const value = JSON.parse(String(message.data)) as { setup?: (typeof events)[number] };
        if (!value.setup) return;
        events.push(value.setup);
        if (value.setup.state === "failed") status.send(JSON.stringify({ action: "retry", host_id: done.host_id }));
        if (value.setup.stage === "ready" && value.setup.state === "done") resolve();
      };
    });
    status.close();
    return { done, events };
  });
  expect(result.events.every((event) => event.host_id === result.done.host_id && event.session_id === result.done.session_id && event.window_id === "original-window")).toBe(true);
  expect(result.events.some((event) => event.stage === "join" && event.state === "failed" && event.attempt === 1)).toBe(true);
  expect(result.events.at(-1)).toMatchObject({ stage: "ready", state: "done", attempt: 2 });
  expect(result.events.every((event, index) => index === 0 || event.sequence > result.events[index - 1]!.sequence)).toBe(true);
});
