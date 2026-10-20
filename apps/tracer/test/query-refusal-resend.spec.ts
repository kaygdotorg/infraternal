/** Keeps a split query out of saved typing through a refused resume in the production browser (#244, D307). */
import { expect, test, type WebSocketRoute } from "playwright/test";
import { encodeMuxedFrame, WebSocketFrameDecoder, type WireFrame } from "../../../packages/protocol/src/codec";

test("a pending query answers once across refusal and Send again without becoming fresh-shell typing", async ({ page }) => {
  const request = page.context().request;
  await request.post("/__mock/reset");
  await request.post("/__mock/open-terminal");
  const inputs: WireFrame[] = [];
  let routes = 0;
  let initial: WebSocketRoute | undefined;
  let initialUpstream: WebSocketRoute | undefined;
  let refused: WebSocketRoute | undefined;
  let resumeSeen = false;
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    routes++;
    const decoder = new WebSocketFrameDecoder();
    if (routes === 2) {
      refused = socket;
      socket.onMessage((message) => {
        if (typeof message !== "string") decoder.feed(new Uint8Array(message), (_stream, frame) => {
          if (frame.type === "Resume") resumeSeen = true;
        });
      });
      return;
    }
    const upstream = socket.connectToServer();
    socket.onMessage((message) => {
      if (typeof message !== "string") decoder.feed(new Uint8Array(message), (_stream, frame) => {
        if (frame.type === "Input") inputs.push({ ...frame, bytes: frame.bytes.slice() });
      });
      upstream.send(message);
    });
    if (routes === 1) { initial = socket; initialUpstream = upstream; }
  });
  await page.goto("/?mock=1&proto=product&theme=ink&bg=none");
  const card = page.locator('.cl[data-view="console"] .ui-window').first();
  await expect(card).toHaveAttribute("data-status", "live", { timeout: 30_000 });
  const prefix = await request.post("/__mock/live-query-output", { data: { text: "\u001b[6" } });
  expect(prefix.ok()).toBe(true);
  const prefixState = await prefix.json() as { output_sequence: string };
  const querySequence = BigInt(prefixState.output_sequence) - 3n;
  initialUpstream!.close(); initial!.close();
  await expect.poll(() => resumeSeen).toBe(true);
  await card.locator(".terminal-host textarea").focus();
  await page.keyboard.type("saved-typing");
  refused!.send(Buffer.from(encodeMuxedFrame(0, { type: "Close", code: 1008, reason: "the server refused to resume the connection" })));
  const resend = card.getByRole("button", { name: "Send again", exact: true });
  await expect(resend).toBeVisible();
  await expect(card).toHaveAttribute("data-status", "live");
  expect(inputs).toHaveLength(0);
  // Replayed raw output restores the partial control without answering it; only its live final byte answers.
  expect((await request.post("/__mock/live-query-output", { data: { text: "n" } })).ok()).toBe(true);
  await expect.poll(() => inputs.filter(frame => frame.type === "Input" && frame.replyTo !== undefined).length).toBe(1);
  await resend.evaluate(button => { (button as HTMLButtonElement).click(); (button as HTMLButtonElement).click(); });
  await expect(resend).toBeHidden();
  await expect.poll(() => inputs.filter(frame => frame.type === "Input" && frame.replyTo === undefined).length).toBe(1);
  const typing = inputs.filter(frame => frame.type === "Input" && frame.replyTo === undefined);
  expect(typing[0]?.type === "Input" ? new TextDecoder().decode(typing[0].bytes) : "").toBe("saved-typing");
  expect(typing[0]?.type === "Input" ? typing[0].inSeq : undefined).toBe(0n);
  const replies = inputs.filter(frame => frame.type === "Input" && frame.replyTo !== undefined);
  expect(replies).toHaveLength(1);
  expect(replies[0]?.type === "Input" ? replies[0].replyTo : undefined).toBe(querySequence);
});
