/** Verifies D307 through the real server, infraternal agent, shim and raw PTY with three viewers. */
import { expect, test, type Page } from "playwright/test";
import { WebSocket } from "ws";
import { encodeMuxedFrame, WebSocketFrameDecoder, type WireFrame } from "../../../packages/protocol/src/codec";
import { TerminalQueries } from "../src/terminal-queries";
import { startRealServer, type RealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";

/** Uses the existing real-server enrolment controls; no authentication data enters diagnostics. */
async function enrol(page: Page, server: RealServer): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill("query_test");
  await page.locator("#setup-display-name").fill("Query test");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
}

/** Attaches a real protocol viewer, answering CPR with the query's exact output identity. */
async function viewer(server: RealServer, cookie: string, session: string): Promise<{ socket: WebSocket; send: (frame: WireFrame) => void; replies: () => number }> {
  const socket = new WebSocket(server.backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: server.origin, Cookie: cookie } });
  const decoder = new WebSocketFrameDecoder(); const scanner = new TerminalQueries();
  let replaying = true; let replies = 0;
  const send = (frame: WireFrame): void => { socket.send(encodeMuxedFrame(1, frame)); };
  const attached = new Promise<void>((resolve, reject) => {
    socket.on("error", reject);
    socket.on("message", (data) => decoder.feed(new Uint8Array(Buffer.from(data as Buffer)), (stream, frame) => {
      if (frame.type === "Hello") socket.send(encodeMuxedFrame(0, { type: "Hello", version: 1, caps: 4n, clientInfo: "query-reply-test" }));
      if (frame.type === "Welcome") {
        send({ type: "AttachTerm", sessionId: Buffer.from(session, "hex"), lastOutSeq: 0n, lastInSeq: 0n });
        send({ type: "Resize", cols: 80, rows: 24, pxW: 640, pxH: 432 });
        send({ type: "Credit", bytes: 1048576 });
      }
      if (frame.type === "Ping") socket.send(encodeMuxedFrame(stream, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs }));
      if (frame.type === "Event") {
        const notice = JSON.parse(new TextDecoder().decode(frame.eventJson)) as { type?: string };
        if (notice.type === "terminal.replay_complete") { replaying = false; resolve(); }
      }
      if (frame.type === "Output") {
        scanner.scan(frame.bytes, frame.outSeq, (_, replyTo, _started, query) => {
          if (!replaying && query === "\u001b[6n") { replies++; send({ type: "Input", inSeq: 0n, replyTo, bytes: Buffer.from("ordinary text") }); send({ type: "Input", inSeq: 0n, replyTo, bytes: Buffer.from("\u001b[1;1R") }); }
        });
        send({ type: "Credit", bytes: frame.bytes.length });
      }
    }));
  });
  await attached;
  return { socket, send, replies: () => replies };
}

test("three real viewers produce one PTY reply and refused marked input cannot stall typing", async ({ browser }) => {
  test.setTimeout(120_000);
  const server = await startRealServer();
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const extras: WebSocket[] = [];
  try {
    const page = await context.newPage(); await enrol(page, server);
    await expect.poll(() => server.bridges.filter((bridge) => !bridge.closed).at(-1)?.attached.size ?? 0, { timeout: 30_000 }).toBe(1);
    const bridge = server.bridges.filter((candidate) => !candidate.closed && candidate.attached.size > 0).at(-1)!;
    const session = [...bridge.attached.values()][0]!.at(-1)!;
    const output = (): string => server.bridges.flatMap((candidate) => [...candidate.output.values()]).join("");
    const second = await viewer(server, bridge.cookie, session); extras.push(second.socket);
    const third = await viewer(server, bridge.cookie, session); extras.push(third.socket);
    // Unknown identities and marked non-reply bytes must neither write to the
    // shell nor advance the selected viewer's typing cursor.
    for (let index = 0; index < 10_000; index++) second.send({ type: "Input", inSeq: 0n, replyTo: 0xffff_ffff_ffff_ffffn, bytes: Buffer.from("ordinary text") });
    const program = 'import os,termios,tty,select,re; old=termios.tcgetattr(0); tty.setraw(0); os.write(1,bytes([27])+b"[6n"); data=os.read(0,1024); ready=select.select([0],[],[],0.4)[0]; data+=os.read(0,1024) if ready else b""; termios.tcsetattr(0,termios.TCSANOW,old); print("QUERY_REPLIES:%d BYTES:%d"%(len(re.findall(rb"\\x1b\\[[0-9]+;[0-9]+R",data)),len(data)),flush=True)';
    const command = Buffer.from(`python3 -c '${program}'\n`);
    third.send({ type: "Input", inSeq: 0n, bytes: command });
    await expect.poll(output, { timeout: 30_000 }).toMatch(/QUERY_REPLIES:1 BYTES:[6-9](?:\D|$)/);
    expect(second.replies()).toBe(1); expect(third.replies()).toBe(1);
    third.send({ type: "Input", inSeq: BigInt(command.length), bytes: Buffer.from("printf 'TYPING_%s\\n' OK\n") });
    await expect.poll(output, { timeout: 15_000 }).toContain("TYPING_OK");
    await page.screenshot({ path: tracerEvidencePath("query-replies-real.png") });
  } finally {
    for (const socket of extras) socket.terminate();
    await context.close(); await server.dispose();
  }
});
