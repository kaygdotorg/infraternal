/** Verifies D307 through the real server, infraternal agent, shim and raw PTY with three viewers. */
import { expect, test, type Page } from "playwright/test";
import { WebSocket } from "ws";
import { readFile } from "node:fs/promises";
import { once } from "node:events";
import { encodeMuxedFrame, WebSocketFrameDecoder, type WireFrame } from "../../../packages/protocol/src/codec";
import { Ghostty } from "../vendor/ghostty-web/dist/ghostty-web.js";
import { terminalQueryCorpus } from "../test/terminal-query-corpus";
import { TerminalQueries } from "../src/terminal-queries";
import { personName, startRealServer, type RealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";

// The fixture runs in Node, so use fetchable bytes rather than the browser-only file shim.
const wasm = await readFile(new URL("../vendor/ghostty-web/dist/ghostty-vt.wasm", import.meta.url));
const engine = await Ghostty.load(`data:application/wasm;base64,${wasm.toString("base64")}`);

/** Uses the existing real-server enrolment controls; no authentication data enters diagnostics. */
async function enrol(page: Page, server: RealServer): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("query_test"));
  await page.locator("#setup-display-name").fill("Query test");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
}

/** Attaches a protocol viewer with the shipping VT engine and absolute output identities. */
async function viewer(server: RealServer, cookie: string, session: string, options: {
  delay?: number;
  beforeReply?: () => WireFrame;
  legacy?: boolean;
  answerReplay?: boolean;
} = {}): Promise<{ socket: WebSocket; send: (frame: WireFrame) => void; replies: () => number; output: () => string; snapshots: () => number }> {
  const socket = new WebSocket(server.backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: server.origin, Cookie: cookie } });
  const decoder = new WebSocketFrameDecoder(); const scanner = new TerminalQueries();
  const terminal = engine.createTerminal(80, 24);
  socket.on("close", () => terminal.free());
  let replaying = true; let replies = 0; let inputSequence = 0n; let output = ""; let snapshots = 0;
  const send = (frame: WireFrame): void => {
    if (frame.type === "Input" && frame.replyTo === undefined) inputSequence = frame.inSeq + BigInt(frame.bytes.length);
    socket.send(encodeMuxedFrame(1, frame));
  };
  const attached = new Promise<void>((resolve, reject) => {
    socket.on("error", reject);
    socket.on("message", (data) => decoder.feed(new Uint8Array(Buffer.from(data as Buffer)), (stream, frame) => {
      if (frame.type === "Hello") socket.send(encodeMuxedFrame(0, { type: "Hello", version: 1, caps: options.legacy ? 0n : 4n, clientInfo: "query-reply-test" }));
      if (frame.type === "Welcome") {
        send({ type: "AttachTerm", sessionId: Buffer.from(session, "hex"), lastOutSeq: 0n, lastInSeq: 0n });
        send({ type: "Resize", cols: 80, rows: 24, pxW: 640, pxH: 432 });
        send({ type: "Credit", bytes: 1048576 });
      }
      if (frame.type === "Ping") socket.send(encodeMuxedFrame(stream, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs }));
      if (frame.type === "Snapshot") snapshots++;
      if (frame.type === "Event") {
        const notice = JSON.parse(new TextDecoder().decode(frame.eventJson)) as { type?: string };
        if (notice.type === "terminal.replay_complete") { replaying = false; resolve(); }
      }
      if (frame.type === "Output") {
        output += new TextDecoder().decode(frame.bytes);
        terminal.writeSlices(frame.bytes, (writeSlice) => {
          let start = 0;
          const write = (end: number, replyTo: bigint): void => {
            writeSlice(end);
            let response = "";
            for (let next = terminal.readResponse(); next !== null; next = terminal.readResponse()) response += next;
            if ((!replaying || options.answerReplay) && response) {
              replies++;
              const answer = (): void => {
                const reply: WireFrame = { type: "Input", inSeq: options.legacy ? inputSequence : 0n, ...(options.legacy ? {} : { replyTo }), bytes: Buffer.from(response) };
                const preceding = options.beforeReply?.();
                // A WebSocket message may contain multiple muxed frames. Keep
                // both frames in one receive batch to expose queue reordering.
                if (preceding) socket.send(Buffer.concat([encodeMuxedFrame(1, preceding), encodeMuxedFrame(1, reply)]));
                else send(reply);
              };
              if (options.delay) setTimeout(answer, options.delay);
              else answer();
            }
            start = end;
          };
          scanner.scan(frame.bytes, frame.outSeq, (end, replyTo) => write(end, replyTo));
          if (start < frame.bytes.length) write(frame.bytes.length, frame.outSeq + BigInt(start));
        });
        send({ type: "Credit", bytes: frame.bytes.length });
      }
    }));
  });
  await attached;
  return { socket, send, replies: () => replies, output: () => output, snapshots: () => snapshots };
}

test("three real viewers produce one PTY reply and refused marked input cannot stall typing", async ({ browser }) => {
  test.setTimeout(240_000);
  const server = await startRealServer();
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const extras: WebSocket[] = [];
  try {
    const page = await context.newPage(); await enrol(page, server);
    await expect.poll(() => server.bridges.filter((bridge) => !bridge.closed).at(-1)?.attached.size ?? 0, { timeout: 30_000 }).toBe(1);
    const bridge = server.bridges.filter((candidate) => !candidate.closed && candidate.attached.size > 0).at(-1)!;
    const session = [...bridge.attached.values()][0]!.at(-1)!;
    const browserReplies = (): number => server.bridges.reduce((total, candidate) => total + (candidate.replyAttempts ?? 0), 0);
    const output = (): string => server.bridges.flatMap((candidate) => [...candidate.output.values()]).join("");
    // Unknown identities and marked non-reply bytes must neither write to the
    // shell nor advance the selected viewer's typing cursor.
    const flooded = await viewer(server, bridge.cookie, session); extras.push(flooded.socket);
    for (let index = 0; index < 10_000; index++) flooded.send({ type: "Input", inSeq: 0n, replyTo: 0xffff_ffff_ffff_ffffn, bytes: Buffer.from("ordinary text") });
    // Finish the flood transport before establishing the three live renderers.
    // A bounded socket may retire under the flood; its replacement must still
    // replay and participate, rather than being counted as a silent viewer.
    if (flooded.socket.readyState !== WebSocket.CLOSED) {
      const closed = once(flooded.socket, "close");
      flooded.socket.close();
      await closed;
    }
    const second = await viewer(server, bridge.cookie, session); extras.push(second.socket);
    const third = await viewer(server, bridge.cookie, session); extras.push(third.socket);
    const program = 'import os,termios,tty,select,re; old=termios.tcgetattr(0); tty.setraw(0); os.write(1,bytes([27])+b"[6n"); data=os.read(0,1024); ready=select.select([0],[],[],0.4)[0]; data+=os.read(0,1024) if ready else b""; termios.tcsetattr(0,termios.TCSANOW,old); print("QUERY_REPLIES:%d BYTES:%d"%(len(re.findall(rb"\\x1b\\[[0-9]+;[0-9]+R",data)),len(data)),flush=True)';
    const command = Buffer.from(`python3 -c '${program}'\n`);
    third.send({ type: "Input", inSeq: 0n, bytes: command });
    await expect.poll(output, { timeout: 30_000 }).toMatch(/QUERY_REPLIES:1 BYTES:[6-9](?:\D|$)/);
    await expect.poll(() => [second.replies(), third.replies()]).toEqual([1, 1]);
    third.send({ type: "Input", inSeq: BigInt(command.length), bytes: Buffer.from("printf 'TYPING_%s\\n' OK\n") });
    await expect.poll(output, { timeout: 15_000 }).toContain("TYPING_OK");
    // Corpus membership is decided by the shipping engine, never by a request
    // allow-list. Each accepted byte stream must reach the real PTY once even
    // though three independent renderer instances answer it.
    // Observe beyond the full expiry window so delayed viewers cannot escape the PTY byte count.
    let inSeq = BigInt(command.length + Buffer.byteLength("printf 'TYPING_%s\\n' OK\n"));
    let answered = 0;
    for (const [index, request] of terminalQueryCorpus.entries()) {
      const reference = engine.createTerminal(80, 24);
      reference.write("\u001b[H" + request);
      const response = reference.readResponse();
      reference.free();
      if (response === null) continue;
      answered++;
      const attemptsBefore = [browserReplies(), second.replies(), third.replies()] as const;
      const marker = `CORPUS_${index}`;
      const encoded = Buffer.from("\u001b[H" + request).toString("hex");
      const probe = `import os,termios,tty,select; old=termios.tcgetattr(0); tty.setraw(0); os.write(1,bytes.fromhex("${encoded}")); data=os.read(0,4096); ready=select.select([0],[],[],1.1)[0]; data+=os.read(0,4096) if ready else b""; termios.tcsetattr(0,termios.TCSANOW,old); print("${marker}:%s"%data.hex(),flush=True)`;
      const input = Buffer.from(`python3 -c '${probe}'\n`);
      third.send({ type: "Input", inSeq, bytes: input });
      inSeq += BigInt(input.length);
      await expect.poll(output, { timeout: 15_000 }).toMatch(new RegExp(`${marker}:${Buffer.from(response).toString("hex")}(?:[^0-9a-f]|$)`));
      console.log(`QUERY_CASE index=${index} request=${Buffer.from(request).toString("hex")}`);
      await expect.poll(() => [
        browserReplies() - attemptsBefore[0],
        second.replies() - attemptsBefore[1],
        third.replies() - attemptsBefore[2],
      ], { message: `corpus ${index}, request ${Buffer.from(request).toString("hex")}, live browser bridges ${server.bridges.filter((candidate) => !candidate.closed).length}, viewer sockets ${second.socket.readyState}/${third.socket.readyState}, snapshots ${second.snapshots()}/${third.snapshots()}` }).toEqual([1, 1, 1]);
    }
    expect(answered).toBeGreaterThanOrEqual(30);
    console.log(`QUERY_CORPUS forms=${answered} viewers=3 PTY_copies=1`);
    await page.screenshot({ path: tracerEvidencePath("query-replies-real.png") });
  } finally {
    for (const socket of extras) socket.terminate();
    await context.close(); await server.dispose();
  }
});

test("review: two requests in one PTY write survive three viewers including an expired answer", async ({ browser }) => {
  test.setTimeout(120_000);
  const server = await startRealServer();
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const extras: WebSocket[] = [];
  try {
    const page = await context.newPage(); await enrol(page, server);
    await expect.poll(() => server.bridges.some((bridge) => bridge.attached.size > 0)).toBe(true);
    const bridge = server.bridges.find((candidate) => !candidate.closed && candidate.attached.size > 0)!;
    const session = [...bridge.attached.values()][0]!.at(-1)!;
    await page.close();
    const first = await viewer(server, bridge.cookie, session); extras.push(first.socket);
    const second = await viewer(server, bridge.cookie, session); extras.push(second.socket);
    const late = await viewer(server, bridge.cookie, session, { delay: 1200 }); extras.push(late.socket);
    const program = 'import os,termios,tty,select,time; old=termios.tcgetattr(0); tty.setraw(0); os.write(1,bytes([27])+b"[H"+bytes([27])+b"[6n"+bytes([27])+b"[5n"); data=b""; end=time.monotonic()+2; exec("while time.monotonic()<end:\\n r=select.select([0],[],[],max(0,end-time.monotonic()))[0]\\n if r: data+=os.read(0,4096)"); termios.tcsetattr(0,termios.TCSANOW,old); print("REVIEW_PAIR:%s"%data.hex(),flush=True)';
    first.send({ type: "Input", inSeq: 0n, bytes: Buffer.from(`python3 -c '${program}'\n`) });
    await expect.poll(() => [first.replies(), second.replies()]).toEqual([2, 2]);
    // Deliberately answer replay as an outdated viewer could: server arbitration,
    // rather than the browser's replay suppression, must refuse the duplicates.
    const reattached = await viewer(server, bridge.cookie, session, { answerReplay: true }); extras.push(reattached.socket);
    expect(reattached.replies()).toBe(2);
    const output = first.output;
    await expect.poll(output, { timeout: 20_000 }).toMatch(/REVIEW_PAIR:1b5b313b31521b5b306e(?:[^0-9a-f]|$)/);
    expect([first.replies(), second.replies(), late.replies()]).toEqual([2, 2, 2]);
  } finally {
    for (const socket of extras) socket.terminate();
    await context.close(); await server.dispose();
  }
});

test("review: typing sent before a renderer reply reaches the PTY first", async ({ browser }) => {
  test.setTimeout(120_000);
  const server = await startRealServer();
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const extras: WebSocket[] = [];
  try {
    const page = await context.newPage(); await enrol(page, server);
    await expect.poll(() => server.bridges.some((bridge) => bridge.attached.size > 0)).toBe(true);
    const bridge = server.bridges.find((candidate) => !candidate.closed && candidate.attached.size > 0)!;
    const session = [...bridge.attached.values()][0]!.at(-1)!;
    await page.close();
    const program = 'import os,termios,tty,select,time; old=termios.tcgetattr(0); tty.setraw(0); os.write(1,bytes([27])+b"[H"+bytes([27])+b"[6n"); data=b""; end=time.monotonic()+2; exec("while time.monotonic()<end:\\n r=select.select([0],[],[],max(0,end-time.monotonic()))[0]\\n if r: data+=os.read(0,4096)"); termios.tcsetattr(0,termios.TCSANOW,old); print("REVIEW_ORDER:%s"%data.hex(),flush=True)';
    const command = Buffer.from(`python3 -c '${program}'\n`);
    const first = await viewer(server, bridge.cookie, session, { beforeReply: () => ({
      type: "Input", inSeq: BigInt(command.length), bytes: Buffer.from("A"),
    }) }); extras.push(first.socket);
    // A second attached renderer consumes output but does not answer until expiry.
    const second = await viewer(server, bridge.cookie, session, { delay: 1200 }); extras.push(second.socket);
    first.send({ type: "Input", inSeq: 0n, bytes: command });
    const output = first.output;
    await expect.poll(output, { timeout: 20_000 }).toContain("REVIEW_ORDER:411b5b313b3152");
  } finally {
    for (const socket of extras) socket.terminate();
    await context.close(); await server.dispose();
  }
});

test("review: an unmarked legacy viewer keeps typing and replies on its ordinary input cursor", async ({ browser }) => {
  test.setTimeout(120_000);
  const server = await startRealServer();
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const extras: WebSocket[] = [];
  try {
    const page = await context.newPage(); await enrol(page, server);
    await expect.poll(() => server.bridges.some((bridge) => bridge.attached.size > 0)).toBe(true);
    const bridge = server.bridges.find((candidate) => !candidate.closed && candidate.attached.size > 0)!;
    const session = [...bridge.attached.values()][0]!.at(-1)!;
    await page.close();
    const legacy = await viewer(server, bridge.cookie, session, { legacy: true }); extras.push(legacy.socket);
    const modern = await viewer(server, bridge.cookie, session); extras.push(modern.socket);
    const program = 'import os,termios,tty,select,time; old=termios.tcgetattr(0); tty.setraw(0); os.write(1,bytes([27])+b"[H"+bytes([27])+b"[6n"); data=b""; end=time.monotonic()+2; exec("while time.monotonic()<end:\\n r=select.select([0],[],[],max(0,end-time.monotonic()))[0]\\n if r: data+=os.read(0,4096)"); termios.tcsetattr(0,termios.TCSANOW,old); print("REVIEW_LEGACY:%s"%data.hex(),flush=True)';
    const command = Buffer.from(`python3 -c '${program}'\n`);
    legacy.send({ type: "Input", inSeq: 0n, bytes: command });
    const output = legacy.output;
    // Unmarked responses retain compatibility: the server cannot distinguish
    // them from typing, so the modern and legacy viewers each contribute one.
    await expect.poll(output, { timeout: 20_000 }).toMatch(/REVIEW_LEGACY:1b5b313b31521b5b313b3152(?:[^0-9a-f]|$)/);
    expect([legacy.replies(), modern.replies()]).toEqual([1, 1]);
    legacy.send({ type: "Input", inSeq: BigInt(command.length + 6), bytes: Buffer.from("printf 'LEGACY_%s\\n' OK\n") });
    await expect.poll(output, { timeout: 15_000 }).toContain("LEGACY_OK");
  } finally {
    for (const socket of extras) socket.terminate();
    await context.close(); await server.dispose();
  }
});

test("review: sixteen outstanding request positions each reach the PTY once", async ({ browser }) => {
  test.setTimeout(120_000);
  const server = await startRealServer();
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const extras: WebSocket[] = [];
  try {
    const page = await context.newPage(); await enrol(page, server);
    await expect.poll(() => server.bridges.some((bridge) => bridge.attached.size > 0)).toBe(true);
    const bridge = server.bridges.find((candidate) => !candidate.closed && candidate.attached.size > 0)!;
    const session = [...bridge.attached.values()][0]!.at(-1)!;
    await page.close();
    const first = await viewer(server, bridge.cookie, session); extras.push(first.socket);
    const second = await viewer(server, bridge.cookie, session); extras.push(second.socket);
    const third = await viewer(server, bridge.cookie, session); extras.push(third.socket);
    const program = 'import os,termios,tty,select,time; old=termios.tcgetattr(0); tty.setraw(0); os.write(1,(bytes([27])+b"[5n")*16); data=b""; end=time.monotonic()+2; exec("while time.monotonic()<end:\\n r=select.select([0],[],[],max(0,end-time.monotonic()))[0]\\n if r: data+=os.read(0,4096)"); termios.tcsetattr(0,termios.TCSANOW,old); print("REVIEW_BURST:%d"%data.count(bytes([27])+b"[0n"),flush=True)';
    first.send({ type: "Input", inSeq: 0n, bytes: Buffer.from(`python3 -c '${program}'\n`) });
    const output = first.output;
    await expect.poll(output, { timeout: 20_000 }).toContain("REVIEW_BURST:16");
    expect([first.replies(), second.replies(), third.replies()]).toEqual([16, 16, 16]);
  } finally {
    for (const socket of extras) socket.terminate();
    await context.close(); await server.dispose();
  }
});
