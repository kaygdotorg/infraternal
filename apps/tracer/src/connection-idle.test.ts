/** Deterministic browser lease timing, idle probe counts, and directional recovery bounds [D81,D265,D267,D300,#199]. */
import { expect, test } from "bun:test";
import { MuxConnection } from "./connection";
import { encodeMuxedFrame, WebSocketFrameDecoder, type WireFrame } from "../../../packages/protocol/src/codec";

function fixture(rtt: number, streams: number, caps = 4n) {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, performance: globals.performance, document: globals.document };
  let now = 0, timerId = 0, probes = 0, wakeups = 0, disconnects = 0;
  let online = () => {};
  let forwarding = true;
  let latestProbe = { nonce: 0n, sentUs: 0n };
  let replyProfile: ((probe: number) => number) | undefined;
  const timers = new Map<number, { at: number; callback(): void }>();
  const browserTimers = new Set<number>();
  const schedule = (callback: () => void, delay: number) => { const id = ++timerId; timers.set(id, { at: now + delay, callback }); return id; };
  const takeBrowserTimer = (onTime = false) => {
    const next = [...timers].filter(([id]) => browserTimers.has(id)).sort((a, b) => a[1].at - b[1].at)[0]!;
    if (onTime) now = Math.max(now, next[1].at);
    browserTimers.delete(next[0]);
    timers.delete(next[0]);
    return next[1].callback;
  };
  const sockets: Socket[] = [];
  const notices: boolean[] = [];
  class Socket {
    static OPEN = 1;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onclose?: () => void;
    onerror?: () => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { sockets.push(this); }
    send(bytes: Uint8Array) {
      new WebSocketFrameDecoder().feed(bytes, (stream, frame) => {
        if (frame.type === "Event" && frame.subId === 0) notices.push((JSON.parse(new TextDecoder().decode(frame.eventJson)) as { hidden: boolean }).hidden);
        if (frame.type === "Ping") {
          latestProbe = { nonce: frame.nonce, sentUs: frame.sentUs };
          probes++;
          if (forwarding) schedule(() => this.receive(stream, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs }), replyProfile?.(probes) ?? rtt);
        }
      });
    }
    receive(stream: number, frame: WireFrame) { this.onmessage?.({ data: encodeMuxedFrame(stream, frame).slice().buffer as ArrayBuffer }); }
    close() {}
  }
  globals.window = {
    setTimeout: (callback: () => void, delay: number) => {
      const id = schedule(() => { browserTimers.delete(id); wakeups++; callback(); }, delay);
      browserTimers.add(id);
      return id;
    },
    clearTimeout: (id: number) => { browserTimers.delete(id); timers.delete(id); },
    addEventListener: (type: string, callback: () => void) => { if (type === "online") online = callback; },
    removeEventListener: (type: string) => { if (type === "online") online = () => {}; },
  };
  globals.location = { protocol: "https:", host: "idle.example.test" };
  globals.WebSocket = Socket;
  globals.performance = { now: () => now };
  const visibilityListeners = new Set<() => void>();
  let hidden = false;
  globals.document = { get hidden() { return hidden; }, get visibilityState() { return hidden ? "hidden" : "visible"; }, addEventListener: (_: string, callback: () => void) => visibilityListeners.add(callback), removeEventListener: (_: string, callback: () => void) => visibilityListeners.delete(callback) };
  const connection = new MuxConnection();
  for (let i = 0; i < streams; i++) connection.openStream({ onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() { disconnects++; }, hasSession: () => true, onStatus() {} });
  sockets[0]!.onopen?.();
  sockets[0]!.receive(0, { type: "Hello", version: 1, caps, clientInfo: "visibility-fixture" });
  sockets[0]!.receive(0, { type: "Welcome", connectionId: new Uint8Array(16), resumeToken: new Uint8Array(32), resumeWindowSeconds: 120 });
  connection.streamAttached(true, 1);
  return {
    connection,
    notices,
    get now() { return now; },
    get responseAllowance() { return (connection as unknown as { responseAllowance(): number }).responseAllowance(); },
    online() { online(); },
    get latestProbe() { return { ...latestProbe }; },
    get confirmationPending() { return (connection as unknown as { livenessConfirmationPending: boolean }).livenessConfirmationPending; },
    get probes() { return probes; }, get wakeups() { return wakeups; }, get disconnects() { return disconnects; }, get sockets() { return sockets.length; },
    receive(stream: number, frame: WireFrame) { sockets[0]!.receive(stream, frame); },
    captureLatestReply() {
      const socket = sockets.at(-1)!;
      const probe = { ...latestProbe };
      // Keep the task callable so a stale timer can be ordered ahead of this queued socket message.
      return () => socket.receive(0, { type: "Pong", ...probe });
    },
    stopForwarding() { forwarding = false; },
    welcomeLatest() {
      const socket = sockets.at(-1)!;
      socket.onopen?.();
      socket.receive(0, { type: "Welcome", connectionId: new Uint8Array(16), resumeToken: new Uint8Array(32), resumeWindowSeconds: 120 });
    },
    setRoundTrip(ms: number) { rtt = ms; },
    setReplyProfile(profile: (probe: number) => number) { replyProfile = profile; },
    setHidden(value: boolean, dispatch = true) { hidden = value; if (dispatch) for (const listener of visibilityListeners) listener(); },
    suspend(ms: number) { now += ms; },
    runBrowserTimer(onTime = false) {
      takeBrowserTimer(onTime)();
    },
    captureBrowserTimer(onTime = false) { return takeBrowserTimer(onTime); },
    replyLatest(valid = true) { sockets.at(-1)!.receive(0, { type: "Pong", nonce: latestProbe.nonce, sentUs: latestProbe.sentUs + (valid ? 0n : 1n) }); },
    advance(ms: number) {
      const until = now + ms;
      for (;;) {
        const next = [...timers].filter(([, timer]) => timer.at <= until).sort((a, b) => a[1].at - b[1].at)[0];
        if (!next) break;
        now = Math.max(now, next[1].at); timers.delete(next[0]); next[1].callback();
      }
      now = until;
    },
    dispose() {
      connection.dispose();
      for (const [key, value] of Object.entries(original)) { if (value === undefined) delete globals[key]; else globals[key] = value; }
    },
  };
}

for (const rtt of [1, 150]) for (const streams of [1, 28]) test(`healthy idle probes back off independently of ${streams} streams at RTT ${rtt}`, () => {
  const f = fixture(rtt, streams);
  try {
    f.advance(1000);
    const probes = f.probes, wakeups = f.wakeups;
    f.advance(1000);
    expect(f.disconnects).toBe(0);
    const maximum = Math.ceil(1000 / Math.max(25, rtt + 10));
    expect(f.probes - probes).toBeLessThanOrEqual(maximum);
    expect(f.wakeups - wakeups).toBeLessThanOrEqual(maximum + 1);
    // Missing both directions must retire within the estimated allowance plus one tick.
    f.stopForwarding();
    // Drain replies already in flight before starting the silence oracle.
    f.advance(rtt);
    f.advance(2 * Math.max(250, 2 * rtt + 75) + 26);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

test("unacknowledged input keeps probes fast until the matching stream acknowledges it", () => {
  const f = fixture(30, 2);
  try {
    f.advance(1000);
    f.connection.send(1, { type: "Input", inSeq: 0n, bytes: new Uint8Array([1]) });
    f.advance(1000);
    const fast = f.probes;
    f.advance(1000);
    expect(f.probes - fast).toBeGreaterThanOrEqual(39);
    f.receive(3, { type: "Ack", inSeqAcked: 1n });
    const sibling = f.probes;
    f.advance(1000);
    expect(f.probes - sibling).toBeGreaterThanOrEqual(39);
    f.receive(1, { type: "Ack", inSeqAcked: 1n });
    f.advance(1000);
    const idle = f.probes;
    f.advance(1000);
    expect(f.probes - idle).toBeLessThanOrEqual(25);
    expect(f.disconnects).toBe(0);
  } finally { f.dispose(); }
});

for (const rtt of [1, 30, 150]) for (const phase of [0, 7, 20, 39]) test(`idle silence deadline survives probe phase ${phase} at RTT ${rtt}`, () => {
  const f = fixture(rtt, 1);
  try {
    f.advance(1000 + phase);
    f.stopForwarding();
    f.advance(rtt); // Allow only the already issued exact replies to drain.
    f.advance(2 * Math.max(250, 2 * rtt + 75) + 26);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

test("retransmitting an earlier input range cannot forget a later unacknowledged byte", () => {
  const f = fixture(30, 1);
  try {
    f.advance(1000);
    const bytes = new Uint8Array([1]);
    f.connection.send(1, { type: "Input", inSeq: 0n, bytes });
    f.connection.send(1, { type: "Input", inSeq: 1n, bytes });
    f.connection.send(1, { type: "Input", inSeq: 0n, bytes });
    f.receive(1, { type: "Ack", inSeqAcked: 1n });
    f.advance(1000);
    const probes = f.probes;
    f.advance(1000);
    expect(f.probes - probes).toBeGreaterThanOrEqual(39);
  } finally { f.dispose(); }
});

test("a delayed first timer starts unknown-RTT grace when its first probe is issued", () => {
  const f = fixture(1200, 1);
  try {
    f.suspend(1999);
    f.advance(1600);
    expect(f.disconnects).toBe(0);
    expect(f.connection.isWelcomed).toBe(true);
  } finally { f.dispose(); }
});

for (const streams of [1, 28]) test(`a healthy idle route tolerates a 20ms RTT step at ${streams} streams without consuming its scheduling allowance before probing`, () => {
  const f = fixture(1, streams);
  try {
    f.advance(1000);
    f.setRoundTrip(20);
    f.advance(120);
    expect(f.disconnects).toBe(0);
    expect(f.connection.isWelcomed).toBe(true);
  } finally { f.dispose(); }
});

for (const streams of [1, 28]) test(`a late timer on a fully answered route preserves its reply allowance across ${streams} streams`, () => {
  const f = fixture(1, streams);
  try {
    f.advance(1001);
    f.setRoundTrip(20);
    // No outstanding probe exists. The next local callback arrives 11ms late,
    // before the former answer's silence budget ends; the peer still needs time
    // to answer the request that has only just been issued.
    f.suspend(35);
    f.advance(21);
    expect(f.disconnects).toBe(0);
    expect(f.connection.isWelcomed).toBe(true);
    f.stopForwarding();
    f.advance(20);
    f.advance(526);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

for (const streams of [1, 28]) test(`a healthy browser route survives 150ms scheduler delay across ${streams} streams`, () => {
  const f = fixture(1, streams);
  try {
    f.advance(1000);
    f.setRoundTrip(151);
    f.advance(500);
    expect(f.disconnects).toBe(0);
    expect(f.connection.isWelcomed).toBe(true);
  } finally { f.dispose(); }
});

test("a quiet dead browser peer is detected within two 250ms allowances plus one probe interval", () => {
  const f = fixture(1, 1);
  try {
    f.advance(1001);
    f.stopForwarding();
    f.advance(200);
    expect(f.connection.isWelcomed).toBe(true);
    f.advance(326);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

test("browser jitter allowance decays after a stable link returns", () => {
  const f = fixture(100, 1);
  try {
    f.advance(2000);
    for (const rtt of [200, 100, 200, 100]) { f.setRoundTrip(rtt); f.advance(1000); }
    expect(f.disconnects).toBe(0);
    f.setRoundTrip(1);
    f.advance(10_000);
    f.stopForwarding();
    f.advance(1); // Drain an already issued correlated reply.
    f.advance(526);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

for (const timerFirst of [false, true]) for (const stall of [150, 1000, 60_000]) test(`a queued healthy reply survives a ${stall}ms browser event-loop stall with ${timerFirst ? "timer" : "reply"} first`, () => {
  const f = fixture(1, 1);
  try {
    f.advance(1000);
    const issued = f.probes;
    while (f.probes === issued) f.advance(1);
    // A request is outstanding; only local callbacks are held. The queued
    // correlated reply may precede the delayed liveness timer on resume.
    f.suspend(stall);
    if (timerFirst) f.runBrowserTimer();
    f.advance(0);
    expect(f.disconnects).toBe(0);
    expect(f.connection.isWelcomed).toBe(true);
    const allowance = f.responseAllowance;
    // A correlated late reply may train the estimator; D300 still gives the
    // recovered route both learned miss intervals before a later outage retires it.
    f.stopForwarding();
    const firstMiss = Math.ceil(allowance / 2);
    f.advance(firstMiss + 1);
    expect(f.connection.isWelcomed).toBe(true);
    f.advance(allowance - firstMiss + 25);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

test("a late timer without a reply counts subsequent responsive silence", () => {
  const f = fixture(1, 1);
  try {
    f.advance(1000);
    f.stopForwarding();
    f.advance(2);
    f.suspend(1000);
    f.runBrowserTimer();
    // No timer may retire synchronously on waking a blocked page.
    expect(f.connection.isWelcomed).toBe(true);
    f.advance(f.responseAllowance + 26);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

test("an outstanding probe gets responsive observation after a renderer stall", () => {
  const f = fixture(1, 1);
  try {
    f.advance(1000);
    f.stopForwarding();
    f.advance(30); // A probe is now outstanding, with most of its allowance left.
    f.suspend(1000);
    f.runBrowserTimer();
    // The stall may have started before the timer's due time. Merely removing
    // lateness after that due time would consume the whole allowance on wake.
    f.advance(200);
    expect(f.connection.isWelcomed).toBe(true);
    f.advance(76);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

for (const valid of [false, true]) test(`retirement gives a queued ${valid ? "correlated" : "mismatched"} pong one task turn`, () => {
  const f = fixture(1, 1);
  try {
    f.advance(1000);
    f.stopForwarding();
    f.advance(200);
    // Deliver the expiry timer exactly on time: this exercises the final task
    // yield independently of any scheduling-lag credit.
    f.runBrowserTimer(true);
    expect(f.connection.isWelcomed).toBe(true);
    f.replyLatest(valid);
    f.advance(1);
    expect(f.connection.isWelcomed).toBe(valid);
  } finally { f.dispose(); }
});

for (const { interval, typing } of [{ interval: 75, typing: true }, { interval: 1000, typing: false }, { interval: 60_000, typing: false }]) test(`a dead ${typing ? "typing" : "idle"} route eventually retires when browser tasks run every ${interval}ms`, () => {
  const f = fixture(1, 1);
  try {
    f.advance(1001);
    f.stopForwarding();
    // Unacknowledged typing keeps the existing 25ms probe cadence active.
    // The browser still executes tasks and sends probes, but no peer replies.
    if (typing) f.connection.send(1, { type: "Input", inSeq: 0n, bytes: new Uint8Array([1]) });
    const probes = f.probes;
    // These are virtual-clock schedules, not host timing measurements. Repeated
    // busy-page tasks and background timer batches must not renew peer proof.
    for (let elapsed = 0; elapsed < 600_000; elapsed += interval) {
      f.suspend(interval);
      f.runBrowserTimer(true);
      if (!f.connection.isWelcomed) break;
    }
    expect(f.probes).toBeGreaterThan(probes);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

for (const gap of [75, 1000, 60_000]) test(`dead-route stall grace is bounded by two allowances and three ${gap}ms task gaps`, () => {
  const f = fixture(1, 1);
  try {
    f.advance(1001);
    f.stopForwarding();
    f.advance(30); // An issued probe is already outstanding; A = 250ms.
    const bound = 2 * 250 + 3 * gap;
    for (let elapsed = gap; elapsed <= bound && f.connection.isWelcomed; elapsed += gap) {
      f.suspend(gap);
      f.runBrowserTimer(true);
    }
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

test("correlated queued replies replenish stall grace across successive healthy stalls", () => {
  const f = fixture(1, 1);
  try {
    f.advance(1001);
    f.stopForwarding();
    for (let cycle = 0; cycle < 10; cycle++) {
      f.advance(30);
      f.suspend(1000);
      f.runBrowserTimer(true);
      f.replyLatest();
      expect(f.connection.isWelcomed).toBe(true);
    }
    f.advance(30);
    // With replies gone, subsequent late callbacks still consume the bound.
    for (let tick = 0; tick < 3 && f.connection.isWelcomed; tick++) {
      f.suspend(1000);
      f.runBrowserTimer(true);
    }
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

// These schedules model browser task order; they do not measure host latency.
for (const kind of ["duplicate", "wrong timestamp", "unknown nonce"] as const) test(`${kind} replies cannot replenish consumed stall grace`, () => {
  const f = fixture(1, 1);
  try {
    f.advance(1001);
    const answered = f.latestProbe;
    f.stopForwarding();
    f.advance(30);
    for (let cycle = 0; cycle < 10 && f.connection.isWelcomed; cycle++) {
      f.suspend(cycle % 2 === 0 ? 100 : 25);
      f.runBrowserTimer(true);
      if (kind === "duplicate") f.receive(0, { type: "Pong", ...answered });
      else {
        const probe = f.latestProbe;
        f.receive(0, { type: "Pong", nonce: probe.nonce + (kind === "unknown nonce" ? 1000n : 0n), sentUs: probe.sentUs + (kind === "wrong timestamp" ? 1n : 0n) });
      }
    }
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

test("a queued correlated reply cancels confirmation without letting a duplicate renew it", () => {
  const f = fixture(1, 1);
  try {
    f.advance(1001);
    f.stopForwarding();
    f.advance(30);
    f.suspend(1000);
    f.runBrowserTimer(true); // Consume local grace.
    f.suspend(250);
    f.runBrowserTimer(true); // Arm confirmation before the socket task.
    const answered = f.latestProbe;
    f.replyLatest();
    expect(f.connection.isWelcomed).toBe(true);
    expect(f.disconnects).toBe(0);
    f.advance(30);
    expect(f.confirmationPending).toBe(false);
    for (let cycle = 0; cycle < 5 && f.connection.isWelcomed; cycle++) {
      f.suspend(1000);
      f.receive(0, { type: "Pong", ...answered });
      f.runBrowserTimer(true);
    }
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

test("a replacement route receives its own one-shot local stall grace", () => {
  const f = fixture(1, 1);
  try {
    f.advance(1001);
    f.stopForwarding();
    f.advance(30);
    f.suspend(1000);
    f.runBrowserTimer(true); // Consume the old route's grace.
    f.connection.forceDrop();
    f.advance(1000);
    f.welcomeLatest();
    f.advance(25); // First probe on the replacement route, A = 2000ms.
    f.suspend(3000);
    f.runBrowserTimer(true);
    f.runBrowserTimer(true);
    expect(f.connection.isWelcomed).toBe(true);
    // The replacement receives one grace, never unlimited callback credit.
    f.suspend(2000);
    f.runBrowserTimer(true);
    f.runBrowserTimer(true);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

test("continuous typing cannot cancel every silent-route confirmation turn", () => {
  const f = fixture(1, 1);
  try {
    f.advance(1001);
    f.stopForwarding();
    f.advance(30);
    // Model an input task queued between each overdue liveness callback and
    // its zero-delay confirmation. D300 gives two A=250ms misses; one local
    // stall observation and at most three G=75ms task gaps bound retirement.
    const allowance = 250, gap = 75;
    const bound = 3 * allowance + 3 * gap;
    let elapsed = 0;
    const startedAt = f.now;
    while (f.now - startedAt < bound && f.connection.isWelcomed) {
      elapsed += gap;
      f.suspend(gap);
      f.runBrowserTimer(true);
      f.connection.sampleRoundTrip();
      f.connection.send(1, { type: "Input", inSeq: BigInt(elapsed / 75), bytes: new Uint8Array([120]) });
    }
    expect(f.connection.isWelcomed).toBe(false);
    expect(f.now - startedAt).toBeLessThanOrEqual(bound);
  } finally { f.dispose(); }
});

function armConfirmation(f: ReturnType<typeof fixture>): () => void {
  f.advance(1001);
  f.stopForwarding();
  f.advance(30);
  f.suspend(1000);
  f.runBrowserTimer(true); // Consume the one local-stall grace.
  f.suspend(250);
  f.runBrowserTimer(true); // Expiry queues a zero-delay confirmation.
  expect(f.confirmationPending).toBe(true);
  return f.captureBrowserTimer();
}

for (const reset of ["reconnect", "close", "dispose"] as const) test(`a pending confirmation is reset by ${reset}`, () => {
  const f = fixture(1, 1);
  try {
    const staleConfirmation = armConfirmation(f);
    const disconnectsBeforeReset = f.disconnects;
    if (reset === "reconnect") f.connection.forceDrop();
    else if (reset === "close") f.connection.forceClose(1001, "review close");
    else f.connection.dispose();
    expect(f.confirmationPending).toBe(false);

    if (reset === "dispose") {
      staleConfirmation();
      expect(f.confirmationPending).toBe(false);
      expect(f.disconnects).toBe(disconnectsBeforeReset);
      return;
    }

    f.advance(100);
    f.welcomeLatest();
    expect(f.connection.isWelcomed).toBe(true);
    staleConfirmation();
    expect(f.connection.isWelcomed).toBe(true);
    expect(f.confirmationPending).toBe(false);
    expect(f.disconnects).toBe(disconnectsBeforeReset + 1);
  } finally { f.dispose(); }
});

test("a stale confirmation from before reconnect cannot close the replacement route", () => {
  const f = fixture(1, 1);
  try {
    const staleConfirmation = armConfirmation(f);
    f.connection.forceDrop();
    expect(f.confirmationPending).toBe(false);
    f.advance(100);
    f.welcomeLatest();
    f.advance(25); // Issue the replacement route's first probe.
    f.replyLatest(); // Learn its short response allowance while it is healthy.
    f.connection.sampleRoundTrip(); // Restore fast probing for the silence control.
    f.advance(25); // Issue a fresh unanswered probe.
    f.suspend(1000);
    f.runBrowserTimer(true); // Consume the replacement route's local-stall grace.
    f.suspend(250);
    f.runBrowserTimer(true); // Arm the replacement route's own confirmation.
    expect(f.confirmationPending).toBe(true);
    const disconnectsBeforeStaleCallback = f.disconnects;
    const currentConfirmation = f.captureBrowserTimer();
    const queuedReply = f.captureLatestReply();

    // The old queued timer must not stand in for the replacement route's task turn.
    staleConfirmation();
    expect(f.connection.isWelcomed).toBe(true);
    expect(f.confirmationPending).toBe(true);
    queuedReply();
    currentConfirmation();

    expect(f.connection.isWelcomed).toBe(true);
    expect(f.confirmationPending).toBe(false);
    expect(f.disconnects).toBe(disconnectsBeforeStaleCallback);
  } finally { f.dispose(); }
});

for (const suspension of [5000, 30_000]) test(`a hidden page resumes its lease after ${suspension}ms without retiring queued replies`, () => {
  const f = fixture(150, 28);
  try {
    f.advance(3000);
    f.setHidden(true);
    f.suspend(suspension);
    f.advance(0);
    expect(f.disconnects).toBe(0);
    f.setHidden(false);
    f.setRoundTrip(600);
    f.advance(3000);
    expect(f.disconnects).toBe(0);
    expect(f.connection.isWelcomed).toBe(true);
  } finally { f.dispose(); }
});

test("a socket lost while hidden waits for visibility before reconnecting", () => {
  const f = fixture(150, 1);
  try {
    f.advance(3000);
    f.setHidden(true);
    f.connection.forceDrop();
    f.online();
    f.advance(60_000);
    expect(f.sockets).toBe(1);
    f.setHidden(false);
    expect(f.sockets).toBe(2);
  } finally { f.dispose(); }
});

test("mobile jitter and one retransmission keep a foreground browser lease", () => {
  const f = fixture(150, 28);
  try {
    f.advance(10_000);
    // Ordered delivery on a lossy reliable transport: a lost packet delays its
    // reply by another RTT. This is a reply-delay model, not packet-level loss.
    f.setReplyProfile(probe => [150, 300, 600, 450][probe % 4]! * (probe % 100 === 0 ? 2 : 1));
    f.advance(60_000);
    expect(f.disconnects).toBe(0);
  } finally { f.dispose(); }
});

for (const supported of [false, true]) test(`visibility notices require both peers to support them: ${supported}`, () => {
  const f = fixture(150, 1, supported ? 4n : 0n);
  try {
    f.setHidden(true);
    f.setHidden(false);
    expect(f.notices).toEqual(supported ? [true, false] : []);
  } finally { f.dispose(); }
});

test("hiding a page cancels a retry scheduled while it was visible", () => {
  const f = fixture(150, 1);
  try {
    f.advance(3000);
    f.connection.forceDrop();
    f.setHidden(true);
    f.advance(1000);
    expect(f.sockets).toBe(1);
    f.setHidden(false);
    expect(f.sockets).toBe(2);
  } finally { f.dispose(); }
});

for (const dispatchVisibleBeforeReplies of [true, false]) test(`review: queued replies cannot retire a restored hidden page when visibility dispatch precedes replies: ${dispatchVisibleBeforeReplies}`, () => {
  const f = fixture(150, 28);
  try {
    f.advance(3000);
    f.setHidden(true);
    f.suspend(30_000);
    // Restore the property separately from dispatching visibilitychange, so
    // already queued socket tasks can run on either side of that notification.
    f.setHidden(false, dispatchVisibleBeforeReplies);
    f.advance(0);
    if (!dispatchVisibleBeforeReplies) f.setHidden(false);
    f.advance(3000);
    expect(f.disconnects).toBe(0);
    expect(f.sockets).toBe(1);
    expect(f.connection.isWelcomed).toBe(true);
    expect(f.notices).toEqual([true, false]);
  } finally { f.dispose(); }
});
