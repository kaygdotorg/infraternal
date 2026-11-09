/** Deterministic browser lease timing, idle probe counts, and directional recovery bounds [D81,D265,D267,D300,#199]. */
import { expect, test } from "bun:test";
import { MuxConnection } from "./connection";
import { encodeMuxedFrame, WebSocketFrameDecoder, type WireFrame } from "../../../packages/protocol/src/codec";

function fixture(rtt: number, streams: number, caps = 4n, subscription = false) {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, performance: globals.performance, document: globals.document };
  let now = 0, timerId = 0, probes = 0, wakeups = 0, disconnects = 0;
  let online = () => {};
  const windowListeners = new Map<string, Set<() => void>>();
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
  const sentFrames: Array<{ stream: number; frame: WireFrame }> = [];
  const notices: boolean[] = [];
  const subscriptionIds: number[] = [];
  class Socket {
    static OPEN = 1;
    static CLOSED = 3;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onclose?: () => void;
    onerror?: () => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { sockets.push(this); }
    send(bytes: Uint8Array) {
      new WebSocketFrameDecoder().feed(bytes, (stream, frame) => {
        sentFrames.push({ stream, frame });
        if (frame.type === "Subscribe") subscriptionIds.push(frame.subId);
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
    addEventListener: (type: string, callback: () => void) => {
      if (type === "online") online = callback;
      let listeners = windowListeners.get(type);
      if (!listeners) { listeners = new Set(); windowListeners.set(type, listeners); }
      listeners.add(callback);
    },
    removeEventListener: (type: string, callback: () => void) => {
      if (type === "online" && online === callback) online = () => {};
      windowListeners.get(type)?.delete(callback);
    },
  };
  globals.location = { protocol: "https:", host: "idle.example.test" };
  globals.WebSocket = Socket;
  globals.performance = { now: () => now };
  const visibilityListeners = new Set<() => void>();
  let hidden = false;
  globals.document = { get hidden() { return hidden; }, get visibilityState() { return hidden ? "hidden" : "visible"; }, addEventListener: (_: string, callback: () => void) => visibilityListeners.add(callback), removeEventListener: (_: string, callback: () => void) => visibilityListeners.delete(callback) };
  const connection = new MuxConnection();
  if (subscription) connection.subscribe({ topic: "canvas.layout" }, () => {});
  for (let i = 0; i < streams; i++) connection.openStream({ onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() { disconnects++; }, hasSession: () => true, onStatus() {} });
  sockets[0]!.onopen?.();
  sockets[0]!.receive(0, { type: "Hello", version: 1, caps, clientInfo: "visibility-fixture" });
  sockets[0]!.receive(0, { type: "Welcome", connectionId: new Uint8Array(16), resumeToken: new Uint8Array(32), resumeWindowSeconds: 120 });
  connection.streamAttached(true, 1);
  return {
    connection,
    notices,
    subscriptionIds,
    get now() { return now; },
    get responseAllowance() { return (connection as unknown as { responseAllowance(): number }).responseAllowance(); },
    online() { online(); },
    get latestProbe() { return { ...latestProbe }; },
    get sentFrames() { return [...sentFrames]; },
    get confirmationPending() { return (connection as unknown as { livenessConfirmationPending: boolean }).livenessConfirmationPending; },
    get outstandingInput() { return (connection as unknown as { unacknowledgedInput: Map<number, bigint> }).unacknowledgedInput.get(1); },
    get probes() { return probes; }, get wakeups() { return wakeups; }, get clientTimers() { return browserTimers.size; }, get disconnects() { return disconnects; }, get sockets() { return sockets.length; },
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
    focus() { for (const listener of windowListeners.get("focus") ?? []) listener(); },
    pageShow() { for (const listener of windowListeners.get("pageshow") ?? []) listener(); },
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

test("visible idle keeps the live socket without recurring client timers or probes", () => {
  const f = fixture(1, 1);
  try {
    f.advance(60_000);
    expect(f.connection.isWelcomed).toBe(true);
    expect(f.clientTimers).toBe(0);
    expect(f.probes).toBe(1);
    expect(f.wakeups).toBe(0);
  } finally { f.dispose(); }
});

test("the first input sends one immediate application probe", () => {
  const f = fixture(1, 1);
  try {
    f.advance(1);
    f.suspend(1000);
    const before = f.probes;
    f.connection.send(1, { type: "Input", inSeq: 0n, bytes: new Uint8Array([120]) });
    expect(f.probes).toBe(before + 1);
    expect(f.latestProbe.nonce).toBeGreaterThan(0n);
    f.advance(1);
    f.connection.send(1, { type: "Input", inSeq: 1n, bytes: new Uint8Array([121]) });
    expect(f.probes).toBe(before + 1);
  } finally { f.dispose(); }
});

test("hidden pages stop client work and return triggers one coalesced probe", () => {
  const f = fixture(1, 1);
  try {
    f.advance(1);
    const before = f.probes;
    f.setHidden(true);
    f.suspend(2 * 60 * 60 * 1000);
    f.advance(0);
    expect(f.clientTimers).toBe(0);
    expect(f.probes).toBe(before);
    f.setHidden(false);
    expect(f.probes).toBe(before + 1);
    f.focus();
    f.pageShow();
    f.connection.send(1, { type: "Input", inSeq: 0n, bytes: new Uint8Array([122]) });
    expect(f.probes).toBe(before + 1);
    f.advance(1);
    expect(f.connection.isWelcomed).toBe(true);
    expect(f.clientTimers).toBe(0);
  } finally { f.dispose(); }
});

for (const event of ["focus", "pageshow"] as const) test(`${event} triggers one probe when visibilitychange was missed`, () => {
  const f = fixture(1, 1);
  try {
    f.advance(1);
    const before = f.probes;
    f.suspend(1200);
    if (event === "focus") f.focus();
    else f.pageShow();
    expect(f.probes).toBe(before + 1);
    expect(f.clientTimers).toBe(1);
    f.advance(1);
    expect(f.clientTimers).toBe(0);
  } finally { f.dispose(); }
});

for (const rtt of [1, 150]) for (const streams of [1, 28]) test(`healthy idle has no recurring client work across ${streams} streams at RTT ${rtt}`, () => {
  const f = fixture(rtt, streams);
  try {
    f.advance(1000);
    const probes = f.probes, wakeups = f.wakeups;
    f.advance(1000);
    expect(f.disconnects).toBe(0);
    expect(f.probes).toBe(probes);
    expect(f.wakeups).toBe(wakeups);
    expect(f.clientTimers).toBe(0);
    f.stopForwarding();
    f.connection.sampleRoundTrip();
    f.advance(f.responseAllowance + 1);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

test("an input burst probes once and then remains timer-free", () => {
  const f = fixture(30, 2);
  try {
    f.advance(30);
    f.suspend(1000);
    const before = f.probes;
    f.connection.send(1, { type: "Input", inSeq: 0n, bytes: new Uint8Array([1]) });
    expect(f.probes).toBe(before + 1);
    f.advance(30);
    f.receive(3, { type: "Ack", inSeqAcked: 1n });
    f.receive(1, { type: "Ack", inSeqAcked: 1n });
    expect(f.probes).toBe(before + 1);
    expect(f.clientTimers).toBe(0);
    expect(f.disconnects).toBe(0);
  } finally { f.dispose(); }
});

for (const rtt of [1, 30, 150]) for (const phase of [0, 7, 20, 39]) test(`idle silence deadline survives probe phase ${phase} at RTT ${rtt}`, () => {
  const f = fixture(rtt, 1);
  try {
    f.advance(1000 + phase);
    f.stopForwarding();
    f.connection.sampleRoundTrip();
    f.advance(f.responseAllowance + 1);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

test("input acknowledgements retain later unacknowledged bytes", () => {
  const f = fixture(30, 1);
  try {
    f.advance(30);
    const bytes = new Uint8Array([1]);
    f.connection.send(1, { type: "Input", inSeq: 0n, bytes });
    f.connection.send(1, { type: "Input", inSeq: 1n, bytes });
    f.connection.send(1, { type: "Input", inSeq: 0n, bytes });
    expect(f.outstandingInput).toBe(2n);
    f.receive(1, { type: "Ack", inSeqAcked: 1n });
    expect(f.outstandingInput).toBe(2n);
    f.receive(1, { type: "Ack", inSeqAcked: 2n });
    expect(f.outstandingInput).toBeUndefined();
  } finally { f.dispose(); }
});

test("a dead route resumes immediately after its return probe expires", () => {
  const f = fixture(1, 1);
  try {
    f.advance(1);
    f.stopForwarding();
    f.setHidden(true);
    f.suspend(120_000);
    f.setHidden(false);
    expect(f.probes).toBe(2);
    const allowance = f.responseAllowance;
    f.advance(allowance + 1);
    expect(f.disconnects).toBe(1);
    expect(f.sockets).toBe(2);
    expect(f.connection.isWelcomed).toBe(false);
    f.welcomeLatest();
    expect(f.connection.isWelcomed).toBe(true);
    expect(f.probes).toBe(3);
  } finally { f.dispose(); }
});

test("input sent during a return probe follows it once and keeps its cumulative sequence", () => {
  const f = fixture(150, 1);
  try {
    f.advance(150);
    f.setHidden(true);
    f.suspend(60_000);
    f.setHidden(false);
    const probe = f.latestProbe.nonce;
    f.connection.send(1, { type: "Input", inSeq: 0n, bytes: new Uint8Array([120]) });
    const tail = f.sentFrames.slice(-2);
    expect(tail.map(({ frame }) => frame.type)).toEqual(["Ping", "Input"]);
    expect(tail[0]!.frame.type === "Ping" && tail[0]!.frame.nonce).toBe(probe);
    expect(f.outstandingInput).toBe(1n);
    expect(f.probes).toBe(2);
    f.advance(150);
    f.receive(1, { type: "Ack", inSeqAcked: 1n });
    expect(f.outstandingInput).toBeUndefined();
    expect(f.clientTimers).toBe(0);
  } finally { f.dispose(); }
});

test("the D300 response allowance applies to one outstanding return probe", () => {
  const f = fixture(150, 1);
  try {
    f.advance(150);
    f.stopForwarding();
    f.connection.sampleRoundTrip();
    const allowance = f.responseAllowance;
    expect(f.clientTimers).toBe(1);
    f.advance(allowance - 1);
    expect(f.connection.isWelcomed).toBe(true);
    f.advance(2);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

// The lease rules below once ran under a recurring probe. They now guard each on-demand probe (return, focus, first
// input): one local-stall grace, one confirmation turn, and only a fresh correlated reply renews the route [D300, #317].

/** A sampled route (A = 250 ms at RTT 1) with one unanswered on-demand probe outstanding. */
function silentProbe(f: ReturnType<typeof fixture>): void {
  f.advance(1); // The Welcome sample is answered.
  f.stopForwarding();
  f.connection.sampleRoundTrip();
}

function armConfirmation(f: ReturnType<typeof fixture>): () => void {
  silentProbe(f);
  f.suspend(1000);
  f.runBrowserTimer(true); // Consume the one local-stall grace.
  f.suspend(250);
  f.runBrowserTimer(true); // Expiry queues a zero-delay confirmation.
  expect(f.confirmationPending).toBe(true);
  return f.captureBrowserTimer();
}

for (const valid of [false, true]) test(`retirement gives a queued ${valid ? "correlated" : "mismatched"} pong one task turn`, () => {
  const f = fixture(1, 1);
  try {
    silentProbe(f);
    // Deliver the expiry timer exactly on time: this exercises the final task
    // yield independently of any scheduling-lag credit.
    f.runBrowserTimer(true);
    expect(f.confirmationPending).toBe(true);
    expect(f.connection.isWelcomed).toBe(true);
    f.replyLatest(valid);
    f.advance(1);
    expect(f.connection.isWelcomed).toBe(valid);
  } finally { f.dispose(); }
});

for (const gap of [75, 1000, 60_000]) test(`dead-route stall grace is bounded by two allowances and three ${gap}ms task gaps`, () => {
  const f = fixture(1, 1);
  try {
    silentProbe(f);
    const bound = 2 * 250 + 3 * gap;
    for (let elapsed = gap; elapsed <= bound && f.connection.isWelcomed; elapsed += gap) {
      f.suspend(gap);
      f.runBrowserTimer(true);
    }
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

for (const { interval, typing } of [{ interval: 75, typing: true }, { interval: 1000, typing: false }, { interval: 60_000, typing: false }]) test(`a dead ${typing ? "typing" : "idle"} route retires when browser tasks run every ${interval}ms`, () => {
  const f = fixture(1, 1);
  try {
    f.advance(1001); // Past the activity cooldown, so the first input probes.
    f.stopForwarding();
    const probes = f.probes;
    if (typing) f.connection.send(1, { type: "Input", inSeq: 0n, bytes: new Uint8Array([1]) });
    else f.connection.sampleRoundTrip();
    expect(f.probes).toBe(probes + 1);
    // Virtual-clock schedules, not host timing. Busy-page tasks and background
    // timer batches must not renew peer proof.
    for (let elapsed = 0; elapsed < 600_000; elapsed += interval) {
      f.suspend(interval);
      f.runBrowserTimer(true);
      if (!f.connection.isWelcomed) break;
      if (typing) f.connection.send(1, { type: "Input", inSeq: BigInt(elapsed / interval + 1), bytes: new Uint8Array([1]) });
    }
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

test("continuous typing cannot cancel every silent-route confirmation turn", () => {
  const f = fixture(1, 1);
  try {
    silentProbe(f);
    // An input task is queued between each overdue liveness callback and its
    // zero-delay confirmation. D300 gives two A=250ms misses; one local stall
    // observation and at most three G=75ms task gaps bound retirement.
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

for (const kind of ["duplicate", "wrong timestamp", "unknown nonce"] as const) test(`${kind} replies cannot replenish consumed stall grace`, () => {
  const f = fixture(1, 1);
  try {
    f.advance(1);
    const answered = f.latestProbe;
    f.stopForwarding();
    f.connection.sampleRoundTrip();
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

test("correlated replies replenish stall grace across successive healthy stalls", () => {
  const f = fixture(1, 1);
  try {
    f.advance(1);
    f.stopForwarding();
    for (let cycle = 0; cycle < 10; cycle++) {
      f.connection.sampleRoundTrip();
      f.suspend(1000);
      f.runBrowserTimer(true);
      f.replyLatest();
      expect(f.connection.isWelcomed).toBe(true);
    }
    f.connection.sampleRoundTrip();
    // With replies gone, subsequent late callbacks still consume the bound.
    for (let tick = 0; tick < 3 && f.connection.isWelcomed; tick++) {
      f.suspend(1000);
      f.runBrowserTimer(true);
    }
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

test("a queued correlated reply cancels confirmation without letting a duplicate renew it", () => {
  const f = fixture(1, 1);
  try {
    silentProbe(f);
    f.suspend(1000);
    f.runBrowserTimer(true); // Consume local grace.
    f.suspend(250);
    f.runBrowserTimer(true); // Arm confirmation before the socket task; it stays queued.
    const answered = f.latestProbe;
    f.replyLatest();
    expect(f.connection.isWelcomed).toBe(true);
    expect(f.disconnects).toBe(0);
    f.advance(30);
    expect(f.confirmationPending).toBe(false);
    f.connection.sampleRoundTrip();
    for (let cycle = 0; cycle < 5 && f.connection.isWelcomed; cycle++) {
      f.suspend(1000);
      f.receive(0, { type: "Pong", ...answered });
      f.runBrowserTimer(true);
    }
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

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
    f.welcomeLatest(); // The replacement route probes once on Welcome.
    f.replyLatest(); // Learn its short response allowance while it is healthy.
    f.connection.sampleRoundTrip(); // A fresh unanswered probe for the silence control.
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

test("a replacement route receives its own one-shot local stall grace", () => {
  const f = fixture(1, 1);
  try {
    silentProbe(f);
    f.suspend(1000);
    f.runBrowserTimer(true); // Consume the old route's grace.
    f.connection.forceDrop();
    f.advance(1000);
    f.welcomeLatest(); // First probe on the replacement route, A = 2000ms.
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

test("a delayed local task gets one stall grace without proving peer loss", () => {
  const f = fixture(1, 1);
  try {
    f.advance(1);
    f.stopForwarding();
    f.connection.sampleRoundTrip();
    f.suspend(f.responseAllowance + 1000);
    f.runBrowserTimer(true);
    expect(f.connection.isWelcomed).toBe(true);
    f.advance(f.responseAllowance / 2 + 1);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

test("legacy application pings are answered without starting a client probe", () => {
  const f = fixture(1, 1);
  try {
    f.advance(1);
    const probes = f.probes;
    f.receive(0, { type: "Ping", nonce: 9n, sentUs: 9n });
    expect(f.probes).toBe(probes);
    expect(f.clientTimers).toBe(0);
  } finally { f.dispose(); }
});

for (const suspension of [5000, 30_000]) test(`a hidden page resumes its lease after ${suspension}ms`, () => {
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

test("a delayed return probe survives one retransmission within the D300 allowance", () => {
  const f = fixture(150, 28);
  try {
    f.advance(10_000);
    f.setHidden(true);
    f.suspend(30_000);
    // Ordered delivery on a reliable transport: one delayed reply models a
    // retransmission delay without pretending to emulate packet loss.
    f.setReplyProfile(() => 600);
    f.setHidden(false);
    f.advance(600);
    expect(f.disconnects).toBe(0);
    expect(f.connection.isWelcomed).toBe(true);
    expect(f.clientTimers).toBe(0);
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


test("a layout subscription starts the connection before any terminal exists", () => {
  const f = fixture(30, 0, 4n, true);
  try { expect(f.connection.isWelcomed).toBe(true); } finally { f.dispose(); }
});

test("resync replaces one subscription ID and disposal prevents later resyncs", () => {
  const f = fixture(30, 0, 4n, true);
  try {
    let opens = 0;
    const subscription = f.connection.subscribe({ topic: "canvas.layout" }, () => {}, () => { opens++; });
    const id = f.subscriptionIds.at(-1);
    for (let n = 0; n < 100; n++) subscription.resync();
    expect(f.subscriptionIds.slice(-101)).toEqual(Array(101).fill(id));
    expect(opens).toBe(101);
    subscription(); subscription.resync();
    expect(opens).toBe(101); expect(f.sockets).toBe(1);
  } finally { f.dispose(); }
});

test("resync reopens a feature subscription with the same server ID", () => {
  const f = fixture(30, 1);
  try {
    let opened = 0;
    const before = f.subscriptionIds.length;
    const off = f.connection.subscribe({ topic: "canvas.layout" }, () => {}, () => { opened++; });
    expect(f.subscriptionIds).toHaveLength(before + 1);
    const subId = f.subscriptionIds.at(-1)!;
    expect(opened).toBe(1);
    off.resync();
    expect(f.subscriptionIds.slice(before)).toEqual([subId, subId]);
    expect(opened).toBe(2);
    off();
    off.resync();
    expect(f.subscriptionIds.slice(before)).toEqual([subId, subId]);
  } finally { f.dispose(); }
});

// The readout is cleared when a terminal attaches and must be refilled by the probe sent at that moment, even when
// an earlier probe (a focus or visibility return) was reported less than two seconds before. Without this the
// readout stayed on its "unavailable" mark until the next key press (#430).
test("an attach probe repopulates a cleared round-trip readout inside the report throttle", () => {
  const f = fixture(300, 1);
  try {
    f.advance(5_000); // let the probe sent at welcome settle, and leave its report far in the past
    const seen: Array<number | undefined> = [];
    f.connection.onRoundTrip((ms) => seen.push(ms));
    f.connection.sampleRoundTrip(); // the activation probe, answered and reported
    f.advance(300);
    expect(seen).toEqual([300]);
    f.connection.sampleRoundTrip(true); // the attach probe: the readout was just cleared, so its answer must show
    f.advance(300);
    expect(seen).toEqual([300, 300]);
    f.connection.sampleRoundTrip(); // an ordinary probe inside the window stays throttled
    f.advance(300);
    expect(seen).toEqual([300, 300]);
  } finally { f.dispose(); }
});
