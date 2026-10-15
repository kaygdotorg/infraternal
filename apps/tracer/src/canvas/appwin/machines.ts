/**
 * The machines that can stream and what each one has open right now (D208 A1).
 *
 * A machine is a host the person can reach whose system is a Mac running the infraternal agent (macOS first, A6). Its
 * inventory is asked with `desktop.windows` and kept here with the time it was asked, so the picker, the palette and
 * the window states all read one copy. Nothing is asked unless someone is looking:
 * - the picker polls while it is open (the wire has no push for the list yet, so the list is live to within a poll);
 * - the palette asks again when it opens and the copy is stale;
 * - a stream that failed asks once, to explain itself.
 * A poll that changes nothing notifies nobody, so an open picker repaints only when the machine's windows changed.
 */
import type { HostEntry } from "../sessions/adapter";
import type { StreamConnection } from "./adapter";
import { parseInventory, sameInventory, type Inventory } from "./inventory";

export interface MachineState {
  machine: HostEntry;
  /** The last good answer. Kept through a failed poll, so the list does not vanish when the machine blinks. */
  inventory?: Inventory;
  status: "loading" | "ready" | "error";
  /** `performance.now()` of the last answer. */
  at: number;
}

/** A copy older than this is asked for again when someone looks. */
export const STALE_MS = 3000;
/** The picker's poll. */
export const POLL_MS = 2000;
/** An ask that gets no answer in this long is an error, so the next one can go. */
const ASK_TIMEOUT_MS = 8000;

/** Whether a host can stream: a Mac the person reaches through an agent (the embedded host is the server itself). */
export const canStream = (host: HostEntry): boolean => host.id !== "embedded" && host.os === "apple" && host.online !== false;

export class Machines {
  private readonly states = new Map<string, MachineState>();
  private readonly listeners = new Set<() => void>();
  private readonly inflight = new Map<string, Promise<void>>();
  private timer = 0;
  private pollers = 0;

  constructor(private readonly connection: StreamConnection, private readonly hosts: () => HostEntry[]) {}

  /** The hosts that can stream, in the canvas's own order. */
  streamable(): HostEntry[] { return this.hosts().filter(canStream); }

  state(id: string): MachineState | undefined { return this.states.get(id); }

  onChange(listener: () => void): () => void { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; }
  private emit(): void { for (const l of [...this.listeners]) l(); }

  /**
   * The call itself. A call made while the socket is down is never sent and would stay pending for ever (and, being shared,
   * would hold every later ask hostage), so it waits for the connection first and gives up after a few seconds.
   */
  private ask(machine: HostEntry): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      const timer = window.setTimeout(() => { off(); reject(new Error("no answer")); }, ASK_TIMEOUT_MS);
      let off = (): void => undefined;
      const go = (): void => {
        this.connection.call("desktop.windows", { host_id: machine.id }).then(
          (reply) => { window.clearTimeout(timer); resolve(reply); },
          (error: unknown) => { window.clearTimeout(timer); reject(error); },
        );
      };
      if (this.connection.isWelcomed) go();
      else { off = this.connection.onWelcome(() => { off(); go(); }); }
    });
  }

  /** Asks one machine. Concurrent asks share the answer. */
  refresh(machine: HostEntry): Promise<void> {
    const running = this.inflight.get(machine.id);
    if (running) return running;
    const before = this.states.get(machine.id);
    if (!before) { this.states.set(machine.id, { machine, status: "loading", at: 0 }); this.emit(); }
    const job = this.ask(machine).then(
      (reply) => {
        const inventory = parseInventory(reply);
        const prev = this.states.get(machine.id);
        const unchanged = prev?.status === "ready" && prev.inventory && sameInventory(prev.inventory, inventory);
        this.states.set(machine.id, { machine, inventory, status: "ready", at: performance.now() });
        if (!unchanged) this.emit();
      },
      () => {
        const prev = this.states.get(machine.id);
        this.states.set(machine.id, { machine, ...(prev?.inventory ? { inventory: prev.inventory } : {}), status: "error", at: performance.now() });
        this.emit();
      },
    ).finally(() => { this.inflight.delete(machine.id); });
    this.inflight.set(machine.id, job);
    return job;
  }

  /** Asks every streamable machine whose copy is older than `maxAge`. */
  refreshAll(maxAge = 0): void {
    const now = performance.now();
    for (const m of this.streamable()) {
      const s = this.states.get(m.id);
      if (!s || now - s.at >= maxAge) void this.refresh(m);
    }
  }

  /** Starts polling while something is looking (reference counted); `stop` ends it. Hidden pages ask nothing. */
  poll(): () => void {
    this.pollers++;
    this.refreshAll();
    if (!this.timer) {
      this.timer = window.setInterval(() => { if (!document.hidden) this.refreshAll(POLL_MS - 100); }, POLL_MS);
    }
    let stopped = false;
    return () => {
      if (stopped) return;
      stopped = true;
      if (--this.pollers <= 0) { window.clearInterval(this.timer); this.timer = 0; this.pollers = 0; }
    };
  }

  dispose(): void { window.clearInterval(this.timer); this.timer = 0; this.listeners.clear(); this.states.clear(); }
}
