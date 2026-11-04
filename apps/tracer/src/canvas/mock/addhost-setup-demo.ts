// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The scripted add-host run for the machine-pill mockup (D255, #189). Mock only; reached with
 * `?mock=1&proto=windows&addhost-demo=pill` (add `&fail=join` for a failing stage; `install`, `join`, `start` and
 * `ready` are accepted).
 *
 * What it plays, with the real wizard on screen:
 *   1. the wizard's own progress page for about 1.5 s (check, sign in, upload), as a server would report it;
 *   2. `done` at 1.5 s: the shell is attachable. The wizard hands the host to the canvas, the window opens with a live
 *      prompt, and the wizard's status flies into the window's machine pill (setup-pill.on-demand.ts);
 *   3. the background stages (install, join, start, ready) as setup events, one after another, each with the timing
 *      of a real step. Nothing in the product is timed: this file is the "server" and the only place that has clocks.
 *
 * `scriptedProvisioning` wraps the mock provisioning service so that every host started in this tab follows the script
 * (including a host the person picks themselves). The autopilot only exists so the demo URL runs by itself: it presses
 * the same controls a person would (open the wizard, pick the Ubuntu host `o2`, press Continue).
 */
import { randomUuid } from "../../identifiers";
import type { ProvisioningRun, ProvisioningHandlers, BootstrapEvent, StartTarget } from "../../provisioning-client";
import type { ProvisioningService } from "../addhost/service";
import { SETUP_STAGES, type SetupEvent, type SetupStageId } from "../addhost/setup-stages";
import type { SetupSource } from "../addhost/setup-pill.on-demand";

/** How long each background stage takes in the mock (ms). The first prompt arrives at `PROMPT_MS`. */
export const PROMPT_MS = 1500;
/** How long each background stage takes in the demo, in milliseconds. */
const STAGE_MS: Record<SetupStageId, number> = { install: 1500, join: 1300, start: 1100, ready: 900 };
/** The step a failing stage reports, as the server would name it. */
const STEP_OF: Record<SetupStageId, NonNullable<SetupEvent["failedStep"]>> = { install: "install", join: "join", start: "start", ready: "readiness" };
/** The server-style text a failing stage reports in the demo. */
const MESSAGE_OF: Record<SetupStageId, string> = {
  install: "Package install exited with status 100.",
  join: "Timed out waiting for the host to join the mesh (60 s).",
  start: "infraternal-agent.service failed to start: exit status 203.",
  ready: "The terminal session did not reattach within 30 s.",
};

/** The scripted setup run: the event `source` the pill subscribes to, a `wrap` that makes a provisioning service follow the script, and which stage fails first. */
export interface SetupDemo {
  source: SetupSource;
  wrap(service: ProvisioningService): ProvisioningService;
  /** Which stage fails the first time it runs; `try again` then succeeds. */
  readonly failStage: SetupStageId | undefined;
  dispose(): void;
}

/** `slow` stretches every timing (`&slow=3` for stills), the wait for the prompt included. */
export function createSetupDemo(failStage: SetupStageId | undefined, slow = 1): SetupDemo {
  const history = new Map<string, SetupEvent[]>();
  const listeners = new Map<string, Set<(event: SetupEvent) => void>>();
  const failed = new Map<string, SetupStageId>();
  const timers = new Set<number>();
  let disposed = false;
  const later = (ms: number, fn: () => void): void => {
    const id = window.setTimeout(() => { timers.delete(id); if (!disposed) fn(); }, ms);
    timers.add(id);
  };
  const emit = (event: SetupEvent): void => {
    const list = history.get(event.hostId) ?? [];
    list.push(event);
    history.set(event.hostId, list);
    for (const listener of listeners.get(event.hostId) ?? []) listener(event);
  };

  /** Plays the stages from `from`; the failing stage reports a failure once and stops there. */
  const play = (hostId: string, from: number, shouldFail: boolean): void => {
    let at = 0;
    for (const stage of SETUP_STAGES.slice(from)) {
      later(at, () => emit({ hostId, stage, state: "running" }));
      if (shouldFail && failStage === stage) {
        later(at + STAGE_MS[stage] * slow * 0.7, () => {
          failed.set(hostId, stage);
          emit({ hostId, stage, state: "failed", failedStep: STEP_OF[stage], message: MESSAGE_OF[stage] });
        });
        return;
      }
      at += STAGE_MS[stage] * slow;
      later(at, () => emit({ hostId, stage, state: "done" }));
    }
  };

  const source: SetupSource = {
    subscribe(hostId, listener) {
      // The events so far, then the live ones: the window can open between two of them.
      for (const event of history.get(hostId) ?? []) listener(event);
      const set = listeners.get(hostId) ?? new Set();
      set.add(listener);
      listeners.set(hostId, set);
      return () => { set.delete(listener); };
    },
    retry(hostId) {
      const stage = failed.get(hostId);
      if (!stage) return;
      failed.delete(hostId);
      play(hostId, SETUP_STAGES.indexOf(stage), false);
    },
  };

  /** One wizard run: the events a server sends until the shell is ready, then the background stages. */
  class ScriptedRun {
    private ended = false;
    private sequence = 0;
    private readonly targets = new Map<string, { attempt: number; hostId: string }>();
    constructor(private readonly handlers: ProvisioningHandlers) {}
    get open(): boolean { return !this.ended; }
    get lastSequence(): number { return this.sequence; }
    private send(id: string, step: BootstrapEvent["step"], message: string, extra: Partial<BootstrapEvent> = {}): void {
      const target = this.targets.get(id)!;
      this.sequence += 1;
      this.handlers.onEvent({ sequence: this.sequence, target: id, attempt: target.attempt, step, message, elapsed_ms: 0, log_tail: [], ...extra });
    }
    start(targets: StartTarget[]): void {
      for (const target of targets) {
        this.targets.set(target.id, { attempt: 0, hostId: randomUuid() });
        const at = (ms: number, fn: () => void): void => later(ms, () => { if (!this.ended) fn(); });
        at(150 * slow, () => this.send(target.id, "check", "Checking SSH and host support."));
        at(450 * slow, () => this.send(target.id, "check", "Signed in.", { authentication: { method: "network", network: "netbird" } }));
        at(800 * slow, () => this.send(target.id, "install", "Uploading the infraternal agent."));
        at(PROMPT_MS * slow, () => {
          const { hostId } = this.targets.get(target.id)!;
          // `done` is "the shell is attachable" (D255); the background stages follow as setup events.
          this.send(target.id, "done", "The shell is ready.", { host_id: hostId });
          play(hostId, 0, true);
        });
      }
    }
    retry(): void { /* the demo's retries are the pill's: setup events, not a new wizard attempt */ }
    startFresh(): void { /* leftovers are not part of this script */ }
    replay(): void { /* the script never drops events */ }
    confirmHostKey(): Promise<void> { return Promise.resolve(); }
    close(): void { if (!this.ended) { this.ended = true; this.handlers.onClose?.(); } }
  }

  return {
    source,
    failStage,
    wrap: (service) => ({ ...service, open: (handlers) => new ScriptedRun(handlers) as unknown as ProvisioningRun }),
    dispose() { disposed = true; for (const id of timers) window.clearTimeout(id); timers.clear(); },
  };
}

/** Parses `&fail=` from the query; anything but a stage name means the run succeeds. */
export function failStageFrom(value: string | null): SetupStageId | undefined {
  return SETUP_STAGES.find((stage) => stage === value);
}

/**
 * Presses the controls a person would: open the wizard, pick the Ubuntu host `o2`, press Continue. Resolves when the
 * progress page is up. Polls the DOM because the wizard's code and its discovery list arrive asynchronously.
 */
export async function runAutopilot(open: () => void, root: ParentNode = document): Promise<void> {
  const until = async <T>(find: () => T | null | undefined, what: string): Promise<T> => {
    for (let i = 0; i < 1200; i++) {
      const found = find();
      if (found) return found;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error(`add-host demo: ${what} did not appear`);
  };
  // `data-demo-step` says how far the autopilot got, for a person (or a spec) wondering why a run stalled.
  const step = (name: string): void => { document.documentElement.dataset.demoStep = name; };
  step("opening");
  // The wizard's code loads on first use; on a slow link or a busy host that can fail once, so the demo asks again.
  open();
  for (let i = 0; i < 40 && !root.querySelector(".ah"); i++) {
    await new Promise((resolve) => setTimeout(resolve, 250));
    if (i % 8 === 7 && !root.querySelector(".ah")) open();
  }
  step("picking");
  // The list can redraw once more when discovery answers, so the pick is repeated until the box is ticked.
  const ticked = (): HTMLInputElement | null => root.querySelector<HTMLInputElement>('.ah-row[data-host="o2"] input:checked');
  for (let i = 0; i < 400 && !ticked(); i++) {
    await new Promise((resolve) => setTimeout(resolve, 150));
    root.querySelector<HTMLElement>('.ah-page[data-page="discovery"] .ah-row[data-host="o2"]')?.click();
    if (ticked()) break;
  }
  step("continuing");
  const next = await until(() => root.querySelector<HTMLButtonElement>('.ah-float [data-ah="continue"]:not([disabled])'), "Continue");
  next.click();
  step("started");
}
