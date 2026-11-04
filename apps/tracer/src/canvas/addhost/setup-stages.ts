// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The setup that continues after a host's shell is up (D255, #189): the pure rules the machine pill's ring follows.
 * Nothing here touches the DOM, so specs pin it.
 *
 * The real stream is `/v1/bootstrap/setup/ws` (contracts/host-setup.md); it also carries `session_id`, `window_id`,
 * `attempt`, `sequence` and `retry_available`. The UI resumes with `sequence` and offers retry only while the server
 * permits another attempt. `setup-feed.ts` is its client.
 *
 * Order of events for one host (D255): the wizard's socket reports `done` as soon as the shell is attachable (the
 * window opens with a live prompt). The infraternal agent then installs, joins and starts in the background. Each
 * background stage arrives as a *setup event*, keyed by the host's UUID, on whatever channel the server uses for the
 * host's status (the wizard's socket while it is open, the host's status stream afterwards). The UI needs only this
 * shape, and never invents progress from time:
 *
 *   { "setup": { "host_id": "<uuid>", "stage": "install" | "join" | "start" | "ready",
 *                "state": "running" | "done" | "failed", "retry_available": boolean,
 *                "failed_step"?: "connect" | "upload" | "install" | "join" | "start" | "readiness",   // with "failed"
 *                "message"?: "<the server's own words, shown only in details>" } }
 *
 * Stages arrive in order. A stage may report `running` then `done`, or `done` alone. `ready` is "the host is joined and
 * its terminal session is reattached through the infraternal agent". A `failed` event ends the run for that attempt; a
 * retry starts again from the failed stage with new `running` events. When `ready` is `done` the ring completes.
 */
export const SETUP_STAGES = ["install", "join", "start", "ready"] as const;
/** One of the four background stages after the shell is up, in the order they happen. */
export type SetupStageId = (typeof SETUP_STAGES)[number];
/** Where one stage stands. `pending` = not started; `failed` = the attempt ended in this stage. */
export type SetupStageState = "pending" | "running" | "done" | "failed";
/** The finer step that failed, as the server names it. Several steps map onto one stage (see `stageOfStep`). */
type FailedStep = "connect" | "upload" | "install" | "join" | "start" | "readiness";

/** One setup message from the server, already checked and renamed for the UI. */
export interface SetupEvent {
  hostId: string;
  stage: SetupStageId;
  state: "running" | "done" | "failed";
  failedStep?: FailedStep;
  /** The server's per-host counter, used to resume a dropped subscription after the last event seen. */
  sequence?: number;
  /** Server attempt eligibility; current authority and worker capacity still apply. */
  retryAvailable?: boolean;
  /** The server's own text. Shown in details only, never as the headline, and never matched on. */
  message?: string;
}

/** True for the server's `{ resync: true, host_id }` notice: the events that follow are the authoritative current stages. */
export function isResync(value: unknown, hostId: string): boolean {
  return isRecord(value) && value.resync === true && value.host_id === hostId;
}

/** What the ring and the popover draw for one host. */
export interface SetupView {
  stages: SetupStageState[];
  failedStep?: FailedStep;
  message?: string;
  /** Every stage is done. */
  complete: boolean;
  /** False when the server has exhausted setup attempts. */
  retryAvailable?: boolean;
}

/** A view with every stage pending: how a host starts before any event has arrived. */
export const freshSetup = (): SetupView => ({ stages: SETUP_STAGES.map(() => "pending"), complete: false });

/** The failed-step names the server may send. Any other name is ignored rather than trusted. */
const STEPS: readonly string[] = ["connect", "upload", "install", "join", "start", "readiness"];
/** A host id must look like a lower-case UUID, or the event is dropped. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** True for a plain object (not null, not an array). */
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

/** Reads one setup message defensively: the server's data is untrusted until shaped. Anything malformed is dropped. */
export function parseSetupEvent(value: unknown): SetupEvent | undefined {
  const body = isRecord(value) && isRecord(value.setup) ? value.setup : undefined;
  if (!body || typeof body.host_id !== "string" || !UUID.test(body.host_id)) return undefined;
  if (!SETUP_STAGES.includes(body.stage as SetupStageId) || typeof body.state !== "string" || !["running", "done", "failed"].includes(body.state)) return undefined;
  const event: SetupEvent = { hostId: body.host_id, stage: body.stage as SetupStageId, state: body.state as SetupEvent["state"] };
  if (event.state === "failed" && body.failed_step !== undefined) {
    if (typeof body.failed_step !== "string") return undefined;
    if (STEPS.includes(body.failed_step)) event.failedStep = body.failed_step as FailedStep;
  }
  if (Number.isSafeInteger(body.sequence) && Number(body.sequence) >= 0) event.sequence = Number(body.sequence);
  if (body.retry_available !== undefined) {
    if (typeof body.retry_available !== "boolean") return undefined;
    event.retryAvailable = body.retry_available;
  }
  if (typeof body.message === "string") event.message = body.message.slice(0, 500);
  return event;
}

/** The stage a failed step belongs to: uploading is part of installing; the final readiness check is `ready`. */
export function stageOfStep(step: FailedStep | undefined, fallback: SetupStageId): SetupStageId {
  switch (step) {
    case "connect": case "upload": case "install": return "install";
    case "join": return "join";
    case "start": return "start";
    case "readiness": return "ready";
    default: return fallback;
  }
}

/**
 * Folds one event into a host's setup view. Stages before the event's stage are done (a stage that skipped `running`
 * still finished); later stages stay pending, so a `running` event after a failure is the retry and clears it.
 */
export function foldSetup(view: SetupView, event: SetupEvent): SetupView {
  // The step names the stage that really failed; the event's own stage is only the one that was running.
  const at = SETUP_STAGES.indexOf(event.state === "failed" ? stageOfStep(event.failedStep, event.stage) : event.stage);
  const stages = SETUP_STAGES.map((_, i): SetupStageState => (i < at ? "done" : i === at ? event.state : "pending"));
  const failed = event.state === "failed";
  return {
    stages,
    complete: stages.every((state) => state === "done"),
    ...(failed ? { retryAvailable: event.retryAvailable, failedStep: event.failedStep ?? (event.stage === "ready" ? "readiness" : event.stage), ...(event.message ? { message: event.message } : {}) } : {}),
  };
}

/** The index in `SETUP_STAGES` of the failed stage, or -1 when no stage failed. */
export const failedIndex = (view: SetupView): number => view.stages.indexOf("failed");

/** Stage names for the pill's spoken label, in the words a person uses. */
export const SETUP_LABEL: Record<SetupStageId, string> = { install: "Installing", join: "Joining this server", start: "Starting", ready: "Getting ready" };

/** What to do next, per failed step. The title already says what happened, so this says only what to try (plain words). */
const NEXT: Record<FailedStep, string> = {
  connect: "Make sure the host is still on, then try again.",
  upload: "Try again.",
  install: "Try again, or open the details to see where it stopped.",
  join: "Try again in a moment.",
  start: "Try again, or open the details to see why.",
  readiness: "Try again in a moment.",
};

/**
 * What the pill's popover says about a failed stage, in plain words (TASTE: messages say what happens and what to do).
 * The new host's window is already live, so the first thing said is that the person's other sessions are untouched.
 */
export function setupGuide(host: string, view: SetupView): { title: string; effect: string; details: string } {
  const step = view.failedStep ?? "install";
  const title = ({
    connect: `The connection to ${host} dropped`,
    upload: `Copying to ${host} didn't finish`,
    install: `Installing on ${host} stopped`,
    join: `${host} couldn't join this server`,
    start: `The infraternal agent didn't start on ${host}`,
    readiness: `${host} isn't ready yet`,
  } satisfies Record<FailedStep, string>)[step];
  const next = view.retryAvailable === false ? "Setup has reached its retry limit. Remove this host, then add it again to start over." : NEXT[step];
  return { title, effect: `Your other sessions keep working. ${next}`, details: view.message ?? "" };
}
