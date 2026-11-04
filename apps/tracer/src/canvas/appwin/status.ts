/**
 * What an app window or a screen window honestly says about itself.
 *
 * A stream that has stopped must never look like a live picture frozen in place. Every state below therefore decides
 * three things at once: what the pill's status dot shows, whether the last picture stays (dimmed) or goes, and what
 * the window says in plain words, with the one thing the person can do about it.
 *
 * A picture that is not changing is not an error: the stream sends nothing while nothing changes (D254), so "no new
 * frame" never turns a live window into a stalled one. Only what the connection and the machine report moves a window
 * out of `live`: the socket dropping, the stream ending, a refusal, a missing permission.
 *
 * Control is a second, small axis (`ControlState`) shown quietly over a live picture, not a state of its own.
 *
 * Pure functions: unit-tested in `status.test.ts`.
 */
import type { WindowStatus } from "../../../../../packages/ui/src/window-card";

/** Where an app window's stream stands. Each kind is described on its own line. `permission`, `closed` and `unsupported` are final until the person acts. */
export type StreamState =
  /** Nothing asked yet (the window exists, the stream has not started). */
  | { kind: "idle" }
  /** The machine is being asked, or the stream is attaching, and no picture has arrived yet. */
  | { kind: "connecting" }
  | { kind: "live" }
  /** Not drawn on purpose (off screen, another view, the page hidden). The last picture, if any, stays dimmed. */
  | { kind: "paused" }
  /** The connection to infraternal dropped; the stream attaches again by itself. */
  | { kind: "reconnecting" }
  /** The app's window is gone from the machine (the app quit or the window closed). */
  | { kind: "closed" }
  /** macOS has not allowed what streaming needs. `what` is the permission's name in System Settings. */
  | { kind: "permission"; what: "Screen Recording" | "Accessibility" }
  /** This browser cannot decode the stream. */
  | { kind: "unsupported"; reason: "decoder" | "canvas" | "codec" }
  /** Anything else that went wrong; `retry` starts it again. */
  | { kind: "failed"; reason: "unreachable" | "refused" | "decode" };

/** Who is driving the machine, as far as this window knows. */
export type ControlState =
  | { kind: "none" }
  /** Control was asked for and not yet approved. */
  | { kind: "requesting" }
  | { kind: "controlled" }
  /** The person may watch but not control (no control right, or another viewer holds control). */
  | { kind: "view-only"; why: "rights" | "other-viewer" }
  /** Someone is using the machine; remote input waits (D208 A3: local input wins for 2 s). */
  | { kind: "paused"; untilMs: number };

/** What the window draws for a stream state: the dot, whether the last picture stays, and an optional card or strip. Made by `describe`. */
export interface StateView {
  /** The pill's status dot. */
  dot: WindowStatus;
  /** The last picture stays, dimmed. False hides it (nothing true to show). */
  keepPicture: boolean;
  /** A centred card over the window, when the state needs the whole window to speak. */
  card?: { mark: "spinner" | "alert" | "lock" | "window" | "unsupported" | "offline"; title: string; hint?: string; action?: { label: string; id: "retry" | "close" } };
  /** A small strip over a live picture. */
  strip?: { mark: "paused" | "offline" | "alert"; text: string };
}

/** The sentence for a permission, in the words System Settings uses, with where to go. */
export function permissionHint(what: "Screen Recording" | "Accessibility", machine: string): string {
  return what === "Screen Recording"
    ? `On ${machine}, open System Settings, Privacy & Security, Screen Recording and allow infraternal. Then try again.`
    : `Controlling ${machine} needs Accessibility. On ${machine}, open System Settings, Privacy & Security, Accessibility and allow infraternal. You can still watch.`;
}

/** Turns a stream state into what the window shows, in plain words. `ctx` names the machine and app, and says whether this is a whole-screen window. */
export function describe(state: StreamState, ctx: { machine: string; app: string; screen: boolean }): StateView {
  const subject = ctx.screen ? "the screen" : ctx.app;
  switch (state.kind) {
    case "idle":
    case "connecting":
      return { dot: "connecting", keepPicture: false, card: { mark: "spinner", title: `Opening ${subject}`, hint: `Asking ${ctx.machine}` } };
    case "live":
      return { dot: "live", keepPicture: true };
    case "paused":
      return { dot: "live", keepPicture: true, strip: { mark: "paused", text: "Paused" } };
    case "reconnecting":
      return { dot: "connecting", keepPicture: true, strip: { mark: "offline", text: "Reconnecting" } };
    case "closed":
      return { dot: "offline", keepPicture: false, card: { mark: "window", title: ctx.screen ? "The screen is not available" : `${ctx.app} was closed`, hint: ctx.screen ? `${ctx.machine} stopped sharing it.` : `The window is gone from ${ctx.machine}.`, action: { label: "Close window", id: "close" } } };
    case "permission":
      return { dot: "offline", keepPicture: false, card: { mark: "lock", title: `${ctx.machine} needs permission`, hint: permissionHint(state.what, ctx.machine), action: { label: "Try again", id: "retry" } } };
    case "unsupported":
      return { dot: "offline", keepPicture: false, card: { mark: "unsupported", title: "This browser can't show app windows", hint: state.reason === "codec" ? "It cannot decode this video format. A current Chrome, Edge, Safari or Firefox can." : "It needs video decoding in the page. A current Chrome, Edge, Safari or Firefox can." } };
    case "failed":
      return { dot: "offline", keepPicture: false, card: { mark: state.reason === "unreachable" ? "offline" : "alert", title: state.reason === "unreachable" ? `${ctx.machine} can't be reached` : state.reason === "decode" ? "The picture could not be decoded" : "Couldn't open it", ...(state.reason === "refused" ? { hint: `${ctx.machine} did not start the stream. It may be off or asleep.` } : {}), action: { label: "Try again", id: "retry" } } };
  }
}

/** The quiet line over a live picture about control, or nothing. */
export function controlLine(control: ControlState, machine: string): { text: string; mark: "controlled" | "view" | "paused" } | undefined {
  switch (control.kind) {
    case "none": return undefined;
    case "requesting": return { text: "Taking control", mark: "controlled" };
    case "controlled": return { text: "Controlled from infraternal", mark: "controlled" };
    case "view-only": return { text: control.why === "rights" ? "View only" : "Another viewer is in control", mark: "view" };
    case "paused": return { text: `Paused while someone uses ${machine}`, mark: "paused" };
  }
}

/** Whether the stream may be asked for again after `state` (the Try again action), or is final. */
export const retryable = (state: StreamState): boolean => state.kind === "failed" || state.kind === "permission";

/**
 * The next state when the connection to the server drops or returns. A window that was never live starts over
 * (connecting); one that was live keeps its picture and says it is reconnecting. A final state stays final.
 */
export function onConnection(state: StreamState, up: boolean, hadPicture: boolean): StreamState {
  if (state.kind === "closed" || state.kind === "unsupported" || state.kind === "permission") return state;
  if (!up) return state.kind === "idle" || state.kind === "paused" ? state : hadPicture ? { kind: "reconnecting" } : { kind: "connecting" };
  return state.kind === "reconnecting" ? { kind: "connecting" } : state;
}
