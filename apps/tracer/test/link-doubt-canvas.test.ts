// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Break-it #234 r2: the kept-link doubt indicator must reach the person on the
 * canvas, the product surface. There the terminal's status element is the
 * detached relay element (canvas/status.ts): it drops routine "…" states and
 * leaves them to the window's status icon, which follows the terminal hooks.
 * `terminal.link_doubt` only writes "Reconnecting…" into that element and calls
 * no hook, so on the canvas nothing changes while the link is doubted.
 */
import { expect, test } from "bun:test";
import { createStatusRelay } from "../src/canvas/status";
import { TerminalClient } from "../src/terminal";
import type { WireFrame } from "../../../packages/protocol/src/codec";

const SESSION = "00000000-0000-0000-0000-000000000000";

test("on the canvas a doubted link changes the toast or the window's connection state", () => {
  const toasts: string[] = [];
  const signals: string[] = [];
  const element = { hidden: true, textContent: "" };
  const callbacks: Array<() => void> = [];
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { document: globals.document, MutationObserver: globals.MutationObserver };
  try {
    globals.document = { createElement: () => element, querySelectorAll: () => [] };
    globals.MutationObserver = class { constructor(callback: () => void) { callbacks.push(callback); } observe() {} disconnect() {} };
    createStatusRelay({ show: (value: { message: string }) => toasts.push(value.message), dismiss() {}, dispose() {} } as never);
    // The relay observes mutations; forward each status write to it.
    const status = {
      get textContent() { return element.textContent; },
      set textContent(value: string) { element.textContent = value; for (const callback of callbacks) callback(); },
      get hidden() { return element.hidden; },
      set hidden(value: boolean) { element.hidden = value; },
    };
    const client = Object.assign(Object.create(TerminalClient.prototype), {
      closed: false, attached: true, attachmentConfirmed: true, sessionGone: false,
      suppressReplayResponses: false, replayResponseFence: undefined,
      streamId: 1, lastOutSeq: 0n, receivedOutSeq: 0n, sessionId: new Uint8Array(16),
      config: {
        status,
        hooks: { onDisconnected: () => signals.push("disconnected"), onAttached: () => signals.push("attached"), onLinkDoubt: (doubted: boolean) => signals.push(`doubt:${doubted}`) },
        onConnectionChange: (connected: boolean) => signals.push(`connection:${connected}`),
      },
      conn: { streamAttached: (ready: boolean) => signals.push(`stream:${ready}`) },
      protocolFailure: (message: string) => signals.push(`failure:${message}`),
    }) as { handleTerminalFrame(frame: WireFrame, message: Uint8Array, at: number): void };
    client.handleTerminalFrame({
      type: "Event", subId: 0,
      eventJson: new TextEncoder().encode(JSON.stringify({ type: "terminal.link_doubt", session_id: SESSION })),
    }, new Uint8Array(), 0);
    expect(element.textContent).toBe("Reconnecting…");
    // Something the person can see must change: a toast, or a hook the status icon follows.
    expect({ toasts, signals }).not.toEqual({ toasts: [], signals: [] });
  } finally {
    for (const key of ["document", "MutationObserver"] as const) {
      if (original[key] === undefined) delete globals[key]; else globals[key] = original[key];
    }
  }
});
