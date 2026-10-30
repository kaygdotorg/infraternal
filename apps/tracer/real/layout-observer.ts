/** Observe layout protocol in test-runner RAM; browser storage is never used as a test/debug transport (D312). */
import type { Page } from "playwright/test";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { reduce, type Intent } from "../src/canvas/model/operations";
import type { CanvasDocument } from "../src/canvas/model/schema";
export interface ObservedLayout { initialized: boolean; canonical: CanvasDocument; document: CanvasDocument; pending: Array<{ op_id: string; intent: Intent; revision?: number; held?: boolean }> }
const states = new WeakMap<Page, ObservedLayout>();
const empty = (): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision: 0, views: [] });
function project(state: ObservedLayout): void {
  state.pending = state.pending.filter((p) => p.revision === undefined || p.revision > state.canonical.revision);
  state.document = structuredClone(state.canonical);
  for (const p of state.pending) if (!p.held) reduce(state.document, p.intent);
}
export function watchLayout(page: Page): Page {
  if (states.has(page)) return page;
  const state: ObservedLayout = { initialized: false, canonical: empty(), document: empty(), pending: [] };
  let generation = 0;
  states.set(page, state);
  page.on("request", (request) => {
    if (!request.isNavigationRequest() || request.frame() !== page.mainFrame()) return;
    generation++; state.initialized = false; state.pending = []; state.canonical = empty(); state.document = empty();
  });
  page.on("websocket", (socket) => {
    const epoch = generation, sent = new WebSocketFrameDecoder(), received = new WebSocketFrameDecoder();
    const calls = new Map<number, string>();
    socket.on("framesent", ({ payload }) => {
      if (epoch !== generation || typeof payload === "string") return;
      sent.feed(new Uint8Array(payload), (_stream, frame) => {
        if (frame.type !== "Call" || frame.actionId !== "canvas.layout.apply") return;
        const input = JSON.parse(new TextDecoder().decode(frame.inputJson)) as { op_id: string; intent: Intent };
        calls.set(frame.callId, input.op_id);
        if (!state.pending.some((p) => p.op_id === input.op_id)) { state.pending.push(input); project(state); }
      });
    });
    socket.on("framereceived", ({ payload }) => {
      if (epoch !== generation || typeof payload === "string") return;
      received.feed(new Uint8Array(payload), (_stream, frame) => {
        if (frame.type === "Event") {
          const event = JSON.parse(new TextDecoder().decode(frame.eventJson));
          if (event.type === "canvas.layout.snapshot") {
            if (event.revision < state.canonical.revision) return;
            state.initialized = true; state.canonical = event.document;
            for (const p of state.pending) if (p.revision === undefined) p.held = true;
          } else if (event.type === "canvas.layout.operation" && event.revision === state.canonical.revision + 1) {
            if (!event.noop) reduce(state.canonical, event.intent); state.canonical.revision = event.revision;
            state.pending = state.pending.filter((p) => p.op_id !== event.op_id);
          } else return;
        } else if (frame.type === "Result" && calls.has(frame.callId)) {
          const id = calls.get(frame.callId); calls.delete(frame.callId);
          const p = state.pending.find((p) => p.op_id === id);
          if (!frame.ok) state.pending = state.pending.filter((p) => p.op_id !== id);
          else if (p) { p.revision = JSON.parse(new TextDecoder().decode(frame.json)).revision; delete p.held; }
        } else return;
        // Terminal traffic must not trigger test-side layout replay or distort qualification.
        project(state);
      });
    });
  });
  return page;
}
export async function cache(page: Page): Promise<ObservedLayout> {
  const value = states.get(page); if (!value) throw Error("layout observer must be installed before navigation");
  return structuredClone(value);
}
