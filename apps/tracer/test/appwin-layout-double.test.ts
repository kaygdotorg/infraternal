/** Production app-window fixture supports shared-layout startup and reconnect using the existing reducer (#146). */
import { expect, test } from "bun:test";
import type { WebSocket } from "ws";
import { decodeMuxedFrame, type WireFrame } from "../../../packages/protocol/src/codec";

test("layout initialization, ordered edits, duplicate receipts and reconnect snapshots", async () => {
  // The layout is served in every mode (the product canvas needs it to connect), so no app-window variable is set here.
  const { appwinLayoutFrame, appwinLayoutReset, appwinSocketClosed } = await import("./appwin-double");
  const frames: WireFrame[] = [];
  let terminated = false;
  const socket = { readyState: 1, terminate() { terminated = true; }, send(bytes: Uint8Array) { frames.push(decodeMuxedFrame(bytes).frame); } } as unknown as WebSocket;
  const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
  const events = (): Array<Record<string, unknown>> => frames.flatMap((frame) => frame.type === "Event" ? [JSON.parse(new TextDecoder().decode(frame.eventJson)) as Record<string, unknown>] : []);
  const subscribe: WireFrame = { type: "Subscribe", subId: 7, filterJson: json({ topic: "canvas.layout" }) };
  expect(appwinLayoutFrame(socket, subscribe)).toBe(true);
  expect(events().at(-1)!.initialized).toBe(false);
  const document = { format: "infraternal.canvas", version: 1, revision: 0, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } }] };
  expect(appwinLayoutFrame(socket, { type: "Call", callId: 1, actionId: "canvas.layout.initialize", inputJson: json({ op_id: "initialize", document }) })).toBe(true);
  expect(events().at(-1)).toMatchObject({ type: "canvas.layout.snapshot", initialized: true, revision: 1 });
  const edit: WireFrame = { type: "Call", callId: 2, actionId: "canvas.layout.apply", inputJson: json({ op_id: "rename", intent: { type: "view.update", view_id: "console", name: "Renamed" } }) };
  expect(appwinLayoutFrame(socket, edit)).toBe(true);
  expect(events().at(-1)).toMatchObject({ type: "canvas.layout.operation", revision: 2 });
  const count = events().length;
  appwinLayoutFrame(socket, edit);
  expect(events()).toHaveLength(count);
  appwinSocketClosed(socket);
  frames.length = 0;
  appwinLayoutFrame(socket, subscribe);
  expect(events().at(-1)).toMatchObject({ revision: 2, document: { views: [{ name: "Renamed" }] } });
  appwinLayoutReset();
  // Closing an old page can leave layout edits buffered in the latency proxy.
  // A new account fixture must retire its transport before accepting those edits.
  expect(terminated).toBe(true);
  const freshSocket = { readyState: 1, send(bytes: Uint8Array) { frames.push(decodeMuxedFrame(bytes).frame); } } as unknown as WebSocket;
  frames.length = 0;
  appwinLayoutFrame(freshSocket, subscribe);
  expect(events().at(-1)).toMatchObject({ revision: 0, initialized: false, document: { views: [] } });
  appwinSocketClosed(freshSocket);
});

test("a check can read the saved layout and replace it as another device would", async () => {
  const { appwinLayoutFrame, appwinLayoutRead, appwinLayoutReplace, appwinLayoutReset, appwinSocketClosed } = await import("./appwin-double");
  appwinLayoutReset();
  const frames: WireFrame[] = [];
  const socket = { readyState: 1, send(bytes: Uint8Array) { frames.push(decodeMuxedFrame(bytes).frame); } } as unknown as WebSocket;
  const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
  const events = (): Array<Record<string, unknown>> => frames.flatMap((frame) => frame.type === "Event" ? [JSON.parse(new TextDecoder().decode(frame.eventJson)) as Record<string, unknown>] : []);
  expect(appwinLayoutRead().initialized).toBe(false);
  appwinLayoutFrame(socket, { type: "Subscribe", subId: 9, filterJson: json({ topic: "canvas.layout" }) });
  const document = { format: "infraternal.canvas", version: 1, revision: 0, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } }] };
  expect(appwinLayoutReplace({ views: "not a layout" }), "an invalid document is refused and changes nothing").toBe(false);
  expect(appwinLayoutRead().initialized).toBe(false);
  expect(appwinLayoutReplace(document)).toBe(true);
  expect(appwinLayoutRead()).toMatchObject({ initialized: true, document: { revision: 1, views: [{ id: "console" }] } });
  expect(events().at(-1), "subscribers receive the replaced layout").toMatchObject({ type: "canvas.layout.snapshot", initialized: true, revision: 1 });
  appwinSocketClosed(socket);
  appwinLayoutReset();
});
