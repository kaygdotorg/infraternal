/** Production app-window fixture supports shared-layout startup and reconnect using the existing reducer (#146). */
import { expect, test } from "bun:test";
import type { WebSocket } from "ws";
import { decodeMuxedFrame, type WireFrame } from "../../../packages/protocol/src/codec";

test("layout initialization, ordered edits, duplicate receipts and reconnect snapshots", async () => {
  const previous = process.env.TRACER_DOUBLE_APPWIN;
  process.env.TRACER_DOUBLE_APPWIN = "1";
  const { appwinLayoutFrame, appwinSocketClosed } = await import("./appwin-double");
  if (previous === undefined) delete process.env.TRACER_DOUBLE_APPWIN;
  else process.env.TRACER_DOUBLE_APPWIN = previous;
  const frames: WireFrame[] = [];
  const socket = { readyState: 1, send(bytes: Uint8Array) { frames.push(decodeMuxedFrame(bytes).frame); } } as unknown as WebSocket;
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
  appwinSocketClosed(socket);
});
