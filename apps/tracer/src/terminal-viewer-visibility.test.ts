/** A window tells the server when its viewer is hidden, so the host stops probing its shim (#562, D265). */
import { expect, test } from "bun:test";
import { TerminalClient } from "./terminal";

/** The private surface of a terminal client that these tests drive. */
type Probe = { reportViewerVisibility(): void; attached: boolean; closed: boolean; suspended: boolean; streamId: number; conn: { acceptsViewerVisibility: boolean }; sendFrame(id: number, frame: { type: string; eventJson?: Uint8Array }): void };

/** A client already attached on stream 7, hidden, whose sent frames are recorded in `sent`. */
function client(over: Partial<Probe>, sent: { id: number; frame: { type: string; eventJson?: Uint8Array } }[]): Probe {
  const terminal = Object.create(TerminalClient.prototype) as Probe;
  return Object.assign(terminal, { attached: true, closed: false, suspended: true, streamId: 7, conn: { acceptsViewerVisibility: true }, sendFrame(id: number, frame: { type: string; eventJson?: Uint8Array }) { sent.push({ id, frame }); } }, over);
}

/** The JSON of an Event frame's payload. */
const topic = (json: Uint8Array | undefined): unknown => JSON.parse(new TextDecoder().decode(json));

test("an attached hidden window reports hidden on its own stream, and shown when it returns", () => {
  const sent: { id: number; frame: { type: string; eventJson?: Uint8Array } }[] = [];
  const terminal = client({}, sent);
  terminal.reportViewerVisibility();
  terminal.suspended = false;
  terminal.reportViewerVisibility();
  expect(sent.map((s) => [s.id, s.frame.type, topic(s.frame.eventJson)])).toEqual([
    [7, "Event", { topic: "terminal.visibility", hidden: true }],
    [7, "Event", { topic: "terminal.visibility", hidden: false }],
  ]);
});

test("nothing is sent before the attach, after close, or to a server without visibility notices", () => {
  for (const over of [{ attached: false }, { closed: true }, { conn: { acceptsViewerVisibility: false } }] as Partial<Probe>[]) {
    const sent: { id: number; frame: { type: string } }[] = [];
    client(over, sent).reportViewerVisibility();
    expect(sent).toEqual([]);
  }
});
