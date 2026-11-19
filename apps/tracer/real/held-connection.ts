// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Protocol connections held from the spec runner, as stand-ins for tabs the person forgot (#523).
 *
 * The real-server specs about the account's connection limit fill the account with these: each sends the same Hello
 * a tab sends, answers the server's pings so it stays live, and never says it is hidden, so the server never takes
 * one over for a newer page.
 */
import type { BrowserContext } from "playwright/test";
import { WebSocket } from "ws";
import { encodeMuxedFrame, WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import type { RealServer } from "./server";

/** The per-account cap in crates/infraternal-server/src/websocket.rs (`new_connection`). */
export const ACCOUNT_SOCKETS = 16;

/** One welcomed protocol connection of the signed-in account that answers pings until `close` (a tab that stays open). */
export async function holdConnection(server: RealServer, context: BrowserContext): Promise<{ close(): void }> {
  const cookie = (await context.cookies()).map((c) => `${c.name}=${c.value}`).join("; ");
  const socket = new WebSocket(server.backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: server.origin, Cookie: cookie } });
  const decoder = new WebSocketFrameDecoder();
  const send = (frame: Parameters<typeof encodeMuxedFrame>[1]): void => { socket.send(encodeMuxedFrame(0, frame)); };
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(Error("held connection was not welcomed")), 15_000);
    socket.on("error", () => { clearTimeout(timer); reject(Error("held connection failed")); });
    socket.on("close", () => { clearTimeout(timer); reject(Error("held connection closed before its welcome")); });
    socket.on("message", (bytes) => decoder.feed(new Uint8Array(Buffer.from(bytes as Buffer)), (_stream, frame) => {
      if (frame.type === "Hello") send({ type: "Hello", version: 1, caps: 0n, clientInfo: "connection-limit-spec" });
      if (frame.type === "Ping") send({ ...frame, type: "Pong" });
      if (frame.type === "Welcome") { clearTimeout(timer); resolve(); }
    }));
  });
  return { close: () => { socket.close(1000, "spec done"); } };
}
