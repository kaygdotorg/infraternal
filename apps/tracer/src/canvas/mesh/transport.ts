/** The product's `MeshTransport`: the one multiplexed connection (`src/connection.ts`, D183). */
import type { MuxConnection } from "../../connection";
import type { MeshTransport } from "./protocol";

/** Adapts the page's one connection to the `MeshTransport` the Mesh uses. Calls fail at once while the socket is down, and the Mesh starts asking only after a terminal is attached. */
export function connectionTransport(connection: MuxConnection): MeshTransport {
  return {
    // A frame sent while the socket is down is dropped and its call would wait for the next drop; failing at once
    // lets the source say "could not reach the server" and retry when the connection is back.
    call: (action, input) => (connection.isWelcomed ? connection.call(action, input) : Promise.reject(new Error("not connected"))),
    // The Mesh asks only once a terminal is attached: the shell comes first and a Mesh failure never delays it.
    onReady: (listener) => connection.onTerminalAttached(listener),
    subscribe: (topic, onEvent, onOpen) => connection.subscribe({ topic }, onEvent, onOpen),
  };
}
