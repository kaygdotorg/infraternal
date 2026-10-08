/**
 * TEST DOUBLE preview forwarder: exposes the loopback-only mock server on a LAN
 * address so mockups can be opened from a phone. The mock server binds
 * localhost on purpose (it sits behind the latency proxy in tests); this plain
 * TCP relay is for previews only and is never part of a product build.
 *
 * Usage: bun test/preview-forward.ts <listen-host> <listen-port> <target-port>
 */
type Side = { peer?: import("bun").Socket<Side>; queue: Uint8Array[] };

const [listenHost, listenPortText, targetPortText] = process.argv.slice(2);
const listenPort = Number(listenPortText);
const targetPort = Number(targetPortText);
if (!listenHost || !Number.isInteger(listenPort) || !Number.isInteger(targetPort)) {
  throw new Error("usage: bun test/preview-forward.ts <listen-host> <listen-port> <target-port>");
}

Bun.listen<Side>({
  hostname: listenHost,
  port: listenPort,
  socket: {
    open(client) {
      client.data = { queue: [] };
      void Bun.connect<Side>({
        hostname: "localhost",
        port: targetPort,
        socket: {
          open(upstream) {
            upstream.data = { peer: client, queue: [] };
            client.data.peer = upstream;
            for (const chunk of client.data.queue) upstream.write(chunk);
            client.data.queue = [];
          },
          data(upstream, chunk) { upstream.data.peer?.write(chunk); },
          close(upstream) { upstream.data.peer?.end(); },
          error(upstream) { upstream.data.peer?.end(); },
        },
      }).catch(() => client.end());
    },
    data(client, chunk) {
      if (client.data.peer) client.data.peer.write(chunk);
      else client.data.queue.push(new Uint8Array(chunk));
    },
    close(client) { client.data.peer?.end(); },
    error(client) { client.data.peer?.end(); },
  },
});
console.log(`preview forwarder ${listenHost}:${listenPort} -> localhost:${targetPort}`);
