/** The pool that spreads terminals over sockets (the server takes 32 per socket): where each terminal goes, and when a socket is reused. */
import { expect, test } from "bun:test";
import { ConnectionPool, MuxConnection, STREAMS_PER_SOCKET } from "./connection";

const made: MuxConnection[] = [];
const make = (): MuxConnection => { const c = {} as MuxConnection; made.push(c); return c; };

test("terminals fill the first socket, then open another, and a released slot is reused first", () => {
  made.length = 0;
  const primary = {} as MuxConnection;
  const pool = new ConnectionPool(primary, make);
  const first = Array.from({ length: STREAMS_PER_SOCKET }, () => pool.acquire());
  expect(first.every((c) => c === primary)).toBe(true);
  expect(pool.sockets).toBe(1);
  const next = pool.acquire();
  expect(next).not.toBe(primary);
  expect(made).toEqual([next]);
  pool.release(primary);
  expect(pool.acquire()).toBe(primary); // the freed slot on the first socket, not a third socket
  expect(pool.sockets).toBe(2);
});

test("54 windows need two sockets, and the pool stops opening sockets at its cap", () => {
  made.length = 0;
  const pool = new ConnectionPool({} as MuxConnection, make);
  for (let i = 0; i < 54; i++) pool.acquire();
  expect(pool.sockets).toBe(2);
  for (let i = 0; i < 12 * STREAMS_PER_SOCKET + 20; i++) pool.acquire();
  expect(pool.sockets).toBe(12); // the server allows 16 sockets per person; the pool never takes more than 12
});
