/** Key -> Ack timing of one terminal (#569, D130): what predictive echo decides on instead of the browser<->server ping. */
import { expect, test } from "bun:test";
import { KeyAckRtt } from "./key-ack-rtt";

/** Types `keys` one byte each, `gap` ms apart, and acknowledges each `rtt` ms after it was sent. */
function type(timer: KeyAckRtt, keys: number, gap: number, rtt: number): void {
  let sequence = 0n;
  for (let i = 0; i < keys; i += 1) {
    const at = 1000 + i * gap;
    timer.sent(sequence, 1, at);
    timer.acked(sequence + 1n, at + rtt);
    sequence += 1n;
  }
}

test("a host 150 ms behind a server 4.6 ms away reads as 150 ms, far above the prediction threshold", () => {
  const timer = new KeyAckRtt();
  expect(timer.p90).toBeUndefined();
  // The connection's own ping would say 4.6 ms here; the key's Ack says what the whole path costs.
  type(timer, 20, 120, 150);
  expect(timer.p90).toBe(150);
  expect(timer.p90!).toBeGreaterThan(60);
});

test("the figure is the 90th percentile, so a Wi-Fi tail shows where a mean would hide it", () => {
  const timer = new KeyAckRtt();
  let sequence = 0n;
  // Four keys in five take 20 ms; one in five takes 200 ms. The mean is 56 ms (below the 60 ms threshold), the p90 is not.
  for (let i = 0; i < 30; i += 1) {
    timer.sent(sequence, 1, 1000 + i * 100);
    timer.acked(sequence + 1n, 1000 + i * 100 + (i % 5 === 4 ? 200 : 20));
    sequence += 1n;
  }
  expect(timer.p90).toBe(200);
});

test("the window forgets old keys, so a host that gets closer reads as close", () => {
  const timer = new KeyAckRtt();
  type(timer, 40, 120, 150);
  type(timer, 40, 120, 10);
  expect(timer.p90!).toBe(10);
});

test("one Ack for a batch of keys times only the newest", () => {
  const timer = new KeyAckRtt();
  timer.sent(0n, 1, 1000);
  timer.sent(1n, 1, 1100);
  timer.sent(2n, 1, 1200);
  expect(timer.acked(3n, 1350)).toBe(150);
});

test("an Ack that covers no timed key, or arrives after a reset, gives no sample", () => {
  const timer = new KeyAckRtt();
  expect(timer.acked(5n, 100)).toBeUndefined();
  timer.sent(0n, 1, 1000);
  timer.reset();
  expect(timer.acked(1n, 1100)).toBeUndefined();
  expect(timer.p90).toBeUndefined();
});

test("a sample from input held across a stall is discarded", () => {
  const timer = new KeyAckRtt();
  timer.sent(0n, 1, 1000);
  expect(timer.acked(1n, 9000)).toBeUndefined();
  expect(timer.p90).toBeUndefined();
});
