/**
 * The round trip of one terminal's own keys, measured from the key being sent to the infraternal agent's `Ack`
 * for it (#569, D130).
 *
 * Why it exists: the connection's ping measures browser <-> server only. A terminal on a host far behind a nearby
 * server (device 5 ms from the server, host 150 ms behind it) types over the whole path, so predictive echo that
 * decided on the ping never ran for it. The shim sends its `Ack` after the PTY write, so key -> `Ack` is the real
 * input path, and the host's own echo needs about the same time to come back. No wire change: the timestamps are
 * the ones the terminal already has.
 *
 * Use: call {@link KeyAckRtt.sent} for each input frame sent on a confirmed attachment, {@link KeyAckRtt.acked}
 * when an `Ack` arrives, and {@link KeyAckRtt.reset} when the attachment is lost (replayed input would be timed
 * from its first send and read as a huge round trip). Read {@link KeyAckRtt.p90}.
 */

/** Recent samples the 90th percentile is taken over: about the last half minute of typing. */
const WINDOW_SAMPLES = 32;
/** Which share of recent samples the reported figure covers; the mean hides a Wi-Fi tail, the 90th percentile does not. */
const PERCENTILE = 0.9;
/** Keys remembered while waiting for their `Ack`; a typing burst longer than this is not worth timing. */
const MAX_TIMED_KEYS = 64;
/** A sample longer than this is a stalled link or a held-then-replayed key, not a round trip. */
const MAX_SAMPLE_MS = 5000;

/** 90th-percentile key -> `Ack` time of one terminal over its recent keys. */
export class KeyAckRtt {
  /** Sent inputs in order: the sequence just past their last byte, and when they were sent. */
  private readonly timed: { end: bigint; at: number }[] = [];
  /** The last {@link WINDOW_SAMPLES} samples, oldest first. */
  private readonly samples: number[] = [];

  /**
   * The 90th percentile (nearest rank) of recent round trips, in milliseconds, or undefined until one key has been
   * acknowledged. Prediction decides on this, not the mean: a link whose usual key takes 20 ms but one in ten takes
   * 200 ms (Wi-Fi) must still get prediction, because those slow keys are the ones that feel broken (owner, 2026-11-21).
   */
  get p90(): number | undefined {
    if (this.samples.length === 0) return undefined;
    const sorted = [...this.samples].sort((a, b) => a - b);
    return sorted[Math.ceil(PERCENTILE * sorted.length) - 1];
  }

  /** Notes an input of `length` bytes starting at `sequence`, sent at `at` (milliseconds). */
  sent(sequence: bigint, length: number, at: number): void {
    if (this.timed.length >= MAX_TIMED_KEYS) this.timed.shift();
    this.timed.push({ end: sequence + BigInt(length), at });
  }

  /**
   * Handles an `Ack` covering input up to `acked`, received at `at`. Returns the new {@link KeyAckRtt.p90} when the Ack
   * completed a timed key. When one Ack covers several keys, only the newest is timed: the older ones waited for
   * the batch, which is not the path's round trip.
   */
  acked(acked: bigint, at: number): number | undefined {
    let newest: { end: bigint; at: number } | undefined;
    let covered = 0;
    while (covered < this.timed.length && this.timed[covered]!.end <= acked) {
      newest = this.timed[covered];
      covered += 1;
    }
    if (covered === 0) return undefined;
    this.timed.splice(0, covered);
    const sample = at - newest!.at;
    if (!(sample >= 0) || sample > MAX_SAMPLE_MS) return undefined;
    if (this.samples.length >= WINDOW_SAMPLES) this.samples.shift();
    this.samples.push(sample);
    return this.p90;
  }

  /** Forgets keys in flight and the samples (the attachment ended, the path may have changed). */
  reset(): void {
    this.timed.length = 0;
    this.samples.length = 0;
  }
}
