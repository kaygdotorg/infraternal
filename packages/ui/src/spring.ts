/**
 * One animated number: the motion engine behind every canvas, layout and morph animation (DECISIONS 70: physical,
 * interruptible motion). It only runs while moving and stops at rest: zero idle work (DECISIONS 81).
 *
 * Two ways to move, because a UI motion and a finger's throw want different curves (TASTE §3, "Fast, ease-out, under
 * 300 ms"; owner 2026-11-09: "Use ease-out for anything entering or leaving the screen. Keep UI animations under 300ms."):
 *
 * - `set(to)` plays the product's ease-out curve (`easeOut`, the same as CSS `var(--ease-out)`) for exactly
 *   `visualDuration` seconds. Most of the distance is covered in the first frames, then it glides in and stops on the
 *   target at the duration, with no tail. Retargeting mid-flight starts a new curve from wherever the value is, so a
 *   reversal reacts on the next frame. A spring released from rest was rejected for this: it starts at zero speed, so
 *   it covers 1 to 3 % of the way in the first frame (an S-curve, the slow start the owner noticed) and, critically
 *   damped, takes 1.3 to 1.5 times its duration to settle (#471 has the measured table).
 * - `fling(to, velocity)` runs a critically damped spring that starts at the finger's velocity, so a released drag
 *   carries on from where the finger left it. That is what a spring is for. Damping ratio 1 means it never passes its
 *   target (TASTE §3, "No overshoot, ever").
 *
 * A config is `{ visualDuration }` in seconds, at most 0.3 (checked by `apps/tracer/test/motion-speed.test.ts`). The type
 * keeps `bounce?: 0` only so an old call site that passes 0 still compiles. Raw `{ stiffness, damping }` always runs the
 * physics (also for `set`) and is the only way to build an under-damped spring. It is rejected everywhere outside the
 * allow-list in `no-overshoot.test.ts` (the count-up, which is overdamped).
 *
 * @example
 * const s = new Spring(0, (v) => { el.style.transform = `translateX(${v}px)`; }, { visualDuration: 0.24 });
 * s.set(120);            // ease-out to 120 px in 240 ms
 * s.fling(0, -1800);     // a release: settle back to 0 from the finger's speed
 * s.set(0, true);        // keyboard or reduced motion: jump there
 */
import { easeOut } from "./motion";

/** Either a visual duration (an ease-out curve, and a critically damped fling) or raw stiffness and damping. */
export type SpringConfig = { visualDuration: number; bounce?: 0 } | { stiffness: number; damping: number };

/** One animated number; see the module comment for `set` (ease-out curve) and `fling` (spring from a finger's speed). */
export class Spring {
  /** The current value. A caller may write it before `set` to start the motion from somewhere else. */
  value: number;
  private target: number;
  /** Units per second: measured from frame to frame while a curve plays, so a `fling` mid-curve keeps going smoothly. */
  private velocity = 0;
  private raf = 0;
  /** The time of the last frame (or of the `set` that started the motion), in `performance.now()` milliseconds. */
  private last = 0;
  private stiffness = 0;
  private damping = 0;
  /** Angular frequency of a duration-based spring (its fling); 0 for a raw stiffness/damping spring. */
  private omega = 0;
  /** Length of the ease-out curve in milliseconds; 0 for a raw spring, which has no curve. */
  private durationMs = 0;
  /** The curve now playing: where it started, when, and the value last written, or undefined while the physics runs. */
  private curve: { from: number; start: number; shown: number } | undefined;
  /** Set by `configure`: the next `set` restarts the curve with the new duration even when the target is unchanged. */
  private retime = false;
  /** Rest thresholds of the physics (fling and raw springs); a curve always ends exactly on its target. */
  restDelta = 0.001;
  restVelocity = 0.002;
  constructor(initial: number, private readonly onUpdate: (v: number) => void, cfg: SpringConfig = { visualDuration: 0.2 }) {
    this.configure(cfg);
    this.value = this.target = initial;
    onUpdate(initial);
  }
  /** Changes the timing (keeps position and velocity), e.g. a faster exit. A curve in flight keeps its timing until the next `set`. */
  configure(cfg: SpringConfig) {
    if ("stiffness" in cfg) {
      this.stiffness = cfg.stiffness;
      this.damping = cfg.damping;
      this.omega = 0;
      this.durationMs = 0;
    } else {
      // The fling's angular frequency: the same mapping as before #471, so a throw keeps the feel the owner approved;
      // damping ratio 1 is the fastest settle with no overshoot.
      const omega = (2 * Math.PI) / (cfg.visualDuration * 1.2);
      this.stiffness = omega * omega;
      this.damping = 2 * omega;
      this.omega = omega;
      this.durationMs = cfg.visualDuration * 1000;
      this.retime = true;
    }
  }
  /**
   * Moves toward `to` starting with `velocity` (units per second), the way a released drag carries on: the motion
   * continues from where the finger left it instead of starting from rest. Reduced motion jumps like `set`.
   */
  fling(to: number, velocity: number) {
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) { this.set(to, true); return; }
    this.target = to;
    this.curve = undefined;
    this.retime = false;
    this.velocity = velocity;
    this.capVelocity();
    this.run();
  }
  /** Moves toward `to` on the ease-out curve (a raw spring: with its physics); `instant` (keyboard input, reduced motion) jumps there. */
  set(to: number, instant = false) {
    if (instant || matchMedia("(prefers-reduced-motion: reduce)").matches) {
      cancelAnimationFrame(this.raf); this.raf = 0; this.velocity = 0; this.curve = undefined;
      this.target = to; this.value = to; this.onUpdate(to); return;
    }
    if (!this.durationMs) { this.target = to; this.capVelocity(); this.run(); return; }
    // The same target while its curve plays (a caller that re-sends it every frame) keeps the curve; restarting would
    // stall the motion at its fast start forever.
    // A fling heading for the same target keeps its finger velocity for the same reason.
    const playing = this.raf && (!this.curve || this.curve.shown === this.value);
    if (playing && to === this.target && !this.retime) return;
    if (!this.raf && to === this.value) { this.target = to; return; }
    this.retime = false;
    this.target = to;
    const now = performance.now();
    this.curve = { from: this.value, start: now, shown: this.value };
    if (!this.raf) { this.last = now; this.raf = requestAnimationFrame(this.step); }
  }
  /** Starts the physics loop if it is not running. */
  private run(): void {
    if (!this.raf) { this.last = performance.now(); this.raf = requestAnimationFrame(this.step); }
  }
  /**
   * A fling keeps the finger's velocity, but a critically damped spring that is already moving toward its target faster
   * than omega x distance would run past it and come back: x(t) = (x0 + (v0 + omega x0) t) e^(-omega t) changes sign
   * exactly when v0 > omega |x0|. So the speed toward the target is capped at that bound; speed away from it is kept.
   * From then on the motion cannot cross the target (no overshoot, TASTE section 3). Raw springs are left alone.
   */
  private capVelocity(): void {
    if (!this.omega) return;
    const d = this.target - this.value, bound = this.omega * d;
    this.velocity = d >= 0 ? Math.min(this.velocity, bound) : Math.max(this.velocity, bound);
  }
  private readonly step = (now: number) => {
    const dt = Math.max(0, (now - this.last) / 1000);
    this.last = now;
    const curve = this.curve;
    if (curve) {
      // A caller wrote `value` mid-curve (the camera re-reads a gesture's position): play the rest from there.
      if (curve.shown !== this.value) { curve.from = this.value; curve.start = now; }
      // The curve follows elapsed time, so a missed frame skips ahead instead of stretching the motion.
      const p = Math.max(0, (now - curve.start) / this.durationMs);
      const next = p >= 1 ? this.target : curve.from + (this.target - curve.from) * easeOut(p);
      this.velocity = dt > 0 ? (next - this.value) / dt : 0;
      this.value = curve.shown = next;
      if (p >= 1) { this.velocity = 0; this.curve = undefined; this.raf = 0; this.onUpdate(this.value); return; }
      this.onUpdate(this.value);
      this.raf = requestAnimationFrame(this.step);
      return;
    }
    // Solve the same damped oscillator over the full elapsed interval. Dropping
    // elapsed time stretches animations when rendering misses frames; subdividing
    // an unbounded interval would instead make the next frame expensive.
    const x = this.value - this.target, v = this.velocity;
    const a = this.damping / 2, discriminant = a * a - this.stiffness;
    if (Math.abs(discriminant) <= Math.max(1, this.stiffness) * 1e-8) {
      const b = v + a * x, decay = Math.exp(-a * dt);
      this.value = this.target + (x + b * dt) * decay;
      this.velocity = (v - a * b * dt) * decay;
    } else if (discriminant < 0) {
      const w = Math.sqrt(-discriminant), decay = Math.exp(-a * dt);
      const sin = Math.sin(w * dt), cos = Math.cos(w * dt);
      this.value = this.target + (x * cos + (v + a * x) / w * sin) * decay;
      this.velocity = (v * cos - (a * v + this.stiffness * x) / w * sin) * decay;
    } else {
      const w = Math.sqrt(discriminant), r1 = -a + w, r2 = -a - w;
      const first = (v - r2 * x) / (r1 - r2) * Math.exp(r1 * dt);
      const second = (r1 * x - v) / (r1 - r2) * Math.exp(r2 * dt);
      this.value = this.target + first + second;
      this.velocity = r1 * first + r2 * second;
    }
    if (Math.abs(this.velocity) < this.restVelocity && Math.abs(this.value - this.target) < this.restDelta) {
      this.value = this.target; this.velocity = 0; this.raf = 0; this.onUpdate(this.value); return;
    }
    this.onUpdate(this.value);
    this.raf = requestAnimationFrame(this.step);
  };
}
