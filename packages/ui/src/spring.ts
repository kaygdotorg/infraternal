/**
 * A damped spring for one number (DECISIONS 70: physical, interruptible motion).
 * Configured by visual duration; the spring is critically damped, so a value never passes its target (TASTE §3,
 * "No overshoot, ever"). Retargeting mid-flight keeps velocity, so rapid toggles reverse smoothly. It only runs
 * while moving and stops at rest: zero idle work (DECISIONS 81).
 *
 * There is no bounce setting: a config is `{ visualDuration }`. The type keeps `bounce?: 0` only so an old call site that
 * passes 0 still compiles; any other value does not, and the code below ignores it anyway.
 * Raw `{ stiffness, damping }` is the only way to build an under-damped spring. It is rejected everywhere outside
 * the allow-list in `no-overshoot.test.ts` (the droplet split, which the owner asked to wobble, TASTE §3 "Splits are playful physics").
 */
/** Either a visual duration (critically damped) or raw stiffness and damping. */
export type SpringConfig = { visualDuration: number; bounce?: 0 } | { stiffness: number; damping: number };

export class Spring {
  value: number;
  private target: number;
  private velocity = 0;
  private raf = 0;
  private last = 0;
  private stiffness = 0;
  private damping = 0;
  /** Angular frequency of a duration-based (critically damped) spring; 0 for a raw stiffness/damping spring. */
  private omega = 0;
  /** Rest thresholds scale with the distance travelled, so a count from 0 to 10 000 settles too. */
  restDelta = 0.001;
  restVelocity = 0.002;
  constructor(initial: number, private readonly onUpdate: (v: number) => void, cfg: SpringConfig = { visualDuration: 0.2 }) {
    this.configure(cfg);
    this.value = this.target = initial;
    onUpdate(initial);
  }
  /** Changes the physics mid-flight (keeps position and velocity), e.g. a faster exit. */
  configure(cfg: SpringConfig) {
    if ("stiffness" in cfg) {
      this.stiffness = cfg.stiffness;
      this.damping = cfg.damping;
      this.omega = 0;
    } else {
      // Visual duration maps to angular frequency; damping ratio 1 is the fastest settle with no overshoot.
      const omega = (2 * Math.PI) / (cfg.visualDuration * 1.2);
      this.stiffness = omega * omega;
      this.damping = 2 * omega;
      this.omega = omega;
    }
  }
  /**
   * Moves toward `to` starting with `velocity` (units per second), the way a released drag carries on: the motion
   * continues from where the finger left it instead of starting from rest. Reduced motion jumps like `set`.
   */
  fling(to: number, velocity: number) {
    this.set(to);
    if (this.raf) this.velocity = velocity;
  }
  /** Moves toward `to`; `instant` (keyboard input, reduced motion) jumps there. */
  set(to: number, instant = false) {
    this.target = to;
    this.capVelocity();
    if (instant || matchMedia("(prefers-reduced-motion: reduce)").matches) {
      cancelAnimationFrame(this.raf); this.raf = 0; this.velocity = 0; this.value = to; this.onUpdate(to); return;
    }
    if (!this.raf) { this.last = performance.now(); this.raf = requestAnimationFrame(this.step); }
  }
  /**
   * Retargeting keeps the velocity (interruptible motion), but a critically damped spring that is already moving toward
   * its new target faster than omega x distance would run past it and come back: x(t) = (x0 + (v0 + omega x0) t) e^(-omega t)
   * changes sign exactly when v0 > omega |x0|. So the speed toward the target is capped at that bound; speed away from it
   * is kept. From then on the motion cannot cross the target (no overshoot, TASTE section 3). Raw springs are left alone.
   */
  private capVelocity(): void {
    if (!this.omega) return;
    const d = this.target - this.value, bound = this.omega * d;
    this.velocity = d >= 0 ? Math.min(this.velocity, bound) : Math.max(this.velocity, bound);
  }
  private readonly step = (now: number) => {
    const dt = Math.max(0, (now - this.last) / 1000);
    this.last = now;
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
