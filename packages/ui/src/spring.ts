/**
 * A damped spring for one number (DECISIONS 70: physical, interruptible motion).
 * Configured by visual duration and bounce. Retargeting
 * mid-flight keeps velocity, so rapid toggles reverse smoothly. It only runs while
 * moving and stops at rest: zero idle work (DECISIONS 81).
 */
/** Either visual duration and bounce or raw stiffness and damping. */
export type SpringConfig = { visualDuration: number; bounce: number } | { stiffness: number; damping: number };

/** Bounce as an overshoot ratio (0.2 = 20%) → damping ratio ζ. */
export const zetaOf = (bounce: number) => (bounce <= 0 ? 1 : -Math.log(bounce) / Math.sqrt(Math.PI ** 2 + Math.log(bounce) ** 2));

export class Spring {
  value: number;
  private target: number;
  private velocity = 0;
  private raf = 0;
  private last = 0;
  private stiffness = 0;
  private damping = 0;
  /** Rest thresholds scale with the distance travelled, so a count from 0 to 10 000 settles too. */
  restDelta = 0.001;
  restVelocity = 0.002;
  constructor(initial: number, private readonly onUpdate: (v: number) => void, cfg: SpringConfig = { visualDuration: 0.2, bounce: 0.2 }) {
    this.configure(cfg);
    this.value = this.target = initial;
    onUpdate(initial);
  }
  /** Changes the physics mid-flight (keeps position and velocity), e.g. a faster exit. */
  configure(cfg: SpringConfig) {
    if ("stiffness" in cfg) {
      this.stiffness = cfg.stiffness;
      this.damping = cfg.damping;
    } else {
      // Visual duration maps to angular frequency; bounce fixes the damping ratio.
      const omega = (2 * Math.PI) / (cfg.visualDuration * 1.2);
      this.stiffness = omega * omega;
      this.damping = 2 * zetaOf(cfg.bounce) * omega;
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
    if (instant || matchMedia("(prefers-reduced-motion: reduce)").matches) {
      cancelAnimationFrame(this.raf); this.raf = 0; this.velocity = 0; this.value = to; this.onUpdate(to); return;
    }
    if (!this.raf) { this.last = performance.now(); this.raf = requestAnimationFrame(this.step); }
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
