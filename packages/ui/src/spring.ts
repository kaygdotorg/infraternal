/**
 * A damped spring for one number (DECISIONS 70: physical, interruptible motion).
 * Configured like Apple and Motion springs: a visual duration and a bounce. Retargeting
 * mid-flight keeps velocity, so rapid toggles reverse smoothly. It only runs while
 * moving and stops at rest: zero idle work (DECISIONS 81).
 */
/** Either Apple/Motion-style (visual duration + bounce) or raw physics (stiffness + damping). */
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
      // Same mapping Motion uses for visualDuration springs: ω = 2π / (1.2 · duration).
      const omega = (2 * Math.PI) / (cfg.visualDuration * 1.2);
      this.stiffness = omega * omega;
      this.damping = 2 * zetaOf(cfg.bounce) * omega;
    }
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
    let dt = Math.min(0.064, (now - this.last) / 1000);
    this.last = now;
    while (dt > 0) { // fixed sub-steps keep integration stable on slow frames
      const h = Math.min(dt, 1 / 240);
      this.velocity += (-this.stiffness * (this.value - this.target) - this.damping * this.velocity) * h;
      this.value += this.velocity * h;
      dt -= h;
    }
    if (Math.abs(this.velocity) < this.restVelocity && Math.abs(this.value - this.target) < this.restDelta) {
      this.value = this.target; this.velocity = 0; this.raf = 0; this.onUpdate(this.value); return;
    }
    this.onUpdate(this.value);
    this.raf = requestAnimationFrame(this.step);
  };
}
