/**
 * Count-up (#21): a number that springs from one value to another. Reimplemented from
 * the behaviour of the sveltebits count-up (MIT + Commons Clause, not copied): same
 * spring shaping (stiffness 100/d, damping 20 + 40/d for duration d), the same decimal
 * handling, an optional thousands separator. It reuses our one Spring (spring.ts).
 *
 * `loading()` is the app-wide rule for waits (DECISIONS 102): nothing is shown for
 * short waits (no flash of a loader), and after the threshold a count-up appears —
 * real progress when the work reports it, otherwise elapsed seconds. Never fake
 * progress.
 */
import { Spring } from "./spring";

const decimalsOf = (n: number) => { const s = n.toString(); const d = s.split(".")[1]; return d && parseInt(d, 10) !== 0 ? d.length : 0; };

export interface CountUp { to(value: number): void; destroy(): void }

export function countUp(el: HTMLElement, from: number, opts: { duration?: number; separator?: string; decimals?: number; suffix?: string } = {}): CountUp {
  const duration = opts.duration ?? 2;
  let decimals = opts.decimals ?? decimalsOf(from);
  const fmt = (v: number) => {
    const s = new Intl.NumberFormat("en-US", { useGrouping: !!opts.separator, minimumFractionDigits: decimals, maximumFractionDigits: decimals }).format(v);
    return (opts.separator ? s.replace(/,/g, opts.separator) : s) + (opts.suffix ?? "");
  };
  el.classList.add("countup");
  const spring = new Spring(from, (v) => { el.textContent = fmt(v); }, { stiffness: 100 / duration, damping: 20 + 40 / duration });
  return {
    to(value: number) {
      if (opts.decimals === undefined) decimals = Math.max(decimals, decimalsOf(value));
      spring.restDelta = Math.max(0.001, Math.abs(value - spring.value) * 1e-4);
      spring.restVelocity = spring.restDelta * 2;
      spring.set(value);
    },
    destroy() { spring.set(spring.value, true); },
  };
}

export interface Loading { progress(fraction: number): void; done(): void }

/**
 * Shows a count-up in `el` only if the work takes longer than `threshold` ms.
 * Call progress(0..1) when the work knows how far it is; otherwise elapsed time counts.
 */
export function loading(el: HTMLElement, threshold = 400): Loading {
  let counter: CountUp | undefined;
  let known = false;
  let tick = 0;
  const started = performance.now();
  const show = window.setTimeout(() => {
    el.hidden = false;
    // Elapsed time starts at the real elapsed value (not 0.0), so it never appears to rewind.
    counter = known ? countUp(el, 0, { duration: 1, suffix: "%" }) : countUp(el, (performance.now() - started) / 1000, { duration: 1, decimals: 1, suffix: "s" });
    if (!known) {
      const step = () => { counter?.to((performance.now() - started) / 1000); };
      step();
      tick = window.setInterval(step, 250); // elapsed time: four gentle updates a second, only while waiting
    }
  }, threshold);
  return {
    progress(f: number) {
      if (!known) { known = true; clearInterval(tick); if (counter) { counter.destroy(); counter = countUp(el, 0, { duration: 1, suffix: "%" }); } }
      counter?.to(Math.round(Math.min(1, Math.max(0, f)) * 100));
    },
    done() { clearTimeout(show); clearInterval(tick); counter?.destroy(); el.hidden = true; },
  };
}
