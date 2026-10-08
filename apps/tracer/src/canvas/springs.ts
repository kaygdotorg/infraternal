/**
 * Rest thresholds for the canvas's springs. A spring runs a requestAnimationFrame loop until it is "at rest"; the
 * library default (0.001 in the spring's own unit) is far below what anyone can see, so a flight kept rewriting inline
 * styles for one to two seconds after it had visibly ended. A canvas spring rests when the remaining motion is under a
 * quarter of a device pixel (a scale under 0.0005) and its velocity is just as small; it then lands exactly on its
 * target and its loop stops: at rest the canvas does no per-frame work at all.
 */
import type { Spring } from "../../../../packages/ui/src/spring";

/** A quarter of a device pixel, in CSS pixels. */
export const quarterDevicePx = (): number => 0.25 / (devicePixelRatio || 1);
/** A scale (or a 0..1 progress) so close to its target that nothing can show it. */
export const SCALE_REST = 0.0005;

/** Sets both thresholds of `spring` to `delta`, in the spring's own unit. Returns the spring. */
export function restAt<S extends Spring>(spring: S, delta: number): S {
  spring.restDelta = delta;
  spring.restVelocity = delta;
  return spring;
}

/** A spring whose value is a length in CSS pixels, at a canvas scale of `zoom`. */
export const restPx = <S extends Spring>(spring: S, zoom = 1): S => restAt(spring, quarterDevicePx() / Math.max(zoom, 0.01));
