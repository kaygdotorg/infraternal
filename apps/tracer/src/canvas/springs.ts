/**
 * Rest thresholds for the canvas's springs. A spring runs a requestAnimationFrame loop until it is "at rest"; the
 * library default (0.001 in the spring's own unit) is far below what anyone can see, so a flight kept rewriting inline
 * styles for one to two seconds after it had visibly ended. A canvas spring rests when the remaining motion is under a
 * quarter of a device pixel (a scale under 0.0005) and its velocity is under a quarter of a device pixel per frame; it then lands exactly on its
 * target and its loop stops: at rest the canvas does no per-frame work at all.
 */
import type { Spring } from "../../../../packages/ui/src/spring";

/** A quarter of a device pixel, in CSS pixels. */
export const quarterDevicePx = (): number => 0.25 / (devicePixelRatio || 1);
/** A scale (or a 0..1 progress) so close to its target that nothing can show it. */
export const SCALE_REST = 0.0005;

/**
 * Sets the thresholds of `spring`: it rests within `delta` of its target (in the spring's own unit) and moving slower
 * than `delta` per frame at 60 Hz. Velocity is per second, so the second threshold is `delta * 60`: a tail that still
 * creeps a fifth of a pixel every frame is not at rest, one that moves under a quarter of a pixel per frame is.
 */
export function restAt<S extends Spring>(spring: S, delta: number): S {
  spring.restDelta = delta;
  spring.restVelocity = delta * 60;
  return spring;
}

/** A spring whose value is a length in CSS pixels, at a canvas scale of `zoom`. */
export const restPx = <S extends Spring>(spring: S, zoom = 1): S => restAt(spring, quarterDevicePx() / Math.max(zoom, 0.01));
