/**
 * The droplet split loads on demand (D188): its WebGL drawing is about 4 KB gzip and is needed only when a window
 * splits. This handle loads it once (and warms it when the browser is idle after the canvas is up, so the first split
 * does not wait for a fetch or for a GL context on a device with a fine pointer) and lets a hidden page end a split in progress without loading anything.
 */
import { onDemand } from "../../on-demand";

/** The type of the droplet module, so callers get its exports without importing it at load time. */
type Droplet = typeof import("./droplet.on-demand");
/** The module once loaded; `undefined` until then. */
let loaded: Droplet | undefined;

/** Loads the droplet module (once). Later calls return the same module at once. */
export const loadDroplet = (): Promise<Droplet> => loaded ? Promise.resolve(loaded) : onDemand(() => import("./droplet.on-demand")).then((m) => (loaded = m));
/** Ends the split that is playing, if any (a no-op while the module has never loaded). */
export const endSplit = (): void => loaded?.endSplit();
/** Fetches the module when the browser is idle. */
export const warmDroplet = (): void => {
  const idle = (f: () => void): void => { (window.requestIdleCallback ?? ((g: () => void) => window.setTimeout(g, 2000)))(f); };
  idle(() => { void loadDroplet().then((m) => window.setTimeout(() => idle(m.warmContext), 3000)).catch(() => undefined); });
};
