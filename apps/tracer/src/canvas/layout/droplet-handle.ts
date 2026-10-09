/**
 * The droplet split loads on demand (D188): its WebGL drawing is about 4 KB gzip and is needed only when a window
 * splits. This handle loads it once (and warms it when the browser is idle after the canvas is up, so the first split
 * does not wait for a fetch) and lets a hidden page end a split in progress without loading anything.
 */
import { onDemand } from "../../on-demand";

type Droplet = typeof import("./droplet.on-demand");
let loaded: Droplet | undefined;

export const loadDroplet = (): Promise<Droplet> => loaded ? Promise.resolve(loaded) : onDemand(() => import("./droplet.on-demand")).then((m) => (loaded = m));
/** Ends the split that is playing, if any (a no-op while the module has never loaded). */
export const endSplit = (): void => loaded?.endSplit();
/** Fetches the module when the browser is idle. */
export const warmDroplet = (): void => { (window.requestIdleCallback ?? ((f: () => void) => window.setTimeout(f, 2000)))(() => { void loadDroplet().catch(() => undefined); }); };
