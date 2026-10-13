/**
 * Marks for detected operating systems: the platform names, the label-to-platform mapping and the markup of a mark.
 *
 * Only the machine glyph (`unknown`) ships here. The artwork of each platform is its own module under
 * `host-marks/` and is fetched the first time a host of that platform is seen: a person with Debian hosts never
 * transfers the other five marks (about 5 KB of path data, D188). The canvas calls `ensureHostMarks` where a
 * platform first enters it (the host list, a host's facts), so by the time a window draws the mark it is loaded.
 * A mark drawn before its module arrived (a path that skipped that call) is the machine glyph tagged with
 * `data-os`, and is replaced in place when the module arrives, so no caller has to wait or re-render.
 */

export type HostPlatform = "ubuntu" | "debian" | "redhat" | "proxmox" | "nixos" | "apple" | "unknown";

/** Maps an operating-system label from host facts to the shared mark set. */
export function hostPlatformFromOs(os: string): HostPlatform {
  const normalized = os.toLowerCase();
  if (normalized.includes("proxmox")) return "proxmox";
  if (normalized.includes("ubuntu")) return "ubuntu";
  if (normalized.includes("debian")) return "debian";
  if (normalized.includes("rhel") || normalized.includes("red hat")) return "redhat";
  if (normalized.includes("nixos")) return "nixos";
  if (normalized.includes("macos") || normalized.includes("mac os")) return "apple";
  return "unknown";
}

/** The machine glyph, also the stand-in while a platform's own mark is on its way. */
const UNKNOWN_PATH = "M4 5.5A2.5 2.5 0 0 1 6.5 3h11A2.5 2.5 0 0 1 20 5.5v8a2.5 2.5 0 0 1-2.5 2.5h-3.7l1.4 2H17v2H7v-2h1.8l1.4-2H6.5A2.5 2.5 0 0 1 4 13.5zm2 .5v7h12V6z";

type Drawn = Exclude<HostPlatform, "unknown">;
// Simple Icons path data are CC0. Each platform's data is its own on-demand module so that only the marks in use transfer.
const MARK_LOADERS: Record<Drawn, () => Promise<{ default: string }>> = {
  ubuntu: () => import("./host-marks/ubuntu.on-demand"),
  debian: () => import("./host-marks/debian.on-demand"),
  redhat: () => import("./host-marks/redhat.on-demand"),
  proxmox: () => import("./host-marks/proxmox.on-demand"),
  nixos: () => import("./host-marks/nixos.on-demand"),
  apple: () => import("./host-marks/apple.on-demand"),
};
const paths = new Map<HostPlatform, string>([["unknown", UNKNOWN_PATH]]);
const loading = new Map<Drawn, Promise<void>>();

/**
 * Fetches the marks of `platforms` (once each) and resolves when they can be drawn. A failed fetch is forgotten, so
 * the next sighting retries, and resolves anyway: a mark that cannot load is the machine glyph, never an error.
 */
export function ensureHostMarks(platforms: Iterable<HostPlatform | undefined>): Promise<void> {
  const pending: Promise<void>[] = [];
  for (const platform of platforms) {
    if (!platform || platform === "unknown" || paths.has(platform)) continue;
    let load = loading.get(platform);
    if (!load) {
      load = MARK_LOADERS[platform]().then((module) => {
        paths.set(platform, module.default);
        // Marks drawn as the stand-in before this arrived take their own path now.
        for (const path of document.querySelectorAll<SVGPathElement>(`svg[data-os="${platform}"] > path`)) {
          path.setAttribute("d", module.default);
          path.parentElement!.removeAttribute("data-os");
        }
      }, () => { loading.delete(platform); });
      loading.set(platform, load);
    }
    pending.push(load);
  }
  return Promise.all(pending).then(() => undefined);
}

/** Static SVG markup for a platform; unknown detections use the machine glyph. */
export function hostIconMarkup(platform: HostPlatform, className = "os-mark"): string {
  const path = platform in MARK_LOADERS ? paths.get(platform) : UNKNOWN_PATH;
  if (path !== undefined) return `<svg class="${className}" viewBox="0 0 24 24" aria-hidden="true"><path d="${path}"/></svg>`;
  void ensureHostMarks([platform]);
  return `<svg class="${className}" viewBox="0 0 24 24" aria-hidden="true" data-os="${platform}"><path d="${UNKNOWN_PATH}"/></svg>`;
}
