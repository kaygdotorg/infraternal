/**
 * The build's commit id, injected by `build.ts` as `__BUILD_COMMIT__` (the output of
 * `git rev-parse HEAD` when the bundle was made) and `__BUILD_DATE__` (its ISO time). They feed
 * Settings, About. It is never hardcoded: a build outside a
 * git checkout reports "dev". The short form is the first seven characters.
 */
declare const __BUILD_COMMIT__: string | undefined;
declare const __BUILD_DATE__: string | undefined;

/** The build's identity: `full` and `short` commit id (`dev` outside a git checkout) and the ISO `built` time. */
export interface BuildVersion {
  short: string;
  full: string;
  /** ISO timestamp of the build; empty when unknown. */
  built: string;
}

/** Reads the commit and date that the build injected. A commit that is not 7 to 40 hexadecimal characters counts as unknown and reads `dev`. */
export function buildVersion(): BuildVersion {
  const full = typeof __BUILD_COMMIT__ === "string" && /^[0-9a-f]{7,40}$/.test(__BUILD_COMMIT__) ? __BUILD_COMMIT__ : "dev";
  const built = typeof __BUILD_DATE__ === "string" ? __BUILD_DATE__ : "";
  return { short: full.slice(0, 7), full, built };
}
