/**
 * The build's commit id, injected by `build.ts` as `__BUILD_COMMIT__` (the output of
 * `git rev-parse HEAD` when the bundle was made). It is never hardcoded: a build outside a
 * git checkout reports "dev". The short form is the first seven characters.
 */
declare const __BUILD_COMMIT__: string | undefined;

export interface BuildVersion {
  short: string;
  full: string;
}

export function buildVersion(): BuildVersion {
  const full = typeof __BUILD_COMMIT__ === "string" && /^[0-9a-f]{7,40}$/.test(__BUILD_COMMIT__) ? __BUILD_COMMIT__ : "dev";
  return { short: full.slice(0, 7), full };
}
