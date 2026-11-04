/**
 * Which scheme the sign-in pages use: light or dark.
 *
 * The sign-in pages are monochrome in both schemes (the app's own themes are the coloured ones), so
 * a theme only decides which way round. A theme chosen with `?theme=` or saved by the app
 * (`tracer.theme`) wins; with none, the system's `prefers-color-scheme` decides. The result is
 * written to the root as `data-auth-scheme` (auth.css reads it), to the browser chrome colour, and
 * passed to the backdrop so its glyphs follow.
 *
 * Only the auth screens own the attribute: `releaseAuthScheme` removes it when the app takes over,
 * so the app's own theme code is the only thing that paints the signed-in page.
 */
import { THEMES } from "../../../packages/ui/src/themes";

/** The pages' own backgrounds, also the meta theme colour, so the browser chrome blends in. */
const PAGE = { light: "#f6f6f4", dark: "#101113" } as const;

/** The theme id from `?theme=` or the saved `tracer.theme`, whichever is a known theme (the URL wins); `undefined` when neither is. */
function savedTheme(): string | undefined {
  const asked = new URLSearchParams(location.search).get("theme");
  let saved: string | null = null;
  try { saved = localStorage.getItem("tracer.theme"); } catch { /* storage may be blocked */ }
  return [asked, saved].find((id): id is string => id !== null && Object.hasOwn(THEMES, id));
}

/** True when the sign-in pages should be light. */
export function authIsLight(): boolean {
  const id = savedTheme();
  if (id) return !THEMES[id]!.dark;
  return matchMedia("(prefers-color-scheme: light)").matches;
}

/** The callback of the latest {@link useAuthScheme} caller, told when the scheme changes. */
let listener: ((light: boolean) => void) | undefined;
/** Whether the system and storage listeners are already installed; they are added once. */
let bound = false;

/** Writes the scheme to the root attribute and the browser chrome colour, and returns whether it is light. */
function apply(): boolean {
  const light = authIsLight();
  const root = document.documentElement;
  root.dataset.authScheme = light ? "light" : "dark";
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", PAGE[light ? "light" : "dark"]);
  return light;
}

/** Applies the scheme for an auth screen and returns it; `onChange` hears later changes (system, storage). */
export function useAuthScheme(onChange?: (light: boolean) => void): boolean {
  if (onChange) listener = onChange;
  const light = apply();
  if (!bound) {
    bound = true;
    const changed = (): void => {
      if (document.documentElement.dataset.authScheme === undefined) return;
      listener?.(apply());
    };
    matchMedia("(prefers-color-scheme: light)").addEventListener("change", changed);
    addEventListener("storage", changed);
  }
  return light;
}

/** The app takes over: stop painting the page. */
export function releaseAuthScheme(): void {
  delete document.documentElement.dataset.authScheme;
}
