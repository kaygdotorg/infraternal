/**
 * The version pill (D160): a very small pill in the sidebar's footer, on the line of the person's pill and the gear,
 * that says in one glance whether this server is up to date and which edition it runs.
 *
 *   ( ✓ 0.4.2 CE )      up to date          ( ! 0.5.0 EE )   an update is waiting     ( ✕ 0.4.2 CE )   updates cannot be checked
 *
 * - One status mark, from the shared `.ui-mark` vocabulary (a tick for what is fine, an exclamation for something that
 *   waits for you, a quiet cross for what cannot be known). The mark is the whole status: no dot, no second colour.
 * - The edition is two letters, CE (Community) or EE (Enterprise code, any paid licence). When a licence is about to
 *   end or has ended, the two letters turn amber; the mark still speaks only about updates.
 * - The pill is a button: the caller opens its panel (canvas/version/panel.ts). It carries the warm tooltip and a
 *   full spoken name, since the visible text is only a number and two letters.
 * - It is the shared footer `.ui-pill` at the footer's own height (`--pill-h`), exactly as tall as the person's pill and
 *   the gear, on desktop and on touch; its touch target is therefore the pill itself (44 px).
 * - It sits between the person's pill and the gear and never shrinks; as the sidebar narrows the name yields first, then
 *   the two edition letters (see version.css).
 *
 * - When nothing is known about updates (no source can answer yet) the pill shows no mark at all: a quiet number and the
 *   edition, never a status that was not checked.
 *
 * Loaded on demand (D188): the first screen carries none of it. Its styles are in `styles.css` with the rest of the footer.
 */
export type VersionStatus = "current" | "available" | "offline" | "unknown";

export interface VersionPillState {
  version: string;
  status: VersionStatus;
  edition: "CE" | "EE";
  /** `soon`: the licence ends within two weeks. `ended`: it has ended. Both tint the edition. */
  attention?: "soon" | "ended";
  /** The warm tooltip: the status in words, then the edition. */
  tip: string;
  /** The spoken name. */
  label: string;
}

export interface VersionPill {
  readonly root: HTMLButtonElement;
  set(state: VersionPillState): void;
  dispose(): void;
}

const MARK: Record<Exclude<VersionStatus, "unknown">, "ok" | "warn" | "off"> = { current: "ok", available: "warn", offline: "off" };

/** Puts the pill into `foot` (the sidebar footer) just before the settings button. */
export function mountVersionPill(foot: HTMLElement, initial: VersionPillState): VersionPill {
  const root = document.createElement("button");
  root.type = "button";
  root.className = "ui-pill ui-version-pill";
  root.setAttribute("aria-haspopup", "dialog");
  root.setAttribute("aria-expanded", "false");
  const mark = document.createElement("span");
  mark.className = "ui-mark ui-version-mark";
  mark.setAttribute("aria-hidden", "true");
  const number = document.createElement("span");
  number.className = "ui-version-number";
  const edition = document.createElement("span");
  edition.className = "ui-version-edition";
  // One line box: the tick, the number and the letters share a text baseline (see version.css), so none is centred on its own.
  const line = document.createElement("span");
  line.className = "ui-version-line";
  line.append(mark, number, edition);
  root.append(line);
  foot.dataset.version = "";
  foot.insertBefore(root, foot.querySelector(".ui-sidebar-settings"));

  let status: VersionStatus | undefined;
  const set = (state: VersionPillState): void => {
    if (status !== state.status) {
      // A new status morphs in with the shared mark entrance (180 ms); the first paint does not animate.
      if (state.status === "unknown") { delete mark.dataset.mark; mark.hidden = true; }
      else { mark.hidden = false; mark.dataset.mark = MARK[state.status]; }
      if (status && state.status !== "unknown") { mark.classList.remove("is-new"); void mark.offsetWidth; mark.classList.add("is-new"); }
      status = state.status;
    }
    root.dataset.status = state.status;
    number.textContent = state.version;
    edition.textContent = state.edition;
    if (state.attention) edition.dataset.attention = state.attention; else delete edition.dataset.attention;
    root.dataset.tip = state.tip;
    root.setAttribute("aria-label", state.label);
  };
  set(initial);
  return {
    root,
    set,
    dispose() { root.remove(); delete foot.dataset.version; },
  };
}
