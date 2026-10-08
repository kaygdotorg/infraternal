/**
 * The sidebar's footer (D160): who is signed in, the settings entry and the build.
 *
 *   row 1   [ monogram  Display name ]                         ( gear )
 *   row 2   [ commit-glyph  infraternal · 9c62448 ]
 *
 * Every control is the shared `.ui-pill`; this file only lays them out (styles.css,
 * `.ui-sidebar-foot`). The name pill is a status, not a button, so it takes no pointer
 * events. The version pill copies the full commit id on click or tap: its leading glyph
 * swaps to the shared tick (`swapIcon`) and the shared tooltip flashes "Copied", so there is
 * no copy icon (TASTE: copy without buttons). The settings pill opens nothing yet: it
 * answers with a short tooltip so a press is never silent.
 *
 *   const foot = createSidebarFoot({ displayName, version: { short, full } });
 *   sidebar.append(foot.root);
 */
import { confirmAction, swapIcon } from "./copy-feedback";
import { flashTip } from "./tooltip";

export interface SidebarFootOptions {
  displayName: string;
  version: { short: string; full: string };
  /** Runs when the settings pill is pressed; without it the pill answers "Coming soon". */
  onSettings?: () => void;
}

export interface SidebarFoot {
  readonly root: HTMLElement;
  readonly version: HTMLButtonElement;
  readonly settings: HTMLButtonElement;
  dispose(): void;
}

const GEAR = '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3h0a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9v0a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z"/>';
const COMMIT = '<circle cx="12" cy="12" r="3.5"/><path d="M3 12h5.5M15.5 12H21"/>';
const HOLD_MS = 900;

/** The first letter of the name, upper-cased, for the monogram (never empty). */
const monogram = (name: string): string => [...name.trim()][0]?.toUpperCase() ?? "?";

export function createSidebarFoot(options: SidebarFootOptions): SidebarFoot {
  const root = document.createElement("div");
  root.className = "ui-sidebar-foot";

  const account = document.createElement("div");
  account.className = "ui-sidebar-row";
  const user = document.createElement("div");
  user.className = "ui-pill ui-sidebar-user";
  user.setAttribute("role", "group");
  user.setAttribute("aria-label", `Signed in as ${options.displayName}`);
  const letter = document.createElement("span");
  letter.className = "ui-sidebar-monogram";
  letter.setAttribute("aria-hidden", "true");
  letter.textContent = monogram(options.displayName);
  const name = document.createElement("span");
  name.className = "ui-sidebar-name";
  name.textContent = options.displayName;
  user.append(letter, name);

  const settings = document.createElement("button");
  settings.type = "button";
  settings.className = "ui-pill ui-pill-icon ui-sidebar-settings";
  settings.setAttribute("aria-label", "Settings");
  settings.dataset.tip = "Settings";
  settings.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">${GEAR}</svg>`;
  account.append(user, settings);

  const version = document.createElement("button");
  version.type = "button";
  version.className = "ui-pill ui-sidebar-version";
  version.dataset.tip = "Copy commit id";
  version.setAttribute("aria-label", `Copy commit id ${options.version.short}`);
  version.innerHTML = `${swapIcon(COMMIT)}<span class="ui-sidebar-build">infraternal <span class="ui-sidebar-dot" aria-hidden="true">·</span> <span class="ui-sidebar-commit">${options.version.short}</span></span>`;
  const row2 = document.createElement("div");
  row2.className = "ui-sidebar-row";
  row2.append(version);
  root.append(account, row2);

  let touched = false;
  const onPointerDown = (event: PointerEvent): void => { touched = event.pointerType === "touch"; };
  const onVersion = async (event: MouseEvent): Promise<void> => {
    try {
      if (!navigator.clipboard) return;
      await navigator.clipboard.writeText(options.version.full);
    } catch {
      return;
    }
    // A keyboard activation (detail 0) shows the result at once, without the morph.
    confirmAction(version, "Copied", event.detail === 0 && !touched);
    flashTip(version, "Copied", HOLD_MS);
  };
  const onSettings = (): void => {
    if (options.onSettings) options.onSettings();
    else flashTip(settings, "Coming soon", HOLD_MS);
  };
  version.addEventListener("pointerdown", onPointerDown);
  version.addEventListener("click", onVersion);
  settings.addEventListener("click", onSettings);

  return {
    root,
    version,
    settings,
    dispose() {
      version.removeEventListener("pointerdown", onPointerDown);
      version.removeEventListener("click", onVersion);
      settings.removeEventListener("click", onSettings);
      root.remove();
    },
  };
}
