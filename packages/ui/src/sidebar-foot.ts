/**
 * The sidebar's footer (D160): who is signed in, and the way into Settings.
 *
 *   [ avatar  Display name        ]  ( gear )
 *   [         secondary line      ]
 *
 * Both controls are the shared `.ui-pill`. The gear opens Settings. The person's own pill opens a small menu (the
 * shared anchored menu, above the pill) with Settings and Sign out; the product passes the rows in `menu`, and a
 * foot without them opens Settings from the pill too. They share one height, so their centres sit on
 * one line. The avatar is the name's initial on a soft gradient derived from the theme's accent
 * (a per-name hue offset, so two people differ without leaving the palette). Every control
 * answers a press with the shared 0.97 scale; nothing here is inert.
 *
 * Variants for the owner to compare (`?footer=a|b`, chosen by the caller):
 *   a (default): two lines (name, then a quiet secondary line), a 40 px pill.
 *   b: one line, a 32 px pill, a thin gradient ring around the avatar.
 *
 * The version is a third small pill on the same line (version-pill.on-demand.ts), added by the canvas once the first screen
 * is up (owner, 2026-10-15 and 2026-11-01; TASTE "Version lives in About" is superseded). The commit and the build date stay in
 * Settings, About (settings-overlay.ts).
 *
 *   const foot = createSidebarFoot({ displayName, secondary, onOpen: () => settings.open("about", "pointer") });
 *   sidebar.append(foot.root);
 */
import { ICONS } from "./icons";
import type { AnchoredPopover } from "./anchored-popover";

export interface SidebarFootMenuItem { id: string; label: string; icon: string; run(source: "pointer" | "keyboard"): void }

export interface SidebarFootOptions {
  displayName: string;
  /** A quiet second line under the name (the username or role); omitted in variant b. */
  secondary?: string;
  variant?: "a" | "b";
  /** Opens Settings (the gear, and the pill when it has no menu). */
  onOpen(source: "pointer" | "keyboard"): void;
  /** The rows of the pill's menu; it opens above the pill, inside `stage`. */
  menu?: SidebarFootMenuItem[];
  stage?: HTMLElement;
}

export interface SidebarFoot {
  readonly root: HTMLElement;
  readonly user: HTMLButtonElement;
  readonly settings: HTMLButtonElement;
  dispose(): void;
}

/** The first letter of the name, upper-cased, for the avatar (never empty). */
export const initial = (name: string): string => [...name.trim()][0]?.toUpperCase() ?? "?";
/** A stable 0..60 degree hue offset per name: neighbours in the palette, never off it. */
export const hueOffset = (name: string): number => { let sum = 0; for (const char of name) sum = (sum * 31 + char.codePointAt(0)!) % 997; return sum % 61; };

export function createSidebarFoot(options: SidebarFootOptions): SidebarFoot {
  const variant = options.variant ?? "a";
  const root = document.createElement("div");
  root.className = "ui-sidebar-foot";
  root.dataset.variant = variant;

  const user = document.createElement("button");
  user.type = "button";
  user.className = "ui-pill ui-sidebar-user";
  const hasMenu = Boolean(options.menu?.length && options.stage);
  user.setAttribute("aria-label", `${options.displayName}${options.secondary ? `, ${options.secondary}` : ""}. ${hasMenu ? "Account menu" : "Open settings"}`);
  if (hasMenu) { user.setAttribute("aria-haspopup", "menu"); user.setAttribute("aria-expanded", "false"); }
  const avatar = document.createElement("span");
  avatar.className = "ui-sidebar-avatar";
  avatar.setAttribute("aria-hidden", "true");
  avatar.style.setProperty("--ui-avatar-hue", `${hueOffset(options.displayName)}`);
  avatar.textContent = initial(options.displayName);
  const names = document.createElement("span");
  names.className = "ui-sidebar-names";
  const name = document.createElement("span");
  name.className = "ui-sidebar-name";
  name.textContent = options.displayName;
  names.append(name);
  if (variant === "a" && options.secondary) {
    const secondary = document.createElement("span");
    secondary.className = "ui-sidebar-secondary";
    secondary.textContent = options.secondary;
    names.append(secondary);
  }
  user.append(avatar, names);

  const settings = document.createElement("button");
  settings.type = "button";
  settings.className = "ui-pill ui-pill-icon ui-sidebar-settings";
  settings.setAttribute("aria-label", "Settings");
  settings.dataset.tip = "Settings";
  settings.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">${ICONS.gear}</svg>`;

  root.append(user, settings);
  const open = (event: MouseEvent): void => options.onOpen(event.detail === 0 ? "keyboard" : "pointer");
  let menu: AnchoredPopover | undefined;
  let opening = false;
  const toggleMenu = (event: MouseEvent): void => {
    if (menu) { menu.close(event.detail === 0 ? "keyboard" : "pointer"); return; }
    if (opening) return;
    opening = true;
    const source = event.detail === 0 ? "keyboard" : "pointer";
    // The menu is loaded the first time it is asked for (D188); the first screen does not carry it.
    void import("./window-menu.on-demand").then((m) => {
      opening = false;
      menu = m.openWindowMenu(options.stage!, user, options.menu!.map((item) => ({ id: item.id, label: item.label, icon: item.icon, run: (e) => item.run(e.detail === 0 ? "keyboard" : "pointer") })),
        source, () => { menu = undefined; }, { label: "Account", side: "above", align: "start", hug: true, maxWidth: 260 });
    }, () => { opening = false; });
  };
  user.addEventListener("click", hasMenu ? toggleMenu : open);
  settings.addEventListener("click", open);
  return {
    root,
    user,
    settings,
    dispose() {
      menu?.close("keyboard");
      user.removeEventListener("click", hasMenu ? toggleMenu : open);
      settings.removeEventListener("click", open);
      root.remove();
    },
  };
}
