/**
 * The sidebar's footer (D160): who is signed in, and the way into Settings.
 *
 *   [ avatar  Display name        ]  ( gear )
 *   [         secondary line      ]
 *
 * Both controls are the shared `.ui-pill` and open the Settings overlay (the person's own
 * pill is where an account section will live). They share one height, so their centres sit on
 * one line. The avatar is the name's initial on a soft gradient derived from the theme's accent
 * (a per-name hue offset, so two people differ without leaving the palette). Every control
 * answers a press with the shared 0.97 scale; nothing here is inert.
 *
 * Variants for the owner to compare (`?footer=a|b`, chosen by the caller):
 *   a (default): two lines (name, then a quiet secondary line), a 40 px pill.
 *   b: one line, a 32 px pill, a thin gradient ring around the avatar.
 *
 * The build's version is not here: it lives in Settings, About (settings-overlay.ts).
 *
 *   const foot = createSidebarFoot({ displayName, secondary, onOpen: () => settings.open("about", "pointer") });
 *   sidebar.append(foot.root);
 */
export interface SidebarFootOptions {
  displayName: string;
  /** A quiet second line under the name (the username or role); omitted in variant b. */
  secondary?: string;
  variant?: "a" | "b";
  /** Opens Settings. */
  onOpen(source: "pointer" | "keyboard"): void;
}

export interface SidebarFoot {
  readonly root: HTMLElement;
  readonly user: HTMLButtonElement;
  readonly settings: HTMLButtonElement;
  dispose(): void;
}

const GEAR = '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3h0a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9v0a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z"/>';

/** The first letter of the name, upper-cased, for the avatar (never empty). */
const initial = (name: string): string => [...name.trim()][0]?.toUpperCase() ?? "?";
/** A stable 0..60 degree hue offset per name: neighbours in the palette, never off it. */
const hueOffset = (name: string): number => { let sum = 0; for (const char of name) sum = (sum * 31 + char.codePointAt(0)!) % 997; return sum % 61; };

export function createSidebarFoot(options: SidebarFootOptions): SidebarFoot {
  const variant = options.variant ?? "a";
  const root = document.createElement("div");
  root.className = "ui-sidebar-foot";
  root.dataset.variant = variant;

  const user = document.createElement("button");
  user.type = "button";
  user.className = "ui-pill ui-sidebar-user";
  user.setAttribute("aria-label", `${options.displayName}${options.secondary ? `, ${options.secondary}` : ""}. Open settings`);
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
  settings.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">${GEAR}</svg>`;

  root.append(user, settings);
  const open = (event: MouseEvent): void => options.onOpen(event.detail === 0 ? "keyboard" : "pointer");
  user.addEventListener("click", open);
  settings.addEventListener("click", open);
  return {
    root,
    user,
    settings,
    dispose() {
      user.removeEventListener("click", open);
      settings.removeEventListener("click", open);
      root.remove();
    },
  };
}
