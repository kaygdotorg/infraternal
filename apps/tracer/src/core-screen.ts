/** Mounts the authenticated terminal shell, theme controls, host tree, and mobile key tray. */
import { bindInputToolbar } from "../../../packages/ui/src/input-toolbar";
import { branchedMenu, type BranchSection, type BranchedMenu, type BranchedOptions } from "../../../packages/ui/src/branched";
import { applyTheme, DEFAULT_CARD, DEFAULT_WINDOW, LEVEL_NAMES, terminalTheme, THEMES, type Theme } from "../../../packages/ui/src/themes";
import { refreshTip } from "../../../packages/ui/src/tooltip";
import { Spring } from "../../../packages/ui/src/spring";
import { readClipboard } from "../../../packages/ui/src/copy-feedback";
import { mountToast, type ToastController } from "../../../packages/ui/src/toast";
import { isMacPlatform, shortcutLabel } from "../../../packages/ui/src/platform";
import { bindTerminalFont, TERMINAL_FONT_SHORTCUTS } from "./terminal-font-shortcuts";
import { bindShortcut, bindingLabel, keyCaps, PALETTE_KEYS, paletteAlternate, paletteCombo, platformCombo, registerShortcuts } from "../../../packages/ui/src/shortcuts";
import { isTypingTarget, mountShortcutsView } from "../../../packages/ui/src/shortcuts-view";
import { askSignOut } from "./sign-out";
import { ICONS } from "../../../packages/ui/src/icons";
import { createSidebarFoot } from "../../../packages/ui/src/sidebar-foot";
import { shortcutsSection } from "../../../packages/ui/src/shortcuts-settings";
import { toolbarSection } from "../../../packages/ui/src/toolbar-settings";
import { readLocal as readPref, writeLocal as writePref } from "../../../packages/ui/src/local-pref";
import { aboutSection, createSettingsOverlay, type SettingsSection } from "../../../packages/ui/src/settings-overlay";
import { buildVersion } from "./build-version";
import { pulseActivity } from "./perf-activity";
import { applyFontVars, fontById, FONTS, loadFont, type MonoFont } from "../../../packages/ui/src/fonts";
import { readLocal, writeLocal } from "../../../packages/ui/src/local-pref";
import { initialFont, rememberFont } from "./font-preference";
import type { InputModifierState, InputModifiers, TerminalClient } from "./terminal";
import type { ITheme } from "../vendor/ghostty-web";
import { recoveryUiEnabled } from "./recovery-ui";
import { titled } from "./palette-entry";

/** True only in preview builds (see build.ts): there a palette row without a title is an error, in production it is repaired. */
declare const __CLUSTERS_PREVIEW__: boolean;
const STRICT_ROWS = typeof __CLUSTERS_PREVIEW__ !== "undefined" && __CLUSTERS_PREVIEW__;
import { quarterDevicePx, restAt } from "./canvas/springs";

const ROOT = document.documentElement;
const THEME_COLOR = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
const MODIFIER_KEYS = ["ctrl", "alt"] as const;

/** A key pressed during a native composition (IME) belongs to the composition; keyCode 229 covers engines that omit `isComposing`. */
function isComposingKey(event: KeyboardEvent): boolean {
  return event.isComposing || event.keyCode === 229;
}

export interface CoreScreenOptions {
  hostName: string;
  mockMode: boolean;
  probeMode: boolean;
  /** The canvas chrome: sidebar footer, the shortcuts list, Settings as a view and the actions the canvas handles. */
  canvas?: boolean;
  /** Offers "Add hosts" in the palette (the add-host flow exists). */
  addHostEntry?: boolean;
  /** Settings is a view on the canvas, not an overlay: every way of opening it dispatches `proto:settings:<section>`. */
  settingsView?: boolean;
  /** The signed-in user's display name, shown in the sidebar footer (canvas preview only). */
  displayName?: string;
  /** The signed-in username, shown as the footer's quiet second line. */
  username?: string;
  /** `?footer=a|b`: which sidebar footer variant to draw. */
  footerVariant?: "a" | "b";
  onRecovery?: () => void;
  onCancelRecovery?: () => Promise<void>;
}

/** One key of the canvas row: an icon button with a warm tooltip (its label). */
export interface ToolbarItem {
  id: string;
  label: string;
  /** Inner SVG markup on the shared 24 px grid (packages/ui icons). */
  icon: string;
  onSelect(): void;
  pressed?: boolean;
  disabled?: boolean;
}
export interface ToolbarRow {
  update(id: string, patch: Partial<Pick<ToolbarItem, "pressed" | "disabled" | "label" | "icon">>): void;
  dispose(): void;
}

export interface CoreScreen {
  stage: HTMLElement;
  /** The pane area under the top bar; the window canvas mounts here (src/canvas.ts). */
  panes: HTMLElement;
  terminalHost: HTMLElement;
  status: HTMLElement;
  probePanel: HTMLElement;
  theme(): ITheme;
  /** The font the person has chosen (a preview in progress does not count). */
  font(): MonoFont;
  /** Registers a terminal and makes it the one that takes the keys (the single-terminal screen). */
  bindTerminal(client: TerminalClient): void;
  /** Registers a terminal on the screen: it follows the theme and font. Returns the remover. */
  registerTerminal(client: TerminalClient): () => void;
  /** The terminal the key tray and the paste button talk to; none while no terminal window is active. */
  setActiveTerminal(client: TerminalClient | undefined): void;
  /** Whether a vertical wheel of this sign is the active terminal's to take (D275). */
  wheelUse(deltaY: number): boolean;
  /** Frees every terminal canvas's pixels (a page that is hidden); `restoreSurface` draws them again from the terminal state. */
  releaseSurface(): void;
  restoreSurface(): void;
  /** Replaces the host/session tree (the canvas lists its windows here); returns the new tree. */
  /** The one shared toast of the screen: every transient message (recovery, connection, flows) uses it. */
  readonly toast: ToastController;
  /**
   * Where the sidebar's inbox (D234) attaches. The card and its registry load with the canvas (nothing in them is
   * needed for the first paint; see canvas/inbox-host.ts); only the toggle's dot and its name live here.
   */
  readonly inboxMount: { parent: HTMLElement; before: Element | null; onCount(count: number): void };
  /**
   * The key tray has two rows, one visible at a time: the keyboard row (always) and a canvas row
   * (when a canvas gives it items). Returns a controller to update item state and remove the row.
   */
  setCanvasRow(items: ToolbarItem[]): ToolbarRow;
  /** Holds the toolbar on the key row (an input lock), or releases it with `undefined`. */
  lockToolbarRow(row: "keys" | undefined): void;
  /** Runs a palette action (`theme:ink`, `font:geist-mono`, `card:2`, `bg:mesh`) as a click on its row would. */
  act(action: string): void;
  /** The appearance choices in force, and the sections of Settings that live in core (for the Settings view). */
  appearance(): { theme: string; font: string; card: number; windows: number; background: string };
  settingsPanels: { toolbar: SettingsSection; shortcuts: SettingsSection; about: SettingsSection };
  /** The row that shows now. */
  toolbarRow(): "canvas" | "keys";
  setHostTree(sections: BranchSection[], activeLeaf: string, onSelect: (id: string) => void, extras?: Pick<BranchedOptions, "openRename">): BranchedMenu;
  /** Adds palette rows computed each time the palette opens (state-dependent actions); returns a remover. */
  addPaletteProvider(provider: () => PaletteEntry[]): () => void;
  /** Refreshes visible contextual rows after authoritative data changes, keeping the query and selected action. */
  refreshPalette(): void;
  /**
   * Opens the palette limited to `entries` only (a view's windows from its hover card, #121). The same search and
   * keys apply; the next open (⌘K, the capsule) shows the whole palette again.
   */
  showPalette(entries: PaletteEntry[]): void;
  setRoundTrip(milliseconds: number | undefined): void;
  setConnection(connected: boolean): void;
  setRecoveryPending(readyAt: number | undefined): void;
  setScrolled(scrolled: boolean): void;
  onInputActivity(): void;
  dispose(): void;
}

const SVG = {
  menu: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3.5 6h13M3.5 10h9M3.5 14h13"/></svg>',
  plus: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M10 5v10M5 10h10"/></svg>',
  search: '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="9" cy="9" r="5.5"/><path d="m13 13 3.5 3.5"/></svg>',
  tab: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12h12M12 8l4 4-4 4M20 6v12"/></svg>',
  ctrl: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 14 6-6 6 6"/></svg>',
  alt: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h4.5l7 10H20M14 7h6"/></svg>',
  up: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 19V5M6 11l6-6 6 6"/></svg>',
  down: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14m-6-6 6 6 6-6"/></svg>',
  left: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M19 12H5m6-6-6 6 6 6"/></svg>',
  right: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14m-6-6 6 6-6 6"/></svg>',
  pipe: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v16"/></svg>',
  tilde: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 13.5c1.2-2.2 3-3 4.6-2 1.7 1 3.1 2.2 4.8 1 1-.7 1.8-1.6 2.6-2.5"/></svg>',
  slash: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M15 4 9 20"/></svg>',
  dash: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 12h10"/></svg>',
  paste: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="6" y="5" width="12" height="15" rx="2.5"/><path d="M9.5 5V4.5A1.5 1.5 0 0 1 11 3h2a1.5 1.5 0 0 1 1.5 1.5V5"/></svg>',
};

const SCREEN = `
  <section class="terminal-screen" id="terminal-screen" aria-label="Terminal">
    <div class="backdrop" aria-hidden="true"></div>
    <div class="panes" id="panes">
      <section class="ui-window pane-card" aria-label="Current terminal pane">
        <div class="terminal-host" id="terminal-host" role="application" aria-label="Remote terminal" tabindex="0" data-captures-keys></div>
      </section>
    </div>
    <!-- The one sidebar toggle. It lives outside the top bar so it can travel into the sidebar's
         header when the sidebar opens (see .sidebar-toggle in style.css); a spacer keeps its slot. -->
    <button class="ui-pill ui-pill-icon sidebar-toggle" id="sidebar-toggle" type="button" aria-label="Show hosts" aria-expanded="false" aria-controls="sidebar">${SVG.menu}</button>
    <header class="top" aria-label="Terminal controls">
      <span class="top-spacer" aria-hidden="true"></span>
      <button class="ui-pill capsule" id="capsule" type="button" aria-haspopup="dialog" aria-controls="palette">
        <span class="capsule-os" id="capsule-os" aria-hidden="true"></span>
        <span class="dot" id="connection-dot" aria-hidden="true"></span>
        <span class="capsule-host" id="capsule-host"></span><span class="capsule-sep" aria-hidden="true">/</span>
        <span class="capsule-session">SSH shell</span><span class="capsule-rtt" id="rtt" aria-label="Connection delay">··</span>
        <span class="capsule-keys" id="capsule-keys" aria-hidden="true"></span>
      </button>
      <nav class="tabs" aria-label="Other sessions">
        <button class="ui-pill ui-pill-icon tab tab-add" type="button" disabled aria-label="New session">${SVG.plus}</button>
      </nav>
    </header>
    <aside class="ui-panel ui-overlay-surface sidebar" id="sidebar" data-overlay-size="large" aria-label="Hosts" hidden>
      <div class="sidebar-head"><span class="sidebar-title">Hosts</span></div>
      <div id="tree"></div>
    </aside>
    <div class="palette-scrim" id="scrim" hidden></div>
    <section class="palette ui-overlay-surface" id="palette" data-overlay-size="large" role="dialog" aria-label="Go to anything" aria-modal="true" hidden>
      <div class="palette-input">${SVG.search}<input id="palette-input" role="searchbox" aria-controls="palette-results" aria-label="Search hosts, sessions, actions and settings" placeholder="Go to a host, a session or an action" autocomplete="off" spellcheck="false"></div>
      <div class="palette-results" id="palette-results" role="listbox" aria-label="Search results"></div>
      <p class="palette-foot"><kbd>↑</kbd><kbd>↓</kbd> to navigate <kbd>↵</kbd> to select <kbd>esc</kbd> to close</p>
    </section>
    ${recoveryUiEnabled() ? `<section class="ui-window recovery-notice" id="recovery-notice" aria-label="Pending account recovery" hidden>
      <p id="recovery-notice-time"></p><button class="ui-pill" id="recovery-cancel" type="button">Cancel recovery</button>
      <p id="recovery-cancel-error" role="alert"></p>
    </section>
    ` : ""}
    <div class="keyblur" aria-hidden="true"></div>
    <aside class="keybar" id="keybar" role="group" aria-label="Extra terminal keys">
      <div id="keytray" class="keytray ui-pill" role="toolbar" aria-label="Extra terminal keys. Press F6 to navigate." aria-keyshortcuts="F6 Shift+F6" aria-orientation="horizontal" tabindex="0" aria-activedescendant="key-escape">
        <div class="keyrows" id="keyrows">
          <div class="keyrow" id="keyrow-canvas" data-row="canvas" role="group" aria-label="Canvas" hidden></div>
          <div class="keyrow" id="keyrow-keys" data-row="keys" role="group" aria-label="Terminal keys">
        <button id="key-escape" type="button" tabindex="-1" data-key="esc" aria-label="Escape" class="key-word">esc</button>
        <button id="key-tab" type="button" tabindex="-1" data-key="tab" aria-label="Tab">${SVG.tab}</button>
        <button id="key-control" type="button" tabindex="-1" data-mod="ctrl" data-mod-state="off" aria-pressed="false" aria-label="Control">${SVG.ctrl}</button>
        <button id="key-option" type="button" tabindex="-1" data-mod="alt" data-mod-state="off" aria-pressed="false" aria-label="Option">${SVG.alt}</button>
        <button id="key-up" type="button" tabindex="-1" data-key="up" aria-label="Up">${SVG.up}</button>
        <button id="key-down" type="button" tabindex="-1" data-key="down" aria-label="Down">${SVG.down}</button>
        <button id="key-left" type="button" tabindex="-1" data-key="left" aria-label="Left">${SVG.left}</button>
        <button id="key-right" type="button" tabindex="-1" data-key="right" aria-label="Right">${SVG.right}</button>
        <button id="key-pipe" type="button" tabindex="-1" data-text="|" aria-label="Pipe">${SVG.pipe}</button>
        <button id="key-tilde" type="button" tabindex="-1" data-text="~" aria-label="Tilde">${SVG.tilde}</button>
        <button id="key-slash" type="button" tabindex="-1" data-text="/" aria-label="Slash">${SVG.slash}</button>
        <button id="key-dash" type="button" tabindex="-1" data-text="-" aria-label="Dash">${SVG.dash}</button>
        <button id="key-paste" type="button" tabindex="-1" data-paste aria-label="Paste">${SVG.paste}</button>
        <button id="key-dpad" type="button" tabindex="-1" class="dpad" data-tip-off aria-label="Arrow keys: drag to move" hidden></button>
          </div>
        </div>
        <span class="keydots" aria-hidden="true"><i></i><i></i></span>
      </div>
    </aside>
    <p id="connection-status" class="connection-status" role="status">Starting terminal…</p>
    <span id="test-double-badge" class="test-double-badge" hidden>TEST DOUBLE</span>
    <aside id="probe-panel" class="probe-panel ui-overlay-surface" data-overlay-size="large" aria-label="Terminal latency probe" hidden>
      <h2>Latency probe</h2><label for="probe-count">Synthetic keys</label>
      <input id="probe-count" type="number" min="1" max="5000" inputmode="numeric" />
      <div class="probe-actions"><button id="probe-run" type="button">Run probe</button><button id="probe-drop" type="button">Drop socket</button><button id="probe-copy" type="button">Copy results</button></div>
      <pre id="probe-results" aria-live="polite">Waiting for terminal.</pre><p id="probe-message" role="status"></p>
    </aside>
  </section>`;

const get = <T extends HTMLElement>(selector: string): T => {
  const node = document.querySelector<T>(selector);
  if (!node) throw new Error(`Required core-screen element is missing: ${selector}`);
  return node;
};

function themeId(value: string | null): string | undefined {
  return value && Object.hasOwn(THEMES, value) ? value : undefined;
}

export interface PaletteEntry {
  group: string;
  glyph: string;
  /** Inline SVG (24 grid, stroked) shown instead of the text glyph. */
  icon?: string;
  label: string;
  hint: string;
  action?: string;
  swatch?: Theme;
  /** Set on font rows: hovering or arrowing onto the row shows that font until the palette closes. */
  previewFont?: MonoFont;
  /** The row is listed only once something is typed: a long family of rows (the headings of the docs) must not fill the list at rest. */
  queryOnly?: boolean;
  /** What is searched in place of the hint, when the hint is for reading only (a docs row's hint names its page and must not match every heading). */
  search?: string;
}

/** The name of a modifier key on this platform: Option is the Mac key, Alt the PC one (Control is the same word everywhere). */
const modifierName = (mod: keyof InputModifiers): string => mod === "ctrl" ? "Control" : isMacPlatform() ? "Option" : "Alt";

/** Mounts the authenticated server host, its live shell session, and terminal controls. */
export function mountCoreScreen(app: HTMLElement, options: CoreScreenOptions): CoreScreen {
  app.innerHTML = SCREEN;
  // The modifier names are read per mount, not in the template: "Option" is the Mac key, "Alt" elsewhere.
  for (const mod of ["ctrl", "alt"] as const) get<HTMLElement>(`[data-mod="${mod}"]`).setAttribute("aria-label", modifierName(mod));
  // The palette key is written per platform (⌘K on a Mac keyboard, Ctrl+Shift+K elsewhere): one keycap per part.
  get<HTMLElement>("#capsule-keys").replaceChildren(...keyCaps(shortcutLabel(PALETTE_KEYS)).map((cap) => { const kbd = document.createElement("kbd"); kbd.className = "capsule-kbd"; kbd.textContent = cap; return kbd; }));
  const stage = get<HTMLElement>("#terminal-screen");
  // The canvas preview never draws the status line, from the first frame (the canvas chunk loads a
  // moment after the screen mounts, and the line's "Starting terminal…" must not flash meanwhile).
  if (options.canvas) stage.dataset.preview = "";
  const terminalHost = get<HTMLElement>("#terminal-host");
  const status = get<HTMLElement>("#connection-status");
  const probePanel = get<HTMLElement>("#probe-panel");
  const sidebar = get<HTMLElement>("#sidebar");
  const sidebarToggle = get<HTMLButtonElement>("#sidebar-toggle");
  const toast = mountToast(stage);
  // Whether any floating thing is open (the test-double badge steps aside for it). A flag from script:
  // `:has()` selectors on the screen or the body would re-evaluate on every change below them.
  const OVERLAYS = ".sidebar:not([hidden]), .palette:not([hidden]), .ui-toast:not([hidden]), .ah-float, .canvas-popover, .ui-settings, .ui-shortcuts";
  let overlayQueued = false;
  const syncOverlay = (): void => {
    overlayQueued = false;
    stage.toggleAttribute("data-overlay", stage.querySelector(OVERLAYS) !== null || document.querySelector(".ui-confirm-tip") !== null);
  };
  // Only a change to one of the floating things can change the answer. The terminals add and remove nodes all the time
  // (every window, every output), and re-running `querySelector` over the whole screen for each of those was the top
  // item of the main thread with 54 terminals open (90-120 ms of every second).
  const OVERLAY_NODE = ".sidebar, .palette, .ui-toast, .ah-float, .canvas-popover, .ui-settings, .ui-shortcuts, .ui-confirm-tip";
  const relevantNode = (n: Node): boolean => n.nodeType === 1 && ((n as Element).matches(OVERLAY_NODE) || (n as Element).querySelector(OVERLAY_NODE) !== null);
  const overlayWatch = new MutationObserver((records) => {
    if (overlayQueued) return;
    for (const r of records) {
      const hit = r.type === "attributes"
        ? (r.target as Element).matches(OVERLAY_NODE)
        : [...r.addedNodes, ...r.removedNodes].some(relevantNode);
      if (hit) { overlayQueued = true; queueMicrotask(syncOverlay); return; }
    }
  });
  overlayWatch.observe(document.body, { childList: true }); // the anchored confirmation lives on the body
  overlayWatch.observe(stage, { childList: true, subtree: true, attributes: true, attributeFilter: ["hidden"] });
  // The footer (who is signed in, settings, the build) is part of the canvas preview.
  // Settings is a shell; About is the only section so far (the build's name, version, commit, date).
  const build = buildVersion();
  const canvasItems = new Map<string, ToolbarItem>();
  const settingsSections: SettingsSection[] = [aboutSection({ name: "infraternal", version: build.short, commit: build.full, built: build.built })];
  const shortcutsPanel = shortcutsSection(stage);
  if (options.canvas && !options.settingsView) settingsSections.unshift(shortcutsPanel);
  const aboutPanel = settingsSections[0]!;
  const settings = options.canvas && !options.settingsView ? createSettingsOverlay({ stage, sections: settingsSections }) : undefined;
  const openSettingsFrom = (source: "pointer" | "keyboard"): void => {
    if (options.settingsView) window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:settings:appearance", source } }));
    else settings?.open("about", source);
  };
  const askSignOutFrom = (anchor: HTMLElement): void => { askSignOut(anchor, toast); };
  const sidebarFoot = options.canvas
    ? createSidebarFoot({
      displayName: options.displayName?.trim() || "Signed in",
      ...(options.username ? { secondary: options.username } : {}),
      ...(options.footerVariant ? { variant: options.footerVariant } : {}),
      onOpen: (source) => openSettingsFrom(source),
      // The person's pill is their account menu (#171): Settings, and the one obvious way out of this device.
      stage,
      menu: [
        { id: "settings", label: "Settings", icon: ICONS.gear, run: (source) => openSettingsFrom(source) },
        { id: "sign-out", label: "Sign out", icon: ICONS.signOut, run: () => askSignOutFrom(sidebarFoot!.user) },
      ],
    })
    : undefined;
  if (sidebarFoot) { sidebar.append(sidebarFoot.root); sidebar.dataset.foot = ""; }
  // While the sidebar is closed the toggle carries a dot, and its name says why, so a pending item is never out of
  // sight and never only a colour. The card itself is made by the canvas (canvas/inbox-host.ts).
  let pending = 0;
  const toggleName = (open: boolean): string => `${open ? "Hide hosts" : "Show hosts"}${pending > 0 ? `, ${pending} waiting for you` : ""}`;
  const inboxMount = {
    parent: sidebar, before: sidebarFoot?.root ?? null,
    onCount: (count: number): void => {
      pending = count;
      sidebarToggle.toggleAttribute("data-pending", count > 0);
      sidebarToggle.setAttribute("aria-label", toggleName(!sidebar.hidden));
    },
  };
  const capsule = get<HTMLButtonElement>("#capsule");
  const palette = get<HTMLElement>("#palette");
  const scrim = get<HTMLElement>("#scrim");
  const paletteInput = get<HTMLInputElement>("#palette-input");
  const paletteResults = get<HTMLElement>("#palette-results");
  const panes = get<HTMLElement>("#panes");
  const keybar = get<HTMLElement>("#keybar");
  const keytray = get<HTMLElement>(".keytray");
  const keyblur = get<HTMLElement>(".keyblur");
  const rtt = get<HTMLElement>("#rtt");
  const dot = get<HTMLElement>("#connection-dot");
  const hostName = options.hostName.trim();
  get<HTMLElement>("#capsule-host").textContent = hostName;
  get<HTMLElement>("#test-double-badge").hidden = !options.mockMode;
  probePanel.hidden = !options.probeMode;

  let branch = branchedMenu(get<HTMLElement>("#tree"), [
    { id: "current-host", label: hostName, meta: "current", live: true, open: true, leaves: [
      { id: "current-shell", label: "SSH shell", meta: "current" },
    ] },
  ], { active: "current-shell" });
  const liveHost = get<HTMLElement>("#tree .bm-sec");
  liveHost.setAttribute("aria-label", hostName);

  const params = new URLSearchParams(location.search);
  // `?card=1..4` and `?windows=1..4`: Solid, Tinted, Clear, Frosted, for the floating cards (default Tinted) and for
  // windows (default Solid). The saved choice comes next.
  const validLevel = (n: number): boolean => Number.isInteger(n) && n >= 1 && n <= 4;
  const levelFrom = (param: string, saved: string, fallback: number): number => {
    const q = Number(params.get(param)), v = Number(readLocal(saved));
    return validLevel(q) ? q : validLevel(v) ? v : fallback;
  };
  let cardLevel = levelFrom("card", "tracer.card", DEFAULT_CARD);
  let windowLevel = levelFrom("windows", "tracer.windows", DEFAULT_WINDOW);
  const systemDark = matchMedia("(prefers-color-scheme: dark)");
  let currentThemeId = themeId(params.get("theme")) ?? themeId(readLocal("tracer.theme")) ?? (systemDark.matches ? "mocha" : "latte");
  // The font follows the same order as the theme: URL, then the saved choice, then the default.
  // `committedFont` is what the person chose; `shownFont` is what is on screen, which differs
  // only while a palette row previews another font.
  let committedFont = initialFont();
  let shownFont = committedFont;
  let fontRequest = 0;
  // Plain (`none`): one solid colour with subtle dots. Soft: the theme's gentle gradient. Plain is the default (D191); a saved choice stays. Mesh: the full
  // theme mesh. The dots sit on all three.
  const validBackground = (v: string | null): v is "none" | "soft" | "mesh" => v === "none" || v === "soft" || v === "mesh";
  let background: string = validBackground(params.get("bg")) ? params.get("bg")! : validBackground(readLocal("tracer.background")) ? readLocal("tracer.background")! : "none";
  /** The terminal paints no background of its own where a window shows the canvas through it (and over the mesh). */
  const translucentTerminal = (): boolean => background === "mesh" || windowLevel > 1;
  /** Every terminal on the screen (they share the look), and the one that takes the keys. */
  const clients = new Set<TerminalClient>();
  let client: TerminalClient | undefined;
  let modifiers: InputModifiers = { ctrl: "off", alt: "off" };
  const modifierTapAt: Record<keyof InputModifiers, number> = { ctrl: -Infinity, alt: -Infinity };
  const modifierPointerTimes: Record<keyof InputModifiers, number[]> = { ctrl: [], alt: [] };
  let terminalFocusTarget: HTMLElement | null = null;
  let resizeTimer = 0;
  let keyboardOpen = false;
  let meshKey = "";
  let backdropModule: Promise<typeof import("../../../packages/ui/src/backdrop")> | undefined;

  const getBackdrop = () => backdropModule ??= import("../../../packages/ui/src/backdrop");
  const paintMesh = async (): Promise<void> => {
    const active = THEMES[currentThemeId]!;
    const width = Math.round(innerWidth * devicePixelRatio);
    const height = Math.round(innerHeight * devicePixelRatio);
    const key = `${active.name}:${width}x${height}`;
    if (meshKey === key) return;
    meshKey = key;
    const renderer = await getBackdrop();
    if (meshKey !== key || background !== "mesh") return;
    ROOT.style.setProperty("--dpr", String(devicePixelRatio));
    const grain = `url(${renderer.grainTile()})`;
    const url = await renderer.renderBackdrop(active, width, height);
    if (meshKey === key && background === "mesh" && url) setMeshImages(`url("${url}")`, grain);
  };

  // The mesh image and the grain tile are read by the backdrop layers only, so they are set there (a rule in a sheet of
  // our own) and not as root tokens: a root token is inherited, and changing one restyles every element of the page.
  const meshSheet = new CSSStyleSheet();
  document.adoptedStyleSheets = [...document.adoptedStyleSheets, meshSheet];
  const setMeshImages = (image: string, grain: string): void => { meshSheet.replaceSync(`:where(.backdrop, .ui-canvas-backdrop) { --mesh-image: ${image}; --grain: ${grain}; }`); };

  const releaseMesh = (): void => {
    meshKey = "";
    setMeshImages("none", "none");
    void backdropModule?.then((renderer) => renderer.releaseBackdrop());
  };

  const applyLook = (instant = false): Promise<void> => {
    const active = THEMES[currentThemeId]!;
    stage.toggleAttribute("data-no-motion", instant);
    ROOT.dataset.theme = currentThemeId;
    ROOT.dataset.bg = background;
    stage.dataset.theme = currentThemeId;
    stage.dataset.bg = background;
    applyTheme(active, ROOT, cardLevel, windowLevel);
    window.dispatchEvent(new CustomEvent("tracer:appearance"));
    THEME_COLOR?.setAttribute("content", active.bg);
    // The terminal's own recolour (every retained row is redrawn) is the heaviest part of a theme
    // switch. It runs in its own task, right after the tokens above, so the interface answers at once
    // and no single task is long (work stays under the 50 ms long-task line at 4x CPU).
    const terminal = terminalTheme(active, translucentTerminal());
    window.setTimeout(() => { for (const c of clients) c.setTheme(terminal); }, 0);
    if (background === "mesh") return paintMesh();
    releaseMesh();
    return Promise.resolve();
  };
  void applyLook();

  // Theme and background picks swap every token in one step, with no animation. Measured
  // at 1440x900 DPR 2: a view-transition crossfade froze rendering for 80-220 ms while it
  // captured two full-screen snapshots, and the old per-element fades repainted every
  // blurred surface per frame; the instant swap costs one repaint (p95 16.7-33 ms headless).
  // The palette closes in the same step so it never fades over a repainting page.
  const swapLook = (): void => {
    // Every token changes in this step, so no element may start a transition from its old value (a window card's border
    // colour, the palette's own close): transitions are off while the first frame with the new styles is made, and on again
    // after it. The attribute is set before anything changes, and removed after two frames, so the style recalculation that
    // would start the transitions always sees it. It costs one attribute and no forced layout (TASTE "No lag while animating").
    ROOT.setAttribute("data-look-swap", "");
    setPalette(false, "keyboard");
    void applyLook(true);
    requestAnimationFrame(() => requestAnimationFrame(() => ROOT.removeAttribute("data-look-swap")));
  };


  /**
   * Shows a font on the whole screen: UI text, the sign-in tokens and the terminal together.
   * A font that has never been used is fetched first and the previous one stays on screen
   * until it arrives, so a preview never flashes a fallback. Each call supersedes the ones
   * before it: arrowing quickly down the list applies only the row the person stopped on.
   */
  const showFont = (font: MonoFont): void => {
    const request = ++fontRequest;
    if (font === shownFont) return;
    void loadFont(font).then(() => {
      if (request !== fontRequest) return;
      shownFont = font;
      applyFontVars(font, ROOT);
      // The terminal re-measures its cells and redraws in its own task, after the interface has the new face.
      window.setTimeout(() => { for (const c of clients) c.setFont(font); }, 0);
    }, () => undefined);
  };

  const baseEntries = (): PaletteEntry[] => [
    { group: "Sessions", glyph: "›_", label: "SSH shell", hint: hostName, action: "session:current" },
    { group: "Hosts", glyph: "●", label: hostName, hint: "current", action: "host:current" },
    ...Object.entries(THEMES).map(([id, theme]) => ({
      group: "Theme", glyph: "◉", label: theme.name, hint: theme.dark ? "dark" : "light", action: `theme:${id}`, swatch: theme,
    })),
    ...FONTS.map((font) => ({
      group: "Font", glyph: "Aa", label: font.label, hint: font.hint, action: `font:${font.id}`, previewFont: font,
    })),
    { group: "Background", glyph: "□", label: "Background: Plain", hint: "one solid colour · subtle dots", action: "bg:none" },
    { group: "Background", glyph: "▦", label: "Background: Soft", hint: "a gentle gradient · dots", action: "bg:soft" },
    { group: "Background", glyph: "▦", label: "Background: Mesh", hint: "the theme's mesh · dots", action: "bg:mesh" },
    ...LEVEL_NAMES.map((name, i) => ({ group: "Transparency", glyph: "◫", label: `Card transparency: ${name}`, hint: "popovers, palette, sidebar", action: `card:${i + 1}` })),
    ...LEVEL_NAMES.map((name, i) => ({ group: "Transparency", glyph: "◫", label: `Window transparency: ${name}`, hint: "terminals and window cards", action: `windows:${i + 1}` })),
    ...(options.addHostEntry ? [
      { group: "Actions", glyph: "+", label: "Add hosts", hint: "", action: "proto:addhost" },
    ] : []),
    ...(options.canvas ? [
      { group: "Help", glyph: "?", label: "Show keyboard shortcuts", hint: bindingLabel("shortcuts") || "?", action: "shortcuts:open" },
      // The hint carries the aliases, so "version", "build" and "commit" find it.
      { group: "Help", glyph: "⌨", label: "Settings: Shortcuts", hint: "keys · rebind · reset", action: "settings:shortcuts" },
      ...(canvasItems.size ? [{ group: "Help", glyph: "▭", label: "Settings: Toolbar", hint: "rows · order · show · hide", action: "settings:toolbar" }] : []),
      { group: "Help", glyph: "i", label: "About infraternal", hint: "version · build · commit", action: "settings:about" },
    ] : []),
    ...(recoveryUiEnabled() && options.onRecovery ? [{ group: "Account", glyph: "◇", label: "Use recovery key", hint: "replace passkey", action: "account:recovery" }] : []),
    ...(options.canvas ? [{ group: "Account", glyph: "⎋", icon: ICONS.signOut, label: "Sign out", hint: "this device", action: "account:signout" }] : []),
  ];
  // Rows can come from providers (the canvas offers Lock or Unlock by state), so the list and its
  // lookup tables are rebuilt each time the palette opens; typing only filters them.
  const providers = new Set<() => PaletteEntry[]>();
  const entries: PaletteEntry[] = [];
  const paletteSearchText = new Map<PaletteEntry, string>();
  const paletteOptionIds = new Map<PaletteEntry, string>();
  const paletteGroupIds = new Map<string, string>();
  // The fixed rows are built, indexed and given their DOM rows once; only the rows a provider computes from
  // state (Lock or Unlock) are new at each open, so opening the palette re-attaches rows instead of rebuilding them.
  let staticEntries = baseEntries();
  const indexEntry = (entry: PaletteEntry, index: number): void => {
    // A row without a title throws in preview builds; in production the repaired title is what is searched and shown.
    const { label } = titled(entry, STRICT_ROWS);
    paletteSearchText.set(entry, `${entry.group} ${label} ${entry.search ?? entry.hint}`.toLocaleLowerCase());
    // Normalize IDs once so typing never sanitizes every matching result.
    paletteOptionIds.set(entry, `palette-option-${entry.action?.replaceAll(/[^a-z0-9_-]/gi, "-") ?? `entry-${index}`}`);
    if (!paletteGroupIds.has(entry.group)) paletteGroupIds.set(entry.group, `palette-group-${entry.group.toLocaleLowerCase().replaceAll(" ", "-")}`);
  };
  staticEntries.forEach(indexEntry);
  /** The fixed rows that depend on state (the toolbar's row appears once a canvas row is registered) are rebuilt when it changes. */
  const rebuildStaticEntries = (): void => {
    for (const entry of staticEntries) { paletteSearchText.delete(entry); paletteOptionIds.delete(entry); }
    staticEntries = baseEntries();
    staticEntries.forEach(indexEntry);
  };
  let contextual: PaletteEntry[] = [];
  const refreshEntries = (): void => {
    for (const entry of contextual) { paletteSearchText.delete(entry); paletteOptionIds.delete(entry); }
    // Context first: a provider's rows (actions on the current window) lead the list.
    contextual = [...providers].flatMap((provider) => provider());
    contextual.forEach((entry, index) => indexEntry(entry, 1000 + index));
    entries.length = 0;
    entries.push(...contextual, ...staticEntries);
  };
  refreshEntries();
  let visibleEntries: PaletteEntry[] = [];
  let visibleOptions: HTMLButtonElement[] = [];
  let selected = 0;
  const headingByGroup = new Map<string, HTMLDivElement>();
  const rowCache = new WeakMap<PaletteEntry, HTMLButtonElement>();

  /**
   * Keeps the screen in step with the selected palette row: a font row previews its font, any
   * other row (or a closed palette) shows the chosen font. Called on every selection change,
   * so hover, arrows, filtering, opening and closing all go through one rule, and Escape or a
   * click outside revert simply by closing.
   */
  const syncFontPreview = (): void => {
    const entry = palette.hidden ? undefined : visibleEntries[selected];
    showFont(entry?.previewFont ?? committedFont);
  };

  const keepPaletteOptionVisible = (option: HTMLButtonElement, index: number): void => {
    option.scrollIntoView({ block: "nearest", behavior: "instant" });
    const entry = visibleEntries[index];
    if (entry && visibleEntries[index - 1]?.group !== entry.group) {
      headingByGroup.get(entry.group)?.scrollIntoView({ block: "nearest", behavior: "instant" });
    }
  };

  const selectPaletteOption = (nextIndex: number): void => {
    if (!visibleOptions.length) return;
    const boundedIndex = Math.max(0, Math.min(visibleOptions.length - 1, nextIndex));
    const previousOption = visibleOptions[selected];
    const nextOption = visibleOptions[boundedIndex];
    if (!nextOption) return;
    if (previousOption !== nextOption) {
      previousOption?.setAttribute("aria-selected", "false");
      nextOption.setAttribute("aria-selected", "true");
      selected = boundedIndex;
    }
    if (paletteInput.getAttribute("aria-activedescendant") !== nextOption.id) {
      paletteInput.setAttribute("aria-activedescendant", nextOption.id);
    }
    keepPaletteOptionVisible(nextOption, boundedIndex);
    syncFontPreview();
  };

  const visiblePalettePageSize = (): number => {
    const port = paletteResults.getBoundingClientRect();
    const top = port.top + paletteResults.clientTop;
    const bottom = top + paletteResults.clientHeight;
    const visibleCount = visibleOptions.reduce((count, option) => {
      const rect = option.getBoundingClientRect();
      return rect.top >= top && rect.bottom <= bottom ? count + 1 : count;
    }, 0);
    return Math.max(1, visibleCount);
  };

  /** Rows of a scoped open (`showPalette`); undefined is the whole palette. They are indexed only while open. */
  let scopedEntries: PaletteEntry[] | undefined;
  const indexScoped = (on: boolean): void => {
    for (const entry of scopedEntries ?? []) {
      if (on) indexEntry(entry, 2000);
      else { paletteSearchText.delete(entry); paletteOptionIds.delete(entry); rowCache.delete(entry); }
    }
  };
  const renderPalette = (query = "", preserveAction?: string): void => {
    const needle = query.trim().toLocaleLowerCase();
    visibleEntries = (scopedEntries ?? entries).filter((entry) => (needle !== "" || !entry.queryOnly) && (paletteSearchText.get(entry)?.includes(needle) ?? false));
    selected = preserveAction === undefined ? Math.min(selected, Math.max(0, visibleEntries.length - 1)) : Math.max(0, visibleEntries.findIndex((entry) => entry.action === preserveAction));
    visibleOptions = [];
    // Clearing the list resets its viewport, avoiding a separate scrollTop read/write.
    paletteResults.replaceChildren();
    let previousGroup = "";
    visibleEntries.forEach((entry, index) => {
      if (entry.group !== previousGroup) {
        let heading = headingByGroup.get(entry.group);
        if (!heading) {
          heading = document.createElement("div");
          heading.id = paletteGroupIds.get(entry.group)!;
          heading.className = "group-label";
          heading.textContent = entry.group;
          headingByGroup.set(entry.group, heading);
        }
        paletteResults.append(heading);
        previousGroup = entry.group;
      }
      // Rows are built once per entry and re-attached on every filter: the list grows with every
      // group added (fonts doubled it), and rebuilding it per keystroke cost more than the budget.
      let result = rowCache.get(entry);
      if (!result) {
        result = document.createElement("button");
        result.id = paletteOptionIds.get(entry)!;
        result.type = "button";
        result.className = "result";
        result.setAttribute("role", "option");
        result.dataset.action = entry.action ?? "";
        const icon = document.createElement("span");
        icon.className = "result-icon";
        if (entry.icon) { icon.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${entry.icon}</svg>`; icon.classList.add("has-svg"); }
        else icon.textContent = entry.glyph;
        if (entry.swatch) {
          icon.classList.add("swatch");
          icon.style.backgroundColor = entry.swatch.bg;
          icon.style.boxShadow = `inset 0 0 0 3px ${entry.swatch.accent}`;
        }
        const label = document.createElement("span");
        label.className = "result-label";
        label.textContent = titled(entry, false).label;
        const hint = document.createElement("span");
        hint.className = "result-hint";
        hint.textContent = entry.hint;
        result.append(icon, label, hint);
        rowCache.set(entry, result);
      }
      result.setAttribute("aria-selected", String(index === selected));
      visibleOptions.push(result);
      paletteResults.append(result);
    });
    const selectedOption = visibleOptions[selected];
    if (selectedOption) {
      if (paletteInput.getAttribute("aria-activedescendant") !== selectedOption.id) {
        paletteInput.setAttribute("aria-activedescendant", selectedOption.id);
      }
    } else {
      paletteInput.removeAttribute("aria-activedescendant");
    }
    if (!visibleEntries.length) {
      const empty = document.createElement("p");
      empty.className = "palette-empty";
      empty.textContent = "No matching hosts, sessions or actions.";
      paletteResults.append(empty);
    }
    syncFontPreview();
  };

  // Desktop docks the sidebar beside the windows instead of over them, so nothing under it
  // becomes unreachable. The canvas never docks it (#114): the sidebar is another layer over the canvas, so opening
  // it changes no layout, resizes no terminal and moves no window; only the sidebar itself slides. The panes' left edge moves once (one terminal fit, no per-frame resize)
  // and a FLIP translate on the compositor makes that single layout change read as a slide.
  const dockedLayout = matchMedia("(hover: hover) and (pointer: fine) and (min-width: 1024px)");
  const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
  const dockPanes = (open: boolean, instant: boolean): void => {
    const docked = open && dockedLayout.matches && stage.dataset.clusters === undefined;
    if ((stage.dataset.sidebar === "docked") === docked) return;
    const before = panes.getBoundingClientRect().left;
    stage.dataset.sidebar = docked ? "docked" : "";
    if (instant || reducedMotion.matches) return;
    const shift = before - panes.getBoundingClientRect().left;
    panes.animate(
      [{ transform: `translateX(${shift}px)` }, { transform: "translateX(0)" }],
      { duration: 240, easing: "cubic-bezier(0.32, 0.72, 0, 1)" },
    );
  };

  const setSidebar = (open: boolean, instant = false): void => {
    pulseActivity("sidebar", 450);
    dockPanes(open, instant);
    // The toggle travels between the top bar and the sidebar header on a transform transition.
    sidebarToggle.classList.toggle("instant", instant);
    stage.toggleAttribute("data-sidebar-open", open);
    if (instant) window.setTimeout(() => sidebarToggle.classList.remove("instant"), 0);
    else if (reducedMotion.matches) sidebarToggle.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160, easing: "ease-out" });
    sidebar.hidden = !open;
    sidebarToggle.setAttribute("aria-expanded", String(open));
    sidebarToggle.setAttribute("aria-label", toggleName(open));
    sidebar.classList.toggle("instant", instant);
    if (instant) window.setTimeout(() => sidebar.classList.remove("instant"), 0);
  };

  // The palette owns the top bar while it is open (TASTE): a top-bar control whose box the palette covers fades out
  // (opacity, 120 ms in style.css) and takes no pointer, and the rest stay. The overlap is measured once, when the
  // palette opens, so no layout is read per frame; on close every control comes back. Only the top bar's controls are
  // listed: the canvas's corner buttons (the sidebar toggle, the "+") and the capsule the palette grows from.
  const PALETTE_COVERABLE = [sidebarToggle, capsule, ...document.querySelectorAll<HTMLElement>(".top > .tabs > .tab-add")];
  const coverTopBar = (open: boolean): void => {
    if (!open) { for (const control of PALETTE_COVERABLE) delete control.dataset.paletteCovered; return; }
    const box = palette.getBoundingClientRect();
    for (const control of PALETTE_COVERABLE) {
      const r = control.getBoundingClientRect();
      const overlaps = r.left < box.right && box.left < r.right && r.top < box.bottom && box.top < r.bottom;
      if (overlaps) control.dataset.paletteCovered = ""; else delete control.dataset.paletteCovered;
    }
  };
  const setPalette = (open: boolean, source: "keyboard" | "pointer" = "pointer", only?: PaletteEntry[]): void => {
    // The source of the last open or close decides its motion (a key-triggered open is the shorter one).
    palette.dataset.openKind = source;
    if (open) {
      shortcuts.close(true);
      settings?.close("keyboard");
      indexScoped(false);
      scopedEntries = only;
      indexScoped(true);
      // Fill the list while the palette is still display:none (no layout runs for it), then show it and
      // focus the field: the browser lays the palette out once, for the focus, not once per step.
      refreshEntries();
      selected = 0;
      paletteInput.value = "";
      renderPalette();
      palette.hidden = false;
      scrim.hidden = false;
      coverTopBar(true);
      paletteInput.focus({ preventScroll: true });
    } else {
      indexScoped(false);
      scopedEntries = undefined;
      palette.hidden = true;
      scrim.hidden = true;
      coverTopBar(false);
      paletteInput.removeAttribute("aria-activedescendant");
      syncFontPreview();
    }
  };
  const sidebarClick = (event: MouseEvent): void => setSidebar(sidebar.hidden, event.detail === 0);
  // The `?` view: the capsule morphs into the shortcut list. Sections come from the registry; the
  // canvas registers its own, and a future container or cluster area registers its sections the same way.
  // The panel lists the area it was opened in first: from a focused terminal the Terminal section leads (D160).
  let shortcutsFromTerminal = false;
  const shortcuts = mountShortcutsView({
    pill: capsule,
    stage,
    areas: () => stage.dataset.canvas !== "on" ? ["terminal"] : shortcutsFromTerminal ? ["terminal", "canvas"] : ["canvas", "terminal"],
  });
  const removeShortcuts = [
    registerShortcuts({ id: "terminal", title: "Terminal", area: "terminal", shortcuts: [
      { id: "tray", label: "Focus the key tray", keys: "F6" },
      { id: "back", label: "Back to the terminal", keys: "Shift+F6" },
      { id: "focus-resend-actions", label: "Focus saved typing actions", keys: { mac: "⌘⇧Space", other: "Ctrl+Shift+Space" }, combo: platformCombo({ code: "Space", mod: true, shift: true }, { code: "Space", mod: true, shift: true }) },
    ] }),
    registerShortcuts({ id: "global", title: "Everywhere", area: "global", shortcuts: [
      { id: "palette", label: "Open the command palette", keys: PALETTE_KEYS, combo: paletteCombo(), alternates: [paletteAlternate()] },
      // ⌘/ on a Mac and Ctrl+Shift+/ elsewhere work inside a focused terminal, where "?" is typed into the shell; "?" stays
      // as the alternate outside text fields.
      { id: "shortcuts", label: "Show these shortcuts", keys: "?", combo: platformCombo({ code: "Slash", key: "/", mod: true, shift: false }, { code: "Slash", key: "/", mod: true, shift: true }), alternates: [{ code: "Slash", key: "?" }] },
      { id: "close", label: "Close the open panel", keys: "Esc" },
      ...TERMINAL_FONT_SHORTCUTS,
    ] }),
  ];
  // The palette's chords come from the registry too (D222). A locked window owns every key, but a Mac's ⌘K still opens
  // the palette, since a terminal never receives ⌘; a declined press goes through to the terminal (Ctrl+K stays the shell's).
  // The font chords act on the one terminal here; on the canvas the canvas binds them to its active window.
  if (!options.canvas) removeShortcuts.push(...bindTerminalFont(() => client));
  removeShortcuts.push(bindShortcut("focus-resend-actions", () => { client?.focusInputResendActions(); }, (event) => !isComposingKey(event) && (client?.hasPendingInputResend() ?? false)));
  removeShortcuts.push(bindShortcut("palette", () => setPalette(palette.hidden, "keyboard"), (event) => !stage.hasAttribute("data-locked") || (isMacPlatform() && event.metaKey)));
  // The panel's keys ("?" and ⌘/) come from the registry, so they can be rebound and reach a focused terminal. Only the canvas
  // screen has the panel, as before.
  if (options.canvas) removeShortcuts.push(bindShortcut("shortcuts", (event) => {
    if (!palette.hidden) return;
    shortcutsFromTerminal = !!(event.target as Element | null)?.closest?.(".terminal-host");
    shortcuts.toggle();
  }));
  const capsuleClick = (event: MouseEvent): void => setPalette(true, event.detail === 0 ? "keyboard" : "pointer");
  const scrimClick = (): void => setPalette(false, "pointer");

  const keydown = (event: KeyboardEvent): void => {
    // Inert descendants cannot block global shortcuts while logout is in flight.
    if (stage.inert) { event.preventDefault(); event.stopImmediatePropagation(); return; }
    if (event.key === "F6") {
      if (event.shiftKey || keytray.contains(event.target as Node)) {
        if (client) client.focus();
        else terminalHost.focus({ preventScroll: true });
      } else {
        keytray.focus({ preventScroll: true });
      }
      event.preventDefault();
      event.stopPropagation();
      return;
    }
    if (event.key === "Escape") {
      if (settings?.isOpen || shortcuts.isOpen) return; // the open overlay takes this Escape itself
      // A control that holds something open (the inbox's expanded line) collapses it first (`data-owns-escape`).
      if (event.target instanceof Element && event.target.closest("[data-owns-escape]")) return;
      // A card that takes Escape from anywhere on the page (`data-owns-escape="page"`: the version panel, which a click leaves focus outside of in Safari) closes itself first.
      if (document.querySelector("[data-owns-escape='page']")) return;
      // An open menu or confirmation (the profile pill's menu, a sign-out question, a row's in-row question) or a revealed row
      // (row-menu.ts closes it) closes first and keeps the sidebar it hangs from.
      if (palette.hidden && document.querySelector(".ui-anchored-popover, .ui-confirm-tip[data-open='true'], .ui-row-ask, [data-swiped]")) return;
      // The palette owns this Escape: it stops here, so a canvas flow (the add-host wizard listens in the document's
      // capture phase, after this window listener) stays open. The capture order is what makes stopping necessary.
      if (!palette.hidden) { setPalette(false, "keyboard"); event.preventDefault(); event.stopPropagation(); }
      else if (!sidebar.hidden) { setSidebar(false, true); event.preventDefault(); }
    }
  };
  const resize = (): void => {
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(() => {
      if (background === "mesh") {
        meshKey = "";
        void paintMesh();
      }
    }, 250);
  };
  const systemThemeChange = (): void => {
    if (!themeId(params.get("theme")) && !themeId(readLocal("tracer.theme"))) {
      currentThemeId = systemDark.matches ? "mocha" : "latte";
      void applyLook();
    }
  };
  const viewportChange = (): void => {
    const viewport = window.visualViewport;
    keyboardOpen = Boolean(viewport && viewport.height < window.innerHeight - 120);
    ROOT.dataset.kb = keyboardOpen ? "open" : "closed";
    if (keyboardOpen) {
      keybar.classList.remove("is-away");
      keyblur.classList.remove("is-away");
    }
  };

  sidebarToggle.addEventListener("click", sidebarClick);
  capsule.addEventListener("click", capsuleClick);
  scrim.addEventListener("click", scrimClick);
  paletteInput.addEventListener("input", () => {
    selected = 0;
    renderPalette(paletteInput.value);
  });
  paletteInput.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      const delta = event.key === "ArrowDown" ? 1 : -1;
      selectPaletteOption(selected + delta);
      event.preventDefault();
    } else if (event.key === "Home") {
      selectPaletteOption(0);
      event.preventDefault();
    } else if (event.key === "End") {
      selectPaletteOption(visibleOptions.length - 1);
      event.preventDefault();
    } else if (event.key === "PageDown" || event.key === "PageUp") {
      const delta = visiblePalettePageSize() * (event.key === "PageDown" ? 1 : -1);
      selectPaletteOption(selected + delta);
      event.preventDefault();
    } else if (event.key === "Enter") {
      const entry = visibleEntries[selected];
      if (entry) runAction(entry.action ?? "", "keyboard");
      setPalette(false, "keyboard");
      event.preventDefault();
    }
  });
  // Hover selects the row under a moving pointer, so a font row previews on hover like it does
  // on arrow keys. Only real movement counts: arrowing scrolls rows under a resting pointer, and
  // that must not steal the selection back.
  let lastPointer = { x: -1, y: -1 };
  paletteResults.addEventListener("pointermove", (event) => {
    if (event.pointerType === "touch" || (event.clientX === lastPointer.x && event.clientY === lastPointer.y)) return;
    lastPointer = { x: event.clientX, y: event.clientY };
    const target = event.target;
    if (!(target instanceof Element)) return;
    const result = target.closest<HTMLButtonElement>(".result");
    const index = result ? visibleOptions.indexOf(result) : -1;
    if (index >= 0 && index !== selected) selectPaletteOption(index);
  });
  // Hover intent: the face of a font row is fetched and decoded as soon as the pointer rests on it
  // (the long part of a cold font switch is the fetch and decode, not the apply), so choosing it is warm.
  paletteResults.addEventListener("pointerover", (event) => {
    const row = (event.target as Element | null)?.closest<HTMLElement>(".result[data-action^='font:']");
    const font = row ? fontById(row.dataset.action!.slice(5)) : undefined;
    if (font) void loadFont(font).catch(() => undefined);
  });
  paletteResults.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const result = target.closest<HTMLButtonElement>(".result");
    if (!result) return;
    if (!runAction(result.dataset.action ?? "", "pointer")) setPalette(false, "pointer");
  });
  window.addEventListener("keydown", keydown, true);
  window.addEventListener("resize", resize);
  systemDark.addEventListener("change", systemThemeChange);
  const dockedLayoutChange = (): void => dockPanes(!sidebar.hidden, true);
  dockedLayout.addEventListener("change", dockedLayoutChange);
  window.visualViewport?.addEventListener("resize", viewportChange);
  window.visualViewport?.addEventListener("scroll", viewportChange);
  viewportChange();

  const keyInput: Record<string, string> = {
    esc: "\x1b", tab: "\t", up: "\x1b[A", down: "\x1b[B", left: "\x1b[D", right: "\x1b[C",
  };
  const markInstant = (button: HTMLButtonElement): void => {
    button.dataset.instant = "";
    requestAnimationFrame(() => requestAnimationFrame(() => { delete button.dataset.instant; }));
  };
  const renderModifiers = (instant = false): void => {
    for (const button of keybar.querySelectorAll<HTMLButtonElement>("[data-mod]")) {
      const name = button.dataset.mod as keyof InputModifiers;
      const state: InputModifierState = modifiers[name];
      button.dataset.modState = state;
      button.setAttribute("aria-pressed", state === "locked" ? "mixed" : String(state === "armed"));
      button.setAttribute("aria-label", state === "off" ? modifierName(name) : `${modifierName(name)}, ${state}`);
      if (instant) markInstant(button);
      refreshTip(button);
    }
    for (const name of MODIFIER_KEYS) client?.setInputModifier(name, modifiers[name]);
  };
  const isTerminalFocus = (element: Element | null): element is HTMLElement =>
    element instanceof HTMLElement && element.closest(".terminal-host") !== null;
  /**
   * After a toolbar tap, a terminal that had input focus when the finger went down gets it back (D129: the keyboard
   * stays up). A terminal that did not have focus is never given it: that would summon the on-screen keyboard from
   * a button that has nothing to type into.
   */
  const restoreTerminalFocus = (): void => {
    const target = terminalFocusTarget;
    terminalFocusTarget = null;
    if (!target || isTerminalFocus(document.activeElement)) return;
    if (target.isConnected) target.focus({ preventScroll: true });
  };
  const rememberTerminalFocus = (): void => {
    const active = document.activeElement;
    terminalFocusTarget = isTerminalFocus(active) ? active : null;
  };
  const keybarPointerDown = (event: PointerEvent): void => {
    rememberTerminalFocus();
    if (!(event.target instanceof Element)) return;
    const modifierButton = event.target.closest<HTMLButtonElement>("button[data-mod]");
    if (modifierButton?.dataset.mod) {
      const name = modifierButton.dataset.mod as keyof InputModifiers;
      const now = performance.now();
      const pointerTimes = modifierPointerTimes[name];
      // iOS may delay the synthetic click; preserve pointerdown order for a real fast double tap.
      while (pointerTimes[0] !== undefined && pointerTimes[0] < now - 300) pointerTimes.shift();
      pointerTimes.push(now);
    }
  };
  const keybarPointerCancel = (): void => {
    modifierPointerTimes.ctrl.length = 0;
    modifierPointerTimes.alt.length = 0;
  };
  const keybarKeydown = (event: KeyboardEvent): void => {
    const buttons = [...keytray.querySelectorAll<HTMLButtonElement>("button:not([hidden]):not(:disabled):not(.dpad)")];
    if (!buttons.length) return;
    const currentId = keytray.getAttribute("aria-activedescendant");
    const currentIndex = Math.max(0, buttons.findIndex((button) => button.id === currentId));
    let nextIndex: number | undefined;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") nextIndex = (currentIndex + 1) % buttons.length;
    else if (event.key === "ArrowLeft" || event.key === "ArrowUp") nextIndex = (currentIndex + buttons.length - 1) % buttons.length;
    else if (event.key === "Home") nextIndex = 0;
    else if (event.key === "End") nextIndex = buttons.length - 1;
    else if (event.key === "Enter" || event.key === " ") {
      buttons[currentIndex]!.click();
      event.preventDefault();
      return;
    }
    if (nextIndex !== undefined) {
      const nextButton = buttons[nextIndex]!;
      keytray.setAttribute("aria-activedescendant", nextButton.id);
      nextButton.scrollIntoView({ block: "nearest", inline: "nearest" });
      event.preventDefault();
    }
  };
  const modifierClick = (button: HTMLButtonElement, event: MouseEvent): void => {
    const name = button.dataset.mod as keyof InputModifiers;
    const state = modifiers[name];
    const now = event.detail === 0 ? performance.now() : modifierPointerTimes[name].shift() ?? performance.now();
    if (event.detail === 0) modifierPointerTimes[name].length = 0;
    if (state === "locked") {
      modifiers[name] = "off";
      modifierTapAt[name] = -Infinity;
    } else if (state === "armed") {
      const age = now - modifierTapAt[name];
      modifiers[name] = age >= 0 && age <= 300 ? "locked" : "off";
      modifierTapAt[name] = -Infinity;
    } else {
      modifiers[name] = "armed";
      modifierTapAt[name] = now;
    }
    renderModifiers(event.detail === 0);
  };
  const injectKey = (data: string): void => {
    try { client?.injectInput(data); } catch { /* connection state is announced in the status line */ }
  };
  const keybarClick = (event: MouseEvent): void => {
    if (rowSwipeMoved) { rowSwipeMoved = false; return; }
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest<HTMLButtonElement>("button");
    if (!button || button.disabled || button.classList.contains("dpad")) return;
    const key = button.dataset.key;
    const text = button.dataset.text;
    if (button.dataset.mod) {
      modifierClick(button, event);
    } else if (key && keyInput[key]) {
      injectKey(keyInput[key]!);
    } else if (text) {
      injectKey(text);
    } else if ("paste" in button.dataset) {
      void readClipboard().then((value) => {
        if (value) injectKey(value);
        else if (value === undefined) openPasteTarget();
      });
    } else if (button.dataset.cv) {
      const item = canvasItems.get(button.dataset.cv);
      if (item && !item.disabled) item.onSelect();
    }
    // A key activated from the keyboard (F6 into the tray, Enter) hands the focus back to the terminal it came from.
    if (event.detail === 0 && !terminalFocusTarget && keytray.contains(document.activeElement)) client?.focus();
    restoreTerminalFocus();
  };
  // The tray never takes or moves focus: some browsers move it on the compatibility mouse events that follow a touch,
  // so those are cancelled too (the terminal keeps its input focus and the keyboard stays up; nothing else gains one).
  const offInputToolbar = bindInputToolbar(keybar, keybarPointerDown);
  keybar.addEventListener("pointercancel", keybarPointerCancel);
  keybar.addEventListener("click", keybarClick);
  keytray.addEventListener("keydown", keybarKeydown);

  // ---- two rows, one visible at a time ------------------------------------------------------
  // The canvas row (top) and the keyboard row (below) share this one tray. A vertical swipe slides
  // between them on a spring; a horizontal swipe scrolls the row when it overflows (native, with
  // momentum and the edge fade). The keyboard row shows while a terminal has input focus, the
  // canvas row otherwise; a manual swipe stands until the next focus change.
  const rowsEl = get<HTMLElement>("#keyrows");
  const canvasRowEl = get<HTMLElement>("#keyrow-canvas");
  const keysRowEl = get<HTMLElement>("#keyrow-keys");
  let rowIndex = 1; // 0 canvas, 1 keys
  let rowSwipeMoved = false;
  const rowHeight = (): number => keysRowEl.offsetHeight || 46;
  const paintRow = (v: number): void => { rowsEl.style.transform = v === 0 ? "" : `translateY(${-v * rowHeight()}px)`; };
  // A row is one 46 px step: the spring rests under a quarter of a device pixel of it (canvas/springs.ts).
  const rowSpring = restAt(new Spring(1, (v) => { if (canvasRowEl.hidden) { rowsEl.style.transform = ""; return; } paintRow(v); }, { visualDuration: 0.38 }), quarterDevicePx() / 46);
  const settleRow = (index: number, instant = false): void => {
    rowIndex = index;
    stage.dataset.row = index === 0 ? "canvas" : "keys";
    keytray.querySelectorAll<HTMLElement>(".keydots i").forEach((dot, i) => dot.toggleAttribute("data-on", i === index));
    canvasRowEl.inert = index !== 0;
    keysRowEl.inert = index !== 1;
    rowSpring.set(index, instant);
  };
  let rowLock: "keys" | undefined;
  // The key row exists only while a terminal has input focus (or an input lock holds it): without one there is
  // nothing to type into, so the toolbar is the canvas row alone, with no second row, no dots and no swipe. When a
  // terminal takes focus the key row slides in with the canvas row one snap swipe away; when focus leaves, it slides
  // away and is taken out of the layout. Without a canvas row (no canvas) the key row is simply always there.
  let keysHideTimer = 0;
  const showKeys = (show: boolean): void => {
    window.clearTimeout(keysHideTimer);
    if (show) { keysRowEl.hidden = false; keytray.dataset.rows = "2"; return; }
    keysHideTimer = window.setTimeout(() => { if (!canvasRowEl.hidden) { keysRowEl.hidden = true; keytray.dataset.rows = "1"; } }, 420);
  };
  const autoRow = (): void => {
    if (canvasRowEl.hidden || editing) return;
    const wanted = Boolean(rowLock) || isTerminalFocus(document.activeElement) || keytray.contains(document.activeElement);
    showKeys(wanted);
    settleRow(wanted ? 1 : 0);
  };
  // The canvas cancels the default focus change of a press (it pans on it), so a press on the canvas that is not in a
  // terminal ends the terminal's input focus itself: the keyboard goes down and the key row slides away.
  document.addEventListener("pointerdown", (event) => {
    const target = event.target;
    if (!(target instanceof Element) || !isTerminalFocus(document.activeElement)) return;
    if (target.closest(".cl-viewport") && !target.closest(".terminal-host")) (document.activeElement as HTMLElement).blur();
  }, true);
  document.addEventListener("focusin", autoRow);
  document.addEventListener("focusout", () => requestAnimationFrame(autoRow));
  let rowSwipe: { id: number; x: number; y: number; from: number; axis: "" | "x" | "y"; samples: Array<{ y: number; t: number }> } | undefined;
  keytray.addEventListener("pointerdown", (event) => {
    rowSwipeMoved = false;
    if (canvasRowEl.hidden || keysRowEl.hidden || !event.isPrimary || editing) return;
    rowSwipe = { id: event.pointerId, x: event.clientX, y: event.clientY, from: rowSpring.value, axis: "", samples: [{ y: event.clientY, t: event.timeStamp }] };
  }, true);
  keytray.addEventListener("pointermove", (event) => {
    const sw = rowSwipe;
    if (!sw || event.pointerId !== sw.id) return;
    if (!sw.axis) {
      const dx = event.clientX - sw.x, dy = event.clientY - sw.y;
      if (Math.hypot(dx, dy) < 8) return;
      sw.axis = Math.abs(dy) > Math.abs(dx) ? "y" : "x";
      if (sw.axis === "y") { keytray.setPointerCapture(event.pointerId); rowSwipeMoved = true; }
    }
    if (sw.axis !== "y") return;
    // Follows the finger one to one, with rubber past either row.
    // The stack follows the finger one to one: dragging up moves it up and reveals the row below (the key
    // row); dragging down reveals the row above (the canvas row).
    let v = sw.from - (event.clientY - sw.y) / rowHeight();
    if (v < 0) v = v * 0.25; else if (v > 1) v = 1 + (v - 1) * 0.25;
    rowSpring.value = v;
    paintRow(v);
    sw.samples.push({ y: event.clientY, t: event.timeStamp });
    if (sw.samples.length > 5) sw.samples.shift();
  });
  const endRowSwipe = (event: PointerEvent): void => {
    const sw = rowSwipe;
    if (!sw || event.pointerId !== sw.id) return;
    rowSwipe = undefined;
    if (sw.axis !== "y") return;
    const a = sw.samples[0]!, b = sw.samples[sw.samples.length - 1]!;
    const vel = b.t > a.t ? (b.y - a.y) / (b.t - a.t) : 0; // px/ms, finger direction (up is negative)
    const projected = rowSpring.value - (vel * 120) / rowHeight();
    settleRow(projected > 0.5 ? 1 : 0);
  };
  keytray.addEventListener("pointerup", endRowSwipe);
  keytray.addEventListener("pointercancel", endRowSwipe);
  keytray.addEventListener("dblclick", (e) => e.preventDefault());
  keytray.addEventListener("click", (event) => {
    if (stage.dataset.scrolled !== "true" || stage.hasAttribute("data-toolbar-open")) return;
    stage.setAttribute("data-toolbar-open", "");
    event.stopPropagation();
    event.preventDefault();
  }, true);

  // ---- the toolbar is customisable (Settings, Toolbar): order and visibility per row, stored locally -----------
  type RowId = "canvas" | "keys";
  interface RowPref { order: string[]; hidden: string[] }
  const loadPrefs = (): Record<RowId, RowPref> => {
    const empty = (): Record<RowId, RowPref> => ({ canvas: { order: [], hidden: [] }, keys: { order: [], hidden: [] } });
    try {
      const raw = JSON.parse(readPref("tracer.toolbar") ?? "null") as Partial<Record<RowId, Partial<RowPref>>> | null;
      const out = empty();
      for (const id of ["canvas", "keys"] as const) {
        const r = raw?.[id];
        if (r) out[id] = { order: Array.isArray(r.order) ? r.order.filter((x): x is string => typeof x === "string") : [], hidden: Array.isArray(r.hidden) ? r.hidden.filter((x): x is string => typeof x === "string") : [] };
      }
      return out;
    } catch { return empty(); }
  };
  // Two layers: the account's layout (shared by every device, kept by the server) and an optional
  // override for this device. The override exists only after "Customise for this device".
  const hasDeviceLayout = (): boolean => readPref("tracer.toolbar") !== null;
  let onDevice = hasDeviceLayout();
  const prefs = loadPrefs();
  const accountPrefs: Record<"canvas" | "keys", { order: string[]; hidden: string[] }> = { canvas: { order: [], hidden: [] }, keys: { order: [], hidden: [] } };
  void fetch("/__mock/account/toolbar", { credentials: "same-origin" }).then((r) => (r.ok ? r.json() : undefined)).then((data: { layout?: typeof accountPrefs | null } | undefined) => {
    if (!data?.layout) return;
    for (const id of ["canvas", "keys"] as const) if (data.layout[id]) accountPrefs[id] = data.layout[id];
    if (!onDevice) { for (const id of ["canvas", "keys"] as const) prefs[id] = accountPrefs[id]; applyPrefs(true); }
  }).catch(() => undefined);
  const saveAccount = (): void => { void fetch("/__mock/account/toolbar", { method: "PUT", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(accountPrefs) }).catch(() => undefined); };
  const rowEl = (id: RowId): HTMLElement => (id === "canvas" ? canvasRowEl : keysRowEl);
  const controlId = (b: HTMLElement): string => b.dataset.cv ?? b.id;
  const controls = (id: RowId): HTMLButtonElement[] => [...rowEl(id).querySelectorAll<HTMLButtonElement>(":scope > button:not(.dpad)")];
  const defaults: Record<RowId, string[]> = { canvas: [], keys: controls("keys").map(controlId) };
  const applyPrefs = (animate: boolean): void => {
    const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
    for (const id of ["canvas", "keys"] as const) {
      const row = rowEl(id);
      const list = controls(id);
      const before = new Map(list.map((b) => [b, b.hidden ? undefined : b.getBoundingClientRect().left]));
      const pref = prefs[id];
      const rank = (b: HTMLElement): number => { const at = pref.order.indexOf(controlId(b)); return at < 0 ? 1000 + defaults[id].indexOf(controlId(b)) : at; };
      for (const b of [...list].sort((a, c) => rank(a) - rank(c))) row.append(b);
      for (const b of list) b.hidden = pref.hidden.includes(controlId(b));
      if (!animate || reducedMotion) continue;
      for (const b of list) {
        const was = before.get(b);
        if (b.hidden) continue;
        const now = b.getBoundingClientRect().left;
        const dx = was === undefined ? 0 : was - now;
        if (was === undefined) { new Spring(1, (p) => { b.style.opacity = p === 0 ? "" : String(1 - p); b.style.transform = p === 0 ? "" : `scale(${1 - 0.4 * p})`; }, { visualDuration: 0.3 }).set(0); continue; }
        if (Math.abs(dx) < 1) continue;
        new Spring(1, (p) => { b.style.transform = p === 0 ? "" : `translateX(${dx * p}px)`; }, { visualDuration: 0.36 }).set(0);
      }
    }
  };
  const toolbarModel = {
    rows() {
      return (["canvas", "keys"] as const).map((id) => ({
        id,
        title: id === "canvas" ? "Canvas row" : "Key row",
        controls: controls(id).map((b) => ({ id: controlId(b), label: b.getAttribute("aria-label") ?? controlId(b), icon: b.querySelector("svg")?.innerHTML ?? '<path d="M6 12h12"/>' })),
        hidden: new Set(prefs[id].hidden),
      }));
    },
    source: (): "account" | "device" => (onDevice ? "device" : "account"),
    change(rowId: string, order: string[], hidden: string[]) {
      prefs[rowId as RowId] = { order, hidden };
      if (onDevice) writePref("tracer.toolbar", JSON.stringify(prefs));
      else { accountPrefs[rowId as RowId] = { order, hidden }; saveAccount(); }
      applyPrefs(true);
    },
    reset() {
      for (const id of ["canvas", "keys"] as const) { prefs[id] = { order: [], hidden: [] }; if (!onDevice) accountPrefs[id] = { order: [], hidden: [] }; }
      if (onDevice) writePref("tracer.toolbar", JSON.stringify(prefs)); else saveAccount();
      applyPrefs(true);
    },
    /** "Customise for this device": copy what is shown into an override for this device. */
    customise() { onDevice = true; writePref("tracer.toolbar", JSON.stringify(prefs)); },
    /** "Use account layout": drop the override. */
    useAccount() {
      onDevice = false;
      try { localStorage.removeItem("tracer.toolbar"); } catch { /* storage is optional */ }
      for (const id of ["canvas", "keys"] as const) prefs[id] = accountPrefs[id];
      applyPrefs(true);
    },
  };
  const toolbarSettings = toolbarSection(toolbarModel);
  applyPrefs(false);

  // ---- long-press the toolbar: edit it in place ---------------------------------------------------------------
  // Controls wiggle, a drag reorders them (the neighbours part, the drop settles) within a row or across
  // rows (drag up for the canvas row, down for the key row), a badge hides one, and a tray of hidden
  // controls slides up with a plus on each. Done, or a tap outside, ends it. It edits the same layout as
  // Settings, Toolbar (account layout, or this device's override).
  let editing = false;
  let editTray: HTMLElement | undefined;
  const buzz = (ms = 8): void => { try { navigator.vibrate?.(ms); } catch { /* not every platform has it */ } };
  const persistLayout = (): void => {
    for (const id of ["canvas", "keys"] as const) {
      const all = controls(id);
      toolbarModel.change(id, all.map(controlId), all.map(controlId).filter((c) => prefs[id].hidden.includes(c)));
    }
  };
  const labelOf = (b: HTMLElement): string => b.getAttribute("aria-label") ?? controlId(b);
  const iconOf = (b: HTMLElement): string => b.querySelector("svg")?.innerHTML ?? '<path d="M6 12h12"/>';
  const paintEditTray = (): void => {
    if (!editTray) return;
    const list = editTray.querySelector<HTMLElement>(".keyedit-list")!;
    list.replaceChildren();
    const hiddenControls = ([...controls("canvas"), ...controls("keys")]).filter((b) => b.hidden);
    for (const b of hiddenControls) {
      const add = document.createElement("button");
      add.type = "button";
      add.className = "keyedit-add";
      add.dataset.id = controlId(b);
      add.setAttribute("aria-label", `Show ${labelOf(b)}`);
      add.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${iconOf(b)}</svg><i aria-hidden="true">+</i>`;
      add.addEventListener("click", () => { buzz(6); for (const id of ["canvas", "keys"] as const) prefs[id] = { order: prefs[id].order, hidden: prefs[id].hidden.filter((h) => h !== controlId(b)) }; persistLayout(); paintBadges(); paintEditTray(); });
      list.append(add);
    }
    editTray.dataset.empty = String(hiddenControls.length === 0);
  };
  const paintBadges = (): void => {
    for (const b of keytray.querySelectorAll<HTMLElement>(".keyrow > button")) {
      b.querySelector(".keyx")?.remove();
      if (!editing || b.hidden) continue;
      const x = document.createElement("i");
      x.className = "keyx";
      x.setAttribute("role", "button");
      x.setAttribute("aria-label", `Hide ${labelOf(b)}`);
      x.textContent = "×";
      b.append(x);
    }
    keytray.querySelectorAll<HTMLElement>(".keyrow > button:not([hidden])").forEach((b, i) => b.style.setProperty("--wiggle", `${(i % 5) * -70}ms`));
  };
  const endEdit = (): void => {
    if (!editing) return;
    editing = false;
    stage.removeAttribute("data-toolbar-edit");
    document.removeEventListener("pointerdown", outsideEdit, true);
    paintBadges();
    const tray = editTray;
    editTray = undefined;
    if (tray) {
      if (matchMedia("(prefers-reduced-motion: reduce)").matches) tray.remove();
      else new Spring(0, (v) => { tray.style.transform = `translateY(${v * 24}px)`; tray.style.opacity = String(1 - v); if (v >= 1) tray.remove(); }, { visualDuration: 0.25 }).set(1);
    }
    buzz(6);
  };
  const outsideEdit = (e: PointerEvent): void => { if (!(e.target as Element).closest(".keytray, .keyedit")) endEdit(); };
  const startEdit = (): void => {
    if (editing || canvasRowEl.hidden) return;
    editing = true;
    stage.setAttribute("data-toolbar-edit", "");
    buzz(12);
    const tray = document.createElement("div");
    tray.className = "keyedit ui-pill";
    tray.innerHTML = `<div class="keyedit-list" role="group" aria-label="Hidden controls"></div><button type="button" class="keyedit-done" aria-label="Done">Done</button>`;
    tray.querySelector(".keyedit-done")!.addEventListener("click", endEdit);
    keybar.append(tray);
    editTray = tray;
    paintEditTray();
    paintBadges();
    if (!matchMedia("(prefers-reduced-motion: reduce)").matches) new Spring(1, (v) => { tray.style.transform = v === 0 ? "" : `translateY(${v * 28}px)`; tray.style.opacity = String(1 - v); }, { visualDuration: 0.4 }).set(0);
    document.addEventListener("pointerdown", outsideEdit, true);
  };
  // Long press (touch) starts it.
  let hold: { id: number; x: number; y: number; timer: number } | undefined;
  keytray.addEventListener("pointerdown", (e) => {
    if (e.pointerType !== "touch" || editing || canvasRowEl.hidden) return;
    hold = { id: e.pointerId, x: e.clientX, y: e.clientY, timer: window.setTimeout(() => { hold = undefined; startEdit(); }, 600) };
  }, true);
  for (const type of ["pointermove", "pointerup", "pointercancel"] as const) keytray.addEventListener(type, (e) => {
    if (!hold || e.pointerId !== hold.id) return;
    if (type !== "pointermove" || Math.hypot(e.clientX - hold.x, e.clientY - hold.y) > 8) { window.clearTimeout(hold.timer); hold = undefined; }
  }, true);
  // In edit mode a tap hides (the badge) instead of pressing, and a drag reorders.
  keytray.addEventListener("click", (e) => {
    if (!editing) return;
    e.stopPropagation(); e.preventDefault();
    const x = (e.target as Element).closest(".keyx");
    const b = x?.closest<HTMLButtonElement>("button");
    if (!b) return;
    buzz(10);
    const id = controlId(b);
    for (const rid of ["canvas", "keys"] as const) if (rowEl(rid).contains(b)) prefs[rid] = { order: prefs[rid].order, hidden: [...prefs[rid].hidden.filter((h) => h !== id), id] };
    persistLayout();
    paintBadges();
    paintEditTray();
  }, true);
  keytray.addEventListener("pointerdown", (e) => {
    if (!editing || (e.target as Element).closest(".keyx")) return;
    const b = (e.target as Element).closest<HTMLButtonElement>(".keyrow > button");
    if (!b) return;
    e.preventDefault();
    e.stopPropagation();
    let dragging = false;
    const startX = e.clientX, startY = e.clientY;
    const rect = b.getBoundingClientRect();
    let ghost: HTMLElement | undefined;
    const trayRect = keytray.getBoundingClientRect();
    const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
    const targetRow = (y: number): RowId => (y < trayRect.top + trayRect.height / 2 - 26 ? "canvas" : y > trayRect.top + trayRect.height / 2 + 26 ? "keys" : (rowEl("canvas").contains(b) ? "canvas" : "keys"));
    const move = (ev: PointerEvent): void => {
      if (!dragging) {
        if (Math.hypot(ev.clientX - startX, ev.clientY - startY) < 5) return;
        dragging = true;
        buzz(8);
        ghost = b.cloneNode(true) as HTMLElement;
        ghost.classList.add("keyghost");
        ghost.querySelector(".keyx")?.remove();
        ghost.style.cssText = `position:fixed;left:${rect.left}px;top:${rect.top}px;width:${rect.width}px;height:${rect.height}px;z-index:30;pointer-events:none`;
        document.body.append(ghost);
        b.style.opacity = "0.25";
      }
      ghost!.style.transform = `translate(${ev.clientX - startX}px, ${ev.clientY - startY}px) scale(1.14)`;
      // Row: dragging up reaches the canvas row, down the key row; the row slides to follow.
      const want = targetRow(ev.clientY);
      const here: RowId = rowEl("canvas").contains(b) ? "canvas" : "keys";
      const row = rowEl(want);
      const siblings = controls(want).filter((c) => c !== b && !c.hidden);
      const x = ev.clientX;
      const index = siblings.filter((c) => { const r = c.getBoundingClientRect(); return r.left + r.width / 2 < x; }).length;
      const ref = siblings[index] ?? null;
      const before = new Map(controls(want).map((c) => [c, c.getBoundingClientRect().left]));
      if (want !== here) { settleRow(want === "canvas" ? 0 : 1); buzz(6); }
      if (b.parentElement !== row || b.nextElementSibling !== ref) {
        row.insertBefore(b, ref);
        if (!reducedMotion) for (const [c, left] of before) {
          if (c === b) continue;
          const dx = left - c.getBoundingClientRect().left;
          if (Math.abs(dx) > 1) new Spring(1, (p) => { c.style.transform = p === 0 ? "" : `translateX(${dx * p}px)`; }, { visualDuration: 0.3 }).set(0);
        }
      }
    };
    const end = (): void => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", end);
      window.removeEventListener("pointercancel", end);
      if (!dragging || !ghost) return;
      const g = ghost;
      const to = b.getBoundingClientRect();
      const from = g.getBoundingClientRect();
      const land = (): void => { g.remove(); b.style.opacity = ""; buzz(10); persistLayout(); paintBadges(); };
      if (reducedMotion) { land(); return; }
      const dx = to.left + to.width / 2 - (from.left + from.width / 2), dy = to.top + to.height / 2 - (from.top + from.height / 2);
      const base = g.style.transform;
      const m = /translate\(([-\d.]+)px, ([-\d.]+)px\)/.exec(base);
      const sx = m ? Number(m[1]) : 0, sy = m ? Number(m[2]) : 0;
      new Spring(0, (v) => { g.style.transform = `translate(${sx + dx * v}px, ${sy + dy * v}px) scale(${1.14 - 0.14 * Math.min(1, v)})`; if (v === 1) land(); }, { visualDuration: 0.34 }).set(1);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", end);
    window.addEventListener("pointercancel", end);
  }, true);

  // Where the clipboard cannot be read (a plain-http origin), a paste target takes the system paste.
  const openPasteTarget = (): void => {
    stage.querySelector(".paste-target")?.remove();
    const box = document.createElement("div");
    box.className = "paste-target ui-overlay-surface";
    const input = document.createElement("input");
    input.type = "text";
    input.placeholder = "Paste here";
    input.setAttribute("aria-label", "Paste into the terminal");
    box.append(input);
    stage.append(box);
    const done = (): void => { box.remove(); document.removeEventListener("pointerdown", outside, true); };
    const outside = (e: PointerEvent): void => { if (!box.contains(e.target as Node)) done(); };
    input.addEventListener("paste", (e) => { const text = e.clipboardData?.getData("text"); e.preventDefault(); if (text) injectKey(text); done(); restoreTerminalFocus(); });
    input.addEventListener("keydown", (e) => { if (e.key === "Escape") done(); });
    document.addEventListener("pointerdown", outside, true);
    input.focus();
  };

  /** Runs a palette action; returns true when the action closed the palette itself. */
  function runAction(action: string, source: "keyboard" | "pointer"): boolean {
    const [kind, value] = action.split(":");
    // An appearance change is its own activity in a frame trace: a User Timing measure from the action to the second
    // frame after it, named by what changed (theme, font, card, windows, bg).
    if (kind === "theme" || kind === "font" || kind === "card" || kind === "windows" || kind === "bg") {
      const start = performance.now();
      requestAnimationFrame(() => requestAnimationFrame(() => performance.measure(`appearance:${kind}`, { start, detail: { value } })));
    }
    if (kind === "account" && value === "recovery") {
      setPalette(false, source);
      options.onRecovery?.();
    } else if (kind === "account" && value === "signout") {
      setPalette(false, source);
      // Asked from where the person can see: the profile pill when the sidebar is open, else the top pill.
      requestAnimationFrame(() => askSignOutFrom(sidebarFoot && !sidebar.hidden ? sidebarFoot.user : get<HTMLElement>("#capsule")));
      return true;
    } else if (kind === "theme" && themeId(value ?? null)) {
      currentThemeId = value!;
      writeLocal("tracer.theme", currentThemeId);
      swapLook();
      return true;
    } else if (kind === "font" && fontById(value)) {
      committedFont = fontById(value)!;
      rememberFont(committedFont);
      showFont(committedFont);
      window.dispatchEvent(new CustomEvent("tracer:appearance"));
      return false;
    } else if (kind === "card" && validLevel(Number(value))) {
      cardLevel = Number(value);
      writeLocal("tracer.card", value!);
      swapLook();
      return true;
    } else if (kind === "windows" && validLevel(Number(value))) {
      windowLevel = Number(value);
      writeLocal("tracer.windows", value!);
      swapLook();
      return true;
    } else if (kind === "bg" && validBackground(value ?? null)) {
      background = value!;
      writeLocal("tracer.background", value!);
      swapLook();
      return true;
    } else if (kind === "settings") {
      setPalette(false, source);
      if (options.settingsView) window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: `canvas:settings:${value ?? "appearance"}`, source } }));
      else settings?.open(value ?? "about", source);
      return true;
    } else if (kind === "shortcuts") {
      // After the palette has gone, so the morph starts from the settled pill.
      setPalette(false, source);
      shortcutsFromTerminal = false;
      requestAnimationFrame(() => shortcuts.open());
      return true;
    } else if (kind === "session" || kind === "host") {
      if (client) client.focus(); else terminalHost.focus({ preventScroll: true });
    } else if ((kind === "proto" || kind === "canvas") && options.canvas) {
      window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action, source } }));
    }
    return false;
  }

  const recoveryNotice = stage.querySelector<HTMLElement>("#recovery-notice")!;
  const cancelRecovery = stage.querySelector<HTMLButtonElement>("#recovery-cancel")!;
  let recoveryReady: number | undefined;
  const cancelClick = (): void => {
    cancelRecovery.disabled = true;
    const error = stage.querySelector<HTMLElement>("#recovery-cancel-error")!;
    error.textContent = "";
    void options.onCancelRecovery?.().catch(() => {
      error.textContent = "Recovery could not be cancelled. Try again.";
    }).finally(() => { cancelRecovery.disabled = false; });
  };
  cancelRecovery?.addEventListener("click", cancelClick);
  const api: CoreScreen = {
    stage,
    panes,
    terminalHost,
    status,
    probePanel,
    theme: () => terminalTheme(THEMES[currentThemeId]!, translucentTerminal()),
    font: () => committedFont,
    bindTerminal(value) {
      api.registerTerminal(value);
      api.setActiveTerminal(value);
    },
    registerTerminal(value) {
      clients.add(value);
      value.setFont(shownFont);
      value.setTheme(terminalTheme(THEMES[currentThemeId]!, translucentTerminal()));
      return () => { clients.delete(value); if (client === value) client = undefined; };
    },
    releaseSurface() { for (const c of clients) c.releaseSurface(); },
    restoreSurface() { for (const c of clients) c.restoreSurface(); },
    wheelUse: (deltaY) => !!client?.wheelUse(deltaY),
    setActiveTerminal(value) {
      client = value;
      if (value) for (const name of MODIFIER_KEYS) value.setInputModifier(name, modifiers[name]);
    },
    addPaletteProvider(provider) {
      providers.add(provider);
      return () => { providers.delete(provider); };
    },
    refreshPalette() {
      if (palette.hidden || scopedEntries) return;
      const action = visibleEntries[selected]?.action;
      refreshEntries();
      renderPalette(paletteInput.value, action);
    },
    showPalette(only) { setPalette(true, "pointer", only); },
    toast,
    inboxMount,
    act(action) { runAction(action, "pointer"); },
    appearance: () => ({ theme: currentThemeId, font: committedFont.id, card: cardLevel, windows: windowLevel, background }),
    settingsPanels: { get toolbar() { return toolbarSettings; }, shortcuts: shortcutsPanel, about: aboutPanel },
    toolbarRow: () => (rowIndex === 0 ? "canvas" : "keys"),
    lockToolbarRow(row) { rowLock = row; autoRow(); },
    setCanvasRow(items) {
      canvasItems.clear();
      canvasRowEl.replaceChildren();
      for (const item of items) {
        canvasItems.set(item.id, { ...item });
        const button = document.createElement("button");
        button.type = "button";
        button.tabIndex = -1;
        button.dataset.cv = item.id;
        button.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${item.icon}</svg>`;
        canvasRowEl.append(button);
      }
      const paint = (id: string): void => {
        const item = canvasItems.get(id);
        const button = canvasRowEl.querySelector<HTMLButtonElement>(`[data-cv="${id}"]`);
        if (!item || !button) return;
        button.setAttribute("aria-label", item.label);
        button.setAttribute("aria-pressed", String(Boolean(item.pressed)));
        button.dataset.pressed = String(Boolean(item.pressed));
        button.toggleAttribute("data-disabled", Boolean(item.disabled));
        button.setAttribute("aria-disabled", String(Boolean(item.disabled)));
        button.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${item.icon}</svg>`;
        refreshTip(button);
      };
      for (const item of items) paint(item.id);
      defaults.canvas = items.map((i) => i.id);
      applyPrefs(false);
      if (items.length && !options.settingsView && !settingsSections.includes(toolbarSettings)) settingsSections.unshift(toolbarSettings);
      rebuildStaticEntries();
      canvasRowEl.hidden = items.length === 0;
      keysRowEl.hidden = items.length > 0 && !isTerminalFocus(document.activeElement);
      keytray.dataset.rows = items.length && !keysRowEl.hidden ? "2" : "1";
      if (!items.length) settleRow(1, true);
      else settleRow(keysRowEl.hidden ? 0 : 1, true);
      return {
        update(id, patch) { const cur = canvasItems.get(id); if (!cur) return; Object.assign(cur, patch); paint(id); },
        dispose() { const at = settingsSections.indexOf(toolbarSettings); if (at >= 0) settingsSections.splice(at, 1); canvasItems.clear(); rebuildStaticEntries(); canvasRowEl.replaceChildren(); canvasRowEl.hidden = true; keysRowEl.hidden = false; keytray.dataset.rows = "1"; settleRow(1, true); },
      };
    },
    setHostTree(sections, activeLeaf, onSelect, extras) {
      branch.dispose();
      branch = branchedMenu(get<HTMLElement>("#tree"), sections, { active: activeLeaf, onSelect, ...extras });
      return branch;
    },
    setRoundTrip(milliseconds) {
      rtt.textContent = milliseconds === undefined ? "··" : `${Math.round(milliseconds)} ms`;
      rtt.setAttribute("aria-label", milliseconds === undefined ? "Connection delay unavailable" : `Connection delay ${Math.round(milliseconds)} milliseconds`);
    },
    setConnection(connected) {
      dot.classList.toggle("live", connected);
      dot.classList.toggle("connecting", !connected);
      stage.dataset.connected = String(connected);
    },
    setRecoveryPending(readyAt) {
      // Keep consuming session/socket state while unapproved presentation stays absent.
      if (!recoveryUiEnabled()) return;
      recoveryNotice.hidden = readyAt === undefined;
      if (readyAt !== undefined) {
        stage.querySelector<HTMLElement>("#recovery-notice-time")!.textContent = `Account recovery requested · Available ${new Date(readyAt * 1000).toLocaleString()}`;
        if (recoveryReady !== readyAt) {
          toast.show({ message: "Recovery requested. You can cancel it from this device.", duration: 5000 });
        }
      } else {
        toast.dismiss();
      }
      recoveryReady = readyAt;
    },
    setScrolled(scrolled) {
      // Scrollback belongs to the card; mobile input controls stay in place [#44].
      // While the history is scrolled back the toolbar shrinks to a slim strip; the bottom or a tap brings it back.
      if (stage.dataset.scrolled !== String(scrolled)) stage.removeAttribute("data-toolbar-open");
      stage.dataset.scrolled = String(scrolled);
    },
    onInputActivity() {
      let changed = false;
      for (const name of MODIFIER_KEYS) {
        if (modifiers[name] === "armed") {
          modifiers[name] = "off";
          modifierTapAt[name] = -Infinity;
          changed = true;
        }
      }
      if (changed) renderModifiers(true);
      keybar.classList.remove("is-away");
      keyblur.classList.remove("is-away");
    },
    dispose() {
      toast.dispose();
      overlayWatch.disconnect();
      cancelRecovery?.removeEventListener("click", cancelClick);
      branch.dispose();
      shortcuts.dispose();
      settings?.dispose();
      for (const remove of removeShortcuts) remove();
      sidebarFoot?.dispose();
      sidebarToggle.removeEventListener("click", sidebarClick);
      capsule.removeEventListener("click", capsuleClick);
      scrim.removeEventListener("click", scrimClick);
      window.removeEventListener("keydown", keydown, true);
      window.removeEventListener("resize", resize);
      systemDark.removeEventListener("change", systemThemeChange);
      dockedLayout.removeEventListener("change", dockedLayoutChange);
      window.visualViewport?.removeEventListener("resize", viewportChange);
      window.visualViewport?.removeEventListener("scroll", viewportChange);
      offInputToolbar();
      keybar.removeEventListener("pointercancel", keybarPointerCancel);
      keybar.removeEventListener("click", keybarClick);
      keytray.removeEventListener("keydown", keybarKeydown);
      window.clearTimeout(resizeTimer);
      releaseMesh();
      delete ROOT.dataset.kb;
    },
  };
  return api;
}
