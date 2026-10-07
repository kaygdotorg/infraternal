/** Mounts the authenticated terminal shell, theme controls, host tree, and mobile key tray. */
import { branchedMenu } from "../../../packages/ui/src/branched";
import { applyTheme, terminalTheme, THEMES, type Theme } from "../../../packages/ui/src/themes";
import { refreshTip } from "../../../packages/ui/src/tooltip";
import type { InputModifierState, InputModifiers, TerminalClient } from "./terminal";
import type { ITheme } from "../vendor/ghostty-web";
import { recoveryUiEnabled } from "./recovery-ui";

const ROOT = document.documentElement;
const THEME_COLOR = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
const MODIFIER_KEYS = ["ctrl", "alt"] as const;

export interface CoreScreenOptions {
  hostName: string;
  mockMode: boolean;
  probeMode: boolean;
  onRecovery?: () => void;
  onCancelRecovery?: () => Promise<void>;
}

export interface CoreScreen {
  stage: HTMLElement;
  terminalHost: HTMLElement;
  status: HTMLElement;
  probePanel: HTMLElement;
  theme(): ITheme;
  bindTerminal(client: TerminalClient): void;
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
        <span class="dot" id="connection-dot" aria-hidden="true"></span>
        <span class="capsule-host" id="capsule-host"></span><span class="capsule-sep" aria-hidden="true">/</span>
        <span class="capsule-session">SSH shell</span><span class="capsule-rtt" id="rtt" aria-label="Round trip">··</span>
        <kbd class="capsule-kbd">⌘K</kbd>
      </button>
      <nav class="tabs" aria-label="Other sessions">
        <button class="ui-pill ui-pill-icon tab tab-add" type="button" disabled aria-label="New session">${SVG.plus}</button>
      </nav>
    </header>
    <aside class="ui-panel sidebar" id="sidebar" aria-label="Hosts" hidden>
      <div class="sidebar-head"><span class="sidebar-title">Hosts</span></div>
      <div id="tree"></div>
    </aside>
    <div class="palette-scrim" id="scrim" hidden></div>
    <section class="palette" id="palette" role="dialog" aria-label="Go to anything" aria-modal="true" hidden>
      <div class="palette-input">${SVG.search}<input id="palette-input" role="searchbox" aria-controls="palette-results" aria-label="Search hosts, sessions, actions and settings" placeholder="Go to a host, a session or an action" autocomplete="off" spellcheck="false"></div>
      <div class="palette-results" id="palette-results" role="listbox" aria-label="Search results"></div>
      <p class="palette-foot"><kbd>↑</kbd><kbd>↓</kbd> to navigate <kbd>↵</kbd> to select <kbd>esc</kbd> to close</p>
    </section>
    ${recoveryUiEnabled() ? `<section class="ui-window recovery-notice" id="recovery-notice" aria-label="Pending account recovery" hidden>
      <p id="recovery-notice-time"></p><button class="ui-pill" id="recovery-cancel" type="button">Cancel recovery</button>
      <p id="recovery-cancel-error" role="alert"></p>
    </section>
    <p class="ui-window recovery-toast" id="recovery-toast" role="status" hidden></p>` : ""}
    <div class="keyblur" aria-hidden="true"></div>
    <aside class="keybar" id="keybar" role="group" aria-label="Extra terminal keys">
      <div id="keytray" class="keytray" role="toolbar" aria-label="Extra terminal keys. Press F6 to navigate." aria-keyshortcuts="F6 Shift+F6" aria-orientation="horizontal" tabindex="0" aria-activedescendant="key-escape">
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
    </aside>
    <p id="connection-status" class="connection-status" role="status">Starting terminal…</p>
    <span id="test-double-badge" class="test-double-badge" hidden>TEST DOUBLE</span>
    <aside id="probe-panel" class="probe-panel" aria-label="Terminal latency probe" hidden>
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

const readLocal = (key: string): string | null => {
  try { return localStorage.getItem(key); } catch { return null; }
};

const writeLocal = (key: string, value: string): void => {
  try { localStorage.setItem(key, value); } catch { /* preferences are optional in private mode */ }
};

function themeId(value: string | null): string | undefined {
  return value && Object.hasOwn(THEMES, value) ? value : undefined;
}

interface PaletteEntry {
  group: string;
  glyph: string;
  label: string;
  hint: string;
  action?: string;
  swatch?: Theme;
}

/** Mounts the authenticated server host, its live shell session, and terminal controls. */
export function mountCoreScreen(app: HTMLElement, options: CoreScreenOptions): CoreScreen {
  app.innerHTML = SCREEN;
  const stage = get<HTMLElement>("#terminal-screen");
  const terminalHost = get<HTMLElement>("#terminal-host");
  const status = get<HTMLElement>("#connection-status");
  const probePanel = get<HTMLElement>("#probe-panel");
  const sidebar = get<HTMLElement>("#sidebar");
  const sidebarToggle = get<HTMLButtonElement>("#sidebar-toggle");
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

  const branch = branchedMenu(get<HTMLElement>("#tree"), [
    { id: "current-host", label: hostName, meta: "current", live: true, open: true, leaves: [
      { id: "current-shell", label: "SSH shell", meta: "current" },
    ] },
  ], { active: "current-shell" });
  const liveHost = get<HTMLElement>("#tree .bm-sec");
  liveHost.setAttribute("aria-label", hostName);

  const params = new URLSearchParams(location.search);
  const systemDark = matchMedia("(prefers-color-scheme: dark)");
  let currentThemeId = themeId(params.get("theme")) ?? themeId(readLocal("tracer.theme")) ?? (systemDark.matches ? "ink" : "paper");
  let background = params.get("bg") === "mesh" || params.get("bg") === "none"
    ? params.get("bg")!
    : (readLocal("tracer.background") === "mesh" ? "mesh" : "none");
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
    ROOT.style.setProperty("--grain", `url(${renderer.grainTile()})`);
    ROOT.style.setProperty("--dpr", String(devicePixelRatio));
    const url = await renderer.renderBackdrop(active, width, height);
    if (meshKey === key && background === "mesh" && url) ROOT.style.setProperty("--mesh-image", `url("${url}")`);
  };

  const releaseMesh = (): void => {
    meshKey = "";
    ROOT.style.setProperty("--mesh-image", "none");
    ROOT.style.setProperty("--grain", "none");
    void backdropModule?.then((renderer) => renderer.releaseBackdrop());
  };

  const applyLook = (instant = false): Promise<void> => {
    const active = THEMES[currentThemeId]!;
    stage.toggleAttribute("data-no-motion", instant);
    ROOT.dataset.theme = currentThemeId;
    ROOT.dataset.bg = background;
    stage.dataset.theme = currentThemeId;
    stage.dataset.bg = background;
    applyTheme(active, ROOT);
    THEME_COLOR?.setAttribute("content", active.bg);
    client?.setTheme(terminalTheme(active, background === "mesh"));
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
    setPalette(false, "keyboard");
    void applyLook(true);
  };


  const entries: PaletteEntry[] = [
    { group: "Sessions", glyph: "›_", label: "SSH shell", hint: hostName, action: "session:current" },
    { group: "Hosts", glyph: "●", label: hostName, hint: "current", action: "host:current" },
    ...Object.entries(THEMES).map(([id, theme]) => ({
      group: "Theme", glyph: "◉", label: theme.name, hint: theme.dark ? "dark" : "light", action: `theme:${id}`, swatch: theme,
    })),
    { group: "Background", glyph: "▦", label: "Mesh from the theme", hint: "one still · no idle work", action: "bg:mesh" },
    { group: "Background", glyph: "□", label: "None", hint: "solid theme color", action: "bg:none" },
    ...(recoveryUiEnabled() && options.onRecovery ? [{ group: "Account", glyph: "◇", label: "Use recovery key", hint: "replace passkey", action: "account:recovery" }] : []),
  ];
  const paletteSearchText = new Map(entries.map((entry) => [
    entry,
    `${entry.group} ${entry.label} ${entry.hint}`.toLocaleLowerCase(),
  ]));
  // Normalize IDs once so typing never sanitizes every matching result.
  const paletteOptionIds = new Map(entries.map((entry, index) => [
    entry,
    `palette-option-${entry.action?.replaceAll(/[^a-z0-9_-]/gi, "-") ?? `entry-${index}`}`,
  ]));
  const paletteGroupIds = new Map([...new Set(entries.map((entry) => entry.group))].map((group) => [
    group,
    `palette-group-${group.toLocaleLowerCase().replaceAll(" ", "-")}`,
  ]));
  let visibleEntries: PaletteEntry[] = [];
  let visibleOptions: HTMLButtonElement[] = [];
  let selected = 0;
  const headingByGroup = new Map<string, HTMLDivElement>();

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

  const renderPalette = (query = ""): void => {
    const needle = query.trim().toLocaleLowerCase();
    visibleEntries = entries.filter((entry) => paletteSearchText.get(entry)?.includes(needle) ?? false);
    selected = Math.min(selected, Math.max(0, visibleEntries.length - 1));
    visibleOptions = [];
    // Clearing the list resets its viewport, avoiding a separate scrollTop read/write.
    paletteResults.replaceChildren();
    let previousGroup = "";
    visibleEntries.forEach((entry, index) => {
      if (entry.group !== previousGroup) {
        const heading = document.createElement("div");
        heading.id = paletteGroupIds.get(entry.group)!;
        heading.className = "group-label";
        heading.textContent = entry.group;
        headingByGroup.set(entry.group, heading);
        paletteResults.append(heading);
        previousGroup = entry.group;
      }
      const result = document.createElement("button");
      result.id = paletteOptionIds.get(entry)!;
      result.type = "button";
      result.className = "result";
      result.setAttribute("role", "option");
      result.setAttribute("aria-selected", String(index === selected));
      result.dataset.action = entry.action ?? "";
      const icon = document.createElement("span");
      icon.className = "result-icon";
      icon.textContent = entry.glyph;
      if (entry.swatch) {
        icon.classList.add("swatch");
        icon.style.backgroundColor = entry.swatch.bg;
        icon.style.boxShadow = `inset 0 0 0 3px ${entry.swatch.accent}`;
      }
      const label = document.createElement("span");
      label.className = "result-label";
      label.textContent = entry.label;
      const hint = document.createElement("span");
      hint.className = "result-hint";
      hint.textContent = entry.hint;
      result.append(icon, label, hint);
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
  };

  // Desktop docks the sidebar beside the windows instead of over them, so nothing under it
  // becomes unreachable. The panes' left edge moves once (one terminal fit, no per-frame resize)
  // and a FLIP translate on the compositor makes that single layout change read as a slide.
  const dockedLayout = matchMedia("(hover: hover) and (pointer: fine) and (min-width: 1024px)");
  const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
  const dockPanes = (open: boolean, instant: boolean): void => {
    const docked = open && dockedLayout.matches;
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
    dockPanes(open, instant);
    // The toggle travels between the top bar and the sidebar header on a transform transition.
    sidebarToggle.classList.toggle("instant", instant);
    stage.toggleAttribute("data-sidebar-open", open);
    if (instant) window.setTimeout(() => sidebarToggle.classList.remove("instant"), 0);
    else if (reducedMotion.matches) sidebarToggle.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160, easing: "ease-out" });
    sidebar.hidden = !open;
    sidebarToggle.setAttribute("aria-expanded", String(open));
    sidebarToggle.setAttribute("aria-label", open ? "Hide hosts" : "Show hosts");
    sidebar.classList.toggle("instant", instant);
    if (instant) window.setTimeout(() => sidebar.classList.remove("instant"), 0);
  };

  const setPalette = (open: boolean, source: "keyboard" | "pointer" = "pointer"): void => {
    palette.hidden = !open;
    scrim.hidden = !open;
    // The source of the last open or close decides its motion: keyboard is instant, pointer animates.
    palette.dataset.openKind = source;
    if (open) {
      selected = 0;
      paletteInput.value = "";
      paletteResults.scrollTop = 0;
      renderPalette();
      paletteInput.focus({ preventScroll: true });
    } else {
      paletteInput.removeAttribute("aria-activedescendant");
    }
  };
  const sidebarClick = (event: MouseEvent): void => setSidebar(sidebar.hidden, event.detail === 0);
  const capsuleClick = (event: MouseEvent): void => setPalette(true, event.detail === 0 ? "keyboard" : "pointer");
  const scrimClick = (): void => setPalette(false, "pointer");

  const keydown = (event: KeyboardEvent): void => {
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
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      event.stopPropagation();
      setPalette(palette.hidden, "keyboard");
      return;
    }
    if (event.key === "Escape") {
      if (!palette.hidden) { setPalette(false, "keyboard"); event.preventDefault(); }
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
      currentThemeId = systemDark.matches ? "ink" : "paper";
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
    const names: Record<keyof InputModifiers, string> = { ctrl: "Control", alt: "Option" };
    for (const button of keybar.querySelectorAll<HTMLButtonElement>("[data-mod]")) {
      const name = button.dataset.mod as keyof InputModifiers;
      const state: InputModifierState = modifiers[name];
      button.dataset.modState = state;
      button.setAttribute("aria-pressed", state === "locked" ? "mixed" : String(state === "armed"));
      button.setAttribute("aria-label", state === "off" ? names[name] : `${names[name]}, ${state}`);
      if (instant) markInstant(button);
      refreshTip(button);
    }
    for (const name of MODIFIER_KEYS) client?.setInputModifier(name, modifiers[name]);
  };
  const isTerminalFocus = (element: Element | null): element is HTMLElement =>
    element instanceof HTMLElement && (element === terminalHost || terminalHost.contains(element));
  const restoreTerminalFocus = (): void => {
    if (isTerminalFocus(document.activeElement)) {
      terminalFocusTarget = null;
      return;
    }
    if (terminalFocusTarget?.isConnected) terminalFocusTarget.focus({ preventScroll: true });
    else if (client) client.focus();
    else terminalHost.focus({ preventScroll: true });
    terminalFocusTarget = null;
  };
  const rememberTerminalFocus = (): void => {
    const active = document.activeElement;
    terminalFocusTarget = isTerminalFocus(active) ? active : null;
  };
  const keybarPointerDown = (event: PointerEvent): void => {
    event.preventDefault();
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
      void navigator.clipboard?.readText().then((value) => {
        if (!value) return;
        injectKey(value);
      }).catch(() => undefined);
    }
    restoreTerminalFocus();
  };
  keybar.addEventListener("pointerdown", keybarPointerDown);
  keybar.addEventListener("pointercancel", keybarPointerCancel);
  keybar.addEventListener("click", keybarClick);
  keytray.addEventListener("keydown", keybarKeydown);

  /** Runs a palette action; returns true when the action closed the palette itself. */
  function runAction(action: string, source: "keyboard" | "pointer"): boolean {
    const [kind, value] = action.split(":");
    if (kind === "account" && value === "recovery") {
      setPalette(false, source);
      options.onRecovery?.();
    } else if (kind === "theme" && themeId(value ?? null)) {
      currentThemeId = value!;
      writeLocal("tracer.theme", currentThemeId);
      swapLook();
      return true;
    } else if (kind === "bg" && (value === "mesh" || value === "none")) {
      background = value;
      writeLocal("tracer.background", value);
      swapLook();
      return true;
    } else if (kind === "session" || kind === "host") {
      terminalHost.focus({ preventScroll: true });
    }
    return false;
  }

  const recoveryNotice = stage.querySelector<HTMLElement>("#recovery-notice")!;
  const recoveryToast = stage.querySelector<HTMLElement>("#recovery-toast")!;
  const cancelRecovery = stage.querySelector<HTMLButtonElement>("#recovery-cancel")!;
  let recoveryReady: number | undefined, recoveryToastTimer = 0;
  const cancelClick = (): void => {
    cancelRecovery.disabled = true;
    const error = stage.querySelector<HTMLElement>("#recovery-cancel-error")!;
    error.textContent = "";
    void options.onCancelRecovery?.().catch(() => {
      error.textContent = "Recovery could not be cancelled. Try again.";
    }).finally(() => { cancelRecovery.disabled = false; });
  };
  cancelRecovery?.addEventListener("click", cancelClick);
  return {
    stage,
    terminalHost,
    status,
    probePanel,
    theme: () => terminalTheme(THEMES[currentThemeId]!, background === "mesh"),
    bindTerminal(value) {
      client = value;
      client.setTheme(terminalTheme(THEMES[currentThemeId]!, background === "mesh"));
      for (const name of MODIFIER_KEYS) client.setInputModifier(name, modifiers[name]);
    },
    setRoundTrip(milliseconds) {
      rtt.textContent = milliseconds === undefined ? "··" : `${Math.round(milliseconds)} ms`;
      rtt.setAttribute("aria-label", milliseconds === undefined ? "Round trip unavailable" : `Round trip ${Math.round(milliseconds)} milliseconds`);
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
          recoveryToast.textContent = "Recovery requested. You can cancel it from this device.";
          recoveryToast.hidden = false;
          window.clearTimeout(recoveryToastTimer);
          recoveryToastTimer = window.setTimeout(() => { recoveryToast.hidden = true; }, 5000);
        }
      } else {
        window.clearTimeout(recoveryToastTimer); recoveryToast.hidden = true;
      }
      recoveryReady = readyAt;
    },
    setScrolled(scrolled) {
      // Scrollback belongs to the card; mobile input controls stay in place [#44].
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
      window.clearTimeout(recoveryToastTimer);
      cancelRecovery?.removeEventListener("click", cancelClick);
      branch.dispose();
      sidebarToggle.removeEventListener("click", sidebarClick);
      capsule.removeEventListener("click", capsuleClick);
      scrim.removeEventListener("click", scrimClick);
      window.removeEventListener("keydown", keydown, true);
      window.removeEventListener("resize", resize);
      systemDark.removeEventListener("change", systemThemeChange);
      dockedLayout.removeEventListener("change", dockedLayoutChange);
      window.visualViewport?.removeEventListener("resize", viewportChange);
      window.visualViewport?.removeEventListener("scroll", viewportChange);
      keybar.removeEventListener("pointerdown", keybarPointerDown);
      keybar.removeEventListener("pointercancel", keybarPointerCancel);
      keybar.removeEventListener("click", keybarClick);
      keytray.removeEventListener("keydown", keybarKeydown);
      window.clearTimeout(resizeTimer);
      releaseMesh();
      delete ROOT.dataset.kb;
    },
  };
}
