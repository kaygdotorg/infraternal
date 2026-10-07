/** Mounts the authenticated terminal shell, theme controls, host tree, and mobile key tray. */
import { branchedMenu } from "../../../packages/ui/src/branched";
import { applyTheme, terminalTheme, THEMES, type Theme } from "../../../packages/ui/src/themes";
import type { TerminalClient } from "./terminal";
import type { ITheme } from "../vendor/ghostty-web";

const ROOT = document.documentElement;
const THEME_COLOR = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');

export interface CoreScreenOptions {
  hostName: string;
  mockMode: boolean;
  probeMode: boolean;
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
      <section class="pane-card" aria-label="Current terminal pane">
        <div class="terminal-host" id="terminal-host" role="application" aria-label="Remote terminal" tabindex="0"></div>
      </section>
    </div>
    <header class="top" aria-label="Terminal controls">
      <button class="icon-btn" id="sidebar-toggle" type="button" aria-label="Show hosts" aria-expanded="false">${SVG.menu}</button>
      <button class="capsule" id="capsule" type="button" aria-haspopup="dialog" aria-controls="palette">
        <span class="dot" id="connection-dot" aria-hidden="true"></span>
        <span class="capsule-host" id="capsule-host"></span><span class="capsule-sep" aria-hidden="true">/</span>
        <span class="capsule-session">SSH shell</span><span class="capsule-rtt" id="rtt" aria-label="Round trip">··</span>
        <kbd class="capsule-kbd">⌘K</kbd>
      </button>
      <nav class="tabs" aria-label="Other sessions">
        <button class="tab tab-add" type="button" disabled aria-label="New session">${SVG.plus}</button>
      </nav>
    </header>
    <aside class="sidebar" id="sidebar" aria-label="Hosts" hidden>
      <div class="sidebar-head"><span class="sidebar-title">Hosts</span></div>
      <div id="tree"></div>
    </aside>
    <div class="palette-scrim" id="scrim" hidden></div>
    <section class="palette" id="palette" role="dialog" aria-label="Go to anything" aria-modal="true" hidden>
      <div class="palette-input">${SVG.search}<input id="palette-input" aria-label="Search hosts, sessions, actions and settings" placeholder="Go to a host, a session or an action" autocomplete="off" spellcheck="false"></div>
      <div class="palette-results" id="palette-results" role="listbox" aria-label="Search results"></div>
      <p class="palette-foot"><kbd>↑</kbd><kbd>↓</kbd> to navigate <kbd>↵</kbd> to select <kbd>esc</kbd> to close</p>
    </section>
    <div class="keyblur" aria-hidden="true"></div>
    <aside class="keybar" id="keybar" role="group" aria-label="Extra terminal keys">
      <div class="keytray">
        <button type="button" data-key="esc" aria-label="Escape" class="key-word">esc</button>
        <button type="button" data-key="tab" aria-label="Tab">${SVG.tab}</button>
        <button type="button" data-mod="ctrl" aria-label="Control">${SVG.ctrl}</button>
        <button type="button" data-mod="alt" aria-label="Option">${SVG.alt}</button>
        <button type="button" data-key="up" aria-label="Up">${SVG.up}</button>
        <button type="button" data-key="down" aria-label="Down">${SVG.down}</button>
        <button type="button" data-key="left" aria-label="Left">${SVG.left}</button>
        <button type="button" data-key="right" aria-label="Right">${SVG.right}</button>
        <button type="button" data-text="|" aria-label="Pipe">${SVG.pipe}</button>
        <button type="button" data-text="~" aria-label="Tilde">${SVG.tilde}</button>
        <button type="button" data-text="/" aria-label="Slash">${SVG.slash}</button>
        <button type="button" data-text="-" aria-label="Dash">${SVG.dash}</button>
        <button type="button" data-paste aria-label="Paste">${SVG.paste}</button>
        <button type="button" class="dpad" data-tip-off aria-label="Arrow keys: drag to move" hidden></button>
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
  const keybar = get<HTMLElement>("#keybar");
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
  let modifier: "ctrl" | "alt" | null = null;
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

  const applyLook = (instant = false): void => {
    const active = THEMES[currentThemeId]!;
    stage.toggleAttribute("data-no-motion", instant);
    ROOT.dataset.theme = currentThemeId;
    ROOT.dataset.bg = background;
    stage.dataset.theme = currentThemeId;
    stage.dataset.bg = background;
    applyTheme(active, ROOT);
    THEME_COLOR?.setAttribute("content", active.bg);
    client?.setTheme(terminalTheme(active, background === "mesh"));
    if (background === "mesh") void paintMesh();
    else releaseMesh();
  };
  applyLook();

  const entries: PaletteEntry[] = [
    { group: "Sessions", glyph: "›_", label: "SSH shell", hint: hostName, action: "session:current" },
    { group: "Hosts", glyph: "●", label: hostName, hint: "current", action: "host:current" },
    ...Object.entries(THEMES).map(([id, theme]) => ({
      group: "Theme", glyph: "◉", label: theme.name, hint: theme.dark ? "dark" : "light", action: `theme:${id}`, swatch: theme,
    })),
    { group: "Background", glyph: "▦", label: "Mesh from the theme", hint: "one still · no idle work", action: "bg:mesh" },
    { group: "Background", glyph: "□", label: "None", hint: "solid theme color", action: "bg:none" },
  ];
  let visibleEntries: PaletteEntry[] = [];
  let selected = 0;

  const renderPalette = (query = ""): void => {
    const needle = query.trim().toLocaleLowerCase();
    const filtered = entries.filter((entry) => `${entry.group} ${entry.label} ${entry.hint}`.toLocaleLowerCase().includes(needle));
    visibleEntries = filtered;
    selected = Math.min(selected, Math.max(0, visibleEntries.length - 1));
    paletteResults.replaceChildren();
    let previousGroup = "";
    filtered.forEach((entry, index) => {
      if (entry.group !== previousGroup) {
        const heading = document.createElement("div");
        heading.className = "group-label";
        heading.textContent = entry.group;
        paletteResults.append(heading);
        previousGroup = entry.group;
      }
      const result = document.createElement("button");
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
      paletteResults.append(result);
    });
    if (!filtered.length) {
      const empty = document.createElement("p");
      empty.className = "palette-empty";
      empty.textContent = "No matching hosts, sessions or actions.";
      paletteResults.append(empty);
    }
  };

  const setSidebar = (open: boolean, instant = false): void => {
    sidebar.hidden = !open;
    sidebarToggle.setAttribute("aria-expanded", String(open));
    sidebarToggle.setAttribute("aria-label", open ? "Hide hosts" : "Show hosts");
    sidebar.classList.toggle("instant", instant);
    if (instant) window.setTimeout(() => sidebar.classList.remove("instant"), 0);
  };

  const setPalette = (open: boolean, source: "keyboard" | "pointer" = "pointer"): void => {
    palette.hidden = !open;
    scrim.hidden = !open;
    palette.dataset.openKind = open ? source : "";
    if (open) {
      selected = 0;
      paletteInput.value = "";
      renderPalette();
      paletteInput.focus({ preventScroll: true });
    }
  };
  const sidebarClick = (event: MouseEvent): void => setSidebar(sidebar.hidden, event.detail === 0);
  const capsuleClick = (event: MouseEvent): void => setPalette(true, event.detail === 0 ? "keyboard" : "pointer");
  const scrimClick = (): void => setPalette(false, "pointer");

  const keydown = (event: KeyboardEvent): void => {
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
      applyLook();
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
  paletteInput.addEventListener("input", () => { selected = 0; renderPalette(paletteInput.value); });
  paletteInput.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      const delta = event.key === "ArrowDown" ? 1 : -1;
      selected = Math.max(0, Math.min(visibleEntries.length - 1, selected + delta));
      renderPalette(paletteInput.value);
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
    runAction(result.dataset.action ?? "", "pointer");
    setPalette(false, "pointer");
  });
  window.addEventListener("keydown", keydown, true);
  window.addEventListener("resize", resize);
  systemDark.addEventListener("change", systemThemeChange);
  window.visualViewport?.addEventListener("resize", viewportChange);
  window.visualViewport?.addEventListener("scroll", viewportChange);
  viewportChange();

  const keyInput: Record<string, string> = {
    esc: "\x1b", tab: "\t", up: "\x1b[A", down: "\x1b[B", left: "\x1b[D", right: "\x1b[C",
  };
  const keybarPointerDown = (event: PointerEvent): void => { event.preventDefault(); };
  const keybarClick = (event: MouseEvent): void => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest<HTMLButtonElement>("button");
    if (!button || button.disabled || button.classList.contains("dpad")) return;
    const key = button.dataset.key;
    const text = button.dataset.text;
    if (button.dataset.mod) {
      const next = modifier === button.dataset.mod ? null : button.dataset.mod as "ctrl" | "alt";
      modifier = next;
      for (const modButton of keybar.querySelectorAll<HTMLButtonElement>("[data-mod]")) {
        modButton.dataset.armed = String(modifier === modButton.dataset.mod);
      }
      client?.setInputModifier(modifier);
    } else if (key && keyInput[key]) {
      try { client?.injectInput(keyInput[key]!); } catch { /* connection state is announced in the status line */ }
    } else if (text) {
      try { client?.injectInput(text); } catch { /* connection state is announced in the status line */ }
    } else if ("paste" in button.dataset) {
      void navigator.clipboard?.readText().then((value) => {
        if (!value) return;
        try { client?.injectInput(value); } catch { /* connection state is announced in the status line */ }
      }).catch(() => undefined);
    }
  };
  keybar.addEventListener("pointerdown", keybarPointerDown);
  keybar.addEventListener("click", keybarClick);

  function runAction(action: string, source: "keyboard" | "pointer"): void {
    const [kind, value] = action.split(":");
    if (kind === "theme" && themeId(value ?? null)) {
      currentThemeId = value!;
      writeLocal("tracer.theme", currentThemeId);
      applyLook(source === "keyboard");
    } else if (kind === "bg" && (value === "mesh" || value === "none")) {
      background = value;
      writeLocal("tracer.background", value);
      applyLook(source === "keyboard");
    } else if (kind === "session" || kind === "host") {
      terminalHost.focus({ preventScroll: true });
    }
  }

  return {
    stage,
    terminalHost,
    status,
    probePanel,
    theme: () => terminalTheme(THEMES[currentThemeId]!, background === "mesh"),
    bindTerminal(value) {
      client = value;
      client.setTheme(terminalTheme(THEMES[currentThemeId]!, background === "mesh"));
      client.setInputModifier(modifier);
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
    setScrolled(scrolled) {
      // Scrollback belongs to the card; mobile input controls stay in place [#44].
      stage.dataset.scrolled = String(scrolled);
    },
    onInputActivity() {
      modifier = null;
      for (const modButton of keybar.querySelectorAll<HTMLButtonElement>("[data-mod]")) modButton.dataset.armed = "false";
      keybar.classList.remove("is-away");
      keyblur.classList.remove("is-away");
    },
    dispose() {
      branch.dispose();
      sidebarToggle.removeEventListener("click", sidebarClick);
      capsule.removeEventListener("click", capsuleClick);
      scrim.removeEventListener("click", scrimClick);
      window.removeEventListener("keydown", keydown, true);
      window.removeEventListener("resize", resize);
      systemDark.removeEventListener("change", systemThemeChange);
      window.visualViewport?.removeEventListener("resize", viewportChange);
      window.visualViewport?.removeEventListener("scroll", viewportChange);
      keybar.removeEventListener("pointerdown", keybarPointerDown);
      keybar.removeEventListener("click", keybarClick);
      window.clearTimeout(resizeTimer);
      releaseMesh();
      delete ROOT.dataset.kb;
    },
  };
}
