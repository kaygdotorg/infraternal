/**
 * The window details popover: machine, connection and session facts for one window,
 * anchored to its header pill.
 *
 * - Material: the shared floating overlay (`.ui-overlay-surface`); content behind it
 *   reads as soft shapes.
 * - Layout: OS mark and name on top, capsule tabs, then a key/value list (keys left,
 *   values right, each cell copies on click or double tap). The list scrolls inside a
 *   popover that never runs past the visible viewport or under the key tray.
 * - Motion: a pointer open grows from the pill (scale 0.96 → 1 with opacity, 200 ms
 *   strong ease-out); closing is quicker (130 ms). Keyboard opens and closes are
 *   instant. The animations use the Web Animations API without fill, so nothing is left
 *   transformed at rest and text stays crisp.
 */
import { createCapsuleTabs } from "../../../packages/ui/src/capsule-tabs";
import { hostIconMarkup } from "../../../packages/ui/src/host-icons";
import { createKeyValueList, type KeyValueRow } from "../../../packages/ui/src/kv-list";
import type { CanvasHost, CanvasSession } from "./canvas";

export interface DetailsPopover {
  readonly windowId: string;
  close(source: "pointer" | "keyboard"): void;
}

interface DetailsInput {
  windowId: string;
  host: CanvasHost;
  session: CanvasSession;
  hostLabel: string;
  icons: { machine: string; connection: string; session: string };
}

type Section = "machine" | "connection" | "session";

const EASE = "cubic-bezier(0.23, 1, 0.32, 1)";
const MARGIN = 12;

function rows(section: Section, host: CanvasHost, session: CanvasSession): KeyValueRow[] {
  const present = (list: KeyValueRow[]): KeyValueRow[] => list.filter((row) => row.value.trim() !== "");
  if (section === "machine") {
    return present([
      { key: "Kernel", value: host.kernel },
      { key: "Architecture", value: host.architecture },
      { key: "Model", value: host.model },
      { key: "CPU", value: host.cores ? `${host.cpu} · ${host.cores} cores` : host.cpu },
      { key: "Memory", value: host.memory ? `${host.memory}% used` : "", meter: host.memory },
      { key: "Disk", value: host.disk ? `${host.disk}% used` : "", meter: host.disk },
      { key: "Uptime", value: host.uptime },
      { key: "Load", value: host.load },
      { key: "Init", value: host.init },
      { key: "Virtualization", value: host.virtualization },
      { key: "Shell", value: host.shell },
      { key: "Locale", value: host.locale },
      { key: "IP addresses", value: host.ips.join(" · ") },
      { key: "Engines", value: host.engines.join(" · ") },
      { key: "infraternal agent", value: host.mode },
    ]);
  }
  if (section === "connection") {
    return present([
      { key: "Route", value: host.connection.route },
      { key: "Transport", value: host.connection.transport },
      { key: "Mesh", value: host.connection.mesh },
      { key: "Certificate", value: host.connection.certificate },
      { key: "Round trip", value: host.connection.roundTrip },
      { key: "Traffic", value: host.connection.bytes },
      { key: "Reconnects", value: String(host.connection.reconnects) },
    ]);
  }
  return present([
    { key: "Session", value: session.name },
    { key: "Started", value: session.started },
    { key: "Age", value: session.age },
    { key: "Viewers", value: String(session.viewers) },
    { key: "Size", value: session.size },
    { key: "Scrollback", value: session.scrollback },
    { key: "Last output", value: session.lastOutput },
  ]);
}

/** Opens the popover under `anchor`; `onClosed` runs once it has gone. */
export function openDetailsPopover(
  stage: HTMLElement,
  anchor: HTMLElement,
  input: DetailsInput,
  source: "pointer" | "keyboard",
  onClosed: () => void,
): DetailsPopover {
  const { host, session } = input;
  const root = document.createElement("section");
  root.className = "canvas-popover ui-overlay-surface";
  root.setAttribute("role", "dialog");
  root.setAttribute("aria-label", `Details for ${input.hostLabel}`);
  const title = [host.osName, host.version].filter(Boolean).join(" ");
  const subtitle = [`${host.user ? `${host.user}@` : ""}${input.hostLabel}`, host.architecture].filter(Boolean).join(" · ");
  root.innerHTML = `
    <header class="canvas-popover-head">
      <span class="canvas-popover-logo">${hostIconMarkup(host.os, "ui-host-mark")}</span>
      <span class="canvas-popover-names"><span class="canvas-popover-title"></span><span class="canvas-popover-sub"></span></span>
    </header>
    <div class="canvas-popover-tabs"></div>
    <div class="canvas-popover-scroll"></div>`;
  root.querySelector<HTMLElement>(".canvas-popover-title")!.textContent = title || input.hostLabel;
  root.querySelector<HTMLElement>(".canvas-popover-sub")!.textContent = subtitle;

  const list = createKeyValueList(`${input.hostLabel} details`);
  const scroll = root.querySelector<HTMLElement>(".canvas-popover-scroll")!;
  scroll.append(list.root);
  const show = (section: Section, animate: boolean): void => {
    list.set(rows(section, host, session));
    scroll.scrollTop = 0;
    if (animate && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
      list.root.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 140, easing: EASE });
    }
  };
  const tabs = createCapsuleTabs([
    { id: "machine", label: "Machine", icon: input.icons.machine },
    { id: "connection", label: "Connection", icon: input.icons.connection },
    { id: "session", label: "Session", icon: input.icons.session },
  ], "machine", (id, how) => show(id as Section, how === "pointer"), "Details", true);
  root.querySelector(".canvas-popover-tabs")!.append(tabs.root);
  show("machine", false);
  stage.append(root);

  // ---- placement: under the pill, inside the visible viewport, above the key tray ----
  const place = (): void => {
    const pill = anchor.getBoundingClientRect();
    const card = anchor.closest(".ui-window")?.getBoundingClientRect() ?? pill;
    const screen = stage.getBoundingClientRect();
    const touch = matchMedia("(pointer: coarse)").matches;
    const width = Math.min(touch ? card.width - 16 : 400, screen.width - MARGIN * 2);
    const left = Math.round(Math.max(MARGIN, Math.min(pill.left - 4, screen.width - width - MARGIN)));
    const top = Math.round(pill.bottom + 8);
    const tray = stage.querySelector<HTMLElement>("#keybar");
    const trayTop = tray && getComputedStyle(tray).display !== "none" ? tray.getBoundingClientRect().top : screen.bottom;
    const bottom = Math.min(trayTop, (window.visualViewport?.height ?? innerHeight)) - MARGIN;
    root.style.left = `${left}px`;
    root.style.top = `${top}px`;
    root.style.width = `${Math.round(width)}px`;
    root.style.maxHeight = `${Math.max(160, Math.round(bottom - top))}px`;
    root.style.transformOrigin = `${Math.round(pill.left + pill.width / 2 - left)}px 0`;
  };
  place();

  if (source === "pointer" && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
    root.animate([
      { opacity: 0, transform: "translateY(-4px) scale(0.96)" },
      { opacity: 1, transform: "none" },
    ], { duration: 200, easing: EASE });
  } else if (source === "pointer") {
    root.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160, easing: "ease" });
  }
  anchor.setAttribute("aria-expanded", "true");

  let closed = false;
  const events = new AbortController();
  const close = (how: "pointer" | "keyboard"): void => {
    if (closed) return;
    closed = true;
    events.abort();
    anchor.setAttribute("aria-expanded", "false");
    const done = (): void => { tabs.dispose(); list.dispose(); root.remove(); onClosed(); };
    if (how === "keyboard" || matchMedia("(prefers-reduced-motion: reduce)").matches) { done(); return; }
    root.style.pointerEvents = "none";
    root.animate([
      { opacity: 1, transform: "none" },
      { opacity: 0, transform: "translateY(-2px) scale(0.98)" },
    ], { duration: 130, easing: EASE, fill: "forwards" }).onfinish = done;
  };
  // Outside presses close it (the pill toggles it itself); Escape closes it instantly.
  document.addEventListener("pointerdown", (event) => {
    const target = event.target as Node;
    if (root.contains(target) || anchor.contains(target)) return;
    close("pointer");
  }, { capture: true, signal: events.signal });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") { event.stopPropagation(); close("keyboard"); anchor.focus({ preventScroll: true }); }
  }, { capture: true, signal: events.signal });
  window.addEventListener("resize", () => place(), { signal: events.signal });
  window.visualViewport?.addEventListener("resize", () => place(), { signal: events.signal });
  if (source === "keyboard") root.querySelector<HTMLElement>(".ui-tab[aria-selected='true']")?.focus({ preventScroll: true });

  return { windowId: input.windowId, close };
}
