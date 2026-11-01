/**
 * Puts the version pill into the sidebar's footer and the panel behind it (#216), and reaches both from the palette.
 *
 * Loaded after the first screen (D188: nothing here is needed to paint the sidebar), the stylesheet first, so the pill
 * appears fully drawn and the footer reflows once. The pill sits on the footer's line: the person, then this pill, then the
 * gear. Pressing it opens the panel inside the sidebar; the palette reaches the same panel ("Version and updates",
 * "Check for updates"), opening the sidebar first when it is closed, because the panel lives in it.
 *
 * The product and the test double mount this the same way; they differ only in the `VersionSource` they pass.
 */
import { ICON_INFO } from "../../../../../packages/ui/src/icons";
import { mountVersionPill, type VersionPill } from "../../../../../packages/ui/src/version-pill.on-demand";
import type { CoreScreen, PaletteEntry } from "../../core-screen";
import { createProductVersionSource, type ProductSourceInput, type VersionSource } from "./source";
import { createFleetController, type FleetController } from "./updates";
import { createVersionPanel, type VersionPanel } from "./panel";
import { pillState } from "./words";

export interface VersionArea {
  readonly panel: VersionPanel;
  readonly fleet: FleetController;
  readonly pill: VersionPill;
  dispose(): void;
}

/** Links a stylesheet and resolves once it is applied (or failed: a missing style must not hide the version). */
function linkStyle(href: string): Promise<HTMLLinkElement> {
  const existing = document.head.querySelector<HTMLLinkElement>(`link[data-version-style]`);
  if (existing) return Promise.resolve(existing);
  return new Promise((resolve) => {
    const link = Object.assign(document.createElement("link"), { rel: "stylesheet", href });
    link.dataset.versionStyle = "";
    link.addEventListener("load", () => resolve(link), { once: true });
    link.addEventListener("error", () => resolve(link), { once: true });
    document.head.append(link);
  });
}

export async function mountVersionArea(core: CoreScreen, source: VersionSource): Promise<VersionArea | undefined> {
  const foot = core.stage.querySelector<HTMLElement>(".ui-sidebar-foot");
  if (!foot) return undefined;
  const style = await linkStyle("./version.css");
  if (!foot.isConnected) { style.remove(); return undefined; }

  const fleet = createFleetController({
    source,
    say: (message) => core.toast.show({ message, tone: "error" }),
  });
  const pill = mountVersionPill(foot, pillState(source.facts(), fleet.settled()));
  const panel = createVersionPanel({ parent: foot.parentElement ?? core.stage, before: foot, anchor: pill.root, source, fleet });
  const paint = (): void => pill.set(pillState(source.facts(), fleet.settled()));
  const stopFleet = fleet.onChange(paint);
  const stopSource = source.onChange(paint);

  pill.root.addEventListener("click", (event) => {
    const how = event.detail === 0 ? "keyboard" : "pointer";
    if (panel.isOpen()) panel.close(false, how); else panel.open(false, how);
  });

  /** The panel is in the sidebar, so the sidebar must be showing it. */
  const withSidebar = (run: () => void): void => {
    if (core.stage.hasAttribute("data-sidebar-open")) { run(); return; }
    core.stage.querySelector<HTMLElement>("#sidebar-toggle")?.click();
    window.setTimeout(run, 80);
  };
  const onAction = (event: Event): void => {
    const detail = (event as CustomEvent<{ action?: string }>).detail;
    if (detail?.action === "canvas:version:open") withSidebar(() => panel.open(true, "keyboard"));
    else if (detail?.action === "canvas:version:check") {
      withSidebar(() => {
        panel.open(true, "keyboard");
        // A check is what was asked for; when the row already asks "proceed?" nothing is started that was not asked for.
        if (fleet.action() === "check") void fleet.press();
      });
    }
  };
  window.addEventListener("tracer:canvas-action", onAction);
  const removeProvider = core.addPaletteProvider((): PaletteEntry[] => [
    // The hint carries the aliases (the palette searches group, label and hint), so each row is found by what a person would call it.
    { group: "Help", glyph: "i", icon: ICON_INFO, label: "Version and updates", hint: "version · up to date? · edition · licence · hosts behind", action: "canvas:version:open" },
    { group: "Help", glyph: "i", icon: ICON_INFO, label: "Check for updates", hint: "this server and every host · upgrade · latest", action: "canvas:version:check" },
  ]);

  return {
    panel, fleet, pill,
    dispose() {
      window.removeEventListener("tracer:canvas-action", onAction);
      removeProvider();
      stopFleet();
      stopSource();
      panel.dispose();
      pill.dispose();
      fleet.dispose();
      style.remove();
    },
  };
}

/** The product's mount: the facts the build itself has (see `createProductVersionSource` for what is stubbed until #211). */
export const mountProductVersionArea = (core: CoreScreen, input: ProductSourceInput): Promise<VersionArea | undefined> =>
  mountVersionArea(core, createProductVersionSource(input));
