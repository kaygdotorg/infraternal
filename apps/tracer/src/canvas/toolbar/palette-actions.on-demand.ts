/** Dispatches canvas palette actions on first selection; inventory rows stay synchronous and current at sign-in (D188). */
import type { Ctx, WinRec } from "../context";
import { beginRename } from "../mesh/rename.on-demand";
import type { ViewId } from "../model/types";
import { isTerminal } from "../views/body";
import { onDemand } from "../../on-demand";

/** Flies to a Settings window (canvas-locked, snapped to its column). */
export async function openSettings(cx: Ctx, section: string, source?: string): Promise<void> {
  const c = cx.views.get("settings");
  // Settings as rows of windows (#304): a target is `component`, `component.group` or `component.group.setting`, and the
  // sections of the old Settings are mapped to where they went. A target it does not know opens the first window.
  const outline = cx.adapters.settings.outline;
  const target = outline && ((await outline.locate(section)) ?? (await outline.locate(outline.rows()[0]?.id ?? "")));
  const rec = (target ? c?.wins.get(target.windowId) : undefined) ?? c?.wins.get(`s-${section}`) ?? [...(c?.wins.values() ?? [])][0];
  if (!rec) return;
  cx.win.setActive(rec);
  cx.nav.focusWindow(rec);
  // The row is shown once the camera has mostly arrived (a keyboard jump is instant, so it need not wait).
  if (outline && target?.settingId) window.setTimeout(() => outline.reveal(target.windowId, target.settingId!), source === "keyboard" ? 80 : 420);
}

export interface CanvasAction { action?: string; source?: string }

/** Runs a `canvas:` palette action (open a view, split, remove a host, and so on); `selected` is the window that was active when the palette opened. */
export function dispatchCanvasAction(cx: Ctx, detail: CanvasAction, selected: WinRec | undefined): void {
  const { core, views } = cx;
  const [, kind, value] = (detail?.action ?? "").split(":");
  // Focus can change while the chunk loads; a closed selection must never redirect to another window.
  const active = selected?.owner.wins.get(selected.model.id) === selected ? selected : undefined;
  if (kind === "view" && value) { cx.nav.flyView(value as ViewId); }
  else if (kind === "overview") cx.nav.showOverview();
  else if (kind === "settings") void openSettings(cx, value ?? "appearance", detail?.source);
  else if (kind === "windowdocs") { if (active) void onDemand(() => import("../windows/docs-action.on-demand")).then((m) => { m.openWindowDocs(cx, active); }); }
  else if (kind === "share") void cx.sharing?.open();
  else if (kind === "unlink") cx.sharing?.unlinkCurrent();
  else if (kind === "split") { if (active && isTerminal(active)) void cx.win.split(active, value === "right" ? "right" : "down"); }
  else if (kind === "new") { if (active && isTerminal(active)) void cx.win.newWindow(active, value === "right" ? "right" : "below"); }
  else if (kind === "close") { if (active && active.model.kind !== "node" && active.model.kind !== "settings" && active.model.kind !== "docs") cx.win.closeKey(active); }
  else if (kind === "canvaslock") cx.nav.setCanvasLock(value === "on");
  else if (kind === "inputlock") cx.inputLock.toggle();
  else if (kind === "win" && value) {
    const rec = [...views.values()].flatMap((c) => [...c.wins.values()]).find((w) => w.model.id === value);
    if (rec) { cx.win.setActive(rec); cx.nav.focusWindow(rec); }
  }
  else if (kind === "removehost" && value) {
    const host = cx.adapters.sessions.hosts().find((entry) => entry.id === value);
    // Started from the palette, the question is about a host and not about the focused window, so it is centred (TASTE: a confirmation belongs to what it acts on).
    if (host) cx.adapters.hostRemoval?.remove(host.id, host.name, null, () => {
      // Escape or Keep goes back to the terminal the palette was opened from (not on a phone, where focus would raise the keyboard).
      if (!matchMedia("(pointer: coarse)").matches) active?.binding?.focus();
    });
  }
  else if (kind === "rename" && value) {
    // Goes to the Mesh view, where the host's card opens its name field as soon as the card is on screen.
    const host = decodeURIComponent(value);
    cx.nav.flyView("mesh");
    beginRename(cx, host);
  }
  else if (kind === "access" && value) {
    // The machine's details open on the Host tab with the consent under "Access level": a window of the host comes into view,
    // its popover opens, and the row is pressed once it has been drawn.
    const host = decodeURIComponent(value);
    const rec = [...views.values()].flatMap((c) => [...c.wins.values()]).find((w) => w.model.kind === "terminal" && w.model.host === host);
    if (!rec) { core.toast.show({ message: `${host} has no window open. Open a shell on it first.` }); return; }
    cx.win.setActive(rec);
    cx.nav.focusWindow(rec);
    cx.details?.close(true);
    window.setTimeout(() => {
      cx.details?.toggle(rec, "keyboard");
      const t0 = performance.now();
      const press = (): void => {
        const row = [...document.querySelectorAll<HTMLElement>(".canvas-popover .ui-kv-row")].find((r) => r.textContent?.includes("Access level"));
        const button = row?.querySelector<HTMLElement>(".ui-kv-press");
        if (button) button.click(); else if (performance.now() - t0 < 2500) requestAnimationFrame(press);
      };
      press();
    }, 350);
  }
  else if (kind === "open" && value) cx.win.open(value);
  else if (kind === "appwin" && value) {
    const loading = cx.appWindows?.load();
    if (loading) void loading.then((runtime) => runtime?.openFromPalette(value));
  }
  else if (kind === "session" && value) { const [host, sid] = value.split("/"); if (host && sid) cx.win.openSession(host, sid); }
  else if (kind === "sessions") {
    const anchor = active?.card.header.querySelector<HTMLButtonElement>("[data-action='sessions']");
    if (active) window.setTimeout(() => cx.sessionUi?.toggleManager(active, anchor, "pointer"), 60);
  }
  else if (kind === "ctr" && value && cx.adapters.containers) cx.win.open(cx.adapters.containers.host, value);
}
