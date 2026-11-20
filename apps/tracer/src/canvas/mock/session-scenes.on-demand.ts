/**
 * The ten sessions scenes of the mockup (⌘K "Mockup: sessions scene N", or `?sessions=N` in the URL): each puts the
 * canvas in one state of the session UI (D121, D127, D178, D183) so it can be looked at, clicked and captured.
 * On demand (D188): `index.ts` lists the scenes from `session-scene-list.ts` and loads this file when one runs.
 * Test-double scaffolding only: the product never imports this. Every scene starts from the inventory as served
 * and a freshly built Console, so scenes can be run one after another.
 */
import type { Ctx, WinRec } from "../context";
import { reduced } from "../dom";
import type { MockInventory } from "./inventory";

interface SceneDef { title: string; hint: string; run(): void | Promise<void> }

export interface SessionScenes {
  run(n: number): Promise<void>;
  dispose(): void;
}

/** Installs the mock session scenes for the specs: their inventory, the Console rebuild hook and the sessions mockup actions. */
export function installSessionScenes(env: { cx: Ctx; inventory: MockInventory; /** Rebuilds Console from the test double and flies to it. */ rebuild(): void }): SessionScenes {
  const { cx, inventory } = env;
  const timers = new Set<number>();
  const later = (run: () => void, ms: number): void => { const id = window.setTimeout(() => { timers.delete(id); run(); }, ms); timers.add(id); };
  const settle = reduced.matches ? 0 : 520;
  const winOf = (host: string): WinRec | undefined => [...cx.views.get("console")?.wins.values() ?? []].find((w) => w.model.host === host && !w.model.splitOf);
  const manager = (host: string): WinRec | undefined => {
    const rec = winOf(host);
    const anchor = rec?.card.header.querySelector<HTMLButtonElement>("[data-action='sessions']");
    if (!rec) return undefined;
    cx.win.setActive(rec);
    cx.nav.focusWindow(rec);
    later(() => cx.sessionUi?.toggleManager(rec, anchor), settle);
    return rec;
  };
  const reset = (): void => {
    cx.sessionUi?.closeManager();
    cx.toast.dismiss();
    for (const id of timers) window.clearTimeout(id);
    timers.clear();
    env.rebuild();
  };
  const sidebar = (): HTMLElement | null => cx.stage.querySelector<HTMLElement>("#sidebar");
  const scenes: SceneDef[] = [
    { title: "Session manager", hint: "grouped by state, by frecency", run() { reset(); manager("build-01"); } },
    { title: "Sidebar inventory", hint: "open, detached, exited · markers", run() {
      reset();
      if (sidebar()?.hidden) cx.stage.querySelector<HTMLButtonElement>("#sidebar-toggle")?.click();
      // Activity arrives while you look: a quiet dot, then a finished command.
      later(() => inventory.setActivity("studio-mac", "local-api", "output"), 2600);
      later(() => inventory.setActivity("edge-arm", "edge-shell", "ok"), 5200);
    } },
    { title: "Exited session", hint: "final screen · Run again · Dismiss", run() { reset(); later(() => { cx.win.openSession("build-01", "migrate"); }, 80); } },
    { title: "Close keeps it running", hint: "detached · toast · Reopen", run() {
      reset();
      const rec = winOf("build-01");
      if (rec) { cx.win.setActive(rec); cx.nav.focusWindow(rec); later(() => cx.win.close(rec), settle); }
    } },
    { title: "End a session", hint: "names what is running", run() {
      reset();
      manager("edge-arm");
      later(() => cx.stage.querySelector<HTMLElement>(".cl-sx-row[data-id='apt-watch'] .cl-sx-act.is-end")?.click(), settle + 380);
    } },
    { title: "Splits", hint: "right, then down · a fade", run() {
      reset();
      const rec = winOf("build-01");
      if (!rec) return;
      cx.win.setActive(rec);
      cx.nav.focusWindow(rec);
      later(() => { void cx.win.split(rec, "right"); }, settle);
      later(() => { const made = [...cx.views.get("console")?.wins.values() ?? []].find((w) => w.model.splitOf === rec.model.id); if (made) void cx.win.split(made, "down"); }, settle + 1700);
    } },
    { title: "Sized for another device", hint: "scaled to fit · type to take over", run() {
      reset();
      // A window with a static screen (the page's one live terminal cannot be scaled).
      const rec = winOf("nix-cache");
      const device = inventory.devices()[0];
      if (!rec || !device) return;
      cx.win.setActive(rec);
      cx.nav.focusWindow(rec);
      later(() => inventory.typedElsewhere("nix-cache", "flake-dev", device), settle);
    } },
    { title: "Only one session", hint: "empty manager", run() { reset(); manager("nix-cache"); } },
    { title: "Loading sessions", hint: "slow host", run() {
      reset();
      inventory.force("loading");
      manager("build-01");
      if (new URLSearchParams(location.search).get("hold") !== "1") later(() => inventory.force(undefined), 8000);
    } },
    { title: "Sessions unavailable", hint: "error · Try again", run() { reset(); inventory.force("error"); manager("build-01"); } },
  ];
  return {
    async run(n) {
      const scene = scenes[n - 1];
      if (!scene) return;
      // The palette closes first; a scene that opens a surface does so once it has settled.
      await new Promise((done) => later(() => done(undefined), 40));
      await scene.run();
    },
    dispose() { for (const id of timers) window.clearTimeout(id); },
  };
}
