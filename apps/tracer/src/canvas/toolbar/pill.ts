/**
 * The top pill (D177): the view's icon and name, a quiet session count, the connection icon and (desktop) the
 * command hint. It does not name the active window. A tap opens the view switcher; a horizontal swipe on it
 * steps to the previous or next view.
 *
 * The swipe: the pill's content follows the finger (rubber past the first and last view); a flick or a long
 * enough drag commits: the old content slides out, the new one slides in from the other side, the camera
 * springs across and the canvas lock re-engages on landing. A short drag springs back.
 */
import { Spring } from "../../../../../packages/ui/src/spring";
import { createConnectionIndicator } from "../../../../../packages/ui/src/connection-indicator";
import { onDemand } from "../../on-demand";
import type { Crumbs } from "./crumbs.on-demand";
import type { ViewId } from "../model/types";
import type { Ctx } from "../context";
import { ICON, lineIcon, viewIcon } from "../views/icons";
import { restPx } from "../springs";

export interface PillModule {
  readonly capsule: HTMLElement;
  /** Repaints the pill for the current view and lock. */
  paint(): void;
  dispose(): void;
}

export function createPill(cx: Ctx): PillModule {
  const { stage, signal, state, views, camera } = cx;
  const capsule = stage.querySelector<HTMLElement>("#capsule")!;
  const conn = createConnectionIndicator({ announce: false });
  stage.querySelector("#capsule-keys")?.before(conn.root);
  // The icon follows the socket the core screen reports (`data-connected`), so a phone that lost its link never shows a
  // healthy dot beside layout it can no longer sync. It is "connected" until the screen says otherwise.
  const paintLink = (): void => conn.set(stage.dataset.connected === "false" ? "reconnecting" : "connected");
  paintLink();
  const linkWatch = new MutationObserver(() => { paintLink(); paint(); });
  linkWatch.observe(stage, { attributes: true, attributeFilter: ["data-connected"] });
  // The round-trip time the core screen writes into its own pill is mirrored into the connection icon.
  const rttWatch = new MutationObserver(() => { const m = /(\d+)\s*ms/.exec(stage.querySelector("#rtt")?.textContent ?? ""); conn.setRoundTrip(m ? Number(m[1]) : undefined); });
  const rttEl = stage.querySelector("#rtt");
  if (rttEl) rttWatch.observe(rttEl, { childList: true, characterData: true, subtree: true });

  // Settings as rows of windows (#304): the capsule gives way to the breadcrumb Settings › Mesh › Keys while one of its windows is focused.
  // The breadcrumb is only for a screen that has the outline (the mockup today), so its code is fetched only there (D188).
  let crumbs: Crumbs | undefined;
  let crumbsGone = false;
  if (cx.adapters.settings.outline) void onDemand(() => import("./crumbs.on-demand")).then((m) => { if (crumbsGone) return; crumbs = m.createCrumbs(cx); crumbs.paint(); });
  let hold = false;
  const paint = (): void => {
    if (hold) return;
    const c = views.get(state.currentView);
    const free = !state.canvasLock && camera.lod === "thumb";
    const host = stage.querySelector<HTMLElement>("#capsule-host");
    const sess = stage.querySelector<HTMLElement>(".capsule-session");
    const os = stage.querySelector<HTMLElement>("#capsule-os");
    const sep = stage.querySelector<HTMLElement>(".capsule-sep");
    if (sep) sep.style.display = "none";
    if (host) host.textContent = free ? "All views" : (c?.view.name ?? "");
    // Console counts the same live inventory rows the sidebar lists, including detached shims.
    const inventory = cx.adapters.inventory;
    const allowedHosts = new Set(cx.adapters.sessions.hosts().map((entry) => entry.name));
    const n = !c ? 0 : c.view.layout === "graph" ? c.view.nodes.filter((v) => v.kind === "host").length
      : c.view.id === "console" ? inventory
        ? inventory.hosts().filter((name) => allowedHosts.has(name)).reduce((count, name) => count + inventory.list(name).length, 0)
        : c.wins.size : c.wins.size;
    const noun = !c ? "" : c.view.id === "console" ? "session" : c.view.layout === "graph" ? "host" : c.view.id === "docs" ? "page" : "window";
    // Without a connection the inventory is unknown, not empty: "0 sessions" would be untrue.
    if (sess && stage.dataset.connected === "false" && !free && c) sess.innerHTML = '· <span class="cl-noun">offline</span>';
    else if (sess) sess.innerHTML = free || !c ? `· ${views.size}<span class="cl-noun"> views</span>` : `· ${n}<span class="cl-noun"> ${noun}${n === 1 ? "" : "s"}</span>${c.view.team ? " · team" : ""}`;
    capsule.removeAttribute("data-flow");
    cx.sharing?.paintUnlink();
    if (os) os.innerHTML = lineIcon(free || !c ? ICON.views : viewIcon(c.view.id));
    crumbs?.paint();
  };

  // ---- a tap lists the views; a swipe steps between them ---------------------------------------------
  let swiped = false;
  const parts = (): HTMLElement[] => [...capsule.querySelectorAll<HTMLElement>("#capsule-os, .capsule-host, .capsule-session, .ui-conn")];
  const setShift = (x: number, opacity = 1): void => { for (const part of parts()) { part.style.transform = x === 0 ? "" : `translateX(${x}px)`; part.style.opacity = opacity === 1 ? "" : String(opacity); } };
  const shiftSpring = (from: number, to: number, cfg: { visualDuration: number; bounce?: 0 }, done?: () => void): void => {
    const sp = new Spring(from, (v) => { setShift(v, 1 - Math.min(1, Math.abs(v) / (capsule.offsetWidth * 0.6))); if (v === to) done?.(); }, cfg);
    restPx(sp);
    sp.set(to);
  };
  capsule.addEventListener("click", (e) => { e.preventDefault(); e.stopImmediatePropagation(); if (swiped) { swiped = false; return; } cx.viewList.toggle(); }, { capture: true, signal });
  capsule.style.touchAction = "none";
  let drag: { id: number; x: number; samples: Array<{ x: number; t: number }>; moved: boolean } | undefined;
  capsule.addEventListener("pointerdown", (e) => { if (e.button === 0 && !cx.viewList.isOpen()) drag = { id: e.pointerId, x: e.clientX, samples: [{ x: e.clientX, t: e.timeStamp }], moved: false }; }, { signal });
  capsule.addEventListener("pointermove", (e) => {
    const d = drag;
    if (!d || e.pointerId !== d.id) return;
    const dx = e.clientX - d.x;
    if (!d.moved) { if (Math.abs(dx) < 8) return; d.moved = true; capsule.setPointerCapture(e.pointerId); swiped = true; }
    const ids = [...views.keys()], at = ids.indexOf(state.currentView);
    // Rubber at the ends: no previous view before the first, no next after the last.
    const blocked = (dx > 0 && at <= 0) || (dx < 0 && at >= ids.length - 1);
    setShift(blocked ? dx * 0.25 : dx);
    d.samples.push({ x: e.clientX, t: e.timeStamp });
    if (d.samples.length > 5) d.samples.shift();
  }, { signal });
  const end = (e: PointerEvent): void => {
    const d = drag;
    if (!d || e.pointerId !== d.id) return;
    drag = undefined;
    if (!d.moved) return;
    const dx = e.clientX - d.x;
    const a = d.samples[0]!, b = d.samples[d.samples.length - 1]!;
    const v = b.t > a.t ? (b.x - a.x) / (b.t - a.t) : 0;
    const ids = [...views.keys()], at = ids.indexOf(state.currentView);
    const dir = dx < 0 ? 1 : -1; // swipe left: the next view
    const target = ids[at + dir];
    const commits = target && (Math.abs(dx) > 56 || Math.abs(v) > 0.5) && Math.sign(v || dx) === Math.sign(dx);
    const width = capsule.offsetWidth;
    if (!commits) { shiftSpring(dx, 0, { visualDuration: 0.4 }); return; }
    hold = true;
    cx.nav.flyView(target as ViewId);
    shiftSpring(dx, -dir * width * 0.6, { visualDuration: 0.18 }, () => {
      hold = false;
      paint();
      shiftSpring(dir * width * 0.6, 0, { visualDuration: 0.42 });
    });
  };
  capsule.addEventListener("pointerup", end, { signal });
  capsule.addEventListener("pointercancel", end, { signal });

  return { capsule, paint, dispose() { crumbsGone = true; crumbs?.dispose(); conn.dispose(); rttWatch.disconnect(); linkWatch.disconnect(); } };
}
