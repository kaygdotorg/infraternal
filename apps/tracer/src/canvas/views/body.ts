/**
 * What goes inside a window, by the window's kind. The registry of kinds: a terminal binds to a session through
 * the sessions adapter, a settings window renders a panel, a containers window lists containers, a logs window
 * streams text, and a window without access says so. Each kind decides its body here and nowhere else, so a new
 * kind (remote desktop, say) is one more branch and one more adapter.
 */
import type { Ctx, WinRec } from "../context";
import { el } from "../dom";
import { onDemand } from "../../on-demand";
import { paintLink } from "../windows/link";

/** True for kinds whose window is a terminal session: the only kind that can split. */
export const isTerminal = (rec: WinRec): boolean => rec.model.kind === "terminal" && !rec.model.noAccess;

/** True for windows that take the person's keys and pointer: a terminal, and an app window or a screen (D208). The input lock can hold only these. */
export const isInteractive = (rec: WinRec): boolean => isTerminal(rec) || rec.model.kind === "app" || rec.model.kind === "screen";
/** Policy for the view's terminal-exit callback, extracted so clean exits can be tested without a browser canvas. */
export function shouldCloseWindowAfterExit(status: number, setupPending: boolean): boolean {
  return status === 0 && !setupPending;
}

/**
 * Fills the window's card body for its kind: a terminal binds to its session, an app window or screen loads its on-demand body, and so on.
 * A window with no access shows a plain notice instead. Any earlier content of the body is replaced.
 */
export function makeBody(cx: Ctx, rec: WinRec): void {
  const m = rec.model;
  const body = rec.card.body;
  body.replaceChildren();
  if (m.noAccess) {
    const box = el("div", "cl-noaccess");
    box.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="11" width="14" height="9.5" rx="2.5"/><path d="M8.5 11V8a3.5 3.5 0 0 1 7 0v3"/></svg><p class="cl-noaccess-title">No access</p><p class="cl-noaccess-hint"></p>';
    (box.querySelector(".cl-noaccess-hint") as HTMLElement).textContent = `You do not have access to ${m.host}. Ask ${rec.owner.view.from ?? "an admin"} or an admin for access.`;
    body.append(box);
    return;
  }
  if (m.kind === "terminal") {
    const binding = cx.adapters.sessions.bind(m, { view: rec.owner.view.id, ...(cx.adapters.inventory ? { showSessions: (event?: MouseEvent) => {
      // The header's existing manager owns lazy loading, host selection and focus.
      const anchor = rec.card.root.querySelector<HTMLButtonElement>('[data-action="sessions"]');
      cx.sessionUi?.toggleManager(rec, anchor, event?.detail === 0 ? "keyboard" : "pointer");
    } } : {}), connectionChanged: () => {
      paintLink(rec, false, undefined);
      cx.sessionUi?.paint(rec);
    }, changed: () => {
      cx.store.changed();
      // A session id the window just learned (a new shell was created on the server): the inventory knows it is open.
      if (m.sessionId) cx.adapters.inventory?.attach(m.host, m.sessionId, m.session ? { name: m.session, pinned: m.sessionPinned === true } : undefined);
    }, exited: (status) => {
      const setupPending = rec.setup?.isPending() ?? false;
      if (shouldCloseWindowAfterExit(status, setupPending)) cx.win.close(rec);
    }, refused: (message, action) => cx.sessionUi?.refused(rec, message, action) ?? false, unreachable: (message) => cx.sessionUi?.unreachable(rec, message) });
    rec.binding = binding;
    if (binding.connected === false) paintLink(rec, false, undefined);
    binding.mount(body);
    return;
  }
  if (m.kind === "app" || m.kind === "screen") {
    void onDemand(() => import("../appwin/body.on-demand")).then((module) => {
      module.mountAppWindowBody(cx, rec);
    }).catch(() => { if (!rec.closing) body.textContent = "Could not load app windows. Try again."; });
    return;
  }
  if (m.kind === "settings") {
    // The panels load the first time a Settings window is drawn (on demand); until then the window is empty for a frame or two.
    let release: (() => void) | undefined, gone = false;
    rec.cleanup = () => { gone = true; release?.(); };
    void onDemand(() => import("./settings-body.on-demand")).then((mod) => {
      if (gone) return;
      release = mod.renderSettingsBody(cx, m.id.slice(2), body);
    });
    return;
  }
  if (m.kind === "docs") {
    // A docs page is read, so its code and its text wait until the window first comes near the screen (the Docs view can sit
    // unvisited for a whole session at no cost). Opening a page from the palette flies here, which is the same moment.
    let release: (() => void) | undefined, gone = false;
    const near = new IntersectionObserver((entries) => {
      if (!entries.some((entry) => entry.isIntersecting)) return;
      near.disconnect();
      void onDemand(() => import("../docs/docs-body.on-demand")).then((mod) => {
        if (!gone) release = mod.mountDocsBody(cx, m.id.slice(2), body);
      });
    }, { rootMargin: "50%" });
    near.observe(body);
    rec.cleanup = () => { gone = true; near.disconnect(); release?.(); };
    return;
  }
  if (m.kind === "flow") {
    // A flow fills its own body (the add-host wizard); the window only gives it a frame and a place on the canvas.
    body.classList.add("cl-flow");
    return;
  }
  if (m.kind === "logs") {
    // Logs windows are rare (no product path opens one yet), so their body loads on demand (D188), like Settings.
    // A feed pushes only to a window with `pushLog`, so nothing arrives before the body has mounted its backlog.
    let gone = false;
    rec.cleanup = () => { gone = true; };
    void onDemand(() => import("./log-body.on-demand")).then((mod) => {
      if (gone) return;
      const log = mod.mountLogBody(body, m.lines ?? []);
      rec.stream = log.scroller;
      rec.pushLog = log.push;
    });
    return;
  }
  if (m.kind === "containers") {
    const list = el("div", "cl-list");
    list.setAttribute("role", "list");
    for (const row of cx.adapters.containers?.rows() ?? []) {
      const b = el("button", "cl-row");
      b.type = "button";
      b.dataset.name = row.name;
      b.dataset.state = row.state;
      b.setAttribute("role", "listitem");
      b.setAttribute("aria-label", `${row.name}, ${row.state}. Open a shell`);
      b.innerHTML = '<span class="cl-state" aria-hidden="true"></span><span class="cl-name"></span><span class="cl-image"></span><span class="cl-cpu"></span>';
      (b.querySelector(".cl-name") as HTMLElement).textContent = row.name;
      (b.querySelector(".cl-image") as HTMLElement).textContent = row.image;
      (b.querySelector(".cl-cpu") as HTMLElement).textContent = row.cpu;
      b.addEventListener("click", () => cx.win.open(cx.adapters.containers!.host, row.name), { signal: cx.signal });
      list.append(b);
    }
    body.append(list);
  }
}
