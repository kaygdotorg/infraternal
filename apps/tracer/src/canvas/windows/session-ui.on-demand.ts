/**
 * What a window shows about its session, and how you move between sessions (D121, D127, D178, D183). It exists
 * only when the canvas has a session inventory; without one a window is just a terminal and none of this is drawn.
 *
 * - The session manager: the "Sessions" action in a window's pill opens that host's sessions in the shared
 *   anchored popover, grouped Open / Detached / Exited and ordered by frecency, each with its activity mark.
 *   Choosing a session attaches this window to it (the old one keeps running, detached); one that is open in
 *   another window flies to that window instead. Rows rename inline (a rename pins the name), open beside (a
 *   split), end (the compact confirm names what is running) and, once exited, run again or be dismissed. On touch
 *   a row swipes open 1:1 with the finger to show the same actions.
 * - An exited session shows its final screen read-only, with one floating pill: Run again, Dismiss.
 * - A session the host no longer has (#158) shows the same pill, quieter: "Session ended", New shell (a new shell
 *   on the same host, in this window) and Close window. There is no exit code or final screen to show.
 * - A session another device typed in last is shown scaled to fit with a quiet "Sized for <device>" badge; typing
 *   or tapping the badge takes the size over (D183).
 *
 * Motion (TASTE section 3): surfaces animate, results never do. The attached screen appears at once; the pill's
 * session name slides in and the frame lights up for a moment (opacity only); a removed row fades and the rows
 * below close the gap by transform. Transform and opacity only, interruptible, nothing left transformed at rest.
 *
 * This file is on demand (D188): it loads the first time someone opens the manager, shows an exited session or
 * a session another device sized. The tiny hooks that stay on the critical and deferred paths are in
 * `session-hooks.ts`, which owns the inventory's change listener and `windowFor`.
 *
 * The inventory is the source of truth: every change it reports repaints the windows, the tree and an open
 * manager. This module never changes a session itself except through the inventory's verbs.
 */
import { mountConfirmTip, type ConfirmTipController } from "../../../../../packages/ui/src/tooltip";
import { openAnchoredPopover, type AnchoredPopover, type PopoverSource } from "../../../../../packages/ui/src/anchored-popover";
import { hostIconMarkup } from "../../../../../packages/ui/src/host-icons";
import { ICON_ALERT, ICON_X, icon } from "../../../../../packages/ui/src/icons";
import { createSpinner } from "../../../../../packages/ui/src/spinner";
import { Spring } from "../../../../../packages/ui/src/spring";
import type { Ctx, WinRec } from "../context";
import { coarse, el, reduced } from "../dom";
import { byFrecency, type SessionRecord, type SessionState } from "../sessions/inventory";
import { isTerminal } from "../views/body";
import { ICON, SESSION_ICON } from "../views/icons";

/** What the on-demand half does; `session-hooks.ts` calls it once it has loaded. */
export interface SessionUiPart {
  paint(rec: WinRec): void;
  toggleManager(rec: WinRec, anchor: HTMLElement, source: PopoverSource): void;
  closeManager(): void;
  arrived(rec: WinRec): void;
  /** Repaints an open manager (the inventory changed). */
  render(): void;
  dispose(): void;
}

const EASE = "cubic-bezier(0.23, 1, 0.32, 1)";
const STATE_LABEL: Record<SessionState, string> = { open: "Open", detached: "Detached", exited: "Exited" };

const button = (cls: string, label: string, paths: string): HTMLButtonElement => {
  const node = el("button", cls);
  node.type = "button";
  node.setAttribute("aria-label", label);
  node.innerHTML = icon(paths);
  return node;
};

export function createSessionUi(cx: Ctx): SessionUiPart {
  const inventory = cx.adapters.inventory!;
  const { stage, signal } = cx;
  let manager: Manager | undefined;
  let confirm: ConfirmTipController | undefined;

  const windowFor = (host: string, id: string): WinRec | undefined => cx.sessionUi?.windowFor(host, id);
  const recordOf = (rec: WinRec): SessionRecord | undefined => (rec.model.sessionId ? inventory.get(rec.model.host, rec.model.sessionId) : undefined);

  // ---- the window's own surfaces -----------------------------------------------------------------
  const leaving = new WeakSet<WinRec>();
  const scaleFor = (rec: WinRec, size: string): number => {
    const theirs = Number(size.split("×")[0]) || 80;
    // Layout width, not the on-screen box: the camera's zoom scales the whole window and must not change the fit.
    const ours = Math.max(20, Math.floor((rec.card.body.clientWidth - 32) / ((coarse.matches ? 13 : 14) * 0.6)));
    return Math.min(1, Math.max(0.55, ours / theirs));
  };
  const paint = (rec: WinRec): void => {
    if (!isTerminal(rec)) return;
    const s = recordOf(rec);
    const body = rec.card.body;
    const exited = s?.state === "exited";
    rec.card.setStatus(exited ? "offline" : "live");
    let strip = body.querySelector<HTMLElement>(".cl-sx-strip");
    if (exited && s) {
      if (!strip) {
        strip = el("div", "cl-sx-strip ui-pill");
        strip.setAttribute("role", "group");
        body.append(strip);
      }
      const failed = (s.exit?.code ?? 0) !== 0;
      const gone = Boolean(s.gone);
      // Rebuilt only when what it says changes, so a refresh never resets a hover or a press on it.
      const signature = gone ? `${s.id}:gone` : `${s.id}:${s.exit?.code ?? 0}`;
      if (strip.dataset.signature !== signature) {
        strip.dataset.signature = signature;
        strip.dataset.result = gone ? "ended" : failed ? "fail" : "ok";
        strip.setAttribute("aria-label", gone ? `${s.name} ended` : `${s.name} exited with code ${s.exit?.code ?? 0}`);
        const mark = el("span", "ui-mark");
        mark.dataset.mark = gone ? "ended" : failed ? "fail" : "ok";
        const text = el("span", "cl-sx-strip-text", gone ? "Session ended" : `Exited ${s.exit?.code ?? 0}`);
        const again = el("button", "cl-sx-again");
        again.type = "button";
        if (gone) {
          // The obvious next step: a new shell on the same host, in this same window.
          again.innerHTML = `${icon(ICON.plus)}<span>New shell</span>`;
          again.addEventListener("click", () => newShell(rec, s));
        } else {
          again.innerHTML = `${icon(SESSION_ICON.again)}<span>Run again</span>`;
          again.addEventListener("click", () => inventory.runAgain(rec.model.host, s.id));
        }
        const dismiss = button("cl-sx-dismiss", gone ? "Close window" : "Dismiss", ICON_X);
        dismiss.dataset.tip = gone ? "Close window" : "Dismiss";
        dismiss.addEventListener("click", () => dismissSession(rec.model.host, s));
        strip.replaceChildren(mark, text, ...(gone && !rec.binding?.openNew ? [] : [again]), dismiss);
      }
    } else strip?.remove();
    // Another device typed last: shown scaled to fit, with a badge that offers the size back.
    const preview = body.querySelector<HTMLElement>(".cl-preview");
    const badge = body.querySelector<HTMLElement>(".cl-sx-badge");
    const device = s ? inventory.sizedFor(rec.model.host, s.id) : undefined;
    if (device && preview && s) {
      preview.dataset.scaled = "";
      preview.style.setProperty("--sx-k", String(scaleFor(rec, s.size)));
      if (!badge) {
        const node = el("button", "cl-sx-badge");
        node.type = "button";
        node.innerHTML = `${icon(device.kind === "phone" ? SESSION_ICON.phone : SESSION_ICON.laptop)}<span></span>`;
        node.querySelector("span")!.textContent = `Sized for ${device.name}`;
        node.setAttribute("aria-label", `Sized for ${device.name}. Type here to take over the size`);
        node.dataset.tip = "Type here to take over the size";
        node.addEventListener("click", () => takeOver(rec));
        body.append(node);
      }
    } else if (!leaving.has(rec)) {
      if (preview) { delete preview.dataset.scaled; preview.style.removeProperty("--sx-k"); }
      badge?.remove();
    }
  };

  /** Takes the size over: the terminal is already at its new size (the work is done); only the picture settles. */
  const takeOver = (rec: WinRec): void => {
    const s = recordOf(rec);
    if (!s || !inventory.sizedFor(rec.model.host, s.id)) return;
    const preview = rec.card.body.querySelector<HTMLElement>(".cl-preview");
    const badge = rec.card.body.querySelector<HTMLElement>(".cl-sx-badge");
    const k = Number(preview?.style.getPropertyValue("--sx-k")) || 1;
    leaving.add(rec);
    if (preview && !reduced.matches) {
      delete preview.dataset.scaled;
      const spring = new Spring(k, (v) => {
        if (v === 1) { preview.style.transform = ""; preview.style.transformOrigin = ""; return; }
        preview.style.transform = `scale(${v})`;
        preview.style.transformOrigin = "0 0";
      }, { visualDuration: 0.34, bounce: 0.12 });
      spring.set(1);
    }
    const done = (): void => { leaving.delete(rec); badge?.remove(); paint(rec); };
    if (badge && !reduced.matches) {
      badge.style.pointerEvents = "none";
      badge.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 160, easing: "ease-out", fill: "forwards" }).onfinish = done;
    } else done();
    inventory.takeOver(rec.model.host, s.id);
    flash(rec);
  };
  // Typing in a window that is sized for another device takes the size over.
  window.addEventListener("keydown", (event) => {
    const rec = cx.state.activeWin;
    if (!rec || event.metaKey || event.ctrlKey || event.altKey || (event.key.length > 1 && event.key !== "Enter")) return;
    if ((event.target as Element | null)?.closest?.("input, textarea")) return;
    const s = recordOf(rec);
    if (s && inventory.sizedFor(rec.model.host, s.id)) takeOver(rec);
  }, { signal });

  // ---- small motion helpers ----------------------------------------------------------------------
  const flash = (rec: WinRec): void => {
    if (reduced.matches) return;
    const frame = el("span", "cl-sx-flash");
    frame.setAttribute("aria-hidden", "true");
    rec.card.root.append(frame);
    frame.animate([{ opacity: 0.9 }, { opacity: 0 }], { duration: 520, easing: "ease-out" }).onfinish = () => frame.remove();
  };
  const slideLabel = (rec: WinRec): void => {
    if (reduced.matches) return;
    rec.card.pill.querySelector<HTMLElement>(".ui-window-session")?.animate([{ opacity: 0, transform: "translateY(6px)" }, { opacity: 1, transform: "none" }], { duration: 220, easing: EASE });
  };

  // ---- ending and dismissing --------------------------------------------------------------------
  const closeWindowOf = (host: string, id: string): void => {
    const w = windowFor(host, id);
    if (w && !w.owner.view.team) cx.win.close(w);
  };
  const dismissSession = (host: string, s: SessionRecord): void => { inventory.dismiss(host, s.id); closeWindowOf(host, s.id); };
  /** An ended session's window starts a new shell on the same host in place; the ended record goes. */
  const newShell = (rec: WinRec, s: SessionRecord): void => {
    if (!rec.binding?.openNew) return;
    delete rec.model.sessionId;
    inventory.dismiss(rec.model.host, s.id);
    rec.binding.openNew();
    paint(rec);
    cx.store.changed();
  };

  // ---- the manager --------------------------------------------------------------------------------
  class Manager {
    readonly popover: AnchoredPopover;
    private readonly scroll: HTMLElement;
    private readonly swipes: Array<() => void> = [];
    private renaming: string | undefined;
    /** Which status card was showing, so a change between two of them crossfades instead of swapping. */
    private shown: string = "ready";
    constructor(readonly rec: WinRec, anchor: HTMLElement, source: PopoverSource) {
      this.popover = openAnchoredPopover({
        stage, anchor, label: `Sessions on ${rec.model.host}`, className: "cl-sx-pop", align: "end", maxWidth: 380,
        bottomLimit: () => { const tray = stage.querySelector<HTMLElement>("#keybar"); return tray && getComputedStyle(tray).display !== "none" ? tray.getBoundingClientRect().top - 8 : undefined; },
      }, source, () => { this.dispose(); manager = undefined; });
      const root = this.popover.root;
      root.innerHTML = `<header class="cl-sx-head"><span class="cl-sx-logo"></span><span class="cl-sx-names"><span class="cl-sx-title"></span><span class="cl-sx-sub">Sessions</span></span></header><div class="cl-sx-scroll"></div>`;
      root.querySelector<HTMLElement>(".cl-sx-logo")!.innerHTML = rec.model.os ? hostIconMarkup(rec.model.os, "ui-host-mark") : "";
      root.querySelector<HTMLElement>(".cl-sx-title")!.textContent = rec.model.host;
      this.scroll = root.querySelector<HTMLElement>(".cl-sx-scroll")!;
      this.scroll.addEventListener("click", (event) => this.onClick(event));
      // Arrows walk the rows.
      root.addEventListener("keydown", (event) => {
        if ((event.key !== "ArrowDown" && event.key !== "ArrowUp") || (event.target as Element).closest(".cl-sx-name-input")) return;
        const rows = [...this.scroll.querySelectorAll<HTMLElement>(".cl-sx-main")];
        const at = rows.indexOf(document.activeElement as HTMLElement);
        const next = rows[Math.max(0, Math.min(rows.length - 1, at + (event.key === "ArrowDown" ? 1 : -1)))];
        if (next) { event.preventDefault(); next.focus(); }
      });
      // The canvas moving under it ends it: the card belongs to its window, not to the screen.
      cx.viewport.addEventListener("wheel", () => this.close("pointer"), { passive: true, signal: this.life.signal });
      this.render();
      if (source === "keyboard") this.scroll.querySelector<HTMLElement>(".cl-sx-main")?.focus({ preventScroll: true });
    }
    private readonly life = new AbortController();
    close(source: PopoverSource): void { this.popover.close(source); }
    private dispose(): void {
      this.life.abort();
      this.swipes.forEach((stop) => stop());
      if (confirm) { confirm.close(false); confirm = undefined; }
    }

    render(): void {
      this.swipes.splice(0).forEach((stop) => stop());
      const host = this.rec.model.host;
      const status = inventory.status();
      const rows: HTMLElement[] = [];
      if (status !== "ready") rows.push(this.state(status));
      else {
        const list = inventory.list(host);
        for (const state of ["open", "detached", "exited"] as const) {
          const members = list.filter((s) => s.state === state).sort(byFrecency);
          if (!members.length) continue;
          const group = el("section", "cl-sx-group");
          group.setAttribute("role", "group");
          group.setAttribute("aria-label", STATE_LABEL[state]);
          const ul = el("ul", "cl-sx-list");
          for (const s of members) ul.append(this.row(host, s));
          group.append(el("h3", "cl-sx-eyebrow", STATE_LABEL[state]), ul);
          rows.push(group);
        }
        if (list.every((s) => s.id === this.rec.model.sessionId)) rows.push(el("p", "cl-sx-empty", `No other sessions on ${host}`));
      }
      this.scroll.replaceChildren(...rows);
      // Loading turns into an error and back with a short crossfade (a status changing state); the rows themselves
      // are content you were waiting for, so they appear at once.
      if (status !== "ready" && this.shown !== "ready" && this.shown !== status && !reduced.matches) rows[0]?.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160, easing: "ease-out" });
      this.shown = status;
    }

    private state(status: string): HTMLElement {
      const node = el("div", "cl-sx-state");
      node.dataset.kind = status;
      if (status === "loading") {
        node.setAttribute("role", "status");
        node.append(createSpinner(), el("span", "", "Loading sessions"));
      } else {
        node.setAttribute("role", "alert");
        node.innerHTML = `${icon(ICON_ALERT, "cl-sx-state-icon")}<span class="cl-sx-state-title">Could not load sessions</span><span class="cl-sx-state-note"></span>`;
        node.querySelector<HTMLElement>(".cl-sx-state-note")!.textContent = `${this.rec.model.host} did not answer.`;
        const retry = button("cl-sx-retry ui-pill ui-pill-icon", "Try again", SESSION_ICON.retry);
        retry.addEventListener("click", () => { void inventory.reload(); });
        node.append(retry);
      }
      return node;
    }

    private row(host: string, s: SessionRecord): HTMLElement {
      const li = el("li", "cl-sx-row");
      li.dataset.id = s.id;
      li.dataset.state = s.state;
      const current = this.rec.model.sessionId === s.id;
      if (current) li.dataset.current = "";
      const failed = s.state === "exited" && !s.gone && (s.exit?.code ?? 0) !== 0;
      const mark = s.gone ? "ended" : s.state === "exited" ? (failed ? "fail" : "ok") : s.activity;
      const detail = [
        s.gone ? "ended" : s.state === "exited" ? `exited with code ${s.exit?.code ?? 0}` : s.state === "open" ? (current ? "this window" : "open in another window") : "detached",
        s.running ? `running ${s.running}` : "",
        mark === "output" ? "new output" : mark === "ok" && s.state !== "exited" ? "command finished" : mark === "fail" && s.state !== "exited" ? "command failed" : "",
      ].filter(Boolean).join(", ");
      const main = el("button", "cl-sx-main");
      main.type = "button";
      main.setAttribute("aria-label", `${s.name}, ${detail}`);
      main.dataset.tipOff = ""; // the row's text is its name; the label is for screen readers, never a tooltip
      if (current) main.setAttribute("aria-current", "true");
      const dot = el("span", "ui-state-dot");
      dot.dataset.state = s.state;
      const text = el("span", "cl-sx-text");
      const line = el("span", "cl-sx-line");
      line.append(el("span", "cl-sx-name", s.name));
      if (s.pinned) line.insertAdjacentHTML("beforeend", `<span class="cl-sx-pin" aria-hidden="true" data-tip="Name pinned">${icon(SESSION_ICON.pin)}</span>`);
      if (mark) { const m = el("span", "ui-mark"); m.dataset.mark = mark; m.setAttribute("aria-hidden", "true"); line.append(m); }
      text.append(line, el("span", "cl-sx-sub-line", s.lastOutput || " "));
      const meta = el("span", "cl-sx-meta");
      const top = el("span", "cl-sx-meta-top");
      if (s.viewers > 0) top.insertAdjacentHTML("beforeend", `<span class="cl-sx-viewers" aria-label="${s.viewers} viewing">${icon(SESSION_ICON.users)}${s.viewers}</span>`);
      const age = el("span", failed ? "is-fail" : "", s.gone ? "ended" : s.state === "exited" ? `exit ${s.exit?.code ?? 0} · ${s.age}` : s.age);
      top.append(age);
      meta.append(top, el("span", "cl-sx-meta-sub", s.size));
      main.append(dot, text, meta);

      // The row's actions: on hover or focus on desktop, behind a swipe on touch.
      const acts = el("span", "cl-sx-acts");
      const add = (act: string, label: string, paths: string): void => {
        const node = button(`ui-window-action cl-sx-act ${act === "end" ? "is-end" : ""}`.trim(), label, paths);
        node.dataset.act = act;
        acts.append(node);
      };
      // An ended session has nothing to run again: it can only be dismissed, where the inventory can.
      if (s.gone) { if (inventory.can?.dismiss !== false) add("dismiss", "Dismiss", ICON_X); }
      else if (s.state === "exited") { add("again", "Run again", SESSION_ICON.again); add("dismiss", "Dismiss", ICON_X); }
      else {
        const can = inventory.can;
        if (!coarse.matches && !current && !this.rec.owner.view.team) add("beside", "Open beside", SESSION_ICON.beside);
        if (can?.rename !== false) add("rename", "Rename", SESSION_ICON.rename);
        if (can?.end !== false) add("end", "End session", SESSION_ICON.end);
      }
      li.append(main, acts);
      if (this.renaming === s.id) queueMicrotask(() => this.edit(li, host, s));
      if (coarse.matches) this.swipes.push(swipeRow(li, main, acts));
      return li;
    }

    private onClick(event: MouseEvent): void {
      const target = event.target as Element;
      const li = target.closest<HTMLElement>(".cl-sx-row");
      if (!li?.dataset.id) return;
      const host = this.rec.model.host;
      const s = inventory.get(host, li.dataset.id);
      if (!s) return;
      const act = target.closest<HTMLElement>(".cl-sx-act")?.dataset.act;
      const how: PopoverSource = event.detail === 0 ? "keyboard" : "pointer";
      if (act === "rename") { this.edit(li, host, s); return; }
      if (act === "end") { this.confirmEnd(target.closest<HTMLElement>(".cl-sx-act")!, li, host, s); return; }
      if (act === "dismiss") { this.remove(li, () => dismissSession(host, s)); return; }
      if (act === "again") { this.popover.close(how); inventory.runAgain(host, s.id); this.choose(s, how, false); return; }
      if (act === "beside") { this.popover.close(how); void cx.win.newWindow(this.rec, "right", false, s.id); return; }
      if (target.closest(".cl-sx-name-input")) return;
      if (li.hasAttribute("data-swiped")) { li.dispatchEvent(new CustomEvent("sx-close")); return; }
      this.choose(s, how, true);
    }

    /** One open elsewhere takes you to its window; any other attaches this window to it. */
    private choose(s: SessionRecord, how: PopoverSource, closeFirst: boolean): void {
      const rec = this.rec;
      if (closeFirst) this.popover.close(how);
      if (rec.model.sessionId === s.id) return;
      const elsewhere = windowFor(rec.model.host, s.id);
      if (elsewhere) { cx.win.setActive(elsewhere); cx.nav.focusWindow(elsewhere); return; }
      cx.win.attach(rec, s.id);
    }

    private confirmEnd(anchor: HTMLElement, li: HTMLElement, host: string, s: SessionRecord): void {
      confirm?.close(false);
      confirm = mountConfirmTip(anchor, {
        label: "End session",
        boundary: this.rec.card.root,
        message: `End '${s.name}'?`,
        detail: s.running ? `${s.running} is still running. Ending the session stops it.` : "Nothing is running in it.",
        confirmLabel: "End session",
        cancelLabel: "Cancel",
        onConfirm: () => {
          confirm = undefined;
          // Ending this window's own session closes the window, and the card with it.
          if (s.id === this.rec.model.sessionId) { this.popover.close("pointer"); inventory.end(host, s.id); closeWindowOf(host, s.id); return; }
          this.remove(li, () => { inventory.end(host, s.id); closeWindowOf(host, s.id); });
        },
        onCancel: () => { confirm = undefined; },
      });
    }

    /** The row fades, then the rows below close the gap with a transform (no layout animation, no jump). */
    private remove(li: HTMLElement, commit: () => void): void {
      const below = [...this.scroll.querySelectorAll<HTMLElement>(".cl-sx-row")].filter((row) => row !== li);
      const tops = new Map(below.map((row) => [row.dataset.id, row.getBoundingClientRect().top]));
      const finish = (): void => {
        commit();
        if (reduced.matches) return;
        for (const row of this.scroll.querySelectorAll<HTMLElement>(".cl-sx-row")) {
          const was = tops.get(row.dataset.id);
          if (was === undefined) continue;
          const dy = was - row.getBoundingClientRect().top;
          if (Math.abs(dy) > 1) row.animate([{ transform: `translateY(${dy}px)` }, { transform: "none" }], { duration: 260, easing: EASE });
        }
      };
      if (reduced.matches) { finish(); return; }
      li.style.pointerEvents = "none";
      li.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 140, easing: "ease-out", fill: "forwards" }).onfinish = finish;
    }

    /** Renaming in place: the name becomes a field, and a committed name is pinned (it stops following the command). */
    private edit(li: HTMLElement, host: string, s: SessionRecord): void {
      const name = li.querySelector<HTMLElement>(".cl-sx-name");
      if (!name || li.querySelector(".cl-sx-name-input")) return;
      const input = el("input", "cl-sx-name-input");
      input.value = s.name;
      input.setAttribute("aria-label", "Session name");
      input.spellcheck = false;
      input.autocomplete = "off";
      name.replaceWith(input);
      this.renaming = s.id;
      input.focus({ preventScroll: true });
      input.select();
      let done = false;
      const finish = (commit: boolean): void => {
        if (done) return;
        done = true;
        this.renaming = undefined;
        if (commit) inventory.rename(host, s.id, input.value);
        this.render();
      };
      input.addEventListener("keydown", (event) => {
        event.stopPropagation();
        if (event.key === "Enter") { event.preventDefault(); finish(true); }
        else if (event.key === "Escape") { event.preventDefault(); finish(false); }
      });
      input.addEventListener("blur", () => finish(true));
    }
  }

  /** A touch row swipes left 1:1 with the finger to show its actions; release springs it open or shut. */
  function swipeRow(li: HTMLElement, main: HTMLElement, acts: HTMLElement): () => void {
    let width = 0;
    const slide = (value: number): void => {
      main.style.transform = value ? `translateX(${value}px)` : "";
      li.style.setProperty("--sx-open", String(Math.min(1, Math.max(0, -value / (width || 1)))));
    };
    let start: { id: number; x: number; y: number; base: number } | undefined, dragging = false, open = false;
    const spring = new Spring(0, slide, { visualDuration: 0.3, bounce: 0.08 });
    const down = (event: PointerEvent): void => {
      if (event.pointerType === "mouse" || (event.target as Element).closest(".cl-sx-act, .cl-sx-name-input")) return;
      width = acts.offsetWidth + 8;
      start = { id: event.pointerId, x: event.clientX, y: event.clientY, base: open ? -width : 0 };
    };
    const move = (event: PointerEvent): void => {
      if (!start || event.pointerId !== start.id) return;
      const dx = event.clientX - start.x, dy = event.clientY - start.y;
      if (!dragging) {
        if (Math.abs(dx) < 8 || Math.abs(dx) < Math.abs(dy) * 1.4) { if (Math.abs(dy) > 10) start = undefined; return; }
        dragging = true;
        li.setPointerCapture(event.pointerId);
      }
      const value = Math.max(-width, Math.min(0, start.base + dx));
      spring.value = value;
      slide(value);
      spring.set(value, true);
    };
    const up = (event: PointerEvent): void => {
      if (!start || event.pointerId !== start.id) return;
      if (dragging) {
        open = spring.value < -width / 2;
        spring.set(open ? -width : 0);
        li.toggleAttribute("data-swiped", open);
        // The click that ends a drag must not choose the row.
        li.dataset.dragged = "";
        window.setTimeout(() => { delete li.dataset.dragged; }, 0);
      }
      start = undefined;
      dragging = false;
    };
    const close = (): void => { open = false; spring.set(0); li.removeAttribute("data-swiped"); };
    const swallow = (event: Event): void => { if (li.dataset.dragged !== undefined) { event.stopPropagation(); event.preventDefault(); } };
    li.addEventListener("pointerdown", down);
    li.addEventListener("pointermove", move);
    li.addEventListener("pointerup", up);
    li.addEventListener("pointercancel", up);
    li.addEventListener("click", swallow, true);
    li.addEventListener("sx-close", close);
    return () => {
      li.removeEventListener("pointerdown", down);
      li.removeEventListener("pointermove", move);
      li.removeEventListener("pointerup", up);
      li.removeEventListener("pointercancel", up);
      li.removeEventListener("click", swallow, true);
      li.removeEventListener("sx-close", close);
    };
  }

  return {
    paint,
    toggleManager(rec, anchor, source) {
      if (manager?.rec === rec) { manager.close(source); return; }
      manager?.close("keyboard");
      cx.win.setActive(rec);
      manager = new Manager(rec, anchor, source);
    },
    closeManager() { manager?.close("keyboard"); },
    arrived(rec) { slideLabel(rec); flash(rec); },
    render() { manager?.render(); },
    dispose() { manager?.close("keyboard"); confirm?.close(false); },
  };
}
