/**
 * Mockup sessions: terminal windows show preview text from the test double, except the one window that carries the
 * page's single live terminal (the build-01 window), which gets the real renderer. Product code uses
 * `sessions/live.ts` instead.
 */
import type { CoreScreen } from "../../core-screen";
import type { HostEntry, SessionBinding, SessionService } from "../sessions/adapter";
import type { WindowModel } from "../model/types";
import { el } from "../dom";
import { previewLine } from "../windows/preview";
import { shellLines } from "./data";
import { allowedHosts, type MockWorld } from "./world";

/** The window that holds the live terminal in mockups. */
export const LIVE_WINDOW = "w-build-01";

export function createMockSessions(core: CoreScreen, world: MockWorld): SessionService & { dispose(): void } {
  // The one live terminal (the real renderer) is parked here while no window holds it.
  const holder = el("div", "cl-holder");
  holder.setAttribute("aria-hidden", "true");
  core.stage.append(holder);
  holder.append(core.terminalHost);
  let splits = 0;
  const listeners = new Set<() => void>();
  return {
    bind(model: WindowModel): SessionBinding {
      const live = model.id === LIVE_WINDOW;
      return {
        mount(body) {
          if (live) { body.append(core.terminalHost); return; }
          const pre = el("pre", "canvas-preview cl-preview");
          pre.innerHTML = `${(model.lines ?? []).map(previewLine).join("\n")}<span class="cl-cursor" aria-hidden="true"></span>`;
          body.append(pre);
        },
        focus() { if (live) core.terminalHost.focus({ preventScroll: true }); },
        setActive() {}, refit() {},
        // The live terminal's canvas holds pixels only while its window can be seen.
        setVisible(visible) { if (live) { if (visible) core.restoreSurface(); else core.releaseSurface(); } },
        dispose() { if (live) holder.append(core.terminalHost); },
      };
    },
    open(host, options) {
      const s = world.screens.get(host);
      if (options?.container) {
        const c = options.container;
        return { id: `w-shell-${c}`, kind: "terminal", host, user: "root", os: s?.os ?? "ubuntu", session: `${c} · sh`, lines: shellLines("root", c, "sh") };
      }
      if (options?.from) {
        const m = options.from;
        const n = ++splits;
        return { ...m, id: `${m.id}-s${n}`, session: `split ${n}`, splitOf: m.id, lines: shellLines(m.user ?? "kayg", m.host, "echo ready") };
      }
      return { id: `w-${host}`, kind: "terminal", host, user: s?.user ?? "kayg", os: s?.os ?? "unknown", lines: s?.screen ?? [`kayg@${host}:~$ `] };
    },
    hosts(): HostEntry[] { return allowedHosts(world.role).map((name) => ({ id: name, name })); },
    onChange(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    dispose() { holder.remove(); },
  };
}
