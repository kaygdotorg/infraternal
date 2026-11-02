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
import { DEFAULT_SESSION, type MockInventory } from "./inventory";
import { allowedHosts, type MockWorld } from "./world";

/** The window that holds the live terminal in mockups. */
export const LIVE_WINDOW = "w-build-01";

export function createMockSessions(core: CoreScreen, world: MockWorld, inventory?: MockInventory): SessionService & { enroll(host: string): void; dispose(): void } {
  // The one live terminal (the real renderer) is parked here while no window holds it.
  const holder = el("div", "cl-holder");
  holder.setAttribute("aria-hidden", "true");
  core.stage.append(holder);
  holder.append(core.terminalHost);
  let splits = 0;
  // Enrollment belongs to the current mock person, never every role in a scene.
  const enrolled = new Map<string, typeof world.role>();
  const listeners = new Set<() => void>();
  return {
    bind(model: WindowModel): SessionBinding {
      // The live terminal is the window's own session; a window pointed at another session shows that one's screen.
      const live = model.id === LIVE_WINDOW && (!model.sessionId || model.sessionId === DEFAULT_SESSION[model.host]);
      return {
        mount(body) {
          if (live) { body.append(core.terminalHost); return; }
          const pre = el("pre", "canvas-preview cl-preview");
          pre.innerHTML = `${(model.lines ?? []).map(previewLine).join("\n")}<span class="cl-cursor" aria-hidden="true"></span>`;
          body.append(pre);
        },
        focus() { if (live) core.terminalHost.focus({ preventScroll: true }); },
        setActive() {}, refit() {},
        // Only the live terminal has a scrollback; the previews are plain text that does not scroll.
        ...(live ? { wheelUse: (deltaY: number) => core.wheelUse(deltaY) } : {}),
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
      if (options?.session && inventory) {
        const rec = inventory.get(host, options.session);
        if (rec) return { id: `w-${host}-${rec.id}`, kind: "terminal", host, user: s?.user ?? "kayg", os: s?.os ?? "unknown", session: rec.name, sessionId: rec.id, lines: rec.screen };
      }
      if (options?.from) {
        const m = options.from;
        const n = ++splits;
        const rec = inventory?.create?.(host);
        if (rec) return { ...m, id: `${m.id}-s${n}`, session: rec.name, sessionId: rec.id, splitOf: m.id, lines: rec.screen };
        return { ...m, id: `${m.id}-s${n}`, session: `split ${n}`, splitOf: m.id, lines: shellLines(m.user ?? "kayg", m.host, "echo ready") };
      }
      const first = DEFAULT_SESSION[host] ? inventory?.get(host, DEFAULT_SESSION[host]!) : inventory?.list(host)[0];
      return { id: `w-${host}`, kind: "terminal", host, user: s?.user ?? "kayg", os: s?.os ?? "unknown", ...(first ? { session: first.name, sessionId: first.id } : {}), lines: s?.screen ?? [`kayg@${host}:~$ `] };
    },
    enroll(host) { enrolled.set(host, world.role); for (const listener of listeners) listener(); },
    hosts(): HostEntry[] {
      const names = new Set([...allowedHosts(world.role), ...[...enrolled].filter(([, role]) => role === world.role).map(([name]) => name)]);
      return [...names].map((name) => ({ id: name, name }));
    },
    onChange(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    dispose() { holder.remove(); },
  };
}
