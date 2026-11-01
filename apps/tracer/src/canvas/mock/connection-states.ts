/**
 * Test double of a window's connection (#212): palette rows "Mockup: connection – …" set the shared connection indicator of
 * the active window (or every window of the current view) to each state, so every icon, its motion and its sentence can be
 * reached and photographed on the test double. The real states come from the window's binding (windows/link.ts); this only
 * stands in for a network that can be made to fail on demand. Nothing here talks to a server.
 */
import type { ConnectionIndicatorState } from "../../../../../packages/ui/src/connection-indicator";
import type { PaletteEntry } from "../../core-screen";
import type { Ctx, WinRec } from "../context";

interface Demo { label: string; hint: string; id: string; state: ConnectionIndicatorState; detail?: string; held?: number }

const STATES: Demo[] = [
  { id: "connected", label: "connected", hint: "a calm green dot", state: "connected" },
  { id: "slow", label: "slow", hint: "amber, breathes three times", state: "slow" },
  { id: "connecting", label: "connecting", hint: "an arc turns: the first attach", state: "connecting" },
  { id: "reconnecting", label: "reconnecting", hint: "an arc turns: the link was lost", state: "reconnecting" },
  { id: "reconnecting-held", label: "reconnecting, keys kept", hint: "the arc and an amber key", state: "reconnecting", held: 7 },
  { id: "resumed", label: "resumed", hint: "a tick, then back to the dot", state: "resumed" },
  { id: "approximate", label: "resumed, screen rebuilt", hint: "a screen, then back to the dot", state: "approximate" },
  { id: "offline", label: "offline", hint: "a slashed ring", state: "offline" },
  { id: "offline-held", label: "offline, keys kept", hint: "a slashed ring and an amber key", state: "offline", held: 3 },
  { id: "ended", label: "session ended", hint: "a slashed ring: this session has ended", state: "offline", detail: "This session has ended." },
];

export interface ConnectionStates { entries(): PaletteEntry[]; run(id: string): void }

export function connectionStates(cx: Ctx): ConnectionStates {
  const targets = (): WinRec[] => {
    const active = cx.state.activeWin;
    if (active) return [active];
    const view = cx.views.get(cx.state.currentView);
    return view ? [...view.wins.values()] : [];
  };
  const apply = (spec: Demo): void => { for (const rec of targets()) rec.card.setConnection(spec.state, spec.detail, spec.held ?? 0); };
  let timer = 0;
  return {
    entries: () => [
      ...STATES.map((s): PaletteEntry => ({ group: "Mockup", glyph: "◇", label: `Mockup: connection – ${s.label}`, hint: s.hint, action: `proto:conn:${s.id}` })),
      { group: "Mockup", glyph: "◇", label: "Mockup: connection – play every state", hint: "one every 2.6 s", action: "proto:conn:demo" },
    ],
    run(id) {
      window.clearInterval(timer);
      if (id === "demo") {
        let step = 0;
        apply(STATES[step++]!);
        timer = window.setInterval(() => { if (step >= STATES.length) { window.clearInterval(timer); return; } apply(STATES[step++]!); }, 2600);
        return;
      }
      const spec = STATES.find((s) => s.id === id);
      if (spec) apply(spec);
    },
  };
}
