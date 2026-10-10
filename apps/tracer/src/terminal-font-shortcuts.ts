/**
 * Keyboard font size for a terminal (D222): ⌘+ / ⌘− / ⌘0 on a Mac, Ctrl++ / Ctrl+− / Ctrl+0 elsewhere. The chords are
 * registry shortcuts (Settings, Shortcuts can rebind them), and the target is whichever terminal the screen shows: the
 * single terminal, or the active window on the canvas. The "=" alternate lets a US keyboard press Ctrl+= for larger, the
 * same key without Shift. Auto-repeat is consumed but does nothing, so one press is one step.
 */
import { bindShortcut, type Shortcut } from "../../../packages/ui/src/shortcuts";

/** The three font shortcuts as registry entries. Registered once per screen, so the `?` panel lists them under Everywhere. */
export const TERMINAL_FONT_SHORTCUTS: Shortcut[] = [
  { id: "font-larger", label: "Larger terminal text", keys: { mac: "⌘+", other: "Ctrl++" }, combo: { code: "Equal", key: "+", mod: true }, alternates: [{ code: "Equal", key: "=", mod: true }] },
  { id: "font-smaller", label: "Smaller terminal text", keys: { mac: "⌘−", other: "Ctrl+−" }, combo: { code: "Minus", key: "-", mod: true } },
  { id: "font-reset", label: "Reset terminal text size", keys: { mac: "⌘0", other: "Ctrl+0" }, combo: { code: "Digit0", key: "0", mod: true } },
];

/** Binds the three font shortcuts to the terminal `target` returns (none when the screen shows no terminal). Returns the removers. */
export function bindTerminalFont(target: () => { adjustFontSize(step: number | "reset"): void } | undefined): Array<() => void> {
  const step = (run: (terminal: { adjustFontSize(step: number | "reset"): void }) => void) => (event: KeyboardEvent): void => {
    if (event.repeat) return;
    const terminal = target();
    if (terminal) run(terminal);
  };
  return [
    bindShortcut("font-larger", step((t) => t.adjustFontSize(1))),
    bindShortcut("font-smaller", step((t) => t.adjustFontSize(-1))),
    bindShortcut("font-reset", step((t) => t.adjustFontSize("reset"))),
  ];
}
