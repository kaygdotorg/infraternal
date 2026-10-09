/**
 * How a window names itself in a list under its view's name (the zoomed-out hover card): the window's own name first
 * and a short detail second. The view's name is already the heading, so a window never repeats it: a settings window
 * shows the settings section it holds (its host field), a terminal shows user@host and its session.
 */
import type { WindowModel } from "../model/types";

export function windowLabel(m: WindowModel): [name: string, detail: string] {
  if (m.kind === "terminal") return [m.user ? `${m.user}@${m.host}` : m.host, m.session ?? ""];
  return [m.host, m.session ?? ""];
}
