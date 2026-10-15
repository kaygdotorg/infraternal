/**
 * How a window names itself in a list under its view's name (the zoomed-out hover card and the palette's scoped
 * list): the window's own name first and a short detail second. The view's name is already the heading, so a window
 * never repeats it: a settings window shows the settings section it holds (its host field).
 *
 * A terminal takes its name from its session (D178): the session's name is the one the person set, or the automatic
 * one the inventory keeps (the foreground command or the folder). Its detail says what tells it apart from its
 * neighbours: the command running in it, else the last line it printed, else its state or how long ago it was used. Only without an inventory
 * does a terminal fall back to its window's session name, and then to "user@host" (#121: no new naming here).
 */
import type { WindowModel } from "../model/types";
import type { SessionInventory } from "../sessions/inventory";
import { SETTINGS_SECTIONS } from "../views/settings";

/** `inventory` is the canvas's session inventory, when it has one; a window's session is looked up in it. */
export function windowLabel(m: WindowModel, inventory?: SessionInventory): [name: string, detail: string] {
  // A settings window is named by its section. The title comes from the section list by the window's id (`s-<section>`),
  // so a window rebuilt without its host field (a restored layout) is still titled, never blank.
  if (m.kind === "settings") return [m.host || SETTINGS_SECTIONS.find((s) => `s-${s.id}` === m.id)?.title || "Settings", m.session ?? ""];
  // An app window or a screen is named by what it shows ("Safari · Inbox"), with the machine as its detail.
  if (m.kind === "app" || m.kind === "screen") return [m.session || m.host, m.host];
  if (m.kind !== "terminal") return [m.host || m.kind, m.session ?? ""];
  const who = m.user ? `${m.user}@${m.host}` : m.host;
  const session = m.sessionId ? inventory?.get(m.host, m.sessionId) : undefined;
  if (!session) return m.session ? [m.session, who] : [who, ""];
  const detail = session.running
    || session.lastOutput
    || (session.state === "exited" ? `exited ${session.exit?.code ?? 0}` : session.state === "detached" ? "detached" : session.age);
  return [session.name, detail];
}
