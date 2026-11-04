/** Paints a round avatar for the person's pill and card: the initial on a colour derived from the name, or the picture. */
import { hueOffset, initial } from "../../../../../packages/ui/src/sidebar-foot";
import type { Person } from "./model";
import { shownName } from "./words";

/**
 * Fills `node` with the person's avatar. It sets the colour hue from the shown name, writes the initial as text, or sets the
 * picture as the background image when there is one, and marks the node `data-picture` so styles can tell the two apart.
 * Call it again after the name or picture changes; it overwrites what it painted before.
 */
export function paintAvatar(node: HTMLElement, person: Pick<Person, "name" | "username" | "picture">): void {
  const name = shownName(person);
  node.style.setProperty("--ui-avatar-hue", String(hueOffset(name)));
  node.textContent = person.picture ? "" : initial(name);
  node.style.backgroundImage = person.picture ? `url("${person.picture}")` : "";
  node.toggleAttribute("data-picture", Boolean(person.picture));
}
