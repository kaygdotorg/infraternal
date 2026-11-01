/** Paints a round avatar for the person's pill and card: the initial on a colour derived from the name, or the picture. */
import { hueOffset, initial } from "../../../../../packages/ui/src/sidebar-foot";
import type { Person } from "./model";
import { shownName } from "./words";

export function paintAvatar(node: HTMLElement, person: Pick<Person, "name" | "username" | "picture">): void {
  const name = shownName(person);
  node.style.setProperty("--ui-avatar-hue", String(hueOffset(name)));
  node.textContent = person.picture ? "" : initial(name);
  node.style.backgroundImage = person.picture ? `url("${person.picture}")` : "";
  node.toggleAttribute("data-picture", Boolean(person.picture));
}
