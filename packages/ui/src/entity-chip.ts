/**
 * Entity chips: a recognised thing named inside a sentence (a tag, a group, a host, a user, a route, an exit node, a
 * domain) is drawn as a small chip so it stands out from the words around it. One component serves every dialog,
 * confirmation, toast, list and card, so a tag looks the same everywhere (D160).
 *
 * - tag and group: a solid fill in the colour of the name (`entity-palette.ts`), with a `#` or a people glyph.
 * - host: a left-to-right gradient across the colours of its tags, in tag order (one tag: solid; none: neutral), with
 *   its operating system's mark.
 * - user: a radial gradient of its groups' colours from the centre out (one: solid; none: neutral), with its initial.
 * - route, exit node, domain: neutral, with the kind's icon.
 * A colour a person chose (`EntityRef.color`) overrides the derived one. Chips are text-height, sit on the baseline,
 * wrap as one unit and never animate. Colours are CSS variables, so a theme switch recolours them with no script.
 *
 * `entityText` turns a plain-language template with `{placeholders}` into text and chips, so copy stays an ordinary
 * string; `entityPlain` gives the same sentence as plain text for labels and tests.
 */
import { entityColorIndex, entityTextFor } from "./entity-palette";
import { hostIconMarkup, type HostPlatform } from "./host-icons";

export type EntityKind = "tag" | "group" | "host" | "user" | "route" | "exit" | "domain";

export interface EntityRef {
  kind: EntityKind;
  /** What is written in the chip. */
  name: string;
  /** host: the names of its tags in order. user: the names of its groups. */
  via?: readonly string[];
  /** A colour the person chose (six-digit hex); it replaces the derived colour. */
  color?: string;
  /** host: the detected operating system, for its mark. */
  platform?: HostPlatform;
}

const GLYPH: Record<Exclude<EntityKind, "host" | "user">, string> = {
  tag: `<path d="M9.5 4 8 20M16 4l-1.5 16M5 9h15M4 15h15"/>`,
  group: `<circle cx="9" cy="8.5" r="3"/><path d="M3.5 19c0-3 2.5-5 5.5-5s5.5 2 5.5 5"/><path d="M16 5.8a3 3 0 0 1 0 5.4M18 14.4c1.8.6 3 2.3 3 4.6"/>`,
  route: `<circle cx="6" cy="6" r="2"/><circle cx="18" cy="18" r="2"/><path d="M8 6h5a4 4 0 0 1 0 8h-2a4 4 0 0 0 0 4h5"/>`,
  exit: `<path d="M10 5H6a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h4M14 8l4 4-4 4M18 12H9"/>`,
  domain: `<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.5 3.5 5.3 3.5 8.5s-1 6-3.5 8.5c-2.5-2.5-3.5-5.3-3.5-8.5s1-6 3.5-8.5z"/>`,
};

/** `tag:ci` and `ci` are the same tag: the colour follows the bare name. */
const bare = (name: string): string => name.replace(/^(tag|group):/, "");
const colorVar = (name: string): string => `var(--ui-ent-${entityColorIndex(bare(name))})`;

/** The paint of a chip: a CSS background and the text colour that is legible on every stop of it. */
function paint(ref: EntityRef): { background: string; color: string } {
  const NEUTRAL = { background: "color-mix(in oklab, var(--fg) 14%, transparent)", color: "var(--fg)" };
  if (ref.color) return { background: ref.color, color: entityTextFor(ref.color) };
  const text = "var(--ui-ent-text)";
  if (ref.kind === "tag" || ref.kind === "group") return { background: colorVar(ref.name), color: text };
  if (ref.kind === "host" || ref.kind === "user") {
    const stops = (ref.via ?? []).map(colorVar);
    if (stops.length === 0) return NEUTRAL;
    if (stops.length === 1) return { background: stops[0]!, color: text };
    return { background: ref.kind === "host" ? `linear-gradient(90deg in oklab, ${stops.join(", ")})` : `radial-gradient(ellipse at center in oklab, ${stops.join(", ")})`, color: text };
  }
  return NEUTRAL;
}

function glyph(ref: EntityRef): string {
  if (ref.kind === "host") return hostIconMarkup(ref.platform ?? "unknown", "ui-entity-glyph ui-entity-fill");
  if (ref.kind === "user") return `<span class="ui-entity-initial" aria-hidden="true">${ref.name.trim().charAt(0).toUpperCase().replace(/[<>&]/g, "")}</span>`;
  return `<svg class="ui-entity-glyph" viewBox="0 0 24 24" aria-hidden="true">${GLYPH[ref.kind]}</svg>`;
}

/** One chip. */
export function entityChip(ref: EntityRef): HTMLElement {
  const chip = document.createElement("span");
  chip.className = "ui-entity";
  chip.dataset.kind = ref.kind;
  const p = paint(ref);
  chip.style.background = p.background;
  chip.style.color = p.color;
  chip.insertAdjacentHTML("afterbegin", glyph(ref));
  const label = document.createElement("span");
  label.className = "ui-entity-name";
  label.textContent = ref.name;
  chip.append(label);
  return chip;
}

/**
 * A tile for a named thing that has no picture of its own on the wire (an app on another machine): its first letter on
 * the colour its name always gets (`entity-palette.ts`), so the same app looks the same in the picker, the palette and its
 * window. Square, text-height, never animated, legible by the palette's contrast guarantee.
 */
export function entityTile(name: string): HTMLElement {
  const tile = document.createElement("span");
  tile.className = "ui-entity ui-entity-tile";
  tile.dataset.kind = "tile";
  tile.setAttribute("aria-hidden", "true");
  tile.style.background = `var(--ui-ent-${entityColorIndex(name)})`;
  tile.style.color = "var(--ui-ent-text)";
  const letter = /[\p{L}\p{N}]/u.exec(name)?.[0] ?? "?";
  tile.textContent = letter.toUpperCase();
  return tile;
}

const PLACEHOLDER = /\{([a-z][\w-]*)\}/gi;

/** The sentence with its placeholders written out, as plain text (labels, titles, tests). */
export function entityPlain(template: string, refs: Readonly<Record<string, EntityRef>>): string {
  return template.replace(PLACEHOLDER, (all, key: string) => refs[key]?.name ?? all);
}

/** The sentence as text and chips. Text between placeholders stays plain text nodes. */
export function entityText(template: string, refs: Readonly<Record<string, EntityRef>>): DocumentFragment {
  const out = document.createDocumentFragment();
  let last = 0;
  for (const m of template.matchAll(PLACEHOLDER)) {
    const ref = refs[m[1]!];
    if (!ref) continue;
    if (m.index! > last) out.append(template.slice(last, m.index));
    // Punctuation that follows a chip stays with it, so a line never starts with a lone "." or "?".
    const end = m.index! + m[0].length;
    const tail = /^[.,;:?!)]+/.exec(template.slice(end))?.[0] ?? "";
    if (tail) {
      const unit = document.createElement("span");
      unit.className = "ui-entity-unit";
      unit.append(entityChip(ref), tail);
      out.append(unit);
    } else out.append(entityChip(ref));
    last = end + tail.length;
  }
  if (last < template.length) out.append(template.slice(last));
  return out;
}
