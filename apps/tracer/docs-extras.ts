// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The reading aids of a docs page, added after the Markdown is rendered (docs-build.ts `renderDoc`, #302).
 *
 * The bundler's Markdown renderer knows tables, lists and code, and nothing else. Everything a long page needs to be easy to read
 * is written in Markdown that other tools already understand, and turned into markup here, as pure functions of HTML so each one
 * has its own unit test (docs-extras.test.ts) and no dependency is added:
 *
 * - Callouts: GitHub's alert syntax, `> [!NOTE]`, `[!TIP]`, `[!IMPORTANT]`, `[!WARNING]`, `[!CAUTION]`. An alert is a block with an
 *   icon, a title and a tone. A title may follow the marker (`> [!WARNING] Under review`) when the default does not fit.
 * - Reasoning: `> [!WHY] Why keys rotate` is the same syntax with one more kind. It becomes a folded `<details>`: the page states
 *   what is true, and the reasoning is one tap away for the reader who wants it.
 * - Quick facts: `> [!FACTS]` directly under a heading is a short summary of that section. It shows on the page as a panel, and its
 *   text goes into `index.json` for the "?" preview (`factsOf`). The block is capped (FACTS_MAX) so a preview stays a preview.
 * - Citations: `[^name]` in the text and `[^name]: the source` anywhere on the page. They become numbered references in order of
 *   first use, a "References" list at the end with a link back to each place the reference was used, and an entry in the contents.
 * - Quotes: a plain `>` block. A last line that starts with an em dash (`> — Name`) becomes the quote's caption.
 * - Code: a fenced block is wrapped so a click, or a double tap on a phone, copies it (doc-enhance.ts).
 *
 * A mistake in one of these fails the build with the page and the marker named: an unknown alert, a citation with no source, a source
 * nothing cites. The structure a reader relies on cannot rot silently, the same rule `checkOutline` applies to headings.
 */
import { ICON_ALERT, ICON_HELP, ICON_INFO } from "../../packages/ui/src/icons";

/** The most characters a quick-facts block may hold: a sentence or two, because the "?" preview shows it whole. */
export const FACTS_MAX = 320;

/** The plain text of an HTML fragment: tags removed, common entities decoded and spaces collapsed. */
const plain = (html: string): string => html.replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#0*39;/g, "'").replace(/\s+/g, " ").trim();

/** Pieces of HTML that are code, which no reading aid may touch: `[^1]` in a code span is the code's own text. */
const CODE_PIECES = /(<pre[\s\S]*?<\/pre>|<code[\s\S]*?<\/code>)/;
/** Applies `change` to the parts of `html` that are not code and returns the whole, so reading aids never rewrite a code sample. */
function outsideCode(html: string, change: (text: string) => string): string {
  return html.split(CODE_PIECES).map((piece, i) => (i % 2 === 1 ? piece : change(piece))).join("");
}

// ---- callouts, reasoning and quick facts -----------------------------------------------------------------------------------------

/** Inner SVG markup (24 grid, stroked) for the callout kinds, used by {@link KINDS}. */
const ICON_WARN = `<path d="M12 4.5l8.5 14.5h-17z"/><path d="M12 10.5v3.5M12 16.8v.01"/>`;
const ICON_BULB = `<path d="M9 18h6M10 21h4"/><path d="M12 3.5a5.5 5.5 0 0 0-3.2 10c.5.4.7.9.7 1.5h5c0-.6.2-1.1.7-1.5a5.5 5.5 0 0 0-3.2-10z"/>`;
/** A bolt, for the quick facts: the short version of a section. */
const ICON_BOLT = `<path d="M13 3.5L5.5 13.5H11l-1 7 7.5-10H12z"/>`;
const ICON_STOP = `<path d="M8.2 3.5h7.6l4.7 4.7v7.6l-4.7 4.7H8.2l-4.7-4.7V8.2z"/><path d="M12 8v5M12 16.2v.01"/>`;

/** A callout kind: the title shown on the callout and its icon. */
interface Kind { title: string; icon: string }
/** The alert kinds a page may use; the key is the marker in capitals, as GitHub writes it. */
const KINDS: Record<string, Kind> = {
  NOTE: { title: "Note", icon: ICON_INFO },
  TIP: { title: "Tip", icon: ICON_BULB },
  IMPORTANT: { title: "Important", icon: ICON_ALERT },
  WARNING: { title: "Warning", icon: ICON_WARN },
  CAUTION: { title: "Caution", icon: ICON_STOP },
  FACTS: { title: "Quick facts", icon: ICON_BOLT },
  WHY: { title: "Why it works this way", icon: ICON_HELP },
};

/** Wraps inner SVG markup in a decorative 24 by 24 icon. */
const iconSvg = (paths: string): string => `<svg viewBox="0 0 24 24" aria-hidden="true">${paths}</svg>`;

/**
 * Turns `> [!KIND]` blocks into callouts. The marker is the first thing in the quote. What follows it on the same line is the
 * title when more text follows (a line below, or another paragraph); otherwise it is the first line of the body.
 */
export function callouts(html: string, page = "this page"): string {
  return html.replace(/<blockquote>\n<p>\[!([A-Za-z]+)\]([\s\S]*?)<\/blockquote>/g, (_all, marker: string, inner: string) => {
    const kind = KINDS[marker.toUpperCase()];
    if (!kind || marker !== marker.toUpperCase()) {
      throw new Error(`docs page "${page}": unknown callout [!${marker}]; use ${Object.keys(KINDS).map((k) => `[!${k}]`).join(", ")}`);
    }
    const end = inner.indexOf("</p>");
    const first = inner.slice(0, end);
    const rest = inner.slice(end + 4).trim();
    const newline = first.indexOf("\n");
    const line = (newline < 0 ? first : first.slice(0, newline)).trim();
    const after = newline < 0 ? "" : first.slice(newline + 1).trim();
    let title = kind.title;
    let body = after ? `<p>${after}</p>\n` : "";
    if (line) {
      if (after || rest) title = line;
      else body = `<p>${line}</p>\n`;
    }
    body += rest;
    if (!body.trim()) throw new Error(`docs page "${page}": the [!${marker}] callout is empty`);
    if (marker === "WHY") return `<details class="why"><summary>${title}</summary>\n<div class="why-body">\n${body.trim()}\n</div></details>`;
    return `<aside class="callout callout-${marker.toLowerCase()}" role="note"><p class="callout-title">${iconSvg(kind.icon)}<span>${title}</span></p>\n${body.trim()}\n</aside>`;
  });
}

/** The quick facts of a page: the text under its title (if any) and the text under each heading, by heading id. */
export interface Facts { page?: string; headings: Record<string, string> }

/**
 * Reads the quick-facts blocks out of finished HTML (headings already have their ids). A block belongs to the heading above it, or to
 * the page when no heading is above it. The text is plain, so the "?" preview can show it without trusting markup. A block over
 * FACTS_MAX characters, a second block under one heading, or a block under a heading that has no id fails the build.
 */
export function factsOf(html: string, page = "this page"): Facts {
  const found: Facts = { headings: {} };
  let current: string | undefined;
  for (const match of html.matchAll(/<h[23][^>]*\sid="([^"]+)"|<aside class="callout callout-facts"[^>]*>([\s\S]*?)<\/aside>/g)) {
    if (match[1]) { current = match[1]; continue; }
    const text = plain((match[2] ?? "").replace(/^<p class="callout-title">[\s\S]*?<\/p>/, ""));
    const where = current ? `under "${current}"` : "under the title";
    if (text.length > FACTS_MAX) throw new Error(`docs page "${page}": the quick facts ${where} are ${text.length} characters; keep them to ${FACTS_MAX} or fewer`);
    const taken = current ? found.headings[current] !== undefined : found.page !== undefined;
    if (taken) throw new Error(`docs page "${page}": more than one quick-facts block ${where}`);
    if (current) found.headings[current] = text; else found.page = text;
  }
  return found;
}

// ---- quotes ----------------------------------------------------------------------------------------------------------------------

/** A quote that ends with `— Name` gets that line as its caption, set outside the quoted words. Other quotes are left as they are. */
export function quotes(html: string): string {
  return html.replace(/<blockquote>\n([\s\S]*?)<\/blockquote>/g, (all, inner: string) => {
    const tail = /(<p>|\n)(?:—|--)[ \t]+([^\n]+?)<\/p>\s*$/.exec(inner);
    if (!tail) return all;
    const quoted = inner.slice(0, tail.index) + (tail[1] === "\n" ? "</p>" : "");
    return `<figure class="quote"><blockquote>\n${quoted.trim()}\n</blockquote><figcaption>— ${tail[2]}</figcaption></figure>`;
  });
}

// ---- citations -------------------------------------------------------------------------------------------------------------------

/** The "back to the text" arrow of a citation. */
const BACK = iconSvg(`<path d="M9 14L4 9l5-5"/><path d="M4 9h10.5a5.5 5.5 0 0 1 0 11H11"/>`);

/**
 * Takes the source lines (`[^name]: text`, one line each) out of the Markdown *before* it is rendered. The renderer must never see
 * them: a source of one word (`[^a]: Wikipedia.`) is, to Markdown, a link reference definition, and would swallow the line and turn
 * the citation into a broken link. Lines inside a fenced block are code and stay. `inline` renders a source's text to HTML.
 */
export function sourcesOf(markdown: string, inline: (text: string) => string, page = "this page"): { markdown: string; sources: Map<string, string> } {
  const sources = new Map<string, string>();
  let fence: string | undefined;
  const kept = markdown.split("\n").filter((line) => {
    const marker = /^\s*(`{3,}|~{3,})/.exec(line)?.[1];
    if (marker) fence = fence === undefined ? marker : line.trim().startsWith(fence) ? undefined : fence;
    if (fence !== undefined || marker) return true;
    const source = /^\[\^([^\]\s]+)\]:[ \t]+(\S.*)$/.exec(line);
    if (!source) return true;
    const [, name, text] = source as unknown as [string, string, string];
    if (sources.has(name)) throw new Error(`docs page "${page}": the source [^${name}] is written twice`);
    sources.set(name, inline(text.trim()).replace(/^<p>([\s\S]*?)<\/p>\s*$/, "$1").trim());
    return false;
  });
  return { markdown: kept.join("\n"), sources };
}

/**
 * Turns `[^name]` citations into numbered references. `body` has them replaced by links to the list; `references` is the list
 * itself (empty when the page cites nothing), each entry with a link back to every place it was cited. Numbers follow the order of
 * first use. A code span or block is never touched. `sources` come from `sourcesOf`.
 */
export function citations(withoutSources: string, sources: ReadonlyMap<string, string>, page = "this page"): { body: string; references: string } {
  const order: string[] = [];
  const uses = new Map<string, number>();
  const body = outsideCode(withoutSources, (text) => text.replace(/\[\^([^\]\s]+)\]/g, (_all, name: string) => {
    if (!sources.has(name)) throw new Error(`docs page "${page}": [^${name}] cites a source that is not written (add a line "[^${name}]: …")`);
    if (!order.includes(name)) order.push(name);
    const number = order.indexOf(name) + 1;
    const count = (uses.get(name) ?? 0) + 1;
    uses.set(name, count);
    const id = count === 1 ? `ref-${number}` : `ref-${number}-${count}`;
    return `<sup class="cite"><a id="${id}" href="#source-${number}" aria-label="Source ${number}">${number}</a></sup>`;
  }));
  for (const name of sources.keys()) if (!order.includes(name)) throw new Error(`docs page "${page}": the source [^${name}] is never cited`);
  if (order.length === 0) return { body, references: "" };
  const items = order.map((name, i) => {
    const number = i + 1;
    const back = Array.from({ length: uses.get(name) ?? 1 }, (_unused, k) => `<a class="back" href="#${k === 0 ? `ref-${number}` : `ref-${number}-${k + 1}`}" aria-label="Back to where source ${number} is cited">${BACK}</a>`).join("");
    return `<li id="source-${number}">${sources.get(name)}${back}</li>`;
  });
  return { body, references: `<h2 id="references">References</h2>\n<ol class="references">\n${items.join("\n")}\n</ol>` };
}

// ---- code ------------------------------------------------------------------------------------------------------------------------

/**
 * Wraps each fenced block so it can be copied by a click (a double tap on a phone). The block is focusable because it can scroll
 * sideways, and so Enter can copy it from the keyboard.
 */
export function codeBlocks(html: string): string {
  return html.replace(/<pre>(<code[\s\S]*?<\/code>)<\/pre>/g, (_all, code: string) => `<div class="doc-code"><pre tabindex="0">${code}</pre></div>`);
}

/** Every reading aid in the order a page needs them: callouts first (they are quotes until then), then quotes, then code. */
export function readingAids(html: string, page: string): string {
  return codeBlocks(quotes(callouts(html, page)));
}
