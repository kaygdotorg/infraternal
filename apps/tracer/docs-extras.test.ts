// SPDX-License-Identifier: AGPL-3.0-only
/**
 * One test per reading aid of docs-extras.ts (#302): each is checked on the HTML the bundler's renderer really writes (the inputs
 * below are Markdown run through `renderDoc`, not hand-written HTML), and each mistake a page author can make fails the build in
 * words that name the page.
 */
import { expect, test } from "bun:test";
import { renderDoc } from "./docs-build";
import { callouts, citations, codeBlocks, FACTS_MAX, factsOf, quotes } from "./docs-extras";

const page = (body: string): string => `# Demo\n\nA demo page.\n\n${body}`;
const body = (markdown: string): string => renderDoc("demo", page(markdown)).html;

test("each alert kind becomes a callout with its tone, an icon and a default title", () => {
  for (const [kind, title] of [["NOTE", "Note"], ["TIP", "Tip"], ["IMPORTANT", "Important"], ["WARNING", "Warning"], ["CAUTION", "Caution"]] as const) {
    const html = body(`## Heading\n\n> [!${kind}]\n> Something to know, with \`code\`.\n`);
    expect(html).toContain(`<aside class="callout callout-${kind.toLowerCase()}" role="note">`);
    expect(html).toContain(`<span>${title}</span>`);
    expect(html).toContain("<svg");
    expect(html).toContain("Something to know, with <code>code</code>.");
    expect(html).not.toContain("[!");
    expect(html).not.toContain("<blockquote");
  }
});

test("a title after the marker replaces the default; text on the marker line alone is the body", () => {
  expect(body("## H\n\n> [!WARNING] Under review\n> Nothing here is final.\n")).toContain("<span>Under review</span>");
  const inline = body("## H\n\n> [!NOTE] Just one line.\n");
  expect(inline).toContain("<span>Note</span>");
  expect(inline).toContain("<p>Just one line.</p>");
  // The body may continue in further paragraphs and lists.
  const long = body("## H\n\n> [!TIP]\n> First.\n>\n> Second.\n>\n> - one\n> - two\n");
  expect(long).toContain("<p>First.</p>");
  expect(long).toContain("<p>Second.</p>");
  expect(long).toContain("<li>two</li>");
});

test("an unknown, lower-case or empty alert fails the build and names the page", () => {
  expect(() => body("## H\n\n> [!NOTES]\n> text\n")).toThrow('docs page "demo": unknown callout [!NOTES]');
  expect(() => body("## H\n\n> [!note]\n> text\n")).toThrow("unknown callout [!note]");
  expect(() => callouts("<blockquote>\n<p>[!TIP]</p>\n</blockquote>", "demo")).toThrow("the [!TIP] callout is empty");
});

test("a [!WHY] block is a folded section titled with the words after the marker", () => {
  const html = body("## H\n\n> [!WHY] Why keys rotate\n> A key that never changes is a key that can be stolen once and used forever.\n>\n> Rotation makes a stolen copy expire.\n");
  expect(html).toContain('<details class="why"><summary>Why keys rotate</summary>');
  expect(html).not.toContain("<details class=\"why\" open");
  expect(html).toContain("Rotation makes a stolen copy expire.");
  // Without a title it says what it always says.
  expect(body("## H\n\n> [!WHY]\n> Because.\n")).toContain("<summary>Why it works this way</summary>");
});

test("quick facts show as a panel and are read back per heading, and for the page", () => {
  const doc = renderDoc("demo", page("> [!FACTS]\n> The whole page in a line.\n\n## One\n\n> [!FACTS]\n> One in a line, with **bold** and `code`.\n\ntext\n\n### Inside\n\ntext\n\n## Two\n\ntext\n"));
  expect(doc.html).toContain('<aside class="callout callout-facts" role="note">');
  expect(doc.html).toContain("<span>Quick facts</span>");
  expect(doc.facts).toEqual({ page: "The whole page in a line.", headings: { one: "One in a line, with bold and code." } });
});

test("quick facts over the limit, twice under one heading, or with nothing in them fail the build", () => {
  const long = "word ".repeat(FACTS_MAX / 4);
  expect(() => body(`## H\n\n> [!FACTS]\n> ${long}\n`)).toThrow(`keep them to ${FACTS_MAX} or fewer`);
  expect(() => body("## H\n\n> [!FACTS]\n> One.\n\n> [!FACTS]\n> Two.\n")).toThrow("more than one quick-facts block");
  expect(() => body("## H\n\n> [!FACTS]\n")).toThrow("callout is empty");
  expect(factsOf('<h2 id="a">A</h2><p>no facts here</p>')).toEqual({ headings: {} });
});

test("a quote ending with a dash line gets that line as its caption; a plain quote stays a quote", () => {
  const same = quotes("<blockquote>\n<p>Make it work.\n— Ada Lovelace</p>\n</blockquote>");
  expect(same).toBe('<figure class="quote"><blockquote>\n<p>Make it work.</p>\n</blockquote><figcaption>— Ada Lovelace</figcaption></figure>');
  const own = quotes("<blockquote>\n<p>Make it work.</p>\n<p>-- Ada <em>L.</em></p>\n</blockquote>");
  expect(own).toContain("<figcaption>— Ada <em>L.</em></figcaption>");
  expect(own).toContain("<p>Make it work.</p>\n</blockquote>");
  const plain = "<blockquote>\n<p>Just a quote - with a hyphen.</p>\n</blockquote>";
  expect(quotes(plain)).toBe(plain);
  expect(body("## H\n\n> Words worth keeping.\n> — Someone\n")).toContain("<figure class=\"quote\">");
});

test("citations are numbered in the order they are used, link both ways and end the page as References", () => {
  const html = body("## H\n\nFirst[^b] then second[^a], and the first again[^b].\n\n[^a]: The *second* source.\n[^b]: The first source, [with a link](https://example.com).\n");
  // Numbered by first use: b is 1, a is 2.
  expect(html).toContain('<sup class="cite"><a id="ref-1" href="#source-1" aria-label="Source 1">1</a></sup>');
  expect(html).toContain('<sup class="cite"><a id="ref-2" href="#source-2" aria-label="Source 2">2</a></sup>');
  expect(html).toContain('<a id="ref-1-2" href="#source-1"');
  expect(html).toContain('<h2 id="references">References</h2>');
  expect(html).toContain('<li id="source-1">The first source, <a href="https://example.com">with a link</a>.');
  expect(html).toContain('<li id="source-2">The <em>second</em> source.');
  // A source cited twice links back to both places.
  expect(html.match(/<li id="source-1">[\s\S]*?<\/li>/)![0].match(/class="back"/g)!.length).toBe(2);
  expect(html).toContain('href="#ref-1-2"');
  // The source paragraphs are gone from the text, and References is in the contents.
  expect(html).not.toContain("[^");
  expect(html).not.toMatch(/<p>\[/);
  // A source of one word is still a source (Markdown alone would read it as a link definition).
  expect(body("## H\n\nText[^w].\n\n[^w]: Wikipedia.\n")).toContain('<li id="source-1">Wikipedia.');
  expect(renderDoc("demo", page("## H\n\nx[^1]\n\n[^1]: s\n")).headings.map((h) => h.id)).toEqual(["h", "references"]);
});

test("a citation with no source, a source nothing cites, and a source written twice fail the build", () => {
  expect(() => body("## H\n\nText[^x].\n")).toThrow('docs page "demo": [^x] cites a source that is not written');
  expect(() => body("## H\n\nText.\n\n[^x]: Never used.\n")).toThrow("the source [^x] is never cited");
  expect(() => body("## H\n\nText[^x].\n\n[^x]: One.\n\n[^x]: Two.\n")).toThrow("written twice");
});

test("citation markers inside code are the code's own text", () => {
  const html = body("## H\n\nThe syntax is `[^name]` and\n\n```md\nlike[^1]\n[^1]: a line of code\n```\n");
  expect(html).toContain("<code>[^name]</code>");
  expect(html).toContain("like[^1]");
  expect(html).toContain("[^1]: a line of code");
  expect(html).not.toContain("References");
  expect(citations("<p>x</p>", new Map()).references).toBe("");
});

test("a fenced block is wrapped so it can be copied, and stays focusable", () => {
  const html = body("## H\n\n```sh\nexec tmux new-session -s main\n```\n");
  expect(html).toContain('<div class="doc-code"><pre tabindex="0"><code class="language-sh">exec tmux new-session -s main\n</code></pre></div>');
  expect(codeBlocks("<p>no code</p>")).toBe("<p>no code</p>");
});

test("the aids do not disturb the outline: the title block, contents and footer behave as before", () => {
  const doc = renderDoc("demo", page("## One\n\n> [!NOTE]\n> Aside.\n\n### Inside\n\ntext[^1]\n\n[^1]: Source.\n\n---\n\nBehind this page: D1.\n"));
  expect(doc.headings.map((h) => [h.id, h.level])).toEqual([["one", 2], ["inside", 3], ["references", 2]]);
  expect(doc.html.indexOf('<h2 id="references">')).toBeLessThan(doc.html.indexOf('<footer class="notes">'));
});
