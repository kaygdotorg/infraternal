/** Runs axe-core (a dev-only test dependency, MPL-2.0) inside a Playwright page; shared by the audit and the regression spec (#558). */
import { createRequire } from "node:module";
import type { Page } from "playwright/test";

/** The path of the axe-core script that is injected into a page. */
const AXE_PATH = createRequire(import.meta.url).resolve("axe-core/axe.min.js");

/** One rule that failed, with up to five of the elements that failed it. */
export interface Violation { rule: string; impact: string | null; help: string; count: number; nodes: Array<{ target: string; html: string; summary: string }> }

/** What to check: axe tags (default WCAG 2.0 to 2.2 A and AA plus best practices), or exact rule ids, and CSS selectors to leave out. */
export interface AxeOptions { tags?: string[]; rules?: string[]; exclude?: string[] }

/** Injects axe once and runs it on the whole page; returns the violations, trimmed to what a report needs. */
export async function runAxe(page: Page, options: AxeOptions = {}): Promise<Violation[]> {
  if (!(await page.evaluate(() => "axe" in window))) await page.addScriptTag({ path: AXE_PATH });
  const tags = options.tags ?? ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"];
  return page.evaluate(async ({ tags, rules, exclude }) => {
    type Raw = { violations: Array<{ id: string; impact: string | null; help: string; nodes: Array<{ target: unknown[]; html: string; failureSummary?: string }> }> };
    const axe = (window as unknown as { axe: { run(ctx: unknown, opts: unknown): Promise<Raw> } }).axe;
    const context = exclude.length ? { include: [document], exclude: exclude.map((selector) => [selector]) } : document;
    const results = await axe.run(context, { runOnly: rules.length ? { type: "rule", values: rules } : { type: "tag", values: tags } });
    return results.violations.map((v) => ({
      rule: v.id, impact: v.impact, help: v.help, count: v.nodes.length,
      nodes: v.nodes.slice(0, 5).map((n) => ({ target: n.target.join(" "), html: n.html.slice(0, 160), summary: (n.failureSummary ?? "").slice(0, 240) })),
    }));
  }, { tags, rules: options.rules ?? [], exclude: options.exclude ?? [] });
}
