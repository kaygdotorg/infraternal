/**
 * The transparency comparison (mockup only): all four card levels and all four window levels side by side over the
 * same busy content (coloured code on the real canvas backdrop, dots included), so the levels can be judged at once.
 * It opens from the command palette ("Mockup: transparency") and closes with Escape or its close button. Every
 * sample uses the real material through the same tables the settings use (themes.ts), written as local tokens on
 * the sample, so what is shown is what each level looks like in the product.
 */
import type { CoreScreen } from "../../core-screen";
import { CARD_LEVELS, LEVEL_NAMES, THEMES, WINDOW_LEVELS, overlayMaterial } from "../../../../../packages/ui/src/themes";
import { el } from "../dom";

/** The sample terminal rows (host, command, tone) drawn behind the comparison. */
const BUSY: Array<[string, string, string]> = [
  ["git", "log --oneline -12", "ok"], ["", "3fa4460 tracer, ui: the dots sit on the gradient", ""], ["", "cdddcb4 tracer: Mesh grants are edited by dragging", ""],
  ["cargo", "test -p infraternal --release", "ok"], ["", "running 48 tests", ""], ["", "test agent::resume_after_reconnect ... ok", "ok"], ["", "test vt::wide_cells_align ... FAILED", "bad"],
  ["tail", "-f /var/log/syslog", "ok"], ["", "Oct  8 16:02:11 build-01 sshd[2113]: Accepted publickey for kayg", ""], ["", "Oct  8 16:02:12 build-01 kernel: nf_conntrack: table full", "bad"],
  ["htop", "", "ok"], ["", "  PID USER      PR  NI    VIRT    RES  %CPU %MEM", ""], ["", " 2113 kayg      20   0  912340  88112   3.2  1.1 infraternal", ""],
];

/** Shows the comparison over the stage and returns the function that closes it. Escape or the close button also closes it. */
export function mountTransparencyCompare(core: CoreScreen): () => void {
  const stage = core.stage;
  const root = el("section", "cl-compare");
  root.setAttribute("role", "dialog");
  root.setAttribute("aria-label", "Transparency levels");
  const busy = el("pre", "cl-compare-busy");
  busy.setAttribute("aria-hidden", "true");
  const rows = Array.from({ length: 70 }, (_, i) => BUSY[i % BUSY.length]!);
  busy.innerHTML = rows.map(([host, cmd, tone]) => `${host ? `<b class="cl-c-prompt">${host}</b> ` : ""}<span class="${tone === "bad" ? "cl-c-bad" : tone === "ok" ? "cl-c-ok" : ""}">${cmd}</span>`).join("\n");
  const close = el("button", "ui-pill ui-pill-icon cl-compare-close");
  close.type = "button";
  close.setAttribute("aria-label", "Close comparison");
  close.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m7 7 10 10M17 7 7 17"/></svg>';
  const grid = el("div", "cl-compare-grid");
  const theme = THEMES[core.appearance().theme] ?? THEMES.ink!;

  const heading = (text: string): HTMLElement => el("h2", "cl-compare-h", text);
  const cards = el("div", "cl-compare-row");
  const windows = el("div", "cl-compare-row");
  LEVEL_NAMES.forEach((name, i) => {
    const level = i + 1, c = CARD_LEVELS[level]!, w = WINDOW_LEVELS[level]!;
    const card = el("div", "ui-overlay-surface cl-compare-card");
    card.style.setProperty("--ui-overlay-background", overlayMaterial(theme, level).overlay);
    card.style.setProperty("--ui-overlay-blur", `${c.blur}px`);
    if (c.blur === 0) card.style.backdropFilter = "none";
    card.innerHTML = `<strong>${name}</strong><span>${Math.round((theme.dark ? c.dark : c.light) * 100)}% tint · ${c.blur} px blur</span><span class="cl-compare-sample">Popover, palette, sidebar: kayg@build-01 ~ $</span>`;
    cards.append(card);
    const win = el("div", "cl-compare-window");
    const alpha = Math.round((theme.dark ? w.dark : w.light) * 100);
    win.style.background = `color-mix(in srgb, var(--bg) ${alpha}%, transparent)`;
    if (w.blur) win.style.backdropFilter = `blur(${w.blur}px)`;
    win.innerHTML = `<strong>${name}</strong><span>${alpha}% tint · ${w.blur} px blur</span><span class="cl-compare-sample"><b class="cl-c-prompt">kayg@build-01</b>:~$ cargo test</span><span class="cl-compare-sample cl-c-dim">secondary text, 12 files changed</span>`;
    windows.append(win);
  });
  grid.append(heading("Cards"), cards, heading("Windows"), windows);
  root.append(busy, grid, close);
  stage.append(root);
  const off = (): void => root.remove();
  close.addEventListener("click", off);
  const onKey = (e: KeyboardEvent): void => { if (e.key === "Escape") { off(); document.removeEventListener("keydown", onKey, true); } };
  document.addEventListener("keydown", onKey, true);
  return off;
}
