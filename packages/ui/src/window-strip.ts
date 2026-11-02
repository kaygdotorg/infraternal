/**
 * The window strip (D160): the one floating pill a window shows over its content to say what happened to it and to
 * offer the next step. A session that exited (Run again), one the host no longer has (New shell), a refused shell
 * (Try again) and an app window or screen that stopped (Close window) all use it, so they look and move the same.
 *
 * `paintStrip` keeps at most one strip per body. It is rebuilt only when what it says changes (its `signature`), so a
 * repaint never resets a hover or a press on it. Shared material, placement and motion are in packages/ui/styles.css (`.cl-sx-strip`).
 */
import { ICON_X, icon } from "./icons";
/** Creates strip content; DOM allocation occurs only when the signature changes. */
function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls: string, text?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

/** What a window's strip says and does. */
export interface StripView {
  /** Changes when the strip must be rebuilt. */
  signature: string;
  /** Drives the colour and the placement: `ended` and `refused` sit in the middle of the window, the rest at its foot. */
  result: "ok" | "fail" | "ended" | "refused" | "info";
  label: string;
  text: string;
  /** A leading mark: a `ui-mark` kind, or inline SVG markup (`svg`) drawn from the shared icon set. */
  mark?: { kind: "ok" | "fail" | "ended" } | { svg: string };
  action?: { label: string; icon: string; run: () => void };
  dismiss?: { label: string; run: () => void };
}

const button = (cls: string, label: string, paths: string): HTMLButtonElement => {
  const node = el("button", cls);
  node.type = "button";
  node.setAttribute("aria-label", label);
  node.innerHTML = icon(paths);
  return node;
};

/** Shows `view` in `body`'s strip, or removes the strip when `view` is undefined. Returns the strip, if shown. */
export function paintStrip(body: HTMLElement, view: StripView | undefined): HTMLElement | undefined {
  let strip = body.querySelector<HTMLElement>(".cl-sx-strip");
  if (!view) { strip?.remove(); return undefined; }
  if (!strip) {
    strip = el("div", "cl-sx-strip ui-pill");
    strip.setAttribute("role", "group");
    body.append(strip);
  }
  // Rebuilt only when what it says changes, so a refresh never resets a hover or a press on it.
  if (strip.dataset.signature !== view.signature) {
    strip.dataset.signature = view.signature;
    strip.dataset.result = view.result;
    strip.setAttribute("aria-label", view.label);
    const nodes: HTMLElement[] = [];
    const mark = view.mark ?? (view.result === "info" ? undefined : { kind: view.result === "ended" ? "ended" as const : view.result === "ok" ? "ok" as const : "fail" as const });
    if (mark) {
      const node = el("span", "ui-mark");
      if ("kind" in mark) node.dataset.mark = mark.kind;
      else { node.className = "cl-sx-glyph"; node.innerHTML = icon(mark.svg); }
      nodes.push(node);
    }
    nodes.push(el("span", "cl-sx-strip-text", view.text));
    if (view.action) {
      const act = el("button", "cl-sx-again");
      act.type = "button";
      act.innerHTML = `${icon(view.action.icon)}<span>${view.action.label}</span>`;
      act.addEventListener("click", view.action.run);
      nodes.push(act);
    }
    if (view.dismiss) {
      const dismiss = button("cl-sx-dismiss", view.dismiss.label, ICON_X);
      dismiss.dataset.tip = view.dismiss.label;
      dismiss.addEventListener("click", view.dismiss.run);
      nodes.push(dismiss);
    }
    strip.replaceChildren(...nodes);
    // A strip with no button keeps the even padding of its text.
    strip.toggleAttribute("data-bare", !view.action && !view.dismiss);
  }
  return strip;
}
