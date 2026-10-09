/** Tiny DOM helpers shared by the canvas modules. */
export const SVG_NS = "http://www.w3.org/2000/svg";

/** Creates an element with a class and optional text (text is always set as text, never as markup). */
export const el = <K extends keyof HTMLElementTagNameMap>(tag: K, cls = "", text?: string): HTMLElementTagNameMap[K] => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
};

export const coarse = matchMedia("(pointer: coarse)");
export const reduced = matchMedia("(prefers-reduced-motion: reduce)");
