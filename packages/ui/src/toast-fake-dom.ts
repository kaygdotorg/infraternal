/**
 * A tiny DOM double for the toast unit tests: just what `mountToast` touches (children, dataset, listeners with
 * bubbling, style custom properties) and fake timers and frames, so stack order, the cap, holds and swipes are
 * tested without a browser. Browser behaviour (layout, transitions) is covered by the Playwright specs.
 */
type Listener = (event: any) => void;

export class FakeElement {
  tag: string;
  parent: FakeElement | undefined;
  children: FakeElement[] = [];
  dataset: Record<string, string> = {};
  attributes = new Map<string, string>();
  listeners = new Map<string, Listener[]>();
  props = new Map<string, string>();
  style = {
    setProperty: (name: string, value: string) => { this.props.set(name, value); },
    removeProperty: (name: string) => { this.props.delete(name); },
  } as Record<string, unknown>;
  classList = { add() {}, contains: (name: string) => this.className.split(" ").includes(name) };
  hidden = false;
  #text = "";
  /** Own text only (not descendants'), and assigning it drops the children, as in a browser. */
  get textContent(): string { return this.#text; }
  set textContent(value: string) { this.#text = value; this.children = []; }
  innerHTML = "";
  className = "";
  type = "";
  offsetHeight = 40;
  constructor(tag = "div") { this.tag = tag; }
  append(...children: FakeElement[]) { for (const child of children) { child.parent = this; this.children.push(child); } }
  replaceChildren(...children: FakeElement[]) { this.children = []; this.append(...children); }
  querySelector() { return new FakeElement(); }
  querySelectorAll() { return this.children; }
  setAttribute(name: string, value: string) { this.attributes.set(name, value); }
  removeAttribute(name: string) { this.attributes.delete(name); delete this.dataset[name.replace(/^data-/, "")]; }
  addEventListener(name: string, listener: Listener) { this.listeners.set(name, [...(this.listeners.get(name) ?? []), listener]); }
  removeEventListener() {}
  focus() {}
  setPointerCapture() {}
  contains(node: FakeElement | null): boolean { return node === this || this.children.some((child) => child.contains(node)); }
  matches() { return false; }
  closest(selector: string): FakeElement | null {
    const hit = selector === "[data-index]" ? this.dataset.index !== undefined : selector === "button,a" ? this.tag === "button" || this.tag === "a" : false;
    return hit ? this : this.parent?.closest(selector) ?? null;
  }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter((child) => child !== this); this.parent = undefined; }
  /** Dispatches an event on this element, then bubbles it to its ancestors. */
  fire(name: string, event: Record<string, unknown> = {}): void {
    const full = { target: this, ...event };
    for (let node: FakeElement | undefined = this; node; node = node.parent) for (const run of node.listeners.get(name) ?? []) run({ ...full, currentTarget: node });
  }
  click() { this.fire("click"); }
}

export interface FakeClock {
  /** Pending timers by id; `run()` fires and clears all of them, `fire(id)` one. */
  timers: Map<number, () => void>;
  frames: FrameRequestCallback[];
  flushFrames(): void;
  runTimers(): void;
}

/** Installs the globals `mountToast` needs, runs `body`, and restores them even when it throws. */
export function withFakeDom(body: (parent: FakeElement, clock: FakeClock) => void): void {
  const timers = new Map<number, () => void>();
  const frames: FrameRequestCallback[] = [];
  let serial = 0;
  const clock: FakeClock = {
    timers, frames,
    flushFrames() { frames.splice(0).forEach((frame) => frame(0)); },
    runTimers() { const due = [...timers.values()]; timers.clear(); due.forEach((run) => run()); },
  };
  const overrides = {
    document: { createElement: (tag: string) => new FakeElement(tag) },
    window: { setTimeout: (run: () => void) => { timers.set(++serial, run); return serial; }, clearTimeout: (id: number) => { timers.delete(id); } },
    requestAnimationFrame: (callback: FrameRequestCallback) => frames.push(callback),
    cancelAnimationFrame() {},
  };
  const saved = Object.keys(overrides).map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)] as const);
  for (const [key, value] of Object.entries(overrides)) Object.defineProperty(globalThis, key, { configurable: true, value });
  try { body(new FakeElement(), clock); } finally {
    for (const [key, descriptor] of saved) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor); else Reflect.deleteProperty(globalThis, key);
    }
  }
}
