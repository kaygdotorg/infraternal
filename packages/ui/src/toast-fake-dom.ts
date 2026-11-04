/**
 * A tiny DOM double for the toast unit tests: just what `mountToast` touches (children, dataset, listeners with
 * bubbling, style custom properties) and fake timers and frames, so stack order, the cap, holds and swipes are
 * tested without a browser. Browser behaviour (layout, transitions) is covered by the Playwright specs.
 */
type Listener = (event: any) => void;

/** A stand-in for a DOM element with only what the toast code touches. Events bubble through `fire`. */
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
  /** Setting the text drops the children, as in a browser. */
  set textContent(value: string) { this.#text = value; this.children = []; }
  innerHTML = "";
  className = "";
  type = "";
  offsetHeight = 40;
  /** Creates an element with the given tag name. */
  constructor(tag = "div") { this.tag = tag; }
  /** Adds children at the end and sets their parent. */
  append(...children: FakeElement[]) { for (const child of children) { child.parent = this; this.children.push(child); } }
  /** Replaces all children with the given ones. */
  replaceChildren(...children: FakeElement[]) { this.children = []; this.append(...children); }
  /** Returns a fresh empty element: the toast code only needs something to hold. */
  querySelector() { return new FakeElement(); }
  /** Returns the direct children, which is all the tests ask for. */
  querySelectorAll() { return this.children; }
  /** Stores an attribute. */
  setAttribute(name: string, value: string) { this.attributes.set(name, value); }
  /** Removes an attribute and the `data-` entry that mirrors it. */
  removeAttribute(name: string) { this.attributes.delete(name); delete this.dataset[name.replace(/^data-/, "")]; }
  /** Registers a listener for `fire` to call. */
  addEventListener(name: string, listener: Listener) { this.listeners.set(name, [...(this.listeners.get(name) ?? []), listener]); }
  /** Does nothing: the tests never rely on a listener being removed. */
  removeEventListener() {}
  /** Does nothing: focus is not simulated. */
  focus() {}
  /** Does nothing: pointer capture is not simulated. */
  setPointerCapture() {}
  /** Whether `node` is this element or one of its descendants. */
  contains(node: FakeElement | null): boolean { return node === this || this.children.some((child) => child.contains(node)); }
  /** Always false: no selector in the toast code needs to match a fake. */
  matches() { return false; }
  /** Walks up to the nearest ancestor (or self) that fits one of the two selectors the toast code uses. */
  closest(selector: string): FakeElement | null {
    const hit = selector === "[data-index]" ? this.dataset.index !== undefined : selector === "button,a" ? this.tag === "button" || this.tag === "a" : false;
    return hit ? this : this.parent?.closest(selector) ?? null;
  }
  /** Detaches the element from its parent. */
  remove() { if (this.parent) this.parent.children = this.parent.children.filter((child) => child !== this); this.parent = undefined; }
  /** Dispatches an event on this element, then bubbles it to its ancestors. */
  fire(name: string, event: Record<string, unknown> = {}): void {
    const full = { target: this, type: name, ...event };
    for (let node: FakeElement | undefined = this; node; node = node.parent) for (const run of node.listeners.get(name) ?? []) run({ ...full, currentTarget: node });
  }
  /** Fires a `click` event. */
  click() { this.fire("click"); }
}

/** The fake timers and animation frames a test steps by hand. */
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
