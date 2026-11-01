/** Icon choices on the shared toast: each is named, answers once, and help keeps the question open. */
import { expect, test } from "bun:test";
import { mountToast } from "./toast";

class Element {
  children: Element[] = [];
  dataset: Record<string, string> = {};
  attributes = new Map<string, string>();
  listeners = new Map<string, (event: unknown) => void>();
  style = {};
  classList = { add() {} };
  hidden = false;
  textContent = "";
  innerHTML = "";
  className = "";
  type = "";
  append(...children: Element[]) { this.children.push(...children); }
  replaceChildren(...children: Element[]) { this.children = children; }
  querySelector() { return new Element(); }
  querySelectorAll() { return this.children; }
  setAttribute(name: string, value: string) { this.attributes.set(name, value); }
  removeAttribute(name: string) { this.attributes.delete(name); }
  addEventListener(name: string, listener: (event: unknown) => void) { this.listeners.set(name, listener); }
  removeEventListener() {}
  focus() {}
  remove() {}
  click() { this.listeners.get("click")?.({ currentTarget: this }); }
}

function withDom(run: (parent: Element) => void): void {
  const overrides = {
    document: { createElement: () => new Element() },
    window: { setTimeout: () => 1, clearTimeout() {} },
    requestAnimationFrame: (callback: FrameRequestCallback) => { callback(0); return 0; },
  };
  const saved = Object.keys(overrides).map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)] as const);
  for (const [key, value] of Object.entries(overrides)) Object.defineProperty(globalThis, key, { configurable: true, value });
  try { run(new Element()); } finally {
    for (const [key, descriptor] of saved) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor); else Reflect.deleteProperty(globalThis, key);
    }
  }
}

test("icon choices carry a tooltip and an accessible name, run once, and help keeps the notice open", () => {
  withDom((parent) => {
    const toast = mountToast(parent as unknown as HTMLElement);
    const host = parent.children[0]!;
    const ran: string[] = [];
    toast.show({ message: "Question?", duration: 0, iconActions: [
      { label: "Yes", icon: "<path/>", onSelect: () => { ran.push("yes"); } },
      { label: "No", icon: "<path/>", onSelect: () => { ran.push("no"); } },
      { label: "About", icon: "<path/>", keepOpen: true, onSelect: () => { ran.push("about"); } },
    ] });
    const icons = host.children.find((child) => child.className === "ui-toast-icons")!;
    expect(icons.hidden).toBe(false);
    expect(icons.children.map((button) => button.attributes.get("aria-label"))).toEqual(["Yes", "No", "About"]);
    expect(icons.children.map((button) => button.dataset.tip)).toEqual(["Yes", "No", "About"]);
    expect(host.dataset.choices).toBe("true");
    icons.children[2]!.click();
    expect(ran).toEqual(["about"]);
    expect(host.dataset.open).not.toBe("false");
    icons.children[0]!.click();
    icons.children[0]!.click();
    expect(ran).toEqual(["about", "yes"]);
    expect(host.dataset.open).toBe("false");
    toast.dispose();
  });
});

test("a message without choices hides the group", () => {
  withDom((parent) => {
    const toast = mountToast(parent as unknown as HTMLElement);
    const host = parent.children[0]!;
    toast.show({ message: "One", iconActions: [{ label: "Yes", icon: "<path/>", onSelect() {} }] });
    toast.show({ message: "Two" });
    const icons = host.children.find((child) => child.className === "ui-toast-icons")!;
    expect(icons.hidden).toBe(true);
    expect(icons.children).toHaveLength(0);
    expect(host.dataset.choices).toBe("false");
    toast.dispose();
  });
});
