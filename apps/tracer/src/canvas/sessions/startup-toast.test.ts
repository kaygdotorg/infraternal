/** A dismissed startup notice must never hide the confirmed edit's undo action. */
import { expect, test } from "bun:test";
import { mountToast } from "../../../../../packages/ui/src/toast";

class Element {
  children: Element[] = [];
  dataset: Record<string, string> = {};
  style = {};
  classList = { add() {} };
  hidden = false;
  textContent = "";
  innerHTML = "";
  append(...children: Element[]) { this.children.push(...children); }
  querySelector() { return new Element(); }
  setAttribute() {}
  removeAttribute() {}
  addEventListener() {}
  removeEventListener() {}
  remove() {}
}

test("a closing notice cannot hide its replacement before the next animation frame", () => {
  const timers = new Map<number, () => void>();
  const frames: FrameRequestCallback[] = [];
  let serial = 0;
  const overrides = {
    document: { createElement: () => new Element() },
    window: {
      setTimeout: (callback: () => void) => { timers.set(++serial, callback); return serial; },
      clearTimeout: (id: number) => timers.delete(id),
    },
    requestAnimationFrame: (callback: FrameRequestCallback) => frames.push(callback),
  };
  const saved = Object.keys(overrides).map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)] as const);
  for (const [key, value] of Object.entries(overrides)) Object.defineProperty(globalThis, key, { configurable: true, value });
  try {
    const parent = new Element();
    const toast = mountToast(parent as unknown as HTMLElement);
    const host = parent.children[0]!;
    toast.show({ message: "tmux started from .zshrc.", duration: 0 });
    frames.splice(0).forEach((frame) => frame(0));
    toast.dismiss();
    toast.show({ message: "Guard added to .zshrc.", action: { label: "Remove guard", onSelect() {} }, duration: 0 });
    // A busy renderer may not deliver the replacement's opening frame before
    // the previous notice finishes closing. That timer belongs to the old message.
    [...timers.values()].forEach((callback) => callback());
    expect(host.hidden).toBe(false);
    frames.splice(0).forEach((frame) => frame(16));
    expect(host.dataset.open).toBe("true");
    toast.dispose();
  } finally {
    for (const [key, descriptor] of saved) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else Reflect.deleteProperty(globalThis, key);
    }
  }
});
