/** Icon choices on the shared toast: each is named, answers once, and help keeps the question open. */
import { expect, test } from "bun:test";
import { mountToast } from "./toast";
import { withFakeDom } from "./toast-fake-dom";

test("icon choices carry a tooltip and an accessible name, run once, and help keeps the notice open", () => {
  withFakeDom((parent, clock) => {
    const toast = mountToast(parent as unknown as HTMLElement);
    const ran: string[] = [];
    toast.show({ message: "Question?", duration: 0, iconActions: [
      { label: "Yes", icon: "<path/>", onSelect: () => { ran.push("yes"); } },
      { label: "No", icon: "<path/>", onSelect: () => { ran.push("no"); } },
      { label: "About", icon: "<path/>", keepOpen: true, onSelect: () => { ran.push("about"); } },
    ] });
    clock.flushFrames();
    const card = parent.children[0]!.children[0]!;
    const icons = card.children.find((child) => child.className === "ui-toast-icons")!;
    expect(icons.hidden).toBe(false);
    expect(icons.children.map((button) => button.attributes.get("aria-label"))).toEqual(["Yes", "No", "About"]);
    expect(icons.children.map((button) => button.dataset.tip)).toEqual(["Yes", "No", "About"]);
    expect(card.dataset.choices).toBe("true");
    icons.children[2]!.click();
    expect(ran).toEqual(["about"]);
    expect(card.dataset.open).not.toBe("false");
    icons.children[0]!.click();
    icons.children[0]!.click();
    expect(ran).toEqual(["about", "yes"]);
    expect(card.dataset.open).toBe("false");
    toast.dispose();
  });
});

test("a message without choices hides the group", () => {
  withFakeDom((parent) => {
    const toast = mountToast(parent as unknown as HTMLElement);
    toast.show({ message: "One", iconActions: [{ label: "Yes", icon: "<path/>", onSelect() {} }] });
    toast.show({ message: "Two" });
    // Two different messages are two toasts; the second has no choices.
    const cards = parent.children[0]!.children;
    expect(cards).toHaveLength(2);
    const icons = cards[1]!.children.find((child) => child.className === "ui-toast-icons")!;
    expect(icons.hidden).toBe(true);
    expect(icons.children).toHaveLength(0);
    expect(cards[1]!.dataset.choices).toBe("false");
    toast.dispose();
  });
});
