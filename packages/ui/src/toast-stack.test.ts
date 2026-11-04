/** The toast stack (D336): order, the cap, errors that stay, counts, held clocks and the touch swipe. */
import { expect, test } from "bun:test";
import { hiddenByCap, mountToast } from "./toast";
import { withFakeDom, type FakeElement } from "./toast-fake-dom";

const mount = (parent: FakeElement) => mountToast(parent as unknown as HTMLElement);
const hiddenFlags = (stack: FakeElement) => stack.children.map((card) => card.dataset.hidden);
const depth = (card: FakeElement) => card.props.get("--i");

test("hiddenByCap drops the oldest non-errors and never an error for a newer non-error", () => {
  expect(hiddenByCap([false, false, false])).toEqual([false, false, false]);
  expect(hiddenByCap([false, false, false, false, false])).toEqual([true, true, false, false, false]);
  // An old error survives a flood of notices.
  expect(hiddenByCap([true, false, false, false, false])).toEqual([false, true, true, false, false]);
  // Three errors and a notice: the notice shows beside them, so the stack exceeds the cap rather than hide an error.
  expect(hiddenByCap([true, true, true, false])).toEqual([false, false, false, false]);
  // A newer error pushes out the oldest error only when nothing else can go.
  expect(hiddenByCap([true, true, true, true])).toEqual([true, false, false, false]);
});

test("the newest toast is in front, older ones are behind it, and only three are drawn", () => {
  withFakeDom((parent) => {
    const toast = mount(parent);
    for (const n of [1, 2, 3, 4]) toast.show({ message: `message ${n}`, duration: 0 });
    const stack = parent.children[0]!;
    expect(stack.children.map((card) => depth(card))).toEqual(["2", "2", "1", "0"]);
    expect(hiddenFlags(stack)).toEqual(["true", "false", "false", "false"]);
    expect(stack.children.map((card) => card.dataset.front)).toEqual(["false", "false", "false", "true"]);
    toast.dispose();
  });
});

test("an error is never removed or hidden by later info toasts", () => {
  withFakeDom((parent) => {
    const toast = mount(parent);
    const error = toast.show({ message: "can't open a shell", tone: "error", duration: 0 });
    for (const n of [1, 2, 3, 4, 5]) toast.show({ message: `info ${n}`, duration: 0 });
    const stack = parent.children[0]!;
    expect(stack.children[0]!.dataset.hidden).toBe("false");
    expect(stack.children.filter((card) => card.dataset.hidden === "false")).toHaveLength(3);
    // A bare dismiss clears notices but spares the error; only its own id (or Dismiss) removes it.
    toast.dismiss();
    expect(stack.children.filter((card) => card.dataset.open !== "false")).toHaveLength(1);
    expect(stack.children[0]!.dataset.tone).toBe("error");
    toast.dismiss(error);
    expect(stack.children.filter((card) => card.dataset.open !== "false")).toHaveLength(0);
    toast.dispose();
  });
});

test("a first-load error stays beside the unlock prompt that arrives after it", () => {
  withFakeDom((parent, clock) => {
    const toast = mount(parent);
    toast.show({ message: "This server runs without root, so it can only open shells as its own user. Add a host to work elsewhere.", tone: "error", duration: 0 });
    toast.show({ message: "Unlock host connections", duration: 0, action: { label: "Unlock", onSelect() {} } });
    clock.flushFrames();
    const stack = parent.children[0]!;
    expect(stack.children).toHaveLength(2);
    expect(stack.children.map((card) => card.dataset.open)).toEqual(["true", "true"]);
    expect(hiddenFlags(stack)).toEqual(["false", "false"]);
    toast.dispose();
  });
});

test("repeats update one toast with a count, and a changed message morphs it in place", () => {
  withFakeDom((parent) => {
    const toast = mount(parent);
    const closed: string[] = [];
    const first = toast.show({ message: "Message sent", duration: 0, key: "send", onClose: () => closed.push("first") });
    for (let n = 0; n < 11; n++) toast.show({ message: "Message sent", duration: 0, key: "send" });
    const stack = parent.children[0]!;
    expect(stack.children).toHaveLength(1);
    const label = stack.children[0]!.children.find((child) => child.className === "ui-toast-message")!;
    expect(label.textContent).toBe("Message sent");
    expect(label.children[0]!.textContent).toBe(" ×12");
    // Undo turns the same toast into its result; the count starts over and the earlier close hook ran once.
    const second = toast.show({ message: "Unsent", duration: 0, key: "send" });
    expect(stack.children).toHaveLength(1);
    expect(label.textContent).toBe("Unsent");
    expect(label.children).toHaveLength(0);
    expect(second).toBe(first);
    expect(closed).toEqual(["first"]);
    // Same words with another tone are another toast.
    toast.show({ message: "Unsent", tone: "error", duration: 0 });
    expect(stack.children).toHaveLength(2);
    toast.dispose();
  });
});

test("every toast has its own clock, and holding the stack stops all of them", () => {
  withFakeDom((parent, clock) => {
    const toast = mount(parent);
    toast.show({ message: "one", duration: 1000 });
    toast.show({ message: "two", duration: 2000 });
    toast.show({ message: "kept", duration: 0 });
    expect(clock.timers.size).toBe(2);
    const stack = parent.children[0]!;
    stack.fire("pointerover", { pointerType: "mouse" });
    expect(stack.dataset.expanded).toBe("true");
    expect(clock.timers.size).toBe(0);
    // A toast that arrives while the pointer rests on the stack waits as well.
    toast.show({ message: "late", duration: 1000 });
    expect(clock.timers.size).toBe(0);
    // Leaving collapses after a short delay (the pointer may be crossing to a neighbour), then clocks resume.
    stack.fire("pointerleave", { pointerType: "mouse" });
    expect(stack.dataset.expanded).toBe("true");
    clock.runTimers();
    expect(stack.dataset.expanded).toBe("false");
    expect(clock.timers.size).toBe(3);
    toast.dispose();
  });
});

test("a touch swipe down dismisses a toast, a short drag springs back, and a resting finger holds the clocks", () => {
  withFakeDom((parent, clock) => {
    const toast = mount(parent);
    toast.show({ message: "swipe me", duration: 3000 });
    toast.show({ message: "stay", duration: 3000 });
    clock.flushFrames();
    const stack = parent.children[0]!;
    const [first, second] = stack.children as [FakeElement, FakeElement];
    first.fire("pointerdown", { pointerType: "touch", clientY: 100, pointerId: 1 });
    expect(stack.dataset.expanded).toBe("true");
    expect(clock.timers.size).toBe(0);
    first.fire("pointermove", { pointerType: "touch", clientY: 120 });
    expect(first.props.get("--sw")).toBe("20px");
    first.fire("pointerup", { pointerType: "touch", clientY: 120 });
    expect(first.dataset.open).not.toBe("false");
    expect(first.props.has("--sw")).toBe(false);
    first.fire("pointerdown", { pointerType: "touch", clientY: 100, pointerId: 1 });
    first.fire("pointermove", { pointerType: "touch", clientY: 180 });
    first.fire("pointerup", { pointerType: "touch", clientY: 180 });
    expect(first.dataset.open).toBe("false");
    expect(second.dataset.open).toBe("true");
    expect(stack.dataset.expanded).toBe("false");
    toast.dispose();
  });
});

test("the dismiss control and an action each close only their own toast", () => {
  withFakeDom((parent) => {
    const toast = mount(parent);
    const ran: string[] = [];
    toast.show({ message: "a", duration: 0, dismissible: true, action: { label: "Go", onSelect: () => ran.push("go") } });
    toast.show({ message: "b", duration: 0, dismissible: true });
    const [a, b] = parent.children[0]!.children as [FakeElement, FakeElement];
    b.children.find((child) => child.className.includes("ui-toast-close"))!.click();
    expect(b.dataset.open).toBe("false");
    expect(a.dataset.open).not.toBe("false");
    a.children.find((child) => child.className === "ui-toast-actions")!.children[0]!.click();
    expect(ran).toEqual(["go"]);
    expect(a.dataset.open).toBe("false");
    toast.dispose();
  });
});
