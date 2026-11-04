/** A dismissed startup notice must never hide the confirmed edit's undo action. */
import { expect, test } from "bun:test";
import { mountToast } from "../../../../../packages/ui/src/toast";
import { withFakeDom } from "../../../../../packages/ui/src/toast-fake-dom";

test("a closing notice cannot hide its replacement", () => {
  withFakeDom((parent, clock) => {
    const toast = mountToast(parent as unknown as HTMLElement);
    const stack = parent.children[0]!;
    toast.show({ message: "tmux started automatically. Would you like to switch to the Infraternal Multiplexer instead?", duration: 0 });
    clock.flushFrames();
    toast.dismiss();
    toast.show({ message: "Switched. tmux no longer starts in Infraternal terminals (changed .zshrc).", action: { label: "Restore .zshrc", onSelect() {} }, duration: 0 });
    // Every pending timer runs, including the old notice's exit. Each toast owns its clock, so only the old card goes.
    clock.runTimers();
    expect(stack.hidden).toBe(false);
    expect(stack.children).toHaveLength(1);
    expect(stack.children[0]!.dataset.open).toBe("false");
    clock.flushFrames();
    expect(stack.children[0]!.dataset.open).toBe("true");
    toast.dispose();
  });
});
