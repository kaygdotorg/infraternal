/** Keeps terminal input focus during toolbar presses without suppressing touch activation (D129, D160). */
export function bindInputToolbar(element: HTMLElement, press: (event: PointerEvent) => void): () => void {
  // Cancel the compatibility mouse focus change, not pointerdown: WebKit cancels a
  // touch's eventual click when pointerdown is cancelled. Native touch scrolling and
  // pointer cancellation continue to arbitrate taps versus drags.
  const mouseDown = (event: MouseEvent): void => { event.preventDefault(); };
  element.addEventListener("mousedown", mouseDown);
  element.addEventListener("pointerdown", press);
  return () => {
    element.removeEventListener("mousedown", mouseDown);
    element.removeEventListener("pointerdown", press);
  };
}
