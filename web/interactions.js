"use strict";
// Subtle magnetic defaults, adapted to delegated DOM events.
(() => {
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  const fine = matchMedia("(hover: hover) and (pointer: fine)");
  const selector = ".chart-switch button, .range-control button";
  let active = null,
    frame = 0;
  function reset() {
    cancelAnimationFrame(frame);
    if (active) {
      active.style.transition = reduced.matches
        ? "none"
        : "translate .42s cubic-bezier(.2,1.35,.3,1)";
      active.style.translate = "";
      active = null;
    }
  }
  function clearHover(group) {
    const capsule = group?.querySelector(".hover-capsule");
    if (capsule) capsule.classList.remove("visible");
  }
  document.addEventListener("pointermove", (event) => {
    if (event.pointerType === "touch" || reduced.matches || !fine.matches)
      return;
    const button = event.target.closest(selector);
    if (!button) return;
    if (active && active !== button) reset();
    active = button;
    const box = button.getBoundingClientRect();
    const clamp = (value) => Math.max(-7, Math.min(7, value));
    const x = clamp((event.clientX - box.left - box.width / 2) * 0.18 * 1.2);
    const y = clamp((event.clientY - box.top - box.height / 2) * 0.18 * 1.2);
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(() => {
      button.style.transition = "none";
      button.style.translate = `${x}px ${y}px`;
    });
    const group = button.parentElement;
    let capsule = group.querySelector(".hover-capsule");
    if (!capsule) {
      capsule = document.createElement("span");
      capsule.className = "hover-capsule";
      capsule.setAttribute("aria-hidden", "true");
      group.prepend(capsule);
    }
    if (button.getAttribute("aria-pressed") === "true") {
      capsule.classList.remove("visible");
      return;
    }
    capsule.style.width = `${button.offsetWidth}px`;
    capsule.style.translate = `${button.offsetLeft}px 0`;
    capsule.classList.add("visible");
  });
  document.addEventListener("pointerout", (event) => {
    const group = event.target.closest(".chart-switch,.range-control");
    if (active && !active.contains(event.relatedTarget)) reset();
    if (group && !group.contains(event.relatedTarget)) clearHover(group);
  });
  document.addEventListener("pointercancel", () => {
    reset();
    document
      .querySelectorAll(".hover-capsule")
      .forEach((c) => c.classList.remove("visible"));
  });
  document.addEventListener(
    "keydown",
    () => {
      reset();
      document
        .querySelectorAll(".hover-capsule")
        .forEach((c) => c.classList.remove("visible"));
    },
    true,
  );
  reduced.addEventListener("change", () => {
    reset();
    document
      .querySelectorAll(".hover-capsule")
      .forEach((c) => c.classList.remove("visible"));
  });
})();
// Start each newly rendered range strip at 24h without changing its selection.
(() => {
  const initialized = new WeakSet(),
    visible = new WeakSet();
  function prepare() {
    document.querySelectorAll(".range-control").forEach((strip) => {
      if (!initialized.has(strip)) {
        initialized.add(strip);
        strip.addEventListener(
          "wheel",
          (event) => {
            if (
              event.ctrlKey ||
              Math.abs(event.deltaX) >= Math.abs(event.deltaY)
            )
              return;
            const before = strip.scrollLeft;
            strip.scrollLeft += event.deltaY;
            if (strip.scrollLeft !== before) event.preventDefault();
          },
          { passive: false },
        );
      }
      if (!strip.getClientRects().length) {
        visible.delete(strip);
        return;
      }
      if (visible.has(strip)) return;
      visible.add(strip);
      requestAnimationFrame(() => {
        const first = strip.querySelector('[data-hours="24"]');
        if (first) strip.scrollLeft = first.offsetLeft - 3;
        const selected = strip.querySelector('[aria-pressed="true"]');
        if (
          selected &&
          (Number(selected.dataset.hours) < 24 ||
            Number(selected.dataset.hours) > 720)
        )
          strip.scrollLeft = selected.offsetLeft - 3;
      });
    });
  }
  prepare();
  new MutationObserver(prepare).observe(document.querySelector(".shell"), {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["hidden"],
  });
})();
