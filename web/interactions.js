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

// Bounce only after activation, never after background refresh recreates a
// selected button. Resolve controls after the app's synchronous render.
(() => {
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  const selector = ".chart-switch button, .range-control button";
  let pending = 0;
  const shellAnimations = new Map();
  // The whole island responds, including its padding and noninteractive
  // statistic pills. WAAPI restarts without a forced synchronous layout read.
  // Calternal uses a restrained grouped-shell pulse and a stronger single-pill
  // pulse. Keep those envelopes distinct so nested controls don't over-expand.
  function pulseShell(shell) {
    shellAnimations.get(shell)?.cancel();
    const grouped = shell.matches(".chart-switch, .range-control");
    const animation = shell.animate([
      { transform: "scale(1)", offset: 0 },
      { transform: grouped ? "scale(1.04)" : "scale(1.1)", offset: grouped ? .34 : .32 },
      { transform: grouped ? "scale(.99)" : "scale(.97)", offset: grouped ? .64 : .62 },
      { transform: "scale(1)", offset: 1 },
    ], { duration: 420, easing: "cubic-bezier(.34,1.56,.64,1)" });
    shellAnimations.set(shell, animation);
    const release = () => {
      if (shellAnimations.get(shell) === animation) shellAnimations.delete(shell);
    };
    animation.onfinish = release;
    animation.oncancel = release;
  }
  function clear() {
    cancelAnimationFrame(pending);
    document.querySelectorAll(".pill-settling").forEach((item) => item.classList.remove("pill-settling"));
  }
  reduced.addEventListener("change", () => {
    clear();
    for (const animation of shellAnimations.values()) animation.cancel();
    shellAnimations.clear();
  });
  document.addEventListener("animationend", (event) => {
    if (event.animationName === "pill-selection-spring") event.target.classList.remove("pill-settling");
  });
  document.addEventListener("click", (event) => {
    const shell = event.target.closest(".surface-pill");
    if (!shell || event.target.closest(":disabled, [aria-disabled='true']")) return;
    if (!reduced.matches) pulseShell(shell);
    const button = event.target.closest(selector);
    if (!button) return;
    clear();
    if (reduced.matches) return;
    const mode = button.dataset.chartMode;
    const hours = button.dataset.hours;
    pending = requestAnimationFrame(() => {
      if (reduced.matches) return;
      document.querySelectorAll(selector).forEach((item) => {
        if (!item.getClientRects().length || item.getAttribute("aria-pressed") !== "true") return;
        if (mode ? item.dataset.chartMode !== mode : item.dataset.hours !== hours) return;
        item.classList.add("pill-settling");
      });
    });
  }, true);
})();
