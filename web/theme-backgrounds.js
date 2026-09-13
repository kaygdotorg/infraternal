"use strict";
(() => {
  const root = document.documentElement;
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const backdrop = document.createElement("div");
  backdrop.className = "theme-background";
  backdrop.setAttribute("aria-hidden", "true");
  backdrop.dataset.state = "ready";

  function setMotionClass() {
    backdrop.dataset.motion = reducedMotion.matches ? "reduced" : "full";
  }

  function start() {
    if (!document.body || backdrop.parentNode) return;
    document.body.prepend(backdrop);
    setMotionClass();
    new MutationObserver(setMotionClass).observe(root, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });
    if (typeof reducedMotion.addEventListener === "function") {
      reducedMotion.addEventListener("change", setMotionClass);
    } else if (typeof reducedMotion.addListener === "function") {
      reducedMotion.addListener(setMotionClass);
    }
  }

  if (document.body) start();
  else document.addEventListener("DOMContentLoaded", start, { once: true });
})();
