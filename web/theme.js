"use strict";
(() => {
  const choices = window.STATUS_THEMES,
    system = matchMedia("(prefers-color-scheme: dark)");
  let palette = "codex",
    mode = system.matches ? "dark" : "light";
  try {
    const old = localStorage.getItem("status-theme") || "";
    palette =
      localStorage.getItem("status-palette") ||
      {
        light: "codex",
        dark: "codex",
        system: "codex",
        "solarized-light": "solarized",
        "solarized-dark": "solarized",
      }[old] ||
      old ||
      "codex";
    mode =
      localStorage.getItem("status-mode") ||
      (old.includes("light")
        ? "light"
        : old && old !== "system"
          ? "dark"
          : mode);
  } catch {}
  if (!choices.some(([k]) => k === palette)) palette = "codex";
  if (!["dark", "light"].includes(mode)) mode = "dark";
  function syncThemeColor() {
    // Keep theme-color in sync for browsers that support it. Newer Safari
    // versions may derive chrome tint from the page background instead; those
    // roots are painted in safe-areas.css. No image sampling is necessary.
    const color =
      getComputedStyle(document.documentElement)
        .getPropertyValue("--bg")
        .trim() ||
      // CSS loads after this script; use the default Codex token until the
      // active palette's computed token is available at DOMContentLoaded.
      (mode === "light" ? "#ffffff" : "#171717");
    const metas = document.querySelectorAll('meta[name="theme-color"]');
    if (metas.length) {
      metas.forEach((meta) => meta.setAttribute("content", color));
      return;
    }
    if (!document.head) return;
    const meta = document.createElement("meta");
    meta.name = "theme-color";
    meta.content = color;
    document.head.append(meta);
  }
  const sun =
      '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/></svg>',
    moon =
      '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 15.5A9 9 0 0 1 8.5 4 9 9 0 1 0 20 15.5Z"/></svg>';
  function apply() {
    document.documentElement.dataset.theme = palette + "-" + mode;
    syncThemeColor();
    const button = document.getElementById("theme-toggle");
    if (!button) return;
    button.setAttribute("aria-label", "Choose theme");
    button.title = "Choose theme";
    document.getElementById("theme-icon").innerHTML =
      '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8"/><path d="M12 4v16M4 12h16"/></svg>';
    const toggle = document.getElementById("mode-toggle");
    toggle.innerHTML = mode === "dark" ? moon : sun;
    toggle.setAttribute(
      "aria-label",
      "Switch to " + (mode === "dark" ? "light" : "dark") + " mode",
    );
    toggle.title = toggle.getAttribute("aria-label");
    document
      .querySelectorAll("[data-theme-choice]")
      .forEach((b) =>
        b.setAttribute(
          "aria-pressed",
          String(b.dataset.themeChoice === palette),
        ),
      );
  }
  function save() {
    try {
      localStorage.setItem("status-palette", palette);
      localStorage.setItem("status-mode", mode);
    } catch {}
    apply();
  }
  apply();
  document.addEventListener("DOMContentLoaded", () => {
    const button = document.getElementById("theme-toggle"),
      menu = document.getElementById("theme-menu");
    menu.innerHTML = choices
      .map(
        ([key, label]) =>
          `<button type="button" data-theme-choice="${key}" aria-pressed="false">${label}</button>`,
      )
      .join("");
    function close() {
      menu.hidden = true;
      button.setAttribute("aria-expanded", "false");
    }
    close();
    apply();
    menu.addEventListener("keydown", (e) => {
      if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) return;
      e.preventDefault();
      const items = Array.from(menu.querySelectorAll("button")),
        i = items.indexOf(document.activeElement),
        next =
          e.key === "Home"
            ? 0
            : e.key === "End"
              ? items.length - 1
              : (i + (e.key === "ArrowDown" ? 1 : -1) + items.length) %
                items.length;
      items[next].focus();
    });
    button.setAttribute("aria-controls", "theme-menu");
    button.addEventListener("click", () => {
      menu.hidden = !menu.hidden;
      button.setAttribute("aria-expanded", String(!menu.hidden));
      if (!menu.hidden) menu.querySelector("[aria-pressed=true]").focus();
    });
    document.getElementById("mode-toggle").addEventListener("click", () => {
      mode = mode === "dark" ? "light" : "dark";
      save();
    });
    menu.addEventListener("click", (e) => {
      const item = e.target.closest("[data-theme-choice]");
      if (!item) return;
      palette = item.dataset.themeChoice;
      save();
      close();
      button.focus();
    });
    document.addEventListener("pointerdown", (e) => {
      if (!e.target.closest(".theme-picker")) close();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !menu.hidden) {
        close();
        button.focus();
      }
    });
  });
})();
