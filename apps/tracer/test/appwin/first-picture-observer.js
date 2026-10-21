/** Role: latch per-stream open and first live-picture times on one page clock, without a polling timer (#146). */
(() => {
  const opens = [];
  const pictures = new Map();
  const observe = () => {
    document.querySelectorAll('.ui-window[data-kind="app"]').forEach((card, index) => {
      if (opens[index] === undefined || pictures.has(index) || !card.querySelector('.aw-stage[data-picture="live"]')) return;
      const first = performance.now();
      pictures.set(index, { fixture_index: index + 1, window_id: card.dataset.windowId,
        open_ms: opens[index], first_picture_ms: first, elapsed_ms: first - opens[index] });
    });
  };
  const observer = new MutationObserver(observe);
  observer.observe(document.documentElement, { subtree: true, childList: true, attributes: true, attributeFilter: ["data-picture"] });
  window.__firstPictures = {
    open(index) {
      if (!Number.isInteger(index) || index < 0 || index >= 10 || opens[index] !== undefined) throw Error("invalid first-picture open index");
      opens[index] = performance.now();
    },
    rows: () => {
      const cards = document.querySelectorAll('.ui-window[data-kind="app"]');
      return opens.flatMap((open, index) => [pictures.get(index) ?? {
        fixture_index: index + 1, window_id: cards[index]?.dataset.windowId ?? null,
        open_ms: open, first_picture_ms: null, elapsed_ms: null,
      }]);
    },
    stop: () => observer.disconnect(),
  };
})();
