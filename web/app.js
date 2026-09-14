"use strict";
import { TextMorph } from "./torph.js";
import { renderChart } from "./bklit-charts.js";

// The server-generated browser config contains display metadata only. The
// browser never receives a datasource URL, metric selector, or credential.
const CONFIG_ENDPOINT = "/config.json";
const DEFAULT_RANGES = [
  [0.25, "15m", "15 minutes"],
  [1, "1h", "1 hour"],
  [6, "6h", "6 hours"],
  [24, "24h", "24 hours"],
  [168, "7d", "7 days"],
  [720, "30d", "30 days"],
  [2160, "3mo", "3 months"],
  [4320, "6mo", "6 months"],
  [8760, "1y", "1 year"],
];
const MAX_CONFIG_SERVICES = 80;
const MAX_CONFIG_GROUPS = 100;
const MAX_RESULTS = 10000;
const MAX_DURATION_NS = 7 * 24 * 60 * 60 * 1e9;
let GROUPS = [];
let API = "/api/v1/status";
let CONFIG = null;
let globalChartMode = "area";
function plotStart(rows) {
  return Math.max(
    Date.now() - hours * 3600000,
    rows.length ? rows[0].time - 30000 : 0,
  );
}
let RANGES = DEFAULT_RANGES;
const periodLabel = () => RANGES.find((r) => r[0] === hours)[2];
const rangeKey = () => RANGES.find((r) => r[0] === hours)[1];
function rangeButtons() {
  return RANGES.map(
    ([h, key, label]) =>
      `<button data-hours="${h}" aria-label="${label}" aria-pressed="${hours === h}">${key}</button>`,
  ).join("");
}

function configText(value, field, maximum = 240) {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > maximum ||
    /[\u0000-\u001f\u007f]/.test(value)
  )
    throw new Error(`Invalid ${field}`);
  return value;
}

function configSlug(value, field) {
  const slug = configText(value, field, 64);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(slug))
    throw new Error(`Invalid ${field}`);
  return slug;
}

function applyConfig(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload))
    throw new Error("Invalid browser config");
  const site = payload.site;
  if (!site || typeof site !== "object" || Array.isArray(site))
    throw new Error("Invalid site config");
  if (
    Object.keys(site).some(
      (key) =>
        !["brand", "title", "description", "publicUrl", "sourceUrl", "showGroupHeadings"].includes(
          key,
        ),
    )
  )
    throw new Error("Unknown site config");
  const showGroupHeadings = site.showGroupHeadings === undefined ? true : site.showGroupHeadings;
  if (typeof showGroupHeadings !== "boolean") throw new Error("Invalid group heading setting");
  const brand = configText(site.brand, "site.brand");
  const title = configText(site.title, "site.title");
  const description = configText(site.description, "site.description");
  const publicUrl = configText(site.publicUrl, "site.publicUrl", 2048);
  if (!/^https?:\/\/[^\s/?#]+(?:\/[^\s?#]*)?$/.test(publicUrl))
    throw new Error("Invalid public URL");
  const sourceUrl =
    site.sourceUrl === undefined || site.sourceUrl === null
      ? null
      : configText(site.sourceUrl, "site.sourceUrl", 2048);
  if (
    sourceUrl &&
    !/^https:\/\/github\.com\/[A-Za-z0-9][A-Za-z0-9._-]{0,63}\/[A-Za-z0-9][A-Za-z0-9._-]{0,99}\/?$/.test(
      sourceUrl,
    )
  )
    throw new Error("Invalid source URL");

  const rawServices = payload.services;
  if (
    !Array.isArray(rawServices) ||
    !rawServices.length ||
    rawServices.length > MAX_CONFIG_SERVICES
  )
    throw new Error("Invalid service config");
  const serviceBySlug = new Map();
  const groupNames = new Set();
  for (const raw of rawServices) {
    if (!raw || typeof raw !== "object")
      throw new Error("Invalid service entry");
    const slug = configSlug(raw.slug, "service.slug");
    const name = configText(raw.name, "service.name");
    const group = configText(raw.group, "service.group", 120);
    if (serviceBySlug.has(slug)) throw new Error("Duplicate service slug");
    serviceBySlug.set(slug, { slug, name, group });
    groupNames.add(group);
  }
  if (groupNames.size > MAX_CONFIG_GROUPS)
    throw new Error("Too many service groups");

  const rawGroups = payload.groups;
  if (
    !Array.isArray(rawGroups) ||
    rawGroups.length !== groupNames.size ||
    rawGroups.length > MAX_CONFIG_GROUPS
  )
    throw new Error("Invalid service groups");
  const grouped = [];
  const groupedSlugs = new Set();
  for (const rawGroup of rawGroups) {
    if (!rawGroup || typeof rawGroup !== "object")
      throw new Error("Invalid group entry");
    const name = configText(rawGroup.name, "group.name", 120);
    const entries = rawGroup.services;
    if (
      !Array.isArray(entries) ||
      !entries.length ||
      grouped.some(([group]) => group === name)
    )
      throw new Error("Invalid group services");
    const slugs = [];
    for (const entry of entries) {
      if (!entry || typeof entry !== "object")
        throw new Error("Invalid group service");
      const slug = configSlug(entry.slug, "group.service.slug");
      const configured = serviceBySlug.get(slug);
      if (
        !configured ||
        configText(entry.name, "group.service.name") !== configured.name ||
        configured.group !== name
      )
        throw new Error("Group service does not match configured service");
      if (groupedSlugs.has(slug)) throw new Error("Duplicate grouped service");
      groupedSlugs.add(slug);
      slugs.push(slug);
    }
    grouped.push([name, slugs]);
  }
  if (groupedSlugs.size !== serviceBySlug.size)
    throw new Error("Un grouped service");

  const rawRanges = payload.ranges;
  if (!Array.isArray(rawRanges) || rawRanges.length !== DEFAULT_RANGES.length)
    throw new Error("Invalid range config");
  const byRange = new Map();
  for (const range of rawRanges) {
    if (!range || typeof range !== "object")
      throw new Error("Invalid range entry");
    const key = configText(range.key, "range.key", 8);
    const expected = DEFAULT_RANGES.find((entry) => entry[1] === key);
    if (!expected || byRange.has(key) || range.hours !== expected[0])
      throw new Error("Invalid range value");
    byRange.set(key, [
      expected[0],
      key,
      configText(range.description, "range.description", 40),
    ]);
  }
  if (byRange.size !== DEFAULT_RANGES.length)
    throw new Error("Incomplete range config");
  const apiPath = payload.api?.path;
  if (apiPath !== "/api/v1/status") throw new Error("Invalid status API path");

  CONFIG = {
    site: { brand, title, description, publicUrl, sourceUrl, showGroupHeadings },
    serviceBySlug,
  };
  GROUPS = grouped;
  RANGES = DEFAULT_RANGES.map(([, key]) => byRange.get(key));
  API = apiPath;
  document.title = title;
  document
    .querySelector('meta[name="description"]')
    ?.setAttribute("content", description);
  document
    .querySelector('meta[property="og:title"]')
    ?.setAttribute("content", title);
  document
    .querySelector('meta[property="og:description"]')
    ?.setAttribute("content", description);
  document
    .querySelector('meta[property="og:url"]')
    ?.setAttribute("content", publicUrl);
  document
    .querySelector('meta[name="twitter:title"]')
    ?.setAttribute("content", title);
  document
    .querySelector('meta[name="twitter:description"]')
    ?.setAttribute("content", description);
  document
    .querySelector("#brand-name")
    ?.replaceChildren(document.createTextNode(brand));
  document
    .querySelector("#footer-brand")
    ?.replaceChildren(document.createTextNode(brand));
  const sourceLink = $("source-link");
  if (sourceLink) {
    if (sourceUrl) {
      sourceLink.href = sourceUrl;
      sourceLink.hidden = false;
    } else {
      sourceLink.removeAttribute("href");
      sourceLink.hidden = true;
    }
  }
  document.querySelectorAll(".range-control").forEach((control) => {
    control.innerHTML = rangeButtons();
  });
}
function chartSwitch(key) {
  const mode = globalChartMode;
  return surfacePill(
    ["bar", "area"]
      .map(
        (m) =>
          `<button data-chart-key="${esc(key)}" data-chart-mode="${m}" aria-label="${m === "bar" ? "Bar chart" : "Area chart"}" title="${m === "bar" ? "Bar chart" : "Area chart"}" aria-pressed="${mode === m}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="${m === "bar" ? "M5 20V10m7 10V4m7 16v-7" : "M3 20V15l6-8 6 5 6-9v17Z"}"/></svg></button>`,
      )
      .join(""),
    "chart-switch",
    "div",
    ' aria-label="Chart style"',
  );
}

let services = [],
  hours = 24,
  lastFetch = null,
  fetchFailed = false,
  loading = true,
  requestActive = false;
let summaryView = "operational",
  previousDownKeys = new Set(),
  summaryHasData = false,
  summaryAutoDown = false;
let summaryMetaView = "cadence";
// Summary copy and metadata rotate independently, with visibility/failure gates below.
const SUMMARY_ROTATION_MS = 15000,
  SUMMARY_META_ROTATION_MS = 7000,
  AUTO_ROTATION_TICK_MS = 1000;
let summaryRotationStopped = false,
  metadataRotationStopped = false;
let summaryInViewport = true;
let nextSummaryRotationAt = Date.now() + SUMMARY_ROTATION_MS,
  nextMetadataRotationAt = Date.now() + SUMMARY_META_ROTATION_MS;
const $ = (id) => document.getElementById(id);
const summaryObserver =
  typeof IntersectionObserver === "function"
    ? new IntersectionObserver(([entry]) => {
        summaryInViewport = Boolean(entry?.isIntersecting);
        resetAutoRotationDeadlines();
      })
    : null;
summaryObserver?.observe($("status-summary"));
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const percent = (value) =>
  value === null ? "—" : `${(value * 100).toFixed(2)}%`;
// Keep timestamps short for today while retaining a date when the range crosses days.
const dateText = (time, seconds = false) => {
  const date = new Date(time),
    today = new Date();
  return date.toLocaleString([], {
    hourCycle: "h23",
    ...(date.toDateString() === today.toDateString()
      ? {}
      : { month: "short", day: "numeric" }),
    hour: "2-digit",
    minute: "2-digit",
    ...(seconds ? { second: "2-digit" } : {}),
  });
};
const timeText = (time) =>
  new Date(time).toLocaleTimeString([], {
    hourCycle: "h23",
    hour: "2-digit",
    minute: "2-digit",
  });
const chartTime = (time) => dateText(time);
const latencyText = (value) =>
  Number.isFinite(value)
    ? `${Math.round(value / 1e6).toLocaleString()} ms`
    : "—";
const summaryMorphOptions = {
  duration: 360,
  ease: "cubic-bezier(0.19, 1, 0.22, 1)",
  locale: "en",
  numbers: true,
  respectReducedMotion: true,
  scale: false,
};
const summaryMorph = new TextMorph({
  element: $("summary-up"),
  ...summaryMorphOptions,
});
const summaryMetaMorph = new TextMorph({
  element: $("summary-meta-text"),
  ...summaryMorphOptions,
});
function animateSummaryLabel() {
  const toggle = $("summary-toggle");
  toggle.classList.remove("is-switching");
  void toggle.offsetWidth;
  toggle.classList.add("is-switching");
  requestAnimationFrame(() => toggle.classList.remove("is-switching"));
}

function updateSummaryCount(value) {
  summaryMorph.update(value === null ? "—" : String(value));
}
function updateSummaryMeta() {
  const updated = summaryMetaView === "updated";
  const timestamp = lastFetch
    ? new Date(lastFetch).toLocaleTimeString([], {
        hourCycle: "h23",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })
    : "—";
  const label = updated ? "Updated" : "Checks every minute";
  const text = updated ? `${label} ${timestamp}` : label;
  const next =
    summaryMetaView === "updated" ? "check cadence" : "latest update time";
  summaryMetaMorph.update(text);
  $("summary-meta-toggle").setAttribute(
    "aria-pressed",
    String(summaryMetaView === "updated"),
  );
  $("summary-meta-toggle").setAttribute("aria-label", `${text}. Show ${next}.`);
  $("summary-meta-toggle").title = `Show ${next}`;
}
function resetAutoRotationDeadlines(now = Date.now()) {
  nextSummaryRotationAt = now + SUMMARY_ROTATION_MS;
  nextMetadataRotationAt = now + SUMMARY_META_ROTATION_MS;
}
function autoRotationAllowed() {
  return (
    !loading &&
    !fetchFailed &&
    Boolean(lastFetch) &&
    summaryInViewport &&
    !document.hidden &&
    document.visibilityState !== "hidden" &&
    !selectedKey()
  );
}
function autoRotateSummary(now) {
  if (summaryRotationStopped || now < nextSummaryRotationAt) return;
  nextSummaryRotationAt = now + SUMMARY_ROTATION_MS;
  const failedKeys = new Set(
    services
      .filter((service) => state(service) === "down")
      .map((service) => service.slug),
  );
  const hasNewFailure = [...failedKeys].some(
    (key) => !previousDownKeys.has(key),
  );
  summaryView = summaryView === "down" ? "operational" : "down";
  if (hasNewFailure && summaryView !== "down") summaryView = "down";
  summaryAutoDown = hasNewFailure && summaryView === "down";
  overall({ animateText: true });
}
function autoRotateMeta(now) {
  if (metadataRotationStopped || now < nextMetadataRotationAt) return;
  nextMetadataRotationAt = now + SUMMARY_META_ROTATION_MS;
  summaryMetaView = summaryMetaView === "updated" ? "cadence" : "updated";
  updateSummaryMeta();
}
function autoRotate() {
  const now = Date.now();
  if (!autoRotationAllowed()) {
    resetAutoRotationDeadlines(now);
    return;
  }
  autoRotateSummary(now);
  autoRotateMeta(now);
}
function setSummaryCopy({
  headingCount,
  headingLabel,
  state,
  stateCount,
  showState,
  kind,
  view,
  toggleDisabled,
  animateText = false,
}) {
  if (animateText) animateSummaryLabel();
  updateSummaryCount(headingCount);
  $("summary-heading-label").textContent = ` ${headingLabel}`;
  const currentLabel =
    headingCount === null ? headingLabel : `${headingCount} ${headingLabel}`;
  const nextLabel =
    view === "down" ? "services operational" : "services currently down";
  $("summary-heading").setAttribute("aria-label", currentLabel);
  $("summary-toggle").disabled = toggleDisabled;
  $("summary-toggle").setAttribute("aria-pressed", String(view === "down"));
  $("summary-toggle").setAttribute(
    "aria-label",
    toggleDisabled ? currentLabel : `Show ${nextLabel}`,
  );
  $("summary-toggle").title = toggleDisabled
    ? "Current status unavailable"
    : `Show ${nextLabel}`;
  $("summary-state-count").textContent =
    stateCount === null ? "" : String(stateCount);
  $("summary-state-label").textContent =
    stateCount === null ? state : ` ${state}`;
  $("summary-state").hidden = !showState;
  $("status-summary")?.setAttribute("data-summary-state", kind);
}
function current(service) {
  return service.current;
}
function state(service) {
  const latest = current(service);
  if (
    fetchFailed ||
    !latest ||
    !Number.isFinite(latest.time) ||
    latest.time > Date.now() + 300000 ||
    Date.now() - latest.time > 90000
  )
    return "unknown";
  return latest.success ? "up" : "down";
}
function stateText(value) {
  return value === "up"
    ? "Operational"
    : value === "down"
      ? "Failed check"
      : "No recent data";
}
// All plots, cards, and metrics derive from this time-windowed observation set.
function observations(service) {
  const cutoff = Date.now() - hours * 3600000;
  return service.results.filter((r) => r.time >= cutoff);
}
function uptime(service) {
  const rows = observations(service);
  const total = rows.reduce((sum, r) => sum + r.count, 0);
  return total ? rows.reduce((sum, r) => sum + r.passed, 0) / total : null;
}
function historyBars(service) {
  const now = Date.now(),
    width = (hours * 3600000) / 60,
    start = now - hours * 3600000;
  const buckets = Array.from({ length: 60 }, () => []);
  for (const r of service.results) {
    const index = Math.floor((r.time - start) / width);
    if (index >= 0 && index < 60) buckets[index].push(r);
  }
  // Availability uses the same Bklit island and interaction model as latency.
  // Fixed-height buckets encode coverage/status, never a fabricated latency value.
  const data = buckets.map((rows, i) => {
    const count = rows.reduce((sum, r) => sum + r.count, 0);
    const coverage = count / Math.max(1, width / 60000);
    return {
      time: start + (i + 0.5) * width,
      intervalStart: start + i * width,
      intervalEnd: start + (i + 1) * width,
      value: 1,
      success: rows.some((r) => !r.success)
        ? false
        : rows.length && coverage >= 0.7
          ? true
          : null,
      count,
    };
  });
  return chartSlot("availability:" + service.slug, {
    type: "availability",
    compact: true,
    mode: "bar",
    data,
    start,
    end: now,
    label: `Recorded availability for ${service.name}`,
  });
}
const chartSpecs = new Map();
const chartHandles = new Map();
const chartRenderedSpecs = new Map();
const visibleChartKeys = new Set();
const chartUnmountJobs = new Map();
const OFFSCREEN_CHART_RELEASE_MS = 750;
function currentChartSlot(key) {
  return Array.from(document.querySelectorAll("[data-bklit-key]")).find(
    (slot) => slot.getAttribute("data-bklit-key") === key,
  );
}
function cancelChartUnmount(key) {
  const job = chartUnmountJobs.get(key);
  if (!job) return;
  if (job.timer !== null) window.clearTimeout(job.timer);
  if (job.idle !== null && typeof window.cancelIdleCallback === "function")
    window.cancelIdleCallback(job.idle);
  chartUnmountJobs.delete(key);
}
function releaseChartSlot(slot, key) {
  chartUnmountJobs.delete(key);
  if (
    !slot.isConnected ||
    currentChartSlot(key) !== slot ||
    visibleChartKeys.has(key) ||
    slot.contains(document.activeElement)
  )
    return;
  chartHandles.get(key)?.destroy();
  chartHandles.delete(key);
  chartRenderedSpecs.delete(key);
}
function scheduleChartUnmount(slot, key) {
  if (!chartHandles.has(key) || chartUnmountJobs.has(key)) return;
  const job = { timer: null, idle: null };
  job.timer = window.setTimeout(() => {
    job.timer = null;
    if (typeof window.requestIdleCallback === "function")
      job.idle = window.requestIdleCallback(() => releaseChartSlot(slot, key), {
        timeout: 250,
      });
    else releaseChartSlot(slot, key);
  }, OFFSCREEN_CHART_RELEASE_MS);
  chartUnmountJobs.set(key, job);
}
function mountChartSlot(slot) {
  if (!slot?.isConnected) return;
  const key = slot.getAttribute("data-bklit-key"),
    props = chartSpecs.get(key);
  if (!key || !props) return;
  cancelChartUnmount(key);
  const handle = chartHandles.get(key);
  if (handle) {
    if (chartRenderedSpecs.get(key) !== props) {
      handle.update(props);
      chartRenderedSpecs.set(key, props);
    }
  } else {
    chartHandles.set(key, renderChart(slot, props));
    chartRenderedSpecs.set(key, props);
  }
}
// Keep enough overscan that charts are ready before normal scrolling reaches
// them, without paying to create every React root during the first render.
const chartObserver =
  typeof IntersectionObserver === "function"
    ? new IntersectionObserver(
        (entries) => {
          for (const entry of entries) {
            const key = entry.target.getAttribute("data-bklit-key");
            if (!key) continue;
            const currentSlot = currentChartSlot(key);
            if (!entry.target.isConnected || currentSlot !== entry.target) {
              chartObserver.unobserve(entry.target);
              continue;
            }
            if (entry.isIntersecting) {
              visibleChartKeys.add(key);
              mountChartSlot(entry.target);
            } else {
              visibleChartKeys.delete(key);
              scheduleChartUnmount(entry.target, key);
            }
          }
        },
        { rootMargin: "300px 0px" },
      )
    : null;
document.addEventListener("focusout", (event) => {
  const slot = event.target.closest?.("[data-bklit-key]"),
    key = slot?.getAttribute("data-bklit-key");
  if (key && !visibleChartKeys.has(key) && currentChartSlot(key) === slot)
    scheduleChartUnmount(slot, key);
});
function chartSlot(key, props) {
  chartSpecs.set(key, props);
  return `<div class="bklit-mount ${props.type === "availability" ? "bklit-availability" : props.compact ? "bklit-mini" : "bklit-detail"}" data-bklit-key="${esc(key)}"></div>`;
}
// React chart islands stay opaque while their surrounding static DOM shell reconciles.
function chartKey(node) {
  return node?.nodeType === 1 ? node.getAttribute("data-bklit-key") : null;
}
function syncAttrs(current, next) {
  for (const attr of Array.from(current.attributes))
    if (!next.hasAttribute(attr.name)) current.removeAttribute(attr.name);
  for (const attr of Array.from(next.attributes))
    if (current.getAttribute(attr.name) !== attr.value)
      current.setAttribute(attr.name, attr.value);
}
function syncNode(current, next) {
  if (
    current.nodeType !== next.nodeType ||
    current.nodeName !== next.nodeName ||
    chartKey(current) !== chartKey(next)
  ) {
    const replacement = next.cloneNode(true);
    current.replaceWith(replacement);
    return replacement;
  }
  if (current.nodeType === 3) {
    if (current.nodeValue !== next.nodeValue)
      current.nodeValue = next.nodeValue;
    return current;
  }
  if (current.nodeType !== 1) return current;
  syncAttrs(current, next);
  if (chartKey(current)) return current;
  syncChildren(current, next);
  return current;
}
function syncChildren(current, next) {
  const wanted = Array.from(next.childNodes);
  for (let i = 0; i < wanted.length; i++) {
    const expected = wanted[i],
      key = chartKey(expected);
    let existing = current.childNodes[i];
    if (key && chartKey(existing) !== key) {
      existing =
        Array.from(current.children).find((node) => chartKey(node) === key) ||
        null;
      if (existing)
        current.insertBefore(existing, current.childNodes[i] || null);
    }
    if (existing) syncNode(existing, expected);
    else current.appendChild(expected.cloneNode(true));
  }
  while (current.childNodes.length > wanted.length) current.lastChild.remove();
}
function setChartHTML(container, html) {
  const focused = document.activeElement;
  const focusKey =
    container.contains(focused) &&
    focused.closest?.("[data-bklit-key]")?.getAttribute("data-bklit-key");
  const scrollState = [
    [container, container.scrollTop, container.scrollLeft],
    ...Array.from(container.querySelectorAll("*"))
      .filter((node) => node.scrollTop || node.scrollLeft)
      .map((node) => [node, node.scrollTop, node.scrollLeft]),
  ];
  const previous = new Map(
    Array.from(container.querySelectorAll("[data-bklit-key]"), (node) => [
      node.getAttribute("data-bklit-key"),
      node,
    ]),
  );
  const template = document.createElement("template");
  template.innerHTML = html;
  syncChildren(container, template.content);
  container.querySelectorAll("[data-bklit-key]").forEach((slot) => {
    const key = slot.getAttribute("data-bklit-key"),
      props = chartSpecs.get(key),
      handle = chartHandles.get(key);
    if (!props) return;
    if (handle && previous.get(key) === slot) {
      if (visibleChartKeys.has(key)) mountChartSlot(slot);
    } else {
      const staleSlot = previous.get(key);
      if (staleSlot && staleSlot !== slot) {
        chartObserver?.unobserve(staleSlot);
        visibleChartKeys.delete(key);
      }
      cancelChartUnmount(key);
      handle?.destroy();
      chartHandles.delete(key);
      chartRenderedSpecs.delete(key);
      if (chartObserver) {
        chartObserver.observe(slot);
        if (focusKey === key) {
          visibleChartKeys.add(key);
          mountChartSlot(slot);
        }
      } else mountChartSlot(slot);
    }
  });
  for (const [node, top, left] of scrollState)
    if (node.isConnected) {
      node.scrollTop = top;
      node.scrollLeft = left;
    }
  if (focused && !focused.isConnected && focusKey) {
    const mount = Array.from(
      container.querySelectorAll("[data-bklit-key]"),
    ).find((node) => node.getAttribute("data-bklit-key") === focusKey);
    const target =
      mount?.querySelector("[data-bklit-chart],[data-chart-label]") || mount;
    target?.focus({ preventScroll: true });
  }
  const live = new Set(
    Array.from(document.querySelectorAll("[data-bklit-key]"), (node) =>
      node.getAttribute("data-bklit-key"),
    ),
  );
  for (const [key, handle] of chartHandles)
    if (!live.has(key)) {
      cancelChartUnmount(key);
      handle.destroy();
      chartHandles.delete(key);
      chartRenderedSpecs.delete(key);
    }
  for (const [key] of chartSpecs)
    if (!live.has(key)) {
      const staleSlot = previous.get(key);
      if (staleSlot) chartObserver?.unobserve(staleSlot);
      cancelChartUnmount(key);
      visibleChartKeys.delete(key);
      chartSpecs.delete(key);
    }
}
function chartObservations(rows) {
  // Preserve measured gaps as null points; chart interpolation never invents samples.
  const data = [];
  let previous = null;
  for (const p of rows) {
    if (
      previous &&
      p.time - previous.time > Math.max(180000, (p.interval || 60) * 1500)
    )
      data.push({
        time: previous.time + (p.time - previous.time) / 2,
        value: null,
        success: null,
      });
    data.push({
      time: p.time,
      value:
        Number.isFinite(p.duration) && p.duration >= 0
          ? p.duration / 1e6
          : null,
      success: p.success,
      count: p.count,
    });
    previous = p;
  }
  return data;
}
function miniChart(service) {
  const rows = observations(service),
    end = Date.now(),
    start = plotStart(rows);
  return chartSlot("mini:" + service.slug, {
    type: "latency",
    compact: true,
    mode: globalChartMode,
    data: chartObservations(rows),
    start,
    end,
    label: `${service.name} response time`,
    formatValue: (value) => `${Math.round(value).toLocaleString()} ms`,
    emptyLabel: "No response-time observations",
  });
}
// Shared surface primitives keep reusable shells and pills consistent across variants.
function surfacePill(content, variant = "", tag = "span", attributes = "") {
  return `<${tag} class="surface-pill${variant ? ` ${variant}` : ""}"${attributes}>${content}</${tag}>`;
}
function surfaceCard(content, variant, tag = "div") {
  return `<${tag} class="surface-card ${variant}">${content}</${tag}>`;
}
function serviceRow(service) {
  const s = state(service),
    url = `/services/${encodeURIComponent(service.slug)}/`;
  return surfaceCard(
    `<div class="service-heading"><a class="service-name" href="${url}" data-service="${esc(service.slug)}"><svg class="service-health ${s}" viewBox="0 0 24 24" role="img" aria-label="${stateText(s)}"><circle cx="12" cy="12" r="9"/><path d="${s === "up" ? "m7.5 12 3 3 6-6" : s === "down" ? "m9 9 6 6m0-6-6 6" : "M8 12h8"}"/></svg>${esc(service.name)}</a><span class="uptime">${percent(uptime(service))}</span></div>${miniChart(service)}<div class="service-foot"><span>${dateText(plotStart(observations(service)))}</span><span>Now</span></div>`,
    "service",
    "article",
  );
}
function overall({ animateText = false } = {}) {
  const up = services.filter((s) => state(s) === "up").length,
    down = services.filter((s) => state(s) === "down").length;
  const unknown = services.length - up - down;
  if (!loading && !fetchFailed) {
    const failedKeys = new Set(
      services.filter((s) => state(s) === "down").map((s) => s.slug),
    );
    const hasNewFailure = [...failedKeys].some(
      (key) => !previousDownKeys.has(key),
    );
    if (!summaryHasData) {
      summaryView = failedKeys.size ? "down" : "operational";
      summaryAutoDown = failedKeys.size > 0;
    } else if (summaryView === "operational" && hasNewFailure) {
      summaryView = "down";
      summaryAutoDown = true;
    } else if (summaryAutoDown && !failedKeys.size) {
      summaryView = "operational";
      summaryAutoDown = false;
    }
    previousDownKeys = failedKeys;
    summaryHasData = true;
  }
  let headingCount,
    headingLabel,
    stateText = "",
    stateCount = null,
    showState = false,
    kind,
    view = summaryView,
    toggleDisabled = loading || fetchFailed;
  if (loading) {
    headingCount = null;
    headingLabel = "checking service health";
    stateText = "Checking status…";
    view = "operational";
    kind = "unknown";
  } else if (fetchFailed) {
    headingCount = null;
    headingLabel = "status temporarily unavailable";
    stateText = "Live availability is unknown until monitoring refreshes.";
    view = "operational";
    showState = true;
    kind = "unknown";
  } else if (summaryView === "down") {
    headingCount = down;
    headingLabel = "services currently down";
    if (unknown) {
      stateCount = unknown;
      stateText = `${unknown === 1 ? "service has" : "services have"} no recent data.`;
      showState = true;
    }
    kind = down ? "down" : unknown ? "unknown" : "up";
  } else {
    headingCount = up;
    headingLabel = "services operational";
    if (unknown) {
      stateCount = unknown;
      stateText = `${unknown === 1 ? "service has" : "services have"} no recent data.`;
      showState = true;
    }
    kind = unknown ? "unknown" : "up";
  }
  setSummaryCopy({
    headingCount,
    headingLabel,
    state: stateText,
    stateCount,
    showState,
    kind,
    view,
    toggleDisabled,
    animateText,
  });
  updateSummaryMeta();

  $("fetch-error").hidden = !fetchFailed;
  $("fetch-error").textContent =
    "Live status could not be refreshed. Previously recorded history is shown; current availability is unknown. Retrying automatically.";
}
function renderHome() {
  overall();
  const controls = document.getElementById("global-chart-switch");
  if (controls) controls.innerHTML = chartSwitch("global");
  $("services").setAttribute("aria-busy", String(loading));
  if (loading) {
    if (!$("services").querySelector("[data-bklit-key]"))
      setChartHTML(
        $("services"),
        '<div class="initial-state" role="status"><p>Loading history…</p></div>',
      );
    return;
  }
  const bySlug = new Map(services.map((service) => [service.slug, service]));
  const groups = GROUPS.map(([group, slugs]) => {
    const rows = slugs
      .map((slug) => bySlug.get(slug))
      .filter(Boolean)
      .sort((a, b) =>
        a.name.localeCompare(b.name, undefined, { sensitivity: "base" }),
      );
    return rows.length
      ? `<section class="service-group">${CONFIG.site.showGroupHeadings ? `<h2 class="service-group-title">${esc(group)}</h2>` : ""}<div class="service-group-items">${rows.map(serviceRow).join("")}</div></section>`
      : "";
  }).join("");
  setChartHTML($("services"), groups);
  $("services").setAttribute("aria-busy", "false");
}
function selectedKey() {
  const match = location.pathname.match(
    /^\/(?:preview\/)?services\/([^/]+)\/?$/,
  );
  try {
    return match ? decodeURIComponent(match[1]) : null;
  } catch {
    return null;
  }
}
function metric(label, value, description = "") {
  return surfaceCard(
    `<dt>${esc(label)}</dt><dd>${esc(value)}</dd>${description ? `<small>${esc(description)}</small>` : ""}`,
    "detail-metric",
  );
}
function latencyChart(rows, mode = "area") {
  const end = Date.now(),
    start = plotStart(rows),
    data = chartObservations(rows);
  return chartSlot("detail:" + selectedKey(), {
    type: "latency",
    compact: false,
    mode,
    data,
    start,
    end,
    label: "Recorded response time. Gaps indicate missing checks.",
    formatValue: (value) => `${Math.round(value).toLocaleString()} ms`,
    emptyLabel: "No response-time observations in this period.",
  });
}
function checksTable(rows) {
  const max = Math.max(
    ...rows.map((r) => (Number.isFinite(r.duration) ? r.duration : 0)),
    1,
  );
  return surfaceCard(
    `<div class="table-scroll" tabindex="0" role="region" aria-label="All checks in the selected time window"><table><thead><tr><th scope="col">Checked at</th><th scope="col">Status</th><th scope="col">Response time</th></tr></thead><tbody>${
      rows
        .slice()
        .reverse()
        .map(
          (r) =>
            `<tr><td><time datetime="${new Date(r.time).toISOString()}">${esc(chartTime(r.time))}</time></td><td>${surfacePill(`<i class="dot"></i>${r.success ? "Passed" : r.interval > 60 ? "Failures" : "Failed"}`, `status-pill ${r.success ? "up" : "down"}`)}</td><td><span class="response-cell"><svg class="response-bar" viewBox="0 0 80 8" aria-hidden="true"><rect width="80" height="8" rx="4" class="bar-track"/><rect width="${Number.isFinite(r.duration) ? Math.max(0, (r.duration / max) * 80) : 0}" height="8" rx="4" class="bar-value"/></svg><span>${latencyText(r.duration)}</span></span></td></tr>`,
        )
        .join("") ||
      '<tr><td colspan="3">No recorded checks in this period.</td></tr>'
    }</tbody></table></div>`,
    "check-table",
  );
}
function renderDetail() {
  const key = selectedKey();
  const detail = $("service-detail");
  document.querySelector("main").hidden = Boolean(key);
  detail.hidden = !key;
  if (!key) return;
  const service = services.find((s) => s.slug === key);
  if (!service) {
    setChartHTML(
      detail,
      `<h1>${loading ? "Loading service…" : "Service not found"}</h1>`,
    );
    return;
  }
  const s = state(service),
    rows = observations(service),
    latest = current(service),
    durations = rows
      .map((r) => r.duration)
      .filter(Number.isFinite)
      .sort((a, b) => a - b);
  const median = durations.length
    ? (durations[Math.floor((durations.length - 1) / 2)] +
        durations[Math.floor(durations.length / 2)]) /
      2
    : null;
  const timedRows = rows.filter((r) => Number.isFinite(r.duration)),
    timedCount = timedRows.reduce((sum, r) => sum + r.count, 0);
  const average = timedCount
    ? timedRows.reduce((sum, r) => sum + r.duration * r.count, 0) / timedCount
    : null;
  const statusLabel =
    s === "up" ? "Operational" : s === "down" ? "Currently Down" : "Unknown";
  const statusTime =
    s === "unknown" || !latest || !Number.isFinite(latest.time)
      ? "No recent check"
      : dateText(latest.time, true);
  setChartHTML(
    detail,
    `<div class="detail-title"><h1>${esc(service.name)}</h1></div>${fetchFailed ? '<p class="notice">Live updates are unavailable. Current availability is unknown.</p>' : ""}<dl class="detail-metrics">${metric("Observed uptime", percent(uptime(service)))}${metric("Latest response", latest ? latencyText(latest.duration) : "—")}${metric(service.interval > 60 ? "Median interval average" : "Median response", latencyText(median))}${metric(statusLabel, statusTime)}</dl><div class="section-heading"><h2>Availability</h2>${surfacePill(rangeButtons(), "range-control", "div", ' aria-label="History period"')}</div>${surfaceCard(`${historyBars(service)}<div class="service-foot"><span>${esc(dateText(Date.now() - hours * 3600000))}</span><span>Now</span></div>`, "detail-panel")}<p class="history-note">Grey segments mean no or incomplete observations. Uptime excludes missing data.</p>${surfaceCard(`<div class="card-heading"><div><h2>Response time</h2><div class="response-stats">${surfacePill(`Median <strong>${service.interval > 60 ? "≈ " : ""}${latencyText(median)}</strong>`, "response-stat", "span", ` title="${service.interval > 60 ? "Estimated from interval averages" : "Middle recorded response time"}"`)}${surfacePill(`Average <strong>${latencyText(average)}</strong>`, "response-stat")}</div></div>${chartSwitch(service.slug)}</div>${latencyChart(rows, globalChartMode)}`, "chart-card", "section")}<div class="detail-section-title"><div><h2 class="checks-heading"><span class="checks-count">${rows.reduce((sum, r) => sum + r.count, 0).toLocaleString()}</span> Checks</h2></div>${surfacePill(periodLabel(), "period-label")}</div>${checksTable(rows)}`,
  );
}
function render() {
  const scroll = document.querySelector(".table-scroll");
  const position = scroll
    ? { top: scroll.scrollTop, left: scroll.scrollLeft }
    : null;
  const active = document.activeElement;
  const modeFocus = active?.getAttribute("data-chart-mode");
  const rangeFocus = active?.getAttribute("data-hours");
  const tableFocused = active === scroll;
  const serviceKey = active?.getAttribute("data-service");
  if (selectedKey()) {
    // Do not keep overview chart roots alive behind a detail route.
    if ($("services").childNodes.length) setChartHTML($("services"), "");
    renderDetail();
  } else {
    // Detail tables can contain many rows. Release their DOM and chart
    // root before rebuilding the overview.
    if (detail.childNodes.length) setChartHTML(detail, "");
    renderHome();
    renderDetail();
  }
  const nextScroll = document.querySelector(".table-scroll");
  if (position && nextScroll) {
    nextScroll.scrollTop = position.top;
    nextScroll.scrollLeft = position.left;
  }
  let target = tableFocused ? nextScroll : null;
  if (serviceKey)
    target = Array.from(document.querySelectorAll("[data-service]")).find(
      (el) => el.dataset.service === serviceKey,
    );
  if (modeFocus)
    target = Array.from(document.querySelectorAll("[data-chart-mode]")).find(
      (el) => el.dataset.chartMode === modeFocus,
    );
  if (rangeFocus)
    target = Array.from(document.querySelectorAll("[data-hours]")).find(
      (el) => el.dataset.hours === rangeFocus && el.getClientRects().length,
    );
  if (target) target.focus({ preventScroll: true });
  document
    .querySelectorAll("[data-hours]")
    .forEach((b) =>
      b.setAttribute("aria-pressed", String(Number(b.dataset.hours) === hours)),
    );
}
function updateChartMode(nextMode) {
  if (!["area", "bar"].includes(nextMode) || nextMode === globalChartMode)
    return;
  globalChartMode = nextMode;
  document
    .querySelectorAll("[data-chart-mode]")
    .forEach((button) =>
      button.setAttribute(
        "aria-pressed",
        String(button.getAttribute("data-chart-mode") === nextMode),
      ),
    );
  // Mode changes keep the already-normalized application data and mounted DOM
  // shell. Unseen chart slots pick up the new spec when their observer mounts
  // them; visible roots update in place.
  for (const [key, props] of chartSpecs) {
    if (props.type !== "latency" || props.mode === nextMode) continue;
    const nextProps = { ...props, mode: nextMode };
    chartSpecs.set(key, nextProps);
    if (visibleChartKeys.has(key)) {
      chartHandles.get(key)?.update(nextProps);
      chartRenderedSpecs.set(key, nextProps);
    }
  }
}
async function refresh() {
  // Refresh accepts only the allowlisted endpoint shape and keeps all remote
  // strings escaped. Browser config provides the exact service identities.
  if (!CONFIG) return;
  if (requestActive) return;
  requestActive = true;
  const requestedHours = hours;
  try {
    const response = await fetch(API + "?range=" + rangeKey(), {
      signal: AbortSignal.timeout(45000),
      cache: "default",
    });
    if (!response.ok) throw new Error("Unavailable");
    const data = await response.json();
    if (!Array.isArray(data) || data.length > MAX_CONFIG_SERVICES)
      throw new Error("Invalid status response");
    const now = Date.now();
    const windowMs = hours * 3600000;
    const expectedBySlug = CONFIG.serviceBySlug;
    const seenSlugs = new Set();
    const normalizeCurrent = (value) => {
      if (!value || typeof value !== "object" || Array.isArray(value))
        return null;
      if (
        Object.keys(value).some(
          (key) => !["timestamp", "success", "duration"].includes(key),
        )
      )
        return null;
      if (typeof value.success !== "boolean") return null;
      const time = Date.parse(value.timestamp);
      const duration = value.duration;
      if (
        !Number.isFinite(time) ||
        time > now + 300000 ||
        time < now - windowMs - 3600000
      )
        return null;
      if (!(
        duration === null ||
        (Number.isFinite(duration) &&
          duration >= 0 &&
          duration <= MAX_DURATION_NS)
      ))
        return null;
      return {
        time,
        success: value.success,
        duration: duration === null ? null : duration,
      };
    };
    const clean = data
      .filter((s) => {
        if (!s || typeof s !== "object" || Array.isArray(s)) return false;
        if (
          Object.keys(s).some(
            (key) =>
              ![
                "slug",
                "name",
                "group",
                "interval",
                "current",
                "results",
              ].includes(key),
          )
        )
          return false;
        const configured = expectedBySlug.get(s.slug);
        if (
          !configured ||
          s.name !== configured.name ||
          s.group !== configured.group ||
          seenSlugs.has(s.slug)
        )
          return false;
        seenSlugs.add(s.slug);
        return true;
      })
      .map((s) => {
        const interval =
          Number.isSafeInteger(s.interval) &&
          s.interval > 0 &&
          s.interval <= 86400
            ? s.interval
            : 60;
        const results = [];
        const seenTimes = new Set();
        if (Array.isArray(s.results) && s.results.length <= MAX_RESULTS) {
          for (const r of s.results) {
            if (!r || typeof r !== "object" || Array.isArray(r)) continue;
            if (
              Object.keys(r).some(
                (key) =>
                  ![
                    "timestamp",
                    "success",
                    "duration",
                    "count",
                    "passed",
                    "interval",
                  ].includes(key),
              )
            )
              continue;
            if (typeof r.success !== "boolean") continue;
            const time = Date.parse(r.timestamp);
            if (
              !Number.isFinite(time) ||
              time < now - windowMs - 3600000 ||
              time > now + 300000 ||
              seenTimes.has(time)
            )
              continue;
            const count =
              Number.isSafeInteger(r.count) &&
              r.count > 0 &&
              r.count <= 10000000
                ? r.count
                : 1;
            const passed = Number.isFinite(r.passed)
              ? Math.max(0, Math.min(count, Math.floor(r.passed)))
              : r.success
                ? count
                : 0;
            const rowInterval =
              Number.isSafeInteger(r.interval) &&
              r.interval > 0 &&
              r.interval <= 86400
                ? r.interval
                : interval;
            const duration =
              r.duration === null || r.duration === undefined
                ? null
                : Number(r.duration);
            if (!(
              duration === null ||
              (Number.isFinite(duration) &&
                duration >= 0 &&
                duration <= MAX_DURATION_NS)
            ))
              continue;
            seenTimes.add(time);
            results.push({
              time,
              success: r.success,
              count,
              passed,
              interval: rowInterval,
              duration,
            });
          }
        }
        results.sort((a, b) => a.time - b.time);
        return {
          name: s.name,
          slug: s.slug,
          group: s.group,
          interval,
          current: normalizeCurrent(s.current),
          results,
        };
      });
    if (!clean.length) throw new Error("Invalid response");
    for (const [slug, configured] of expectedBySlug)
      if (!seenSlugs.has(slug)) {
        clean.push({
          name: configured.name,
          slug,
          group: configured.group,
          interval: 60,
          current: null,
          results: [],
        });
      }
    if (requestedHours !== hours) return;
    services = clean;
    lastFetch = Date.now();
    fetchFailed = false;
  } catch {
    if (requestedHours !== hours) return;
    fetchFailed = true;
    if (!services.length)
      services = [...CONFIG.serviceBySlug.values()].map((service) => ({
        ...service,
        interval: 60,
        current: null,
        results: [],
      }));
  } finally {
    requestActive = false;
    if (requestedHours !== hours) {
      refresh();
    } else {
      loading = false;
      render();
    }
  }
}
const detail = document.createElement("section");
detail.id = "service-detail";
detail.hidden = true;
document.querySelector("main").after(detail);
document.addEventListener("visibilitychange", () => {
  if (document.hidden || document.visibilityState === "hidden") {
    resetAutoRotationDeadlines();
    return;
  }
  if (!lastFetch || Date.now() - lastFetch >= 60000) refresh();
});
document.addEventListener("click", (event) => {
  const summaryToggle = event.target.closest("#summary-toggle");
  if (summaryToggle && !summaryToggle.disabled) {
    summaryRotationStopped = true;
    summaryView = summaryView === "down" ? "operational" : "down";
    summaryAutoDown = false;
    overall({ animateText: true });
    return;
  }
  const summaryMetaToggle = event.target.closest("#summary-meta-toggle");
  if (summaryMetaToggle) {
    metadataRotationStopped = true;
    summaryMetaView = summaryMetaView === "updated" ? "cadence" : "updated";
    updateSummaryMeta();
    return;
  }
  const mode = event.target.closest("[data-chart-mode]");
  if (mode) {
    updateChartMode(mode.dataset.chartMode);
    return;
  }
  const range = event.target.closest("[data-hours]");
  if (range) {
    if (hours === Number(range.dataset.hours)) return;
    hours = Number(range.dataset.hours);
    loading = true;
    render();
    refresh();
    return;
  }
  const link = event.target.closest("a[data-service],a[data-home]");
  if (link && !event.metaKey && !event.ctrlKey && !event.shiftKey) {
    event.preventDefault();
    history.pushState({}, "", link.getAttribute("href"));
    resetAutoRotationDeadlines();
    render();
    const heading = document.querySelector(
      "#service-detail:not([hidden]) h1,main:not([hidden]) .status-summary",
    );
    if (heading) {
      heading.tabIndex = -1;
      heading.focus({ preventScroll: true });
    }
    window.scrollTo({ top: 0, behavior: "instant" });
  }
});
window.addEventListener("popstate", () => {
  resetAutoRotationDeadlines();
  render();
});
async function bootstrap() {
  try {
    const response = await fetch(CONFIG_ENDPOINT, {
      signal: AbortSignal.timeout(15000),
      cache: "no-store",
    });
    if (!response.ok) throw new Error("Config unavailable");
    applyConfig(await response.json());
    render();
    await refresh();
  } catch {
    fetchFailed = true;
    loading = false;
    render();
  }
}
renderDetail();
bootstrap();
setInterval(() => {
  if (!document.hidden && document.visibilityState !== "hidden") refresh();
}, 60000);
setInterval(autoRotate, AUTO_ROTATION_TICK_MS);

// Bklit owns chart tooltips and keyboard navigation; the old SVG delegation is intentionally absent.
document.addEventListener(
  "keydown",
  () => {
    document.documentElement.dataset.input = "keyboard";
  },
  true,
);
document.addEventListener(
  "pointerdown",
  () => {
    document.documentElement.dataset.input = "pointer";
  },
  true,
);
