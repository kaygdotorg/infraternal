import { flushSync } from "react-dom";
import { createRoot, type Root } from "react-dom/client";
import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useState,
  type ReactElement,
} from "react";
import { AreaChart } from "./vendor/bklit/charts/area-chart";
import { Area } from "./vendor/bklit/charts/area";
import { BarChart } from "./vendor/bklit/charts/bar-chart";
import { Bar } from "./vendor/bklit/charts/bar";
import { BarXAxis } from "./vendor/bklit/charts/bar-x-axis";
import { ChartTooltip } from "./vendor/bklit/charts/tooltip/chart-tooltip";
import { Grid } from "./vendor/bklit/charts/grid";
import { XAxis } from "./vendor/bklit/charts/x-axis";
import { YAxis } from "./vendor/bklit/charts/y-axis";

export type ChartMode = "area" | "bar";
export type ChartKind = "latency" | "availability";

/** A row already normalized by the public status endpoint adapter. */
export interface ChartDataPoint {
  /** Unix epoch milliseconds. */
  time: number;
  /** Start of the source interval represented by this point, when aggregated. */
  intervalStart?: number;
  /** End of the source interval represented by this point, when aggregated. */
  intervalEnd?: number;
  /** Response latency in milliseconds; availability rows use the normalized plot value only. */
  value: number | null;
  /** True for a passing check, false for a recorded failure, null when unknown. */
  success?: boolean | null;
  /** Number of checks represented by this row, when the endpoint grouped rows. */
  count?: number;
}

export interface ChartProps {
  /** The chart family. Availability rows use state markers and check counts. */
  type?: ChartKind;
  /** Bklit chart primitive to render. */
  mode?: ChartMode;
  /** Sanitized rows only; this bundle never performs a network request. */
  data: readonly ChartDataPoint[];
  /** Use the compact overview layout (roughly 100px tall). */
  compact?: boolean;
  /** Explicit x-domain in Unix epoch milliseconds. */
  start?: number;
  /** Explicit x-domain in Unix epoch milliseconds. */
  end?: number;
  /** Locale used by the timestamp formatter. */
  locale?: string | string[];
  /** Optional application formatter for latency values. */
  formatValue?: (
    value: number | null,
    point: ChartDataPoint,
    index: number
  ) => string;
  /** Accessible name for the chart. */
  label?: string;
  /** Empty-state copy. */
  emptyLabel?: string;
}

export interface ChartHandle {
  update(nextProps: ChartProps): ChartHandle;
  destroy(): void;
}

interface PlotPoint extends ChartDataPoint {
  [key: string]: unknown;
  date: Date;
  /** Stable categorical key used by the Bklit bar primitive. */
  category: string;
  /** Failed values are rendered as the second, red Bklit series. */
  failure: number | null;
  /** Passing values occupy the primary bar series; failed rows leave it empty. */
  passing: number | null;
}

interface NormalizedChart {
  props: ChartProps;
  rows: PlotPoint[];
  start: number;
  end: number;
  navigable: number[];
}

const MAX_BAR_SLOTS = 2000;
// Keep mode changes responsive when the visible chart is replaced. Compact
// overview charts are static, while the detail chart gets a short reveal.
const RESPONSE_REVEAL_MS = 120;

const mountedCharts = new WeakMap<Element, ChartHandle>();
const reducedMotionQuery =
  typeof window === "undefined"
    ? null
    : window.matchMedia?.("(prefers-reduced-motion: reduce)") ?? null;

function finite(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function toPlotPoint(
  time: number,
  value: number | null,
  success: boolean | null,
  count?: number,
  intervalStart?: number,
  intervalEnd?: number
): PlotPoint {
  return {
    time,
    intervalStart,
    intervalEnd,
    value,
    success,
    count: finite(count) && count >= 0 ? count : undefined,
    date: new Date(time),
    category: String(time),
    failure: success === false ? value : null,
    passing: success === false ? null : value,
  };
}

/**
 * Bar charts use categorical bands. Fill empty bands at the measured cadence
 * so a long outage remains visibly longer than a short gap. Long windows are
 * bounded to 2000 time bins; each populated bin is a count-weighted mean and
 * retains a failure mark when any source check failed. A single source row is
 * kept at its original timestamp, so the bar tooltip can describe that check
 * rather than the synthetic slot around it.
 */
function densifyBarRows(rows: PlotPoint[], start: number, end: number): PlotPoint[] {
  if (rows.length < 2 || end <= start) return rows;

  const isSourcePoint = (point: PlotPoint) =>
    finite(point.value) ||
    point.success === true ||
    point.success === false ||
    (finite(point.count) && point.count > 0);
  const sourceRows = rows.filter(isSourcePoint);
  const measured = sourceRows.filter((point) => finite(point.value));
  if (measured.length < 2) return rows;
  const cadenceRows = sourceRows.length >= 2 ? sourceRows : measured;
  const deltas: number[] = [];
  for (let index = 1; index < cadenceRows.length; index += 1) {
    const delta = cadenceRows[index].time - cadenceRows[index - 1].time;
    if (delta > 0 && finite(delta)) deltas.push(delta);
  }
  if (deltas.length === 0) return rows;
  deltas.sort((a, b) => a - b);
  const cadence = deltas[Math.floor(deltas.length / 2)];
  const span = end - start;
  const requestedSlotCount = Math.max(1, Math.ceil(span / cadence));
  const slotCount = Math.min(MAX_BAR_SLOTS, requestedSlotCount);

  // A regular series already has one bar per observation. Keep it intact so
  // hover and keyboard readouts retain the source timestamp and value. We
  // still densify when an internal or domain-boundary cadence-sized gap needs
  // visible empty bars.
  const hasCadenceGap =
    deltas.some((delta) => delta > cadence * 1.5) ||
    sourceRows[0].time - start > cadence * 1.5 ||
    end - sourceRows.at(-1).time > cadence * 1.5;
  if (requestedSlotCount <= MAX_BAR_SLOTS && !hasCadenceGap) return rows;

  const width = span / slotCount;
  const buckets: PlotPoint[][] = Array.from({ length: slotCount }, () => []);

  for (const point of rows) {
    const index = Math.max(
      0,
      Math.min(slotCount - 1, Math.floor(((point.time - start) / span) * slotCount))
    );
    buckets[index].push(point);
  }

  return buckets.map((bucket, index) => {
    const slotTime = Math.min(end, start + (index + 0.5) * width);
    const sourcePoints = bucket.filter(isSourcePoint);
    const samples = sourcePoints.filter((point) => finite(point.value));
    const slotStart = start + index * width;
    const slotEnd = index === slotCount - 1 ? end : slotStart + width;
    if (sourcePoints.length === 0) {
      return toPlotPoint(slotTime, null, null, undefined, slotStart, slotEnd);
    }
    if (sourcePoints.length === 1) return sourcePoints[0];

    let totalWeight = 0;
    let weightedValue = 0;
    for (const sample of samples) {
      const weight = finite(sample.count) && sample.count > 0 ? sample.count : 1;
      totalWeight += weight;
      weightedValue += (sample.value ?? 0) * weight;
    }
    const statusPoints = sourcePoints.filter(
      (point) => point.success === true || point.success === false
    );
    const success = statusPoints.some((point) => point.success === false)
      ? false
      : statusPoints.length > 0 && statusPoints.every((point) => point.success === true)
        ? true
        : null;
    const count = bucket.reduce(
      (sum, point) =>
        sum +
        (finite(point.count) && point.count > 0
          ? point.count
          : isSourcePoint(point)
            ? 1
            : 0),
      0
    );
    return toPlotPoint(
      slotTime,
      totalWeight > 0 ? weightedValue / totalWeight : null,
      success,
      count,
      slotStart,
      slotEnd
    );
  });
}

function normalizeProps(input: ChartProps): NormalizedChart {
  const raw = Array.isArray(input.data) ? input.data : [];
  const baseRows = raw
    .map((point, index) => ({ point, index }))
    .filter(({ point }) => point && finite(point.time))
    .map(({ point }) => {
      const value = finite(point.value) && point.value >= 0 ? point.value : null;
      const success =
        point.success === true || point.success === false
          ? point.success
          : null;
      return {
        time: point.time,
        intervalStart:
          finite(point.intervalStart) && point.intervalStart <= point.time
            ? point.intervalStart
            : undefined,
        intervalEnd:
          finite(point.intervalEnd) && point.intervalEnd >= point.time
            ? point.intervalEnd
            : undefined,
        value,
        success,
        count: finite(point.count) && point.count >= 0 ? point.count : undefined,
        date: new Date(point.time),
        category: String(point.time),
        failure: success === false ? value : null,
        passing: success === false ? null : value,
      } satisfies PlotPoint;
    })
    .sort((a, b) => a.time - b.time);

  const times = baseRows.map((point) => point.time);
  const first = times[0] ?? 0;
  const last = times.at(-1) ?? first;
  const start = finite(input.start) ? input.start : first;
  const endCandidate = finite(input.end) ? input.end : last;
  const end = endCandidate >= start ? endCandidate : start;
  // Availability already arrives as the application's fixed set of visual
  // buckets. Keep those rows intact so each segment retains its source
  // interval, count, and three-state result; response bars still use the
  // cadence-aware gap filling above.
  const rows =
    input.type === "availability"
      ? baseRows
      : input.mode === "bar"
        ? densifyBarRows(baseRows, start, end)
        : baseRows;
  const navigable = rows
    .map((point, index) =>
      input.type === "availability" || finite(point.value) ? index : -1
    )
    .filter((index) => index >= 0);

  return { props: input, rows, start, end, navigable };
}

function defaultValue(value: number | null, locale: string | string[]): string {
  if (!finite(value)) return "No response data";
  return `${Math.round(value).toLocaleString(locale)} ms`;
}

function isCurrentLocalDay(date: Date): boolean {
  if (!Number.isFinite(date.getTime())) return false;
  const today = new Date();
  return (
    date.getFullYear() === today.getFullYear() &&
    date.getMonth() === today.getMonth() &&
    date.getDate() === today.getDate()
  );
}

function timeFormatter(
  locale: string | string[],
  compact: boolean,
  date?: Date
) {
  return new Intl.DateTimeFormat(locale, {
    ...(date && !isCurrentLocalDay(date)
      ? { month: "short", day: "numeric" }
      : {}),
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
    ...(compact ? {} : { second: "2-digit" }),
  });
}

function formatTime(date: Date, locale: string | string[], compact: boolean): string {
  return timeFormatter(locale, compact, date).format(date);
}

function intervalLabel(
  point: Record<string, unknown>,
  locale: string | string[],
  compact: boolean
): string | null {
  const start = finite(point.intervalStart) ? point.intervalStart : null;
  const end = finite(point.intervalEnd) ? point.intervalEnd : null;
  if (start == null || end == null || end <= start) return null;
  return `${formatTime(new Date(start), locale, compact)} – ${formatTime(
    new Date(end),
    locale,
    compact
  )}`;
}

function statusText(success: boolean | null | undefined): string {
  return success === false
    ? "Failed check"
    : success === true
      ? "Passed"
      : "No recorded check";
}

function statusClass(success: boolean | null | undefined): string {
  return success === false
    ? "is-failed"
    : success === true
      ? "is-passed"
      : "is-unknown";
}

function availabilityStatusText(success: boolean | null | undefined): string {
  return success === false
    ? "Failed check"
    : success === true
      ? "Passed"
      : "No/incomplete checks";
}

function availabilityCountLabel(
  point: Record<string, unknown>,
  locale: string | string[]
): string {
  const count = finite(point.count) && point.count >= 0 ? point.count : null;
  if (count == null) return "Check count unavailable";
  return `${count.toLocaleString(locale)} ${count === 1 ? "check" : "checks"}`;
}

function TooltipContent({
  point,
  props,
  locale,
}: {
  point: Record<string, unknown>;
  props: ChartProps;
  locale: string | string[];
}) {
  const time = finite(point.time) ? point.time : null;
  const value = finite(point.value) ? point.value : null;
  const success =
    point.success === true || point.success === false ? point.success : null;
  const isAvailability = props.type === "availability";
  const row: ChartDataPoint = {
    time: time ?? 0,
    intervalStart: finite(point.intervalStart) ? point.intervalStart : undefined,
    intervalEnd: finite(point.intervalEnd) ? point.intervalEnd : undefined,
    value,
    success,
    count: finite(point.count) ? point.count : undefined,
  };
  // Never pass a missing sample to the host formatter: existing status-page
  // formatters intentionally assume a finite latency, and formatting null as
  // `0 ms` would fabricate a measurement in the gap tooltip.
  const formatted = !isAvailability && finite(value)
    ? props.formatValue
      ? props.formatValue(value, row, finite(point.index) ? point.index : 0)
      : defaultValue(value, locale)
    : isAvailability
      ? null
      : defaultValue(null, locale);
  const isCompact = Boolean(props.compact);
  // Availability can use 15-second buckets in the shortest range. Keep
  // seconds in its interval readout so both endpoints remain distinguishable;
  // response compact tooltips retain their existing minute-level formatting.
  const timeCompact = isAvailability ? false : isCompact;
  const interval = intervalLabel(point, locale, timeCompact);
  const timestamp = interval ??
    (time != null ? formatTime(new Date(time), locale, timeCompact) : "Unknown time");
  const valueLabel = isAvailability
    ? availabilityCountLabel(point, locale)
    : finite(point.count) && point.count > 1 && finite(value)
      ? `Average response ${formatted}`
      : formatted;

  return (
    <div className="bklit-tooltip-content">
      <time
        dateTime={
          finite(point.intervalStart)
            ? new Date(point.intervalStart).toISOString()
            : time != null
              ? new Date(time).toISOString()
              : undefined
        }
      >
        {timestamp}
      </time>
      <strong>{valueLabel}</strong>
      <span className={statusClass(success)}>
        <i aria-hidden="true" />
        {isAvailability ? availabilityStatusText(success) : statusText(success)}
      </span>
    </div>
  );
}

function tooltipFor(
  props: ChartProps,
  locale: string | string[]
): (args: { point: Record<string, unknown>; index: number }) => ReactElement {
  return ({ point, index }) => (
    <TooltipContent
      locale={locale}
      point={{ ...point, index }}
      props={props}
    />
  );
}

function chartTransition(durationMs = RESPONSE_REVEAL_MS) {
  if (reducedMotionQuery?.matches || durationMs <= 0) {
    return { type: "tween" as const, duration: 0 };
  }
  return {
    type: "tween" as const,
    duration: durationMs / 1000,
    ease: "easeOut" as const,
  };
}

function chartStyle(compact: boolean) {
  return {
    height: "100%",
    aspectRatio: "auto",
    ...(compact ? { minHeight: 92 } : { minHeight: 238 }),
  };
}

function AreaLatencyChart({ chart }: { chart: NormalizedChart }) {
  const { props, rows, start, end } = chart;
  const locale = props.locale ?? "en-US";
  const compact = Boolean(props.compact);
  const animationDuration =
    compact || reducedMotionQuery?.matches ? 0 : RESPONSE_REVEAL_MS;
  const tooltip = useMemo(() => tooltipFor(props, locale), [props, locale]);
  const domain: [Date, Date] = [new Date(start), new Date(end || start + 1)];

  return (
    <AreaChart
    aspectRatio={compact ? "6 / 1" : "16 / 6"}
      animationDuration={animationDuration}
      className="bklit-series"
      data={rows}
      enterTransition={chartTransition(animationDuration)}
        margin={
          compact
            ? { top: 8, right: 5, bottom: 6, left: 5 }
          : { top: 18, right: 24, bottom: 56, left: 56 }
      }
      style={chartStyle(compact)}
      xDataKey="date"
      xDomain={domain}
      xDomainSlotCount={rows.length}
      yDomainTween
      yDomainTweenDuration={animationDuration}
    >
      <Area
        animate={animationDuration > 0}
        dataKey="value"
        fill="var(--chart-line-primary)"
        fillOpacity={compact ? 0.25 : 0.28}
        fadeEdges={compact ? false : true}
        gradientToOpacity={0}
        showMarkers={!compact && rows.length <= 96}
        showHighlight
        stroke="var(--chart-line-primary)"
        strokeWidth={compact ? 1.75 : 2.25}
      />
      {!compact && (
        <Grid
          fadeHorizontal={false}
          horizontal
          numTicksRows={4}
          stroke="var(--chart-grid)"
          strokeDasharray="2 4"
          vertical={false}
        />
      )}
      {!compact && (
        <YAxis
          formatLargeNumbers={false}
          formatValue={(value) => `${Math.round(value).toLocaleString(locale)} ms`}
          numTicks={3}
        />
      )}
      {!compact && (
        <XAxis
          formatLabel={(date) => formatTime(date, locale, true)}
          numTicks={3}
          tickMode="domain"
        />
      )}
      <Area
        animate={false}
        dataKey="failure"
        fill="transparent"
        fillOpacity={0}
        markers={{
          fill: "var(--chart-line-failure)",
          radius: compact ? 3.5 : 5,
          stroke: "var(--chart-line-failure)",
          strokeWidth: 1.5,
        }}
        showHighlight={false}
        showLine={false}
        showMarkers
        stroke="transparent"
      />
      <ChartTooltip
        className="bklit-tooltip-panel"
        content={tooltip}
        damping={18}
        placement="below"
        showCrosshair
        showDatePill={false}
        showDots={!compact}
      />
    </AreaChart>
  );
}

function BarLatencyChart({ chart }: { chart: NormalizedChart }) {
  const { props, rows } = chart;
  const locale = props.locale ?? "en-US";
  const compact = Boolean(props.compact);
  const animationDuration =
    compact || reducedMotionQuery?.matches ? 0 : RESPONSE_REVEAL_MS;
  const tooltip = useMemo(() => tooltipFor(props, locale), [props, locale]);

  return (
    <BarChart
      aspectRatio={compact ? "6 / 1" : "16 / 6"}
      animationDuration={animationDuration}
      barGap={compact ? 0.1 : 0.16}
      className="bklit-series"
      data={rows}
      enterTransition={chartTransition(animationDuration)}
        margin={
          compact
            ? { top: 8, right: 5, bottom: 6, left: 5 }
          : { top: 18, right: 24, bottom: 56, left: 56 }
      }
      revealSignature=""
      stacked
      xDataKey="category"
    >
      <Bar
        animate={animationDuration > 0}
        animationType="grow"
        dataKey="passing"
        fill="var(--chart-line-primary)"
        lineCap="round"
      />
      <Bar
        animate={animationDuration > 0}
        animationType="grow"
        dataKey="failure"
        fill="var(--chart-line-failure)"
        lineCap="round"
      />
      {!compact && (
        <Grid
          fadeHorizontal={false}
          horizontal
          numTicksRows={4}
          stroke="var(--chart-grid)"
          strokeDasharray="2 4"
          vertical={false}
        />
      )}
      {!compact && (
        <YAxis
          formatLargeNumbers={false}
          formatValue={(value) => `${Math.round(value).toLocaleString(locale)} ms`}
          numTicks={3}
        />
      )}
      {!compact && (
        <BarXAxis
          formatLabel={(label) => {
            const time = Number(label);
            return finite(time)
              ? formatTime(new Date(time), locale, true)
              : label;
          }}
          maxLabels={3}
        />
      )}
      <ChartTooltip
        className="bklit-tooltip-panel"
        content={tooltip}
        damping={18}
        placement="below"
        showCrosshair
        showDatePill={false}
        showDots={!compact}
      />
    </BarChart>
  );
}

function AvailabilityBarChart({ chart }: { chart: NormalizedChart }) {
  const { props, rows } = chart;
  const locale = props.locale ?? "en-US";
  const tooltip = useMemo(() => tooltipFor(props, locale), [props, locale]);
  const data = useMemo(
    () =>
      rows.map((point) => ({
        ...point,
        availabilityFailure: point.success === false ? 1 : null,
        availabilityPassing: point.success === true ? 1 : null,
        availabilityUnknown: point.success == null ? 1 : null,
      })),
    [rows]
  );

  return (
    <BarChart
      aspectRatio="auto"
      animationDuration={0}
      barGap={0.16}
      className="bklit-series"
      data={data}
      enterTransition={{ type: "tween", duration: 0 }}
      margin={{ bottom: 0, left: 0, right: 0, top: 0 }}
      revealSignature=""
      stacked
      xDataKey="category"
    >
      <Bar
        animate={false}
        dataKey="availabilityPassing"
        fill="var(--chart-line-primary)"
        lineCap="round"
      />
      <Bar
        animate={false}
        dataKey="availabilityFailure"
        fill="var(--chart-line-failure)"
        lineCap="round"
      />
      <Bar
        animate={false}
        dataKey="availabilityUnknown"
        fill="var(--chart-line-unknown)"
        lineCap="round"
      />
      <ChartTooltip
        className="bklit-tooltip-panel"
        content={tooltip}
        damping={0}
        placement="below"
        showCrosshair
        showDatePill={false}
        showDots={false}
      />
    </BarChart>
  );
}

function KeyboardReadout({
  chart,
  activeIndex,
  id,
}: {
  chart: NormalizedChart;
  activeIndex: number | null;
  id: string;
}) {
  if (activeIndex == null) return null;
  const point = chart.rows[activeIndex];
  if (!point) return null;
  const locale = chart.props.locale ?? "en-US";
  const isAvailability = chart.props.type === "availability";
  const format = chart.props.formatValue ?? ((value: number | null) => defaultValue(value, locale));
  const value = isAvailability
    ? availabilityCountLabel(point, locale)
    : finite(point.value)
      ? format(point.value, point, activeIndex)
      : defaultValue(null, locale);
  const compact = Boolean(chart.props.compact);
  const timeCompact = isAvailability ? false : compact;
  const timestamp =
    intervalLabel(point, locale, timeCompact) ??
    formatTime(point.date, locale, timeCompact);
  const valueLabel = isAvailability
    ? value
    : finite(point.count) && point.count > 1 && finite(point.value)
      ? `Average response ${value}`
      : value;
  const status = isAvailability
    ? availabilityStatusText(point.success)
    : statusText(point.success);
  return (
    <div aria-live="polite" className="bklit-keyboard-readout" id={id}>
      {timestamp} · {valueLabel} · {status}
    </div>
  );
}

function ChartIsland({ props }: { props: ChartProps }) {
  const chart = useMemo(() => normalizeProps(props), [props]);
  const [activeIndex, setActiveIndex] = useState<number | null>(null);
  const readoutId = `bklit-keyboard-readout-${useId().replace(/:/g, "")}`;
  const locale = props.locale ?? "en-US";
  const compact = Boolean(props.compact);
  const availability = props.type === "availability";
  const hasRows = availability
    ? chart.rows.length > 0
    : chart.navigable.length > 0;

  useEffect(() => {
    if (activeIndex != null && !chart.navigable.includes(activeIndex)) {
      setActiveIndex(null);
    }
  }, [activeIndex, chart.navigable]);

  const onKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      const { key } = event;
      if (!(key === "ArrowLeft" || key === "ArrowRight" || key === "Home" || key === "End")) {
        return;
      }
      event.preventDefault();
      const indices = chart.navigable;
      if (indices.length === 0) return;
      const current = activeIndex == null ? -1 : indices.indexOf(activeIndex);
      const next =
        key === "Home"
          ? 0
          : key === "End"
            ? indices.length - 1
            : Math.max(
                0,
                Math.min(
                  indices.length - 1,
                  current < 0 ? (key === "ArrowLeft" ? indices.length - 1 : 0) : current + (key === "ArrowLeft" ? -1 : 1)
                )
              );
      setActiveIndex(indices[next]);
    },
    [activeIndex, chart.navigable]
  );

  const label = props.label ?? (availability ? "Recorded availability" : "Recorded response time");
  const emptyLabel =
    props.emptyLabel ??
    (availability
      ? "No availability observations in this period."
      : "No response-time observations in this period.");
  const interactionLabel = availability
    ? "Use the arrow keys to inspect availability segments."
    : "Use the arrow keys to inspect recorded checks.";
  const layoutClass = availability
    ? "bklit-availability"
    : compact
      ? "bklit-mini"
      : "bklit-detail";

  return (
    <div
      aria-describedby={activeIndex == null ? undefined : readoutId}
      aria-label={`${label}. ${interactionLabel}`}
      className={`bklit-mount ${layoutClass} ${props.mode === "bar" ? "bklit-bars" : "bklit-area"}`}
      data-bklit-chart="true"
      onKeyDown={onKeyDown}
      tabIndex={0}
    >
      {hasRows ? (
        availability ? (
          <AvailabilityBarChart chart={chart} />
        ) : props.mode === "bar" ? (
          <BarLatencyChart chart={chart} />
        ) : (
          <AreaLatencyChart chart={chart} />
        )
      ) : (
        <div className="bklit-empty" role="status">
          {emptyLabel}
        </div>
      )}
      <KeyboardReadout activeIndex={activeIndex} chart={chart} id={readoutId} />
    </div>
  );
}

function renderInto(target: Element, props: ChartProps, root: Root) {
  // React 19 schedules root.render; flushSync keeps the mount/update contract
  // synchronous for the legacy vanilla renderer and its focus restoration.
  flushSync(() => root.render(<ChartIsland props={props} />));
}

export function renderChart(target: Element, props: ChartProps): ChartHandle {
  if (!(target instanceof Element)) {
    throw new TypeError("renderChart target must be a DOM Element");
  }
  const previous = mountedCharts.get(target);
  if (previous) {
    previous.update(props);
    return previous;
  }

  const root = createRoot(target);
  let current = props;
  let destroyed = false;
  const handle: ChartHandle = {
    update(nextProps) {
      if (destroyed) return handle;
      current = nextProps;
      renderInto(target, current, root);
      return handle;
    },
    destroy() {
      if (destroyed) return;
      destroyed = true;
      mountedCharts.delete(target);
      flushSync(() => root.unmount());
    },
  };
  mountedCharts.set(target, handle);
  renderInto(target, current, root);
  return handle;
}

export function unmountChart(target: Element): void {
  mountedCharts.get(target)?.destroy();
}

export default renderChart;
