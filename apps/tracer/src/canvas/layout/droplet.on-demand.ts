/**
 * The droplet split (TASTE section 3): a window divides like a water droplet. Two rounded shapes
 * stretch apart, stay joined by a neck of liquid that thins, snap apart, overshoot a little and
 * wobble to rest; the shapes are the windows' own frames, so the outlines really fuse.
 *
 * How it is drawn. The two shapes are not CSS boxes: for the length of the animation a small WebGL
 * layer (created on start, destroyed at the end) draws the *smooth union* of two rounded-box
 * distance fields, filled with the window material and edged with the window hairline. A smooth
 * union is what makes a neck: while the shapes are closer than `K` px the field bridges them with a
 * concave fillet that thins as they separate and lets go at about `K`. Nothing is filtered or
 * blurred, and the window contents are ordinary DOM above the layer: text is never scaled, only
 * translated with its shape. The new window's content stays hidden until the neck has broken, then
 * fades in.
 *
 * Motion. One spring drives the gap between the two lobes and is retargeted mid-flight. Pull: a soft
 * spring aimed just past the break distance, so the gap crawls off the start (the neck resists) and
 * lingers as it thins; the facing corners round off with the pull (surface tension), so the bridge
 * narrows to a neck. When the gap passes 1.2 K the neck lets go: the same spring is stiffened and aimed
 * at the resting gap, and the velocity it carries squeezes the gap below its resting size for an
 * instant (the lobes nearly touch again, a new short neck forms and lets go) before they wobble to
 * rest. About 600 ms. Reduced motion: the new window only fades in.
 *
 * The frames sit at their final layout positions throughout (the caller laid the column out first);
 * the animation only moves the contents with their shapes (translate) and clips the content of a
 * shape that is shorter than its frame. The layer is at most a few thousand pixels, one draw call.
 */
import { scrollerOf } from "./columns";
import { Spring } from "../../../../../packages/ui/src/spring";

/** Limits `v` to the range `lo`–`hi`. */
const clamp = (v: number, lo: number, hi: number): number => Math.max(lo, Math.min(hi, v));
/** A smooth 0-to-1 ramp of `v` between `a` and `b` (smoothstep): 0 at or below `a`, 1 at or above `b`, with a gentle start and end. */
const smooth = (a: number, b: number, v: number): number => { const t = clamp((v - a) / (b - a), 0, 1); return t * t * (3 - 2 * t); };

/** The neck distance in pixels: the shapes are joined while closer than this and the neck lets go at about this gap. */
const K = 64; // how far apart (px) the shapes are when the neck lets go
// Scale frequency, preserving damping ratios and the physical overshoot. The
// two phases settle in about 600 ms, leaving room for missed rendering frames
// inside the one-second interaction budget [41][70][81].
const MOTION_RATE = 1.5;
/** Scales a spring's stiffness and damping by `MOTION_RATE`, which speeds the motion up and keeps the damping ratio (so the overshoot is the same). */
const physics = (stiffness: number, damping: number) => ({ stiffness: stiffness * MOTION_RATE ** 2, damping: damping * MOTION_RATE });
/** The vertex shader: draws one full-layer quad. */
const VERT = `attribute vec2 a; void main() { gl_Position = vec4(a, 0.0, 1.0); }`;
/**
 * The fragment shader: the smooth union of two rounded boxes (a different radius for each corner), filled with the window material
 * and edged with a hairline. Where the boxes are closer than `uK` the union has a neck.
 */
const FRAG = `precision highp float;
uniform vec2 uRes; uniform float uDpr; uniform vec4 uA; uniform vec4 uB; uniform vec4 uRA; uniform vec4 uRB; uniform float uR; uniform float uK; uniform vec4 uFill; uniform vec4 uLine;
// A rounded box with a radius per corner (right side: bottom, top; left side: bottom, top).
float box(vec2 p, vec4 r, vec4 c) { vec2 d = p - r.xy; vec4 k = c; k.xy = d.x > 0.0 ? k.xy : k.zw; float rr = d.y > 0.0 ? k.x : k.y; vec2 q = abs(d) - r.zw + rr; return min(max(q.x, q.y), 0.0) + length(max(q, 0.0)) - rr; }
void main() {
  vec2 p = vec2(gl_FragCoord.x, uRes.y - gl_FragCoord.y) / uDpr;
  float d1 = box(p, uA, uRA), d2 = box(p, uB, uRB);
  float h = clamp(0.5 + 0.5 * (d2 - d1) / uK, 0.0, 1.0);
  float d = mix(d2, d1, h) - uK * h * (1.0 - h);
  float inside = 1.0 - smoothstep(-0.5, 0.5, d);
  float ring = smoothstep(-1.5, -0.5, d);
  vec4 fill = uFill * inside;
  vec4 line = uLine * inside * ring;
  gl_FragColor = line + fill * (1.0 - line.a);
}`;

/** Cache of resolved colours, cleared when it passes 32 entries. */
const rgbaCache = new Map<string, [number, number, number, number]>();
/** The resolved rgba (premultiplied, 0..1) of any CSS colour string, through a 1 px 2D canvas (read back once per colour). */
function rgba(css: string): [number, number, number, number] {
  const known = rgbaCache.get(css);
  if (known) return known;
  const c = document.createElement("canvas");
  c.width = c.height = 1;
  const g = c.getContext("2d", { willReadFrequently: true })!;
  g.clearRect(0, 0, 1, 1);
  g.fillStyle = css;
  g.fillRect(0, 0, 1, 1);
  const [r, gg, b, a] = g.getImageData(0, 0, 1, 1).data as unknown as number[];
  const al = a! / 255;
  const out: [number, number, number, number] = [(r! / 255) * al, (gg! / 255) * al, (b! / 255) * al, al];
  if (rgbaCache.size > 32) rgbaCache.clear();
  rgbaCache.set(css, out);
  return out;
}

/**
 * The GL context and the compiled program. Creating a context is a round trip to the GPU process and a shader link is
 * another, both blocking the page's main thread (measured: about 17 ms of the first frame of a split, where the budget of a
 * frame is 8.3 ms). A device with a fine pointer (a desktop, which has memory to spare and is the one that runs at 120 Hz)
 * therefore keeps ONE parked context between splits, with a 1 px drawing buffer, and builds it before the first split when
 * the browser is idle (`warmContext`). A touch device still creates the context for the length of the animation and
 * destroys it at the end (the iOS memory rule, README). The context is dropped when the page is hidden (`endSplit`).
 */
interface Gl { canvas: HTMLCanvasElement; gl: WebGLRenderingContext; prog: WebGLProgram; U: Record<string, WebGLUniformLocation> }
/** The parked GL context kept between splits on a fine-pointer device; `undefined` on touch or before `warmContext` has run. */
let pooled: Gl | undefined;
/** True on a device with a fine pointer, which keeps one parked GL context between splits. */
const keepContext = (): boolean => matchMedia("(pointer: fine)").matches;
/** The names of the shader's uniforms, looked up once when the program is built. */
const UNIFORMS = ["uRes", "uDpr", "uR", "uK", "uFill", "uLine", "uA", "uB", "uRA", "uRB"] as const;

/**
 * Creates the layer canvas, the GL context and the compiled program, and draws one pixel so the driver finishes compiling the shader now
 * and not during the first animated frame. Returns `undefined` when WebGL is not available.
 */
function createGl(): Gl | undefined {
  const canvas = document.createElement("canvas");
  canvas.className = "cl-goo";
  const gl = canvas.getContext("webgl", { alpha: true, premultipliedAlpha: true, antialias: false });
  if (!gl) return undefined;
  const compile = (type: number, src: string): WebGLShader => { const sh = gl.createShader(type)!; gl.shaderSource(sh, src); gl.compileShader(sh); return sh; };
  const prog = gl.createProgram()!;
  gl.attachShader(prog, compile(gl.VERTEX_SHADER, VERT));
  gl.attachShader(prog, compile(gl.FRAGMENT_SHADER, FRAG));
  gl.linkProgram(prog);
  gl.useProgram(prog);
  const buf = gl.createBuffer()!;
  gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
  const loc = gl.getAttribLocation(prog, "a");
  gl.enableVertexAttribArray(loc);
  gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
  gl.enable(gl.BLEND);
  gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);
  const U = Object.fromEntries(UNIFORMS.map((n) => [n, gl.getUniformLocation(prog, n)!])) as Gl["U"];
  canvas.width = canvas.height = 1;
  // Drivers may defer shader compilation until the first draw. Prepare that
  // single pixel with the context so animated frames only submit warm drawing
  // work. Desktop context preparation already runs during browser idle time.
  gl.viewport(0, 0, 1, 1);
  gl.uniform2f(U.uRes ?? null, 1, 1);
  gl.uniform1f(U.uDpr ?? null, 1);
  gl.uniform1f(U.uK ?? null, K);
  gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
  gl.finish();
  return { canvas, gl, prog, U };
}

/** Gives up the parked GL context, if there is one. */
const dropContext = (): void => {
  pooled?.gl.getExtension("WEBGL_lose_context")?.loseContext();
  pooled = undefined;
};
/** Builds the parked context when the browser is idle (fine pointers only). */
export const warmContext = (): void => { if (!pooled && keepContext()) pooled = createGl(); };

/** Optional counters for measurement: frames drawn, total and worst draw time in milliseconds, and a trace of `[time, gap]` pairs. */
export interface SplitProbe { frames: number; drawMs: number; maxDrawMs: number; trace?: Array<[number, number]> }

/** The finisher of the animation that is running, if any: there is never more than one GL context alive. */
let running: (() => void) | undefined;
/** Ends the running split at once (its layer and GL context are destroyed). A hidden page calls this. */
export const endSplit = (): void => { running?.(); lingering?.(); dropContext(); };
/** The last animation's layer while it waits two frames to be destroyed (see `finish`); the next one destroys it first. */
let lingering: (() => void) | undefined;

/**
 * Plays the split of `a` and `b`, already in their final places. `down`: b is below a in the same column
 * (the layer lives in that column). `right`: b is in the next column to the right of a (the layer lives in
 * `host`, the element both columns sit in). Both directions are the same drawing, rotated a quarter turn.
 */
export function dropletSplit(a: HTMLElement, b: HTMLElement, direction: "down" | "right" = "down", host?: HTMLElement, probe?: SplitProbe): Promise<void> {
  running?.(); lingering?.(); // one context at a time (and one layer): a split still playing, or a layer still lingering, ends first; the parked context stays
  probe ??= (window as unknown as { __splitProbe?: SplitProbe }).__splitProbe;
  const t00 = performance.now();
  return new Promise((resolve) => {
    const content = (w: HTMLElement): HTMLElement[] => [...w.querySelectorAll<HTMLElement>(":scope > .ui-window-head, :scope > .ui-window-body, :scope > .ui-window-lock, :scope > .ui-window-resize")];
    const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) {
      b.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 180, easing: "ease-out" }).onfinish = () => resolve();
      return;
    }
    // A column of a group has no box of its own (D212): its scroller is the box the split happens in.
    const column = direction === "right" ? host! : scrollerOf(a.parentElement as HTMLElement);
    const right = direction === "right";
    // Rects relative to the layer's parent, in its own (unzoomed) pixels, whatever camera zoom is applied above it.
    const origin = column.getBoundingClientRect();
    const zoom = column.offsetWidth ? origin.width / column.offsetWidth : 1;
    const rectOf = (n: HTMLElement): { x: number; y: number; w: number; h: number } => {
      if (!right) return { x: n.offsetLeft, y: n.offsetTop, w: n.offsetWidth, h: n.offsetHeight };
      const r = n.getBoundingClientRect();
      return { x: (r.left - origin.left) / zoom, y: (r.top - origin.top) / zoom, w: n.offsetWidth, h: n.offsetHeight };
    };
    const ar = rectOf(a), br = rectOf(b);
    // `along` runs from a to b; `across` is the other axis.
    const g = right ? br.x - (ar.x + ar.w) : br.y - (ar.y + ar.h); // the final gap
    const H = right ? br.x + br.w - ar.x : br.y + br.h - ar.y; // the old window's footprint along the axis
    const css = right
      ? { x: ar.x - 6, y: Math.min(ar.y, br.y) - 6, w: H + 12, h: Math.max(ar.y + ar.h, br.y + br.h) - Math.min(ar.y, br.y) + 12 }
      : { x: ar.x - 6, y: ar.y - 6, w: ar.w + 12, h: H + 12 };
    const dpr = Math.min(devicePixelRatio || 1, 2);
    if (pooled?.gl.isContextLost()) pooled = undefined;
    const own = pooled ?? createGl();
    if (!own) { b.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 180, easing: "ease-out" }).onfinish = () => resolve(); return; }
    if (keepContext()) pooled = own;
    const { canvas, gl, U: locs } = own;
    canvas.width = Math.round(css.w * dpr);
    canvas.height = Math.round(css.h * dpr);
    canvas.style.cssText = `position:absolute;left:${css.x}px;top:${css.y}px;width:${css.w}px;height:${css.h}px;pointer-events:none`;
    const U = (n: string): WebGLUniformLocation => locs[n as (typeof UNIFORMS)[number]]!;
    const cs = getComputedStyle(a);
    const dbg = (window as unknown as { __gooDebug?: boolean }).__gooDebug;
    const fill = dbg ? ([0.8, 0.1, 0.1, 1] as [number, number, number, number]) : rgba(cs.backgroundColor === "rgba(0, 0, 0, 0)" ? "rgba(13,14,16,0.9)" : cs.backgroundColor);
    const line = rgba(getComputedStyle(document.documentElement).getPropertyValue("--overlay-line").trim() || "rgba(255,255,255,0.09)");
    const radius = Number.parseFloat(cs.borderTopLeftRadius) || 18;
    gl.viewport(0, 0, canvas.width, canvas.height);
    gl.uniform2f(U("uRes"), canvas.width, canvas.height);
    gl.uniform1f(U("uDpr"), dpr);
    gl.uniform1f(U("uR"), radius);
    gl.uniform1f(U("uK"), K);
    gl.uniform4f(U("uFill"), fill[0], fill[1], fill[2], fill[3]);
    gl.uniform4f(U("uLine"), line[0], line[1], line[2], line[3]);

    if (right) column.prepend(canvas); else column.insertBefore(canvas, a);
    for (const w of [a, b]) { w.dataset.goo = ""; }
    const partsA = content(a), partsB = content(b);
    for (const p of partsB) p.style.opacity = "0";
    const top = right ? ar.x : ar.y, bottom = top + H;
    const extent = (r: { w: number; h: number }): number => (right ? r.w : r.h); // along the axis

    let brokeAt = 0;
    const draw = (gap: number): void => {
      const t0 = performance.now();
      gap = Math.max(0, gap);
      const hA = (H - gap) / 2;
      // Surface tension: while the lobes are pulled past their resting gap, their facing corners round off,
      // so the bridge between them narrows to a neck.
      const pull = brokeAt ? clamp((gap - g) / (K - g), 0, 1) : smooth(0, 1, gap / (K * 0.55));
      const rf = radius + pull * (Math.min(right ? ar.h : ar.w, hA) * 0.5 - radius);
      // Corner order: right-bottom, right-top, left-bottom, left-top. The facing corners are the rounded ones.
      if (right) { gl.uniform4f(U("uRA"), rf, rf, radius, radius); gl.uniform4f(U("uRB"), radius, radius, rf, rf); }
      else { gl.uniform4f(U("uRA"), rf, radius, rf, radius); gl.uniform4f(U("uRB"), radius, rf, radius, rf); }
      if (right) {
        gl.uniform4f(U("uA"), top - css.x + hA / 2, ar.y + ar.h / 2 - css.y, hA / 2, ar.h / 2);
        gl.uniform4f(U("uB"), bottom - css.x - hA / 2, br.y + br.h / 2 - css.y, hA / 2, br.h / 2);
      } else {
        const cx = ar.w / 2 + 6;
        gl.uniform4f(U("uA"), cx, top - css.y + hA / 2, ar.w / 2, hA / 2);
        gl.uniform4f(U("uB"), cx, bottom - css.y - hA / 2, br.w / 2, hA / 2);
      }
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
      // Contents ride with their shapes: A stays at its start, B follows its lobe's leading edge.
      const cutA = Math.max(0, extent(ar) - hA), cutB = Math.max(0, extent(br) - hA);
      if (right) {
        b.style.transform = `translateX(${bottom - hA - br.x}px)`;
        a.style.clipPath = cutA > 0.5 ? `inset(0 ${cutA}px 0 0)` : "";
        b.style.clipPath = cutB > 0.5 ? `inset(0 ${cutB}px 0 0)` : "";
      } else {
        b.style.transform = `translateY(${bottom - hA - br.y}px)`;
        a.style.clipPath = cutA > 0.5 ? `inset(0 0 ${cutA}px 0)` : "";
        b.style.clipPath = cutB > 0.5 ? `inset(0 0 ${cutB}px 0)` : "";
      }
      // The new content appears after the neck has broken.
      const show = brokeAt ? smooth(0, 150, performance.now() - brokeAt) : 0;
      for (const p of partsB) p.style.opacity = String(show);
      probe?.trace?.push([Math.round(performance.now() - t00), Math.round(gap * 10) / 10]);
      if (probe) { const dt = performance.now() - t0; probe.frames++; probe.drawMs += dt; probe.maxDrawMs = Math.max(probe.maxDrawMs, dt); }
    };

    let finished = false;
    const finish = (): void => {
      if (finished) return;
      finished = true;
      if (running === finish) running = undefined;
      spring.set(g, true);
      // Hand back to the real windows without a gap: each frame gets its own fill, border and contents back first
      // (`data-goo-end` keeps its border from fading in from transparent), and the silhouette stays for two frames so
      // the first frame drawn with the real windows already has them painted. Destroying the layer in the same frame
      // the windows return left a frame with neither, which showed as a flash.
      for (const w of [a, b]) { w.dataset.gooEnd = ""; delete w.dataset.goo; w.style.transform = ""; w.style.clipPath = ""; }
      for (const p of [...partsA, ...partsB]) p.style.opacity = "";
      const done = (): void => {
        if (lingering === done) lingering = undefined;
        for (const w of [a, b]) delete w.dataset.gooEnd;
        canvas.remove();
        // A desktop parks the context for the next split (1 px buffer); otherwise it ends with the animation.
        if (pooled === own) { canvas.width = canvas.height = 1; } else { gl.getExtension("WEBGL_lose_context")?.loseContext(); }
        resolve();
      };
      if (document.hidden) done();
      else { lingering = done; requestAnimationFrame(() => requestAnimationFrame(() => { if (lingering === done) done(); })); }
    };
    // One spring for the gap, retargeted mid-flight. Pull: a soft spring aimed far past the break distance, so
    // the gap crawls off the start (the neck resists) and speeds up as it thins. When the gap passes K the
    // neck lets go: the same spring is stiffened and aimed at the resting gap, and its velocity carries the
    // lobes through it (the overshoot, a squeeze below the resting gap) before they wobble to rest.
    const spring = new Spring(0, (gap) => {
      if (!brokeAt && gap >= K * 1.2) {
        brokeAt = performance.now();
        spring.configure(physics(500, 28));
        spring.set(g);
      }
      if (brokeAt && gap === g) { finish(); return; }
      draw(gap);
    }, physics(90, 15));
    spring.restDelta = 0.3; // sub-pixel: the last wobble is not worth another half second of frames
    spring.restVelocity = 3;
    running = finish;
    draw(0);
    requestAnimationFrame(() => { if (!finished) spring.set(K * 1.3); });
  });
}
