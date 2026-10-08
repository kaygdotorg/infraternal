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
import { Spring } from "../../../packages/ui/src/spring";

const clamp = (v: number, lo: number, hi: number): number => Math.max(lo, Math.min(hi, v));
const smooth = (a: number, b: number, v: number): number => { const t = clamp((v - a) / (b - a), 0, 1); return t * t * (3 - 2 * t); };

const K = 64; // how far apart (px) the shapes are when the neck lets go
const VERT = `attribute vec2 a; void main() { gl_Position = vec4(a, 0.0, 1.0); }`;
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

/** The resolved rgba (premultiplied, 0..1) of any CSS colour string, through a 1 px 2D canvas. */
function rgba(css: string): [number, number, number, number] {
  const c = document.createElement("canvas");
  c.width = c.height = 1;
  const g = c.getContext("2d", { willReadFrequently: true })!;
  g.clearRect(0, 0, 1, 1);
  g.fillStyle = css;
  g.fillRect(0, 0, 1, 1);
  const [r, gg, b, a] = g.getImageData(0, 0, 1, 1).data as unknown as number[];
  const al = a! / 255;
  return [(r! / 255) * al, (gg! / 255) * al, (b! / 255) * al, al];
}

export interface SplitProbe { frames: number; drawMs: number; maxDrawMs: number; trace?: Array<[number, number]> }

/** Plays the split of `a` (top) and `b` (bottom), already in their final places in the column. */
export function dropletSplit(a: HTMLElement, b: HTMLElement, probe?: SplitProbe): Promise<void> {
  probe ??= (window as unknown as { __splitProbe?: SplitProbe }).__splitProbe;
  const t00 = performance.now();
  return new Promise((resolve) => {
    const content = (w: HTMLElement): HTMLElement[] => [...w.querySelectorAll<HTMLElement>(":scope > .ui-window-head, :scope > .ui-window-body, :scope > .ui-window-lock, :scope > .ui-window-resize")];
    const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) {
      b.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 180, easing: "ease-out" }).onfinish = () => resolve();
      return;
    }
    const column = a.parentElement!;
    const ar = { x: a.offsetLeft, y: a.offsetTop, w: a.offsetWidth, h: a.offsetHeight };
    const br = { x: b.offsetLeft, y: b.offsetTop, w: b.offsetWidth, h: b.offsetHeight };
    const g = br.y - (ar.y + ar.h); // the final gap
    const H = br.y + br.h - ar.y; // the old window's footprint
    const css = { x: ar.x - 6, y: ar.y - 6, w: ar.w + 12, h: H + 12 };
    const dpr = Math.min(devicePixelRatio || 1, 2);
    const canvas = document.createElement("canvas");
    canvas.className = "cl-goo";
    canvas.width = Math.round(css.w * dpr);
    canvas.height = Math.round(css.h * dpr);
    canvas.style.cssText = `position:absolute;left:${css.x}px;top:${css.y}px;width:${css.w}px;height:${css.h}px;pointer-events:none`;
    const gl = canvas.getContext("webgl", { alpha: true, premultipliedAlpha: true, antialias: false });
    if (!gl) { b.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 180, easing: "ease-out" }).onfinish = () => resolve(); return; }
    const compile = (type: number, src: string): WebGLShader => { const s = gl.createShader(type)!; gl.shaderSource(s, src); gl.compileShader(s); return s; };
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
    const U = (n: string): WebGLUniformLocation => gl.getUniformLocation(prog, n)!;
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
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);

    column.insertBefore(canvas, a);
    for (const w of [a, b]) { w.dataset.goo = ""; }
    const partsA = content(a), partsB = content(b);
    for (const p of partsB) p.style.opacity = "0";
    const top = ar.y, bottom = ar.y + H;

    let brokeAt = 0;
    const draw = (gap: number): void => {
      const t0 = performance.now();
      gap = Math.max(0, gap);
      const hA = (H - gap) / 2;
      // Surface tension: while the lobes are pulled past their resting gap, their facing corners round off,
      // so the bridge between them narrows to a neck.
      const pull = brokeAt ? clamp((gap - g) / (K - g), 0, 1) : smooth(0, 1, gap / (K * 0.55));
      const rf = radius + pull * (Math.min(ar.w, hA) * 0.5 - radius);
      gl.uniform4f(U("uRA"), rf, radius, rf, radius);
      gl.uniform4f(U("uRB"), radius, rf, radius, rf);
      const cx = ar.w / 2 + 6;
      gl.uniform4f(U("uA"), cx, top - css.y + hA / 2, ar.w / 2, hA / 2);
      gl.uniform4f(U("uB"), cx, bottom - css.y - hA / 2, br.w / 2, hA / 2);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
      // Contents ride with their shapes: A stays at the top, B follows its lobe's top edge.
      b.style.transform = `translateY(${bottom - hA - br.y}px)`;
      const cutA = Math.max(0, ar.h - hA), cutB = Math.max(0, br.h - hA);
      a.style.clipPath = cutA > 0.5 ? `inset(0 0 ${cutA}px 0)` : "";
      b.style.clipPath = cutB > 0.5 ? `inset(0 0 ${cutB}px 0)` : "";
      // The new content appears after the neck has broken.
      const show = brokeAt ? smooth(0, 150, performance.now() - brokeAt) : 0;
      for (const p of partsB) p.style.opacity = String(show);
      probe?.trace?.push([Math.round(performance.now() - t00), Math.round(gap * 10) / 10]);
      if (probe) { const dt = performance.now() - t0; probe.frames++; probe.drawMs += dt; probe.maxDrawMs = Math.max(probe.maxDrawMs, dt); }
    };

    const finish = (): void => {
      for (const w of [a, b]) { delete w.dataset.goo; w.style.transform = ""; w.style.clipPath = ""; }
      for (const p of [...partsA, ...partsB]) p.style.opacity = "";
      canvas.remove();
      gl.getExtension("WEBGL_lose_context")?.loseContext();
      resolve();
    };
    // One spring for the gap, retargeted mid-flight. Pull: a soft spring aimed far past the break distance, so
    // the gap crawls off the start (the neck resists) and speeds up as it thins. When the gap passes K the
    // neck lets go: the same spring is stiffened and aimed at the resting gap, and its velocity carries the
    // lobes through it (the overshoot, a squeeze below the resting gap) before they wobble to rest.
    const spring = new Spring(0, (gap) => {
      if (!brokeAt && gap >= K * 1.2) {
        brokeAt = performance.now();
        spring.configure({ stiffness: 500, damping: 28 });
        spring.set(g);
      }
      if (brokeAt && gap === g) { finish(); return; }
      draw(gap);
    }, { stiffness: 90, damping: 15 });
    spring.restDelta = 0.3; // sub-pixel: the last wobble is not worth another half second of frames
    spring.restVelocity = 3;
    draw(0);
    requestAnimationFrame(() => spring.set(K * 1.3));
  });
}
