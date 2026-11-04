/**
 * "Faulty terminal" backdrop (DECISIONS 96, #21): a field of terminal glyphs that
 * drift in and out of a low-frequency noise, with scanlines, flicker and the
 * occasional horizontal glitch band. Black and white: pale glyphs on black, or (light scheme)
 * dark glyphs on near-white.
 *
 * Budget (DECISION 96): renders continuously at half resolution and at most 30 fps
 * while visible. It pauses when the tab is hidden or the canvas is offscreen, stops
 * on `destroy()` after sign-in, and draws one still frame under prefers-reduced-motion.
 * Glyphs come from a small atlas drawn once with the terminal font, so the shader
 * samples a texture instead of building characters procedurally.
 */

/** Full-screen quad vertex shader for the glyph field. */
const VERT = `#version 300 es
in vec2 p; out vec2 uv;
void main() { uv = p * 0.5 + 0.5; gl_Position = vec4(p, 0.0, 1.0); }`;

/** Fragment shader: samples the glyph atlas through low-frequency noise, adds scanlines, flicker and glitch bands, and inks light or dark by the `light` uniform. */
const FRAG = `#version 300 es
precision highp float;
in vec2 uv; out vec4 o;
uniform sampler2D atlas;          // GLYPHS glyphs in one row
uniform vec2 res;                 // canvas pixels
uniform float t;                  // seconds
uniform vec2 mouse;               // 0..1, or -1 when absent
uniform float cell;               // cell height in canvas pixels
uniform float glyphs;
uniform float intro;              // 0..1 page-load reveal
uniform float light;              // 0 pale glyphs on black, 1 dark glyphs on near-white
float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }
float noise(vec2 p) {
  vec2 i = floor(p), f = fract(p); f = f * f * (3.0 - 2.0 * f);
  return mix(mix(hash(i), hash(i + vec2(1, 0)), f.x), mix(hash(i + vec2(0, 1)), hash(i + vec2(1, 1)), f.x), f.y);
}
void main() {
  vec2 px = uv * res;
  px.y = res.y - px.y;
  // Glitch: rare horizontal bands slide sideways for a moment.
  float band = floor(px.y / (cell * 3.0));
  float g = step(0.985, hash(vec2(band, floor(t * 6.0))));
  px.x += g * (hash(vec2(band, t)) - 0.5) * cell * 6.0;
  vec2 cs = vec2(cell * 0.6, cell);              // monospace cell
  vec2 c = floor(px / cs), f = fract(px / cs);
  // Which glyph: changes now and then, per cell, at its own pace.
  float rate = 0.4 + hash(c) * 1.6;
  float idx = floor(hash(c + floor(t * rate)) * glyphs);
  float ink = texture(atlas, vec2((idx + f.x) / glyphs, f.y)).r;
  // Where it is lit: a slow noise field, so text appears in drifting patches.
  float field = noise(c * vec2(0.06, 0.11) + vec2(t * 0.05, -t * 0.03));
  float lit = smoothstep(0.55, 0.85, field);
  // The pointer brightens nearby cells a little.
  if (mouse.x >= 0.0) {
    vec2 d = (uv - mouse) * vec2(res.x / res.y, 1.0);
    lit += 0.35 * exp(-dot(d, d) * 18.0);
  }
  float flicker = 0.9 + 0.1 * hash(vec2(floor(t * 24.0), c.y));
  float scan = 0.82 + 0.18 * sin(px.y * 3.14159 / 2.0);
  float reveal = smoothstep(0.0, 1.0, intro * 1.4 - hash(c) * 0.4);
  float v = ink * lit * flicker * scan * reveal * 0.55;
  // Vignette keeps the middle (where the card is) calm.
  vec2 q = uv - 0.5;
  v *= 1.0 - dot(q, q) * 1.6;
  // The light scheme inverts the ink, not the pattern: the same glyphs, the same drift, the same
  // calm middle, drawn dark on a paper-white field (the page's own light background colour).
  vec3 paper = vec3(0.965, 0.965, 0.957) - vec3(v) * 0.82;
  o = vec4(mix(vec3(v), paper, light), 1.0);
}`;

/** The characters drawn into the atlas, one cell each. */
const GLYPHS = "01<>/\\|=+-_:;{}[]()#$%&*!?~^".split("");
/** Minimum time between frames: 30 frames per second at most (DECISION 96). */
const FRAME_INTERVAL_MS = 1000 / 30;

/** The handle returned by {@link mountFaultyTerminal}. `destroy()` stops all drawing and releases the WebGL context. */
export interface FaultyTerminal {
  /** Switches between the dark field (default) and the light field without remounting. */
  setLight(light: boolean): void;
  destroy(): void;
}

/**
 * Starts the glyph-field backdrop on `canvas`. It renders in a worker through an offscreen canvas when the browser allows,
 * and otherwise on the main thread at the same frame rate. Returns `undefined` when WebGL 2 is unavailable, so the caller
 * can keep its plain background.
 * @param light draw dark glyphs on a light field instead of the default pale-on-black
 * @param font CSS font family used to draw the glyph atlas
 */
export function mountFaultyTerminal(canvas: HTMLCanvasElement, light = false, font = '"Geist Mono", monospace'): FaultyTerminal | undefined {
  return mountOffscreen(canvas, font, light) ?? mountOnMainThread(canvas, font, light);
}

/**
 * A WebGL renderer for the field. The caller owns the schedule: call `resize` when the size changes and `draw` for each
 * frame (`now` in milliseconds from `performance.now()`). `mouse` is the pointer as fractions of the canvas (x from the left,
 * y from the bottom; -1 means no pointer). `glow` is state that `draw` owns: it eases toward `mouse` each frame, so pass the
 * same object every time. `destroy()` frees the GL resources.
 */
export interface FaultyTerminalRenderer {
  setLight(light: boolean): void;
  resize(width: number, height: number, dpr: number): void;
  draw(now: number, reduced: boolean, mouse: PointerPosition, glow: PointerPosition): void;
  destroy(): void;
}

/** A pointer position in canvas fractions; both axes are -1 when there is no pointer. */
interface PointerPosition { x: number; y: number }
/** A canvas the renderer can draw into: on the page, or transferred to a worker. */
type ShaderCanvas = HTMLCanvasElement | OffscreenCanvas;

/** Owns WebGL resources while the caller owns the frame schedule and input source. */
function createRenderer(canvas: ShaderCanvas, font: string, light: boolean): FaultyTerminalRenderer | undefined {
  const gl = canvas.getContext("webgl2", { antialias: false, alpha: false, powerPreference: "low-power" }) as WebGL2RenderingContext | null;
  if (!gl) return undefined;
  const sh = (type: number, src: string) => { const s = gl.createShader(type)!; gl.shaderSource(s, src); gl.compileShader(s); return s; };
  const prog = gl.createProgram()!;
  gl.attachShader(prog, sh(gl.VERTEX_SHADER, VERT));
  gl.attachShader(prog, sh(gl.FRAGMENT_SHADER, FRAG));
  gl.linkProgram(prog);
  gl.useProgram(prog);
  gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const loc = gl.getAttribLocation(prog, "p");
  gl.enableVertexAttribArray(loc);
  gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

  // Glyph atlas: one row, drawn once with the terminal font.
  const G = 48;
  const atlas = typeof document === "undefined"
    ? new OffscreenCanvas(G * GLYPHS.length, G)
    : document.createElement("canvas");
  atlas.width = G * GLYPHS.length; atlas.height = G;
  const ax = atlas.getContext("2d") as CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D | null;
  if (!ax) return undefined;
  ax.fillStyle = "#000"; ax.fillRect(0, 0, atlas.width, atlas.height);
  ax.fillStyle = "#fff"; ax.font = `500 ${G * 0.78}px ${font}`; ax.textAlign = "center"; ax.textBaseline = "middle";
  GLYPHS.forEach((ch, i) => ax.fillText(ch, i * G + G / 2, G / 2 + 2));
  const tex = gl.createTexture();
  gl.bindTexture(gl.TEXTURE_2D, tex);
  gl.texImage2D(gl.TEXTURE_2D, 0, gl.R8, atlas.width, atlas.height, 0, gl.RED, gl.UNSIGNED_BYTE, toRed(ax.getImageData(0, 0, atlas.width, atlas.height).data));
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);

  const u = (n: string) => gl.getUniformLocation(prog, n);
  gl.uniform1f(u("glyphs"), GLYPHS.length);
  gl.uniform1f(u("light"), light ? 1 : 0);
  const SCALE = 0.5; // half resolution: the effect is soft by nature
  const start = performance.now();
  const resize = (width: number, height: number, dpr: number): void => {
    const w = Math.max(1, Math.round(width * dpr * SCALE));
    const h = Math.max(1, Math.round(height * dpr * SCALE));
    if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; gl.viewport(0, 0, w, h); }
    gl.uniform2f(u("res"), w, h);
    gl.uniform1f(u("cell"), Math.max(6, 14 * dpr * SCALE));
  };
  const draw = (now: number, reduced: boolean, mouse: PointerPosition, glow: PointerPosition): void => {
    const s = (now - start) / 1000;
    gl.uniform1f(u("t"), reduced ? 7.0 : s);
    gl.uniform1f(u("intro"), reduced ? 1 : Math.min(1, s / 1.2));
    if (mouse.x < 0) { glow.x = glow.y = -1; }
    else if (glow.x < 0) { glow.x = mouse.x; glow.y = mouse.y; }
    else { glow.x += (mouse.x - glow.x) * 0.18; glow.y += (mouse.y - glow.y) * 0.18; }
    gl.uniform2f(u("mouse"), glow.x, glow.y);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
  };
  return {
    resize,
    draw,
    setLight(next) { gl.uniform1f(u("light"), next ? 1 : 0); },
    destroy() { gl.getExtension("WEBGL_lose_context")?.loseContext(); },
  };
}

/**
 * Creates the worker-safe shader renderer on an offscreen canvas, without attaching browser input or frame loops.
 * Used by the worker; the main-thread path uses the same code.
 * Returns `undefined` when WebGL 2 is unavailable.
 */
export function createFaultyTerminalRenderer(canvas: OffscreenCanvas, font: string, light = false): FaultyTerminalRenderer | undefined {
  return createRenderer(canvas, font, light);
}

/** Keeps fallback WebGL work at the approved cadence when canvas workers are unavailable. */
function mountOnMainThread(canvas: HTMLCanvasElement, font: string, light: boolean): FaultyTerminal | undefined {
  const candidate = createRenderer(canvas, font, light);
  if (!candidate) return undefined;
  // Scheduled callbacks use one validated renderer for their entire lifetime.
  const renderer: FaultyTerminalRenderer = candidate;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const mouse = { x: -1, y: -1 }, glow = { x: -1, y: -1 };
  const onMove = (event: PointerEvent) => {
    const rect = canvas.getBoundingClientRect();
    mouse.x = (event.clientX - rect.left) / rect.width;
    mouse.y = 1 - (event.clientY - rect.top) / rect.height;
    wake();
  };
  const onLeave = () => { mouse.x = mouse.y = -1; wake(); };
  const onPointerDown = () => wake();
  window.addEventListener("pointermove", onMove, { passive: true });
  window.addEventListener("pointerleave", onLeave);
  window.addEventListener("pointerdown", onPointerDown, { passive: true });

  let ready = false, frameTimer: number | undefined, width = -1, height = -1, dpr = -1;
  let stillDirty = true, visible = true, alive = true;
  const resize = (): void => {
    const nextWidth = canvas.clientWidth, nextHeight = canvas.clientHeight, nextDpr = devicePixelRatio;
    if (width === nextWidth && height === nextHeight && dpr === nextDpr) return;
    width = nextWidth; height = nextHeight; dpr = nextDpr;
    renderer.resize(width, height, dpr);
    stillDirty = true;
    if (ready) { if (reduced) drawStill(); else wake(); }
  };
  const ro = new ResizeObserver(resize);
  ro.observe(canvas);
  resize();

  function pause(): void {
    if (frameTimer !== undefined) window.clearTimeout(frameTimer);
    frameTimer = undefined;
  }
  function drawStill(): void {
    if (!alive || !visible || document.hidden || !reduced || !stillDirty) return;
    renderer.draw(performance.now(), true, mouse, glow);
    stillDirty = false;
  }
  function drawFrame(): void {
    frameTimer = undefined;
    if (!alive || !visible || document.hidden || reduced) return;
    renderer.draw(performance.now(), false, mouse, glow);
    // Schedule after drawing so slow frames can only lower, never exceed, the 30 fps cap.
    frameTimer = window.setTimeout(drawFrame, FRAME_INTERVAL_MS);
  }
  function wake(): void {
    if (!alive || !visible || document.hidden) return;
    if (reduced) drawStill();
    else if (frameTimer === undefined) drawFrame();
  }
  const onVisibilityChange = (): void => { if (document.hidden) pause(); else { drawStill(); wake(); } };
  const io = new IntersectionObserver(([entry]) => {
    visible = !!entry?.isIntersecting;
    if (visible) { drawStill(); wake(); } else pause();
  });
  io.observe(canvas);
  document.addEventListener("visibilitychange", onVisibilityChange);
  ready = true;
  canvas.dataset.ready = "true";
  wake();

  return {
    setLight(next) { renderer.setLight(next); stillDirty = true; wake(); },
    destroy() {
      alive = false; pause();
      ro.disconnect(); io.disconnect();
      window.removeEventListener("pointermove", onMove); window.removeEventListener("pointerleave", onLeave);
      window.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      renderer.destroy();
    },
  };
}

/** Compiles and draws the auth field in a worker, leaving first paint responsive. */
function mountOffscreen(canvas: HTMLCanvasElement, font: string, initialLight: boolean): FaultyTerminal | undefined {
  if (typeof Worker === "undefined" || typeof OffscreenCanvas === "undefined" || !canvas.transferControlToOffscreen) return undefined;
  let worker: Worker;
  let offscreen: OffscreenCanvas;
  try {
    worker = new Worker(new URL("./faulty-terminal.worker.js", document.baseURI), { type: "module" });
  } catch {
    return undefined;
  }
  try {
    offscreen = canvas.transferControlToOffscreen();
  } catch {
    worker.terminate();
    return undefined;
  }

  canvas.dataset.ready = "false";
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  let intersecting = true, pageVisible = !document.hidden, alive = true, failedOver = false;
  let fallback: FaultyTerminal | undefined;
  let light = initialLight;
  const post = (message: object): void => {
    if (!alive || failedOver) return;
    try { worker.postMessage(message); }
    catch { onWorkerError(); }
  };
  const size = (): void => post({
    type: "resize",
    width: canvas.clientWidth,
    height: canvas.clientHeight,
    dpr: devicePixelRatio,
  });
  const setVisibility = (): void => post({ type: "visibility", visible: intersecting && pageVisible });
  const onMove = (event: PointerEvent): void => {
    const rect = canvas.getBoundingClientRect();
    post({ type: "pointer", x: (event.clientX - rect.left) / rect.width, y: 1 - (event.clientY - rect.top) / rect.height });
  };
  const onLeave = (): void => post({ type: "pointer", x: -1, y: -1 });
  const onPointerDown = (): void => post({ type: "wake" });
  const onVisibilityChange = (): void => { pageVisible = !document.hidden; setVisibility(); };
  const resizeObserver = new ResizeObserver(size);
  const intersectionObserver = new IntersectionObserver(([entry]) => {
    intersecting = !!entry?.isIntersecting;
    setVisibility();
  });
  const detach = (): void => {
    resizeObserver.disconnect(); intersectionObserver.disconnect();
    window.removeEventListener("pointermove", onMove); window.removeEventListener("pointerleave", onLeave);
    window.removeEventListener("pointerdown", onPointerDown);
    document.removeEventListener("visibilitychange", onVisibilityChange);
    worker.removeEventListener("error", onWorkerError);
  };
  const onWorkerError = (): void => {
    if (!alive || failedOver) return;
    failedOver = true;
    detach();
    worker.terminate();
    const replacement = canvas.cloneNode(false) as HTMLCanvasElement;
    replacement.dataset.ready = "false";
    canvas.replaceWith(replacement);
    fallback = mountOnMainThread(replacement, font, light);
  };
  worker.addEventListener("message", (event: MessageEvent<{ type: string; ok?: boolean }>) => {
    if (event.data.type === "ready" && event.data.ok) canvas.dataset.ready = "true";
    else if (event.data.type === "ready") onWorkerError();
  });
  worker.addEventListener("error", onWorkerError, { once: true });
  resizeObserver.observe(canvas);
  intersectionObserver.observe(canvas);
  window.addEventListener("pointermove", onMove, { passive: true });
  window.addEventListener("pointerleave", onLeave);
  window.addEventListener("pointerdown", onPointerDown, { passive: true });
  document.addEventListener("visibilitychange", onVisibilityChange);
  try {
    worker.postMessage({
      type: "start",
      canvas: offscreen,
      font,
      width: canvas.clientWidth,
      height: canvas.clientHeight,
      dpr: devicePixelRatio,
      reduced,
      light,
      visible: intersecting && pageVisible,
    }, [offscreen]);
  } catch {
    onWorkerError();
  }

  return {
    setLight(next) {
      light = next;
      if (fallback) fallback.setLight(next); else post({ type: "scheme", light: next });
    },
    destroy() {
      if (!alive) return;
      alive = false; detach();
      if (!failedOver) {
        try { worker.postMessage({ type: "destroy" }); } catch { /* The worker may have exited. */ }
        worker.terminate();
      }
      fallback?.destroy();
    },
  };
}

/** Keeps only the red channel of RGBA pixels; the atlas is a one-channel texture. */
function toRed(rgba: Uint8ClampedArray): Uint8Array {
  const out = new Uint8Array(rgba.length / 4);
  for (let i = 0; i < out.length; i++) out[i] = rgba[i * 4]!;
  return out;
}
