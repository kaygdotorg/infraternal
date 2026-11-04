/**
 * Paints the theme-colored mesh into one still image (DECISIONS 83).
 * The WebGL context is released after the draw; no frame loop or GPU allocation
 * remains idle. Resizing or changing the theme asks for one fresh image.
 */
import { contrastRatio, hexToOklab, oklabToHex } from "./color";
import type { Theme } from "./themes";

/** Full-screen quad vertex shader: passes a 0-to-1 `uv` to the fragment shader. */
const VERTEX_SHADER = `#version 300 es
in vec2 p; out vec2 uv;
void main() { uv = p * 0.5 + 0.5; gl_Position = vec4(p, 0.0, 1.0); }`;

// Low-frequency warped Gaussian blobs blend in linear light; final dithering avoids 8-bit banding.
const FRAGMENT_SHADER = `#version 300 es
precision highp float;
in vec2 uv; out vec4 o;
uniform vec3 bg; uniform vec3 c[4]; uniform vec2 at[4]; uniform float radius[4];
uniform float strength; uniform float aspect; uniform float seed;
vec3 lin(vec3 s) { return pow(s, vec3(2.2)); }
vec3 srgb(vec3 l) { return pow(l, vec3(1.0 / 2.2)); }
float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }
float noise(vec2 p) {
  vec2 i = floor(p), f = fract(p); f = f * f * (3.0 - 2.0 * f);
  return mix(mix(hash(i), hash(i + vec2(1, 0)), f.x), mix(hash(i + vec2(0, 1)), hash(i + vec2(1, 1)), f.x), f.y);
}
void main() {
  vec2 q = vec2(uv.x * aspect, uv.y);
  q += 0.09 * vec2(noise(q * 1.7 + seed) - 0.5, noise(q * 1.7 + seed + 7.3) - 0.5);
  vec3 col = lin(bg);
  for (int i = 0; i < 4; i++) {
    vec2 d = q - vec2(at[i].x * aspect, at[i].y);
    float w = exp(-dot(d, d) / (radius[i] * radius[i])) * strength;
    col = mix(col, lin(c[i]), w);
  }
  col = srgb(col) + (hash(gl_FragCoord.xy + seed) - 0.5) / 255.0;
  o = vec4(col, 1.0);
}`;

/** A six-digit hex colour as 0-to-1 red, green and blue, the form the shader takes. */
const rgb = (hex: string): number[] => [1, 3, 5].map((index) => parseInt(hex.slice(index, index + 2), 16) / 255);

/** Stable per-theme blob positions prevent the background from jumping between visits. */
function layout(name: string): Array<{ x: number; y: number; radius: number }> {
  let hash = 2166136261;
  for (const character of name) hash = Math.imul(hash ^ character.charCodeAt(0), 16777619);
  const random = () => ((hash = Math.imul(hash ^ (hash >>> 15), 2246822507) >>> 0) / 4294967296);
  const corners = [[0.12, 0.85], [0.9, 0.9], [0.85, 0.12], [0.15, 0.15]];
  return corners.map(([x, y]) => ({
    x: x! + (random() - 0.5) * 0.2,
    y: y! + (random() - 0.5) * 0.2,
    radius: 0.32 + random() * 0.16,
  }));
}

/** Returns the peak color after linear-light blending at one blob's center. */
export function peakColor(background: string, blobColor: string, strength: number): string {
  const linear = (value: number) => value ** 2.2;
  const output = (value: number) => Math.round(Math.min(1, value) ** (1 / 2.2) * 255);
  const [base, tint] = [rgb(background), rgb(blobColor)];
  return `#${base.map((value, index) => output(linear(value) + (linear(tint[index]!) - linear(value)) * strength).toString(16).padStart(2, "0")).join("")}`;
}

/** Theme glow is reduced until its brightest points preserve the approved text caps. */
export function meshStrength(theme: Theme): number {
  let strength = theme.dark ? 0.85 : 0.7;
  const exempt = contrastRatio(theme.ansi[0], theme.bg) < contrastRatio(theme.ansi[7], theme.bg) ? 0 : 7;
  const textColors = [theme.fg2, ...theme.ansi.filter((_, index) => index !== exempt), ...theme.bright.filter((_, index) => index !== exempt)];
  const passes = (candidate: number) => meshColors(theme).every((color) => {
    const underGlow = peakColor(theme.bg, color, candidate);
    return contrastRatio(theme.fg, underGlow) >= 7
      && textColors.every((text) => contrastRatio(text, underGlow) >= 4.5);
  });
  while (strength > 0.05 && !passes(strength)) strength -= 0.01;
  return strength;
}

/** Keeps each hue but sets OKLab lightness just off the theme background. */
export function meshColors(theme: Theme): string[] {
  const backgroundLightness = hexToOklab(theme.bg)[0];
  return [theme.accent, theme.ansi[4], theme.ansi[5], theme.ansi[6]].map((color) => {
    const [, a, b] = hexToOklab(color);
    return oklabToHex([backgroundLightness + (theme.dark ? 0.07 : -0.05), a * 0.9, b * 0.9]);
  });
}

/** Counter of render requests; a result from an older request than the newest is discarded. */
let newestRender = 0;
/** The object URL of the image now in use, revoked when a newer one replaces it. */
let currentUrl = "";
/** The id for the next request sent to the render worker. */
let nextWorkerRequest = 0;
/** The worker, created on first use; `undefined` where workers are unavailable. */
let renderWorker: Worker | undefined;
/** Requests the worker has not answered yet, by id. */
const workerRequests = new Map<number, { resolve: (blob: Blob | null) => void; reject: (error: Error) => void }>();

/** What the worker posts back: the request `id` and the encoded image, or `null` when it failed. */
interface WorkerResponse { id: number; blob: Blob | null }

/** Creates the optional WebGL worker lazily so auth and idle views load no renderer. */
function getRenderWorker(): Worker | undefined {
  if (typeof Worker === "undefined") return undefined;
  if (renderWorker) return renderWorker;
  const worker = new Worker(new URL("./backdrop.worker.js", document.baseURI), { type: "module" });
  renderWorker = worker;
  worker.addEventListener("message", (event: MessageEvent<WorkerResponse>) => {
    const pending = workerRequests.get(event.data.id);
    if (!pending) return;
    workerRequests.delete(event.data.id);
    pending.resolve(event.data.blob);
  });
  const fail = (): void => {
    worker.terminate();
    if (renderWorker === worker) renderWorker = undefined;
    for (const pending of workerRequests.values()) pending.reject(new Error("backdrop worker failed"));
    workerRequests.clear();
  };
  worker.addEventListener("error", fail, { once: true });
  worker.addEventListener("messageerror", fail, { once: true });
  return worker;
}

/** Sends one bounded render request to the worker, if workers are available. */
function renderInWorker(theme: Theme, width: number, height: number): Promise<Blob | null> | undefined {
  const worker = getRenderWorker();
  if (!worker) return undefined;
  const id = ++nextWorkerRequest;
  return new Promise((resolve, reject) => {
    workerRequests.set(id, { resolve, reject });
    try { worker.postMessage({ id, theme, width, height }); }
    catch (error) {
      workerRequests.delete(id);
      reject(error instanceof Error ? error : new Error("backdrop request could not be sent"));
    }
  });
}

/** Cancels an in-flight result and releases the current still when mesh mode is left. */
export function releaseBackdrop(): void {
  newestRender += 1;
  if (currentUrl) URL.revokeObjectURL(currentUrl);
  currentUrl = "";
}

/** Draws one half-resolution still off-thread and returns its replaceable URL for CSS. */
export async function renderBackdrop(theme: Theme, width: number, height: number): Promise<string> {
  const renderId = ++newestRender;
  let blob: Blob | null = null;
  try { blob = (await renderInWorker(theme, width, height)) ?? null; }
  catch { /* Older engines can still render through the bounded main-thread fallback. */ }
  if (!blob) blob = await renderBackdropBlob(theme, width, height);
  if (renderId !== newestRender) return "";
  if (currentUrl) URL.revokeObjectURL(currentUrl);
  currentUrl = blob ? URL.createObjectURL(blob) : "";
  return currentUrl;
}

/** Draws and snapshots the mesh using OffscreenCanvas when this context supports it. */
export async function renderBackdropBlob(theme: Theme, width: number, height: number): Promise<Blob | null> {
  const canvasWidth = Math.max(1, Math.round(width / 2));
  const canvasHeight = Math.max(1, Math.round(height / 2));
  let canvas: OffscreenCanvas | HTMLCanvasElement | undefined;
  let gl: WebGL2RenderingContext | null = null;
  if (typeof OffscreenCanvas !== "undefined") {
    const offscreen = new OffscreenCanvas(canvasWidth, canvasHeight);
    gl = offscreen.getContext("webgl2", { preserveDrawingBuffer: true, antialias: false });
    if (gl) canvas = offscreen;
  }
  if (!gl && typeof document !== "undefined") {
    const fallback = document.createElement("canvas");
    fallback.width = canvasWidth;
    fallback.height = canvasHeight;
    gl = fallback.getContext("webgl2", { preserveDrawingBuffer: true, antialias: false });
    if (gl) canvas = fallback;
  }
  if (!gl || !canvas) return null;

  const loseContext = () => gl.getExtension("WEBGL_lose_context")?.loseContext();
  const compile = (kind: number, source: string): WebGLShader | undefined => {
    const shader = gl.createShader(kind);
    if (!shader) return undefined;
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
      gl.deleteShader(shader);
      return undefined;
    }
    return shader;
  };
  const vertex = compile(gl.VERTEX_SHADER, VERTEX_SHADER);
  const fragment = compile(gl.FRAGMENT_SHADER, FRAGMENT_SHADER);
  const program = gl.createProgram();
  if (!vertex || !fragment || !program) {
    if (vertex) gl.deleteShader(vertex);
    if (fragment) gl.deleteShader(fragment);
    if (program) gl.deleteProgram(program);
    loseContext();
    return null;
  }
  gl.attachShader(program, vertex);
  gl.attachShader(program, fragment);
  gl.linkProgram(program);
  const linked = gl.getProgramParameter(program, gl.LINK_STATUS);
  if (!linked) {
    gl.deleteShader(vertex);
    gl.deleteShader(fragment);
    gl.deleteProgram(program);
    loseContext();
    return null;
  }

  const colors = meshColors(theme);
  const strength = meshStrength(theme);
  gl.useProgram(program);
  const buffer = gl.createBuffer();
  if (!buffer) {
    gl.deleteShader(vertex);
    gl.deleteShader(fragment);
    gl.deleteProgram(program);
    loseContext();
    return null;
  }
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const position = gl.getAttribLocation(program, "p");
  gl.enableVertexAttribArray(position);
  gl.vertexAttribPointer(position, 2, gl.FLOAT, false, 0, 0);
  const uniform = (name: string) => gl.getUniformLocation(program, name);
  const blobs = layout(theme.name);
  gl.uniform3fv(uniform("bg"), rgb(theme.bg));
  gl.uniform3fv(uniform("c"), colors.flatMap(rgb));
  gl.uniform2fv(uniform("at"), blobs.flatMap((blob) => [blob.x, blob.y]));
  gl.uniform1fv(uniform("radius"), blobs.map((blob) => blob.radius));
  gl.uniform1f(uniform("strength"), strength);
  gl.uniform1f(uniform("aspect"), width / Math.max(1, height));
  gl.uniform1f(uniform("seed"), blobs[0]!.x * 10);
  gl.viewport(0, 0, canvas.width, canvas.height);
  gl.drawArrays(gl.TRIANGLES, 0, 3);
  gl.deleteBuffer(buffer);
  gl.deleteShader(vertex);
  gl.deleteShader(fragment);
  gl.deleteProgram(program);
  // Snapshot before losing the context; workers keep any encoder and readback wait
  // off the UI thread while the immutable PNG is produced.
  const snapshot = "convertToBlob" in canvas
    ? canvas.convertToBlob({ type: "image/png" }).catch(() => null)
    : new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/png"));
  loseContext();
  return snapshot;
}

/** The data URL of the grain tile, built once on first use. */
let grain = "";

/** Builds the one crisp 128 px noise tile used to dither the still mesh. */
export function grainTile(): string {
  if (grain) return grain;
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = 128;
  const context = canvas.getContext("2d");
  if (!context) return "";
  const image = context.createImageData(128, 128);
  for (let index = 0; index < image.data.length; index += 4) {
    const value = Math.random() * 255;
    image.data[index] = image.data[index + 1] = image.data[index + 2] = value;
    image.data[index + 3] = 255;
  }
  context.putImageData(image, 0, 0);
  grain = canvas.toDataURL("image/png");
  return grain;
}
