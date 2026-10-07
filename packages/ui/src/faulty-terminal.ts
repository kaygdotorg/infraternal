/**
 * "Faulty terminal" backdrop (DECISIONS 96, #21): a field of terminal glyphs that
 * drift in and out of a low-frequency noise, with scanlines, flicker and the
 * occasional horizontal glitch band. Black and white. Written from scratch after
 * the sveltebits.xyz effect, whose code cannot be copied (MIT + Commons Clause).
 *
 * Budget (DECISIONS 81): renders at half resolution, at most 30 fps, and only during
 * its 1.2 s intro or briefly after pointer activity. At rest it holds the last frame
 * with no rAF or timer. It also pauses when hidden or offscreen, stops on `destroy()`
 * (after sign-in), and draws one still frame under prefers-reduced-motion.
 * Glyphs come from a small atlas drawn once with the terminal font, so the shader
 * samples a texture instead of building characters procedurally.
 */

const VERT = `#version 300 es
in vec2 p; out vec2 uv;
void main() { uv = p * 0.5 + 0.5; gl_Position = vec4(p, 0.0, 1.0); }`;

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
  o = vec4(vec3(v), 1.0);
}`;

const GLYPHS = "01<>/\\|=+-_:;{}[]()#$%&*!?~^".split("");
const INTRO_MS = 1200;
const QUIET_MS = 700;

export interface FaultyTerminal { destroy(): void }

export function mountFaultyTerminal(canvas: HTMLCanvasElement, font = '"Geist Mono", monospace'): FaultyTerminal | undefined {
  const gl = canvas.getContext("webgl2", { antialias: false, alpha: false, powerPreference: "low-power" });
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
  const atlas = document.createElement("canvas");
  atlas.width = G * GLYPHS.length; atlas.height = G;
  const ax = atlas.getContext("2d")!;
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
  // The glow follows a smoothed pointer, not the raw one: tying a decorative effect
  // directly to the mouse feels artificial (review finding). Eased toward the target
  // each drawn frame; snaps on enter/leave.
  const mouse = { x: -1, y: -1 };
  const glow = { x: -1, y: -1 };
  const onMove = (e: PointerEvent) => {
    const r = canvas.getBoundingClientRect();
    mouse.x = (e.clientX - r.left) / r.width;
    mouse.y = 1 - (e.clientY - r.top) / r.height;
    wake();
  };
  const onLeave = () => { mouse.x = mouse.y = -1; wake(); };
  const onPointerDown = () => wake();
  window.addEventListener("pointermove", onMove, { passive: true });
  window.addEventListener("pointerleave", onLeave);
  window.addEventListener("pointerdown", onPointerDown, { passive: true });

  const SCALE = 0.5; // half resolution: the effect is soft by nature
  let animationReady = false;
  const resize = () => {
    const w = Math.max(1, Math.round(canvas.clientWidth * devicePixelRatio * SCALE));
    const h = Math.max(1, Math.round(canvas.clientHeight * devicePixelRatio * SCALE));
    if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; gl.viewport(0, 0, w, h); }
    gl.uniform2f(u("res"), w, h);
    gl.uniform1f(u("cell"), Math.max(6, 14 * devicePixelRatio * SCALE));
    if (animationReady) {
      if (reduced) draw(performance.now());
      else wake();
    }
  };
  const ro = new ResizeObserver(resize);
  ro.observe(canvas);
  resize();

  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const start = performance.now();
  let raf = 0, idleTimer = 0, last = 0, activeUntil = start + INTRO_MS, visible = true, alive = true;
  const draw = (now: number) => {
    const s = (now - start) / 1000;
    gl.uniform1f(u("t"), reduced ? 7.0 : s);
    gl.uniform1f(u("intro"), reduced ? 1 : Math.min(1, s / 1.2));
    if (mouse.x < 0) { glow.x = glow.y = -1; }
    else if (glow.x < 0) { glow.x = mouse.x; glow.y = mouse.y; }
    else { glow.x += (mouse.x - glow.x) * 0.18; glow.y += (mouse.y - glow.y) * 0.18; }
    gl.uniform2f(u("mouse"), glow.x, glow.y);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
  };
  const loop = (now: number) => {
    if (!alive || !visible || document.hidden) { raf = 0; return; }
    if (now - last >= 1000 / 30) { last = now; draw(now); } // cap at 30 fps
    if (now >= activeUntil) { raf = 0; return; }
    raf = requestAnimationFrame(loop);
  };
  function pause(): void {
    window.clearTimeout(idleTimer);
    idleTimer = 0;
    if (raf) cancelAnimationFrame(raf);
    raf = 0;
  }
  function wake(): void {
    if (!alive || !visible || document.hidden || reduced) return;
    activeUntil = Math.max(activeUntil, performance.now() + QUIET_MS);
    window.clearTimeout(idleTimer);
    idleTimer = window.setTimeout(pause, Math.max(0, activeUntil - performance.now()));
    if (!raf) raf = requestAnimationFrame(loop);
  }
  const onVisibilityChange = () => { if (document.hidden) pause(); else wake(); };
  const io = new IntersectionObserver(([e]) => {
    visible = !!e?.isIntersecting;
    if (visible) wake(); else pause();
  });
  io.observe(canvas);
  document.addEventListener("visibilitychange", onVisibilityChange);
  animationReady = true;
  if (reduced) draw(performance.now()); else wake();

  return {
    destroy() {
      alive = false; pause();
      ro.disconnect(); io.disconnect();
      window.removeEventListener("pointermove", onMove); window.removeEventListener("pointerleave", onLeave);
      window.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      gl.getExtension("WEBGL_lose_context")?.loseContext(); // free the GPU context
    },
  };
}

function toRed(rgba: Uint8ClampedArray): Uint8Array {
  const out = new Uint8Array(rgba.length / 4);
  for (let i = 0; i < out.length; i++) out[i] = rgba[i * 4]!;
  return out;
}
