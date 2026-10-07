/** Runs the intro shader off the UI thread and stops scheduling frames at rest. */
import { createFaultyTerminalRenderer, type FaultyTerminalRenderer } from "./faulty-terminal";

interface StartMessage {
  type: "start";
  canvas: OffscreenCanvas;
  font: string;
  width: number;
  height: number;
  dpr: number;
  reduced: boolean;
  visible: boolean;
}
interface ResizeMessage { type: "resize"; width: number; height: number; dpr: number }
interface PointerMessage { type: "pointer"; x: number; y: number }
interface VisibilityMessage { type: "visibility"; visible: boolean }
type WorkerMessage = StartMessage | ResizeMessage | PointerMessage | VisibilityMessage | { type: "wake" | "destroy" };

interface WorkerScope {
  addEventListener(type: "message", listener: (event: MessageEvent<WorkerMessage>) => void): void;
  postMessage(response: { type: "ready"; ok: boolean }): void;
}

const scope = globalThis as unknown as WorkerScope;
const mouse = { x: -1, y: -1 }, glow = { x: -1, y: -1 };
let renderer: FaultyTerminalRenderer | undefined;
let reduced = false, visible = false, alive = true;
let raf = 0, last = 0, activeUntil = 0;

function pause(): void {
  if (raf) cancelAnimationFrame(raf);
  raf = 0;
}

function wake(): void {
  if (!alive || !renderer || !visible || reduced) return;
  activeUntil = Math.max(activeUntil, performance.now() + 700);
  if (!raf) raf = requestAnimationFrame(loop);
}

function loop(now: number): void {
  if (!alive || !renderer || !visible) { raf = 0; return; }
  if (now - last >= 1000 / 30) {
    last = now;
    renderer.draw(now, false, mouse, glow);
  }
  if (now >= activeUntil) { raf = 0; return; }
  raf = requestAnimationFrame(loop);
}

function start(message: StartMessage): void {
  renderer = createFaultyTerminalRenderer(message.canvas, message.font);
  if (!renderer) { scope.postMessage({ type: "ready", ok: false }); return; }
  reduced = message.reduced;
  visible = message.visible;
  renderer.resize(message.width, message.height, message.dpr);
  activeUntil = performance.now() + 1200;
  scope.postMessage({ type: "ready", ok: true });
  if (reduced) renderer.draw(performance.now(), true, mouse, glow);
  else wake();
}

scope.addEventListener("message", (event) => {
  const message = event.data;
  if (message.type === "start") { start(message); return; }
  if (!renderer || !alive) return;
  if (message.type === "resize") {
    renderer.resize(message.width, message.height, message.dpr);
    if (reduced) renderer.draw(performance.now(), true, mouse, glow);
    else wake();
  } else if (message.type === "pointer") {
    mouse.x = message.x; mouse.y = message.y;
    wake();
  } else if (message.type === "visibility") {
    visible = message.visible;
    if (visible) wake(); else pause();
  } else if (message.type === "wake") {
    wake();
  } else {
    alive = false;
    pause();
    renderer.destroy();
    renderer = undefined;
  }
});
