/** Production-build motion regression checks for issue #40. */
import { expect, test, type Page } from "playwright/test";

interface MotionEvent {
  label: string;
  kind: string;
  selector: string;
  property: string;
  duration: number | string;
  delay: number | string;
  easing: string;
}

interface MotionSample { frames: number; dropped: number; longestGapMs: number }
interface PendingWork { kind: string; delay: number | null; stack: string }
interface MotionProbe {
  label: string;
  events: MotionEvent[];
  frameTimes: number[];
  pending: PendingWork[];
  longTasks: Array<{ startTime: number; duration: number; name: string; attribution: string[] }>;
  rAFs: Map<number, string>;
  timeouts: Map<number, PendingWork>;
  intervals: Map<number, PendingWork>;
  startSample(): void;
  stopSample(): MotionSample;
}

declare global {
  interface Window { __motionAudit: MotionProbe; __faultyReadyMarks: number[] }
}

test("measure deployed motion at 4x CPU and capture production screens", async ({ browser, page }, testInfo) => {
  test.setTimeout(120_000);
  const context = page.context();
  const requestedWorkers: string[] = [];
  const requestedFaultyWorkers: string[] = [];
  page.on("request", (request) => {
    const pathname = new URL(request.url()).pathname;
    if (pathname.endsWith("/backdrop.worker.js")) requestedWorkers.push(request.url());
    if (pathname.endsWith("/faulty-terminal.worker.js")) requestedFaultyWorkers.push(request.url());
  });
  await context.request.post("/__mock/reset");
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.addInitScript(() => {
    const probe = {
      label: "startup",
      events: [] as MotionEvent[],
      frameTimes: [] as number[],
      pending: [] as PendingWork[],
      longTasks: [] as Array<{ startTime: number; duration: number; name: string; attribution: string[] }>,
      sampleTimes: [] as number[],
      sampling: false,
      sampleFrame: 0,
      rAFs: new Map<number, string>(),
      timeouts: new Map<number, PendingWork>(),
      intervals: new Map<number, PendingWork>(),
    };
    const selector = (element: Element): string => {
      if (element.id) return `#${element.id}`;
      const names = [...element.classList].slice(0, 2).join(".");
      return `${element.tagName.toLowerCase()}${names ? `.${names}` : ""}`;
    };
    const stack = (): string => new Error().stack?.split("\n").slice(2, 5).join(" | ") ?? "";
    const faultyReadyMarks: number[] = [];
    new MutationObserver((records) => {
      for (const record of records) {
        if (record.target instanceof HTMLElement && record.target.id === "faulty-field") faultyReadyMarks.push(performance.now());
      }
    }).observe(document, { subtree: true, attributes: true, attributeFilter: ["data-ready"] });
    const frameGaps = (times: number[]): MotionSample => {
      const unique = times.filter((time, index) => index === 0 || time !== times[index - 1]);
      const gaps = unique.slice(1).map((time, index) => time - unique[index]!);
      const missed = gaps.filter((gap) => gap > 25).reduce((sum, gap) => sum + Math.max(1, Math.round(gap / (1000 / 60)) - 1), 0);
      return { frames: unique.length, dropped: missed, longestGapMs: Math.max(0, ...gaps) };
    };
    const nativeRAF = window.requestAnimationFrame.bind(window);
    const nativeCancelRAF = window.cancelAnimationFrame.bind(window);
    const nativeTimeout = window.setTimeout.bind(window);
    const nativeClearTimeout = window.clearTimeout.bind(window);
    const nativeInterval = window.setInterval.bind(window);
    const nativeClearInterval = window.clearInterval.bind(window);
    if (typeof PerformanceObserver !== "undefined") {
      new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          const longTask = entry as PerformanceEntry & { attribution?: Array<{ name?: string }> };
          probe.longTasks.push({
            startTime: entry.startTime,
            duration: entry.duration,
            name: entry.name,
            attribution: (longTask.attribution ?? []).map((item) => item.name ?? ""),
          });
        }
      }).observe({ type: "longtask", buffered: true });
    }

    window.requestAnimationFrame = ((callback: FrameRequestCallback): number => {
      let id = 0;
      id = nativeRAF((time) => {
        probe.rAFs.delete(id);
        if (!probe.frameTimes.length || probe.frameTimes[probe.frameTimes.length - 1] !== time) probe.frameTimes.push(time);
        callback(time);
      });
      probe.rAFs.set(id, "requestAnimationFrame");
      return id;
    }) as typeof window.requestAnimationFrame;
    window.cancelAnimationFrame = ((id: number): void => {
      probe.rAFs.delete(id);
      nativeCancelRAF(id);
    }) as typeof window.cancelAnimationFrame;
    window.setTimeout = ((handler: TimerHandler, timeout?: number, ...args: unknown[]): number => {
      const pending = { kind: "timeout", delay: timeout ?? 0, stack: stack() };
      let id = 0;
      id = nativeTimeout((...callbackArgs: unknown[]) => {
        probe.timeouts.delete(id);
        if (typeof handler === "function") handler(...callbackArgs);
      }, timeout, ...args);
      probe.timeouts.set(id, pending);
      return id;
    }) as typeof window.setTimeout;
    window.clearTimeout = ((id?: number): void => {
      if (id !== undefined) probe.timeouts.delete(id);
      nativeClearTimeout(id);
    }) as typeof window.clearTimeout;
    window.setInterval = ((handler: TimerHandler, timeout?: number, ...args: unknown[]): number => {
      const pending = { kind: "interval", delay: timeout ?? 0, stack: stack() };
      const id = nativeInterval(handler, timeout, ...args);
      probe.intervals.set(id, pending);
      return id;
    }) as typeof window.setInterval;
    window.clearInterval = ((id?: number): void => {
      if (id !== undefined) probe.intervals.delete(id);
      nativeClearInterval(id);
    }) as typeof window.clearInterval;

    const originalAnimate = Element.prototype.animate;
    Element.prototype.animate = function (keyframes: Keyframe[] | PropertyIndexedKeyframes | null, options?: number | KeyframeAnimationOptions): Animation {
      const animation = originalAnimate.call(this, keyframes, options);
      const timing = animation.effect?.getTiming();
      const duration = timing?.duration;
      const propertyNames = Array.isArray(keyframes)
        ? keyframes.flatMap((frame) => frame && typeof frame === "object" ? Object.keys(frame) : [])
        : keyframes && typeof keyframes === "object" ? Object.keys(keyframes) : [];
      probe.events.push({
        label: probe.label,
        kind: "waapi",
        selector: selector(this),
        property: [...new Set(propertyNames.filter((name) => !["offset", "easing", "composite"].includes(name)))].join(","),
        duration: typeof duration === "number" || typeof duration === "string" ? duration : duration?.toString() ?? 0,
        delay: timing?.delay ?? 0,
        easing: timing?.easing ?? "",
      });
      return animation;
    };
    document.addEventListener("transitionrun", (event) => {
      const transition = event as TransitionEvent;
      if (!(transition.target instanceof Element)) return;
      const style = getComputedStyle(transition.target);
      probe.events.push({
        label: probe.label,
        kind: "transition",
        selector: selector(transition.target),
        property: transition.propertyName,
        duration: style.transitionDuration,
        delay: style.transitionDelay,
        easing: style.transitionTimingFunction,
      });
    });
    document.addEventListener("animationstart", (event) => {
      const animation = event as AnimationEvent;
      if (!(animation.target instanceof Element)) return;
      const style = getComputedStyle(animation.target, animation.pseudoElement || null);
      probe.events.push({
        label: probe.label,
        kind: "css-animation",
        selector: `${selector(animation.target)}${animation.pseudoElement}`,
        property: animation.animationName,
        duration: style.animationDuration,
        delay: style.animationDelay,
        easing: style.animationTimingFunction,
      });
    });
    Object.assign(probe, {
      startSample: (): void => {
        probe.sampleTimes = [];
        probe.sampling = true;
        const sample = (time: number): void => {
          if (!probe.sampling) return;
          probe.sampleTimes.push(time);
          probe.sampleFrame = nativeRAF(sample);
        };
        probe.sampleFrame = nativeRAF(sample);
      },
      stopSample: (): MotionSample => {
        probe.sampling = false;
        nativeCancelRAF(probe.sampleFrame);
        return frameGaps(probe.sampleTimes);
      },
    });
    Object.defineProperty(window, "__motionAudit", { value: probe, configurable: false });
    Object.defineProperty(window, "__faultyReadyMarks", { value: faultyReadyMarks, configurable: false });
  });

  const cdp = await context.newCDPSession(page);
  await cdp.send("Emulation.setCPUThrottlingRate", { rate: 4 });
  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "no-preference" });
  const authenticator = await cdp.send("WebAuthn.enable");
  void authenticator;
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
    },
  });
  await page.goto("/?mock=1");
  await expect(page.locator("#setup-card")).toBeVisible();
  await expect(page.locator("#faulty-field")).toHaveAttribute("data-ready", "true");
  expect(requestedFaultyWorkers).toHaveLength(1);
  const setupPath = testInfo.outputPath("motion-audit-setup.png");
  await page.screenshot({ path: setupPath, fullPage: true, mask: [page.locator("#setup-token")] });
  await testInfo.attach("production setup", { path: setupPath, contentType: "image/png" });
  await page.waitForTimeout(1_300); // let the 1.2 s first-run reveal finish before measuring idle
  const authIdleStartFrame = await page.evaluate(() => window.__motionAudit.frameTimes.length);
  await page.waitForTimeout(1_100);
  const authIdle = await page.evaluate((startFrame) => ({
    rafCallbacks: [...window.__motionAudit.rAFs.values()],
    pending: [
      ...[...window.__motionAudit.timeouts.values()],
      ...[...window.__motionAudit.intervals.values()],
    ],
    idleRafFrames: window.__motionAudit.frameTimes.length - startFrame,
  }), authIdleStartFrame);
  expect(authIdle.rafCallbacks).toEqual([]);
  expect(authIdle.pending).toEqual([]);
  expect(authIdle.idleRafFrames).toBe(0);
  console.log(`MOTION_AUDIT auth-idle ${JSON.stringify(authIdle)}`);
  const authStart = await styles(page, ["#setup-card", ".auth-pane", "#setup-viewport", ".auth-step-bar", "#setup-token", ".auth-dot", "#setup-next"]);
  expect(authStart.find((style) => style.selector === "#setup-card")?.animationDuration).toBe("0.24s");
  expect(authStart.find((style) => style.selector === "#setup-token")?.transitionDuration).toBe("0s");
  expect(authStart.find((style) => style.selector === ".auth-dot")?.transitionDuration).toBe("0s");
  console.log(`MOTION_AUDIT auth-start ${JSON.stringify(authStart)}`);

  const setup = await (await context.request.get("/__mock/setup-token")).json() as { setup_token: string };
  await page.locator("#setup-token").fill(setup.setup_token);
  await page.evaluate(() => { window.__motionAudit.label = "keyboard-step-token"; window.__motionAudit.startSample(); });
  await page.locator("#setup-token").press("Enter");
  await expect(page.locator("#setup-username")).toBeVisible();
  await page.waitForTimeout(320);
  const tokenStep = await sampleAndEvents(page, "keyboard-step-token");
  expect(tokenStep.events.filter((event) => ["#setup-viewport", "div.auth-pane", "#setup-username"].includes(event.selector))).toEqual([]);
  console.log(`MOTION_AUDIT keyboard-step-token ${JSON.stringify(tokenStep)}`);

  await page.locator("#setup-username").fill("Ada");
  await page.locator("#setup-display-name").fill("Ada Lovelace");
  await page.evaluate(() => { window.__motionAudit.label = "keyboard-step-identity"; window.__motionAudit.startSample(); });
  await page.locator("#setup-display-name").press("Enter");
  await expect(page.getByRole("heading", { name: "Create your passkey" })).toBeVisible();
  await page.waitForTimeout(320);
  const identityStep = await sampleAndEvents(page, "keyboard-step-identity");
  expect(identityStep.events.filter((event) => ["#setup-viewport", "div.auth-pane"].includes(event.selector))).toEqual([]);
  console.log(`MOTION_AUDIT keyboard-step-identity ${JSON.stringify(identityStep)}`);

  await page.evaluate(() => { window.__motionAudit.label = "create-passkey"; window.__motionAudit.startSample(); });
  await page.getByRole("button", { name: "Create passkey" }).click();
  await expect(page.getByRole("heading", { name: "Save your recovery key" })).toBeVisible();
  await page.waitForTimeout(320);
  const recoveryStep = await sampleAndEvents(page, "create-passkey");
  console.log(`MOTION_AUDIT create-passkey ${JSON.stringify(recoveryStep)}`);

  const recoveryPath = testInfo.outputPath("motion-audit-recovery.png");
  await page.screenshot({ path: recoveryPath, fullPage: true, mask: [page.locator("#recovery-words")] });
  await testInfo.attach("production recovery", { path: recoveryPath, contentType: "image/png" });
  await page.evaluate(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: async () => undefined, readText: async () => "" },
    });
  });
  await page.evaluate(() => { window.__motionAudit.label = "copy-feedback"; window.__motionAudit.startSample(); });
  await page.locator("#copy-recovery").click();
  await expect(page.locator("#copy-recovery")).toHaveAttribute("data-done", "");
  await page.waitForTimeout(220);
  const copy = await sampleAndEvents(page, "copy-feedback");
  const copyFilter = copy.events.find((event) => event.property === "filter");
  const copyDraw = copy.events.find((event) => event.property === "stroke-dashoffset");
  const copyMorph = await page.evaluate(() => {
    const idle = getComputedStyle(document.querySelector<SVGElement>("#copy-recovery .is-idle")!);
    const done = getComputedStyle(document.querySelector<SVGElement>("#copy-recovery .is-done")!);
    return { idleFilter: idle.filter, idleScale: new DOMMatrixReadOnly(idle.transform).a, doneFilter: done.filter };
  });
  expect(copyFilter?.duration).toBe("0.2s");
  expect(copyDraw).toMatchObject({ duration: "0.26s", delay: "0.05s" });
  expect(copyMorph.idleFilter).toBe("blur(2px)");
  expect(copyMorph.idleScale).toBeCloseTo(0.6);
  expect(copyMorph.doneFilter).toBe("none");
  console.log(`MOTION_AUDIT copy-feedback ${JSON.stringify({ ...copy, copyMorph })}`);

  await page.waitForTimeout(520);
  await expect(page.locator("#copy-recovery")).toHaveAttribute("data-done", "");
  await page.evaluate(() => { window.__motionAudit.label = "copy-feedback-return"; window.__motionAudit.startSample(); });
  await page.waitForTimeout(230);
  const copyReturn = await sampleAndEvents(page, "copy-feedback-return");
  expect(copyReturn.events.find((event) => event.selector === "svg.is-done" && event.property === "filter")?.duration).toBe("0.15s, 0.15s, 0.15s");
  await expect(page.locator("#copy-recovery")).not.toHaveAttribute("data-done");
  console.log(`MOTION_AUDIT copy-feedback-return ${JSON.stringify(copyReturn)}`);

  // Keep both recovery actions in view so the browser does not scroll and reset
  // the tooltip's inline transitions while the trigger moves.
  await page.setViewportSize({ width: 1440, height: 1000 });
  // The 900 ms confirmation state and its 150 ms return have completed.
  await page.mouse.move(0, 0);
  await page.waitForTimeout(100);
  await page.evaluate(() => { window.__motionAudit.label = "tooltip-first"; });
  await page.locator("#copy-recovery").hover();
  await page.waitForTimeout(430);
  const tooltipFirst = await page.evaluate(() => ({
    animations: document.querySelector(".tip")?.getAnimations().map((animation) => ({ duration: animation.effect?.getTiming().duration, playState: animation.playState })) ?? [],
    width: document.querySelector<HTMLElement>(".tip")?.getBoundingClientRect().width ?? 0,
    origin: getComputedStyle(document.querySelector<HTMLElement>(".tip")!).transformOrigin,
  }));
  await page.evaluate(() => window.__motionAudit.startSample());
  await page.waitForTimeout(180);
  const tooltipFirstSample = await sampleAndEvents(page, "tooltip-first");
  await page.evaluate(() => { window.__motionAudit.label = "tooltip-move"; });
  await page.evaluate(() => {
    const tip = document.querySelector<HTMLElement>(".tip")!;
    const changes: string[] = [];
    new MutationObserver(() => changes.push(`${performance.now().toFixed(1)} ${tip.style.cssText}`))
      .observe(tip, { attributes: true, attributeFilter: ["style"] });
    Object.assign(window, { __tooltipStyleChanges: changes });
  });
  const scrollBeforeTooltipMove = await page.evaluate(() => scrollY);
  const downloadBox = await page.locator("#download-recovery").boundingBox();
  if (!downloadBox) throw new Error("download action is not in the viewport");
  await page.mouse.move(downloadBox.x + downloadBox.width / 2, downloadBox.y + downloadBox.height / 2);
  const scrollAfterTooltipMove = await page.evaluate(() => scrollY);
  await page.evaluate(() => window.__motionAudit.startSample());
  await page.waitForTimeout(70);
  const tooltipDuringMove = await page.evaluate(() => ({
    width: document.querySelector<HTMLElement>(".tip")?.getBoundingClientRect().width ?? 0,
    animations: document.querySelector<HTMLElement>(".tip")?.getAnimations().map((animation) => ({ duration: animation.effect?.getTiming().duration, playState: animation.playState })) ?? [],
    transition: getComputedStyle(document.querySelector<HTMLElement>(".tip")!).transition,
    styleChanges: (window as unknown as { __tooltipStyleChanges: string[] }).__tooltipStyleChanges,
  }));
  await page.waitForTimeout(170);
  const tooltip = await sampleAndEvents(page, "tooltip-move");
  expect(tooltipDuringMove.width).toBe(190);
  expect(tooltip.events.filter((event) => event.selector === "div.tip" && event.property === "width")).toEqual([]);
  expect(tooltipDuringMove.transition).not.toContain("width");
  console.log(`MOTION_AUDIT tooltip-first ${JSON.stringify(tooltipFirst)}`);
  console.log(`MOTION_AUDIT tooltip-first-sample ${JSON.stringify(tooltipFirstSample)}`);
  console.log(`MOTION_AUDIT tooltip-during-move ${JSON.stringify({ ...tooltipDuringMove, scrollBeforeTooltipMove, scrollAfterTooltipMove })}`);
  console.log(`MOTION_AUDIT tooltip-move ${JSON.stringify(tooltip)}`);

  await page.mouse.move(0, 0);
  await page.waitForTimeout(150);
  await page.evaluate(() => { window.__motionAudit.label = "pointer-checkbox"; window.__motionAudit.startSample(); });
  await page.locator("label.auth-check").click();
  await page.waitForTimeout(50);
  const pointerTickMid = await page.locator("label.auth-check .tick path").evaluate((path) => ({
    inlineOffset: (path as SVGPathElement).style.strokeDashoffset,
    computedOffset: getComputedStyle(path).strokeDashoffset,
    checked: document.querySelector<HTMLInputElement>("#recovery-saved")!.checked,
  }));
  const pointerTickMidOffset = Number.parseFloat(pointerTickMid.inlineOffset);
  await expect.poll(() => page.locator("label.auth-check .tick path").evaluate((path) => Number.parseFloat((path as SVGPathElement).style.strokeDashoffset)), { timeout: 1_500 }).toBe(0);
  const pointerTickEndOffset = await page.locator("label.auth-check .tick path").evaluate((path) => getComputedStyle(path).strokeDashoffset);
  const pointerCheckbox = await sampleAndEvents(page, "pointer-checkbox");
  console.log(`MOTION_AUDIT checkbox-draw-state ${JSON.stringify({ pointerCheckbox, pointerTickMid, pointerTickEndOffset })}`);
  expect(pointerTickMidOffset).toBeGreaterThan(0);
  expect(pointerTickMidOffset).toBeLessThan(1);
  expect(Number.parseFloat(pointerTickEndOffset)).toBe(0);

  await page.locator("#recovery-saved").focus();
  await page.evaluate(() => { window.__motionAudit.label = "keyboard-checkbox"; window.__motionAudit.startSample(); });
  await page.keyboard.press("Space");
  const keyboardOffOffset = Number.parseFloat(await page.locator("label.auth-check .tick path").evaluate((path) => (path as SVGPathElement).style.strokeDashoffset));
  await page.keyboard.press("Space");
  const keyboardTickOffset = Number.parseFloat(await page.locator("label.auth-check .tick path").evaluate((path) => (path as SVGPathElement).style.strokeDashoffset));
  await page.waitForTimeout(80);
  const checkbox = await sampleAndEvents(page, "keyboard-checkbox");
  expect(checkbox.events.filter((event) => event.selector === "#setup-next")).toEqual([]);
  expect(keyboardOffOffset).toBe(1);
  expect(keyboardTickOffset).toBe(0);
  console.log(`MOTION_AUDIT keyboard-checkbox ${JSON.stringify(checkbox)}`);

  await page.locator("#copy-recovery").focus();
  await page.evaluate(() => { window.__motionAudit.label = "keyboard-copy"; window.__motionAudit.startSample(); });
  await page.keyboard.press("Enter");
  await expect(page.locator("#copy-recovery")).toHaveAttribute("data-done", "");
  await page.waitForTimeout(300);
  const keyboardCopy = await sampleAndEvents(page, "keyboard-copy");
  expect(keyboardCopy.events.filter((event) => event.selector.startsWith("svg.") || event.selector === "path")).toEqual([]);
  console.log(`MOTION_AUDIT keyboard-copy ${JSON.stringify(keyboardCopy)}`);

  await page.waitForTimeout(650);
  await expect(page.locator("#copy-recovery")).not.toHaveAttribute("data-done");
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.waitForTimeout(180);
  await page.evaluate(() => { window.__motionAudit.label = "reduced-pointer-copy"; window.__motionAudit.startSample(); });
  await page.locator("#copy-recovery").click();
  await page.waitForTimeout(240);
  const reducedCopy = await sampleAndEvents(page, "reduced-pointer-copy");
  const reducedCopyStyles = await page.locator("#copy-recovery .is-done, #copy-recovery .is-done path").evaluateAll((elements) => elements.map((element) => {
    const style = getComputedStyle(element);
    return { filter: style.filter, transform: style.transform, strokeDashoffset: Number.parseFloat(style.strokeDashoffset) };
  }));
  expect(reducedCopy.events.every((event) => event.property === "opacity")).toBe(true);
  expect(reducedCopy.events.some((event) => event.property === "opacity")).toBe(true);
  expect(reducedCopyStyles).toEqual([
    { filter: "none", transform: "none", strokeDashoffset: 0 },
    { filter: "none", transform: "none", strokeDashoffset: 0 },
  ]);
  console.log(`MOTION_AUDIT reduced-copy ${JSON.stringify({ reducedCopy, reducedCopyStyles })}`);
  await page.emulateMedia({ reducedMotion: "no-preference" });
  await page.waitForTimeout(220);
  await page.waitForTimeout(500); // finish the reduced-copy hold before sampling the keyboard download

  await page.locator("#download-recovery").focus();
  await page.evaluate(() => { window.__motionAudit.label = "keyboard-download"; window.__motionAudit.startSample(); });
  const downloadPromise = page.waitForEvent("download");
  await page.keyboard.press("Enter");
  await downloadPromise;
  await page.waitForTimeout(300);
  const keyboardDownload = await sampleAndEvents(page, "keyboard-download");
  expect(keyboardDownload.events.filter((event) => event.selector.startsWith("svg.") || event.selector === "path")).toEqual([]);
  console.log(`MOTION_AUDIT keyboard-download ${JSON.stringify(keyboardDownload)}`);

  await page.locator("#setup-next").focus();
  await page.evaluate(() => { window.__motionAudit.label = "keyboard-finish-setup"; window.__motionAudit.startSample(); });
  await page.keyboard.press("Enter");
  await expect(page.locator("#welcome-title")).toHaveText("Welcome to infraternal");
  await page.waitForTimeout(1_200);
  const welcome = await sampleAndEvents(page, "keyboard-finish-setup");
  const welcomeStyle = await styles(page, ["#welcome-title", ".welcome-copy p", "#faulty-field"]);
  expect(welcome.events).toEqual([]);
  expect(welcomeStyle.find((style) => style.selector === ".welcome-copy p")?.animationName).toBe("none");
  const welcomePath = testInfo.outputPath("motion-audit-welcome.png");
  await page.screenshot({ path: welcomePath, fullPage: true });
  await testInfo.attach("production welcome", { path: welcomePath, contentType: "image/png" });
  console.log(`MOTION_AUDIT welcome ${JSON.stringify({ welcome, welcomeStyle })}`);

  await expect(page.locator("#terminal-screen")).toBeVisible({ timeout: 15_000 });
  await expect(page.locator("#terminal-screen")).toHaveAttribute("data-connected", "true", { timeout: 30_000 });
  const corePath = testInfo.outputPath("motion-audit-core.png");
  await page.screenshot({ path: corePath, animations: "disabled" });
  await testInfo.attach("production core", { path: corePath, contentType: "image/png" });
  await page.waitForTimeout(800); // allow the 700 ms terminal activity window and backdrop teardown to finish
  const idleStartFrame = await page.evaluate(() => window.__motionAudit.frameTimes.length);
  await page.waitForTimeout(1_100);
  const idle = await page.evaluate((startFrame) => ({
    rafCallbacks: [...window.__motionAudit.rAFs.values()],
    pending: [
      ...[...window.__motionAudit.timeouts.values()],
      ...[...window.__motionAudit.intervals.values()],
    ],
    totalObservedRafFrames: window.__motionAudit.frameTimes.length,
    idleRafFrames: window.__motionAudit.frameTimes.length - startFrame,
  }), idleStartFrame);
  expect(idle.rafCallbacks).toEqual([]);
  expect(idle.pending).toEqual([]);
  expect(idle.idleRafFrames).toBe(0);
  console.log(`MOTION_AUDIT core-idle ${JSON.stringify(idle)}`);

  await page.evaluate(() => { window.__motionAudit.label = "keyboard-palette"; window.__motionAudit.startSample(); });
  await page.keyboard.press("Control+k");
  await expect(page.locator("#palette")).toBeVisible();
  await page.waitForTimeout(220);
  const palette = await sampleAndEvents(page, "keyboard-palette");
  const paletteStyle = await styles(page, ["#palette", "#scrim"]);
  console.log(`MOTION_AUDIT keyboard-palette ${JSON.stringify({ palette, paletteStyle })}`);
  await page.locator("#palette-input").fill("dracula");
  const themeStartAt = await page.evaluate(() => performance.now());
  await page.evaluate(() => { window.__motionAudit.label = "keyboard-theme"; window.__motionAudit.startSample(); });
  await page.keyboard.press("Enter");
  await expect(page.locator("#terminal-screen")).toHaveAttribute("data-theme", "dracula");
  await expect.poll(() => page.evaluate(() => window.__motionAudit.rAFs.size)).toBe(0);
  const keyboardTheme = await sampleAndEvents(page, "keyboard-theme");
  const themeTiming = await page.evaluate((startAt) => {
    const endAt = performance.now();
    return {
      endAt,
      frames: window.__motionAudit.frameTimes.filter((time) => time >= startAt && time <= endAt).length,
      longTasks: window.__motionAudit.longTasks.filter((task) => task.startTime < endAt && task.startTime + task.duration > startAt),
    };
  }, themeStartAt);
  expect(keyboardTheme.events).toEqual([]);
  expect(themeTiming.longTasks).toEqual([]);
  console.log(`MOTION_AUDIT keyboard-theme ${JSON.stringify({ ...keyboardTheme, ...themeTiming })}`);
  await page.keyboard.press("Escape");

  await page.keyboard.press("Control+k");
  await page.locator("#palette-input").fill("Mesh from the theme");
  const backdropStartAt = await page.evaluate(() => performance.now());
  await page.evaluate(() => { window.__motionAudit.label = "keyboard-backdrop"; window.__motionAudit.startSample(); });
  await page.keyboard.press("Enter");
  await page.waitForTimeout(280);
  const keyboardBackdrop = await sampleAndEvents(page, "keyboard-backdrop");
  const backdropTiming = await page.evaluate((startAt) => {
    const endAt = performance.now();
    return {
      startAt,
      endAt,
      longTasks: window.__motionAudit.longTasks.filter((task) => task.startTime < endAt && task.startTime + task.duration > startAt),
    };
  }, backdropStartAt);
  expect(keyboardBackdrop.events.filter((event) => event.selector === "div.backdrop")).toEqual([]);
  expect(backdropTiming.longTasks).toEqual([]);
  await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--mesh-image"))).toContain("blob:");
  expect(requestedWorkers).toHaveLength(1);
  const meshPath = testInfo.outputPath("motion-audit-mesh.png");
  await page.screenshot({ path: meshPath });
  await testInfo.attach("production mesh", { path: meshPath, contentType: "image/png" });
  console.log(`MOTION_AUDIT keyboard-backdrop ${JSON.stringify({ ...keyboardBackdrop, ...backdropTiming, requestedWorkers })}`);
  await page.keyboard.press("Control+k");
  await page.locator("#palette-input").fill("None");
  await page.keyboard.press("Enter");
  await page.waitForTimeout(260);

  await page.locator("#sidebar-toggle").focus();
  await page.evaluate(() => { window.__motionAudit.label = "keyboard-sidebar"; window.__motionAudit.startSample(); });
  await page.keyboard.press("Enter");
  await expect(page.locator("#sidebar")).toBeVisible();
  await page.waitForTimeout(260);
  const sidebar = await sampleAndEvents(page, "keyboard-sidebar");
  console.log(`MOTION_AUDIT keyboard-sidebar ${JSON.stringify(sidebar)}`);
  await page.evaluate(() => { window.__motionAudit.label = "pointer-sidebar"; window.__motionAudit.startSample(); });
  await page.locator("#sidebar-toggle").click();
  await page.waitForTimeout(280);
  const pointerSidebar = await sampleAndEvents(page, "pointer-sidebar");
  console.log(`MOTION_AUDIT pointer-sidebar ${JSON.stringify(pointerSidebar)}`);
  await page.locator("#sidebar-toggle").click();
  await page.waitForTimeout(280);

  await page.locator("#tree .bm-head").focus();
  await page.evaluate(() => { window.__motionAudit.label = "keyboard-fold"; window.__motionAudit.startSample(); });
  await page.keyboard.press("Space");
  await page.waitForTimeout(260);
  const fold = await sampleAndEvents(page, "keyboard-fold");
  console.log(`MOTION_AUDIT keyboard-fold ${JSON.stringify(fold)}`);

  await page.waitForTimeout(280);
  await page.evaluate(() => { window.__motionAudit.label = "pointer-fold"; window.__motionAudit.startSample(); });
  await page.locator("#tree .bm-head").click();
  await page.waitForTimeout(280);
  const pointerFold = await sampleAndEvents(page, "pointer-fold");
  expect(pointerFold.events.filter((event) => event.property === "grid-template-rows")).toEqual([]);
  console.log(`MOTION_AUDIT pointer-fold ${JSON.stringify(pointerFold)}`);
  await page.evaluate(() => { window.__motionAudit.label = "pointer-branch"; window.__motionAudit.startSample(); });
  await page.locator("#tree .bm-leaf:not(:disabled)").click();
  await page.waitForTimeout(320);
  const pointerBranch = await sampleAndEvents(page, "pointer-branch");
  const branch = await page.evaluate(() => ({
    markerTransition: getComputedStyle(document.querySelector<HTMLElement>(".bm-marker")!).transition,
    drawAnimations: document.querySelector<SVGPathElement>(".bm-lit")!.getAnimations().map((animation) => ({ duration: animation.effect?.getTiming().duration, playState: animation.playState })),
    foldTransition: getComputedStyle(document.querySelector<HTMLElement>(".bm-fold")!).transition,
  }));
  expect(pointerBranch.events.filter((event) => event.selector === "path.bm-lit" && event.kind === "waapi")).toEqual([]);
  expect(branch.drawAnimations).toEqual([]);
  expect(pointerBranch.events.filter((event) => event.property === "grid-template-rows")).toEqual([]);
  console.log(`MOTION_AUDIT pointer-branch ${JSON.stringify({ sample: pointerBranch, branch })}`);

  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.evaluate(() => { window.__motionAudit.label = "reduced-pointer-sidebar"; window.__motionAudit.startSample(); });
  await page.locator("#sidebar-toggle").click();
  await page.waitForTimeout(250);
  const reducedSidebar = await sampleAndEvents(page, "reduced-pointer-sidebar");
  const reducedStyles = await styles(page, ["#sidebar", ".bm-fold", ".auth-primary"]);
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator("#sidebar")).toBeVisible();
  await page.waitForTimeout(220);
  await page.evaluate(() => { window.__motionAudit.label = "reduced-pointer-fold"; window.__motionAudit.startSample(); });
  await page.locator("#tree .bm-head").click();
  await page.waitForTimeout(260);
  const reducedFold = await sampleAndEvents(page, "reduced-pointer-fold");
  expect(reducedSidebar.events.filter((event) => event.selector === "#sidebar-toggle" && event.property === "transform")).toEqual([]);
  expect(reducedFold.events.filter((event) => event.property === "transform" || event.property === "grid-template-rows")).toEqual([]);
  console.log(`MOTION_AUDIT reduced-motion ${JSON.stringify({ reducedSidebar, reducedFold, reducedStyles })}`);

  const mobileContext = await browser.newContext({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true });
  try {
    const cookies = await context.cookies();
    await mobileContext.addCookies(cookies);
    const mobile = await mobileContext.newPage();
    await mobile.addInitScript(() => {
      Object.defineProperty(window, "__motionAudit", { value: { label: "mobile", events: [], frameTimes: [], pending: [], longTasks: [], rAFs: new Map(), timeouts: new Map(), intervals: new Map(), startSample() {}, stopSample: () => ({ frames: 0, dropped: 0, longestGapMs: 0 }) }, configurable: true });
    });
    await mobile.goto("/?mock=1&theme=paper");
    await expect(mobile.locator("#terminal-screen")).toHaveAttribute("data-connected", "true", { timeout: 30_000 });
    await expect(mobile.locator("#keybar")).toBeVisible();
    await mobile.waitForTimeout(300);
    const mobileMotion = await mobile.evaluate(() => ({
      keybarTransition: getComputedStyle(document.querySelector<HTMLElement>("#keybar")!).transition,
      keybarState: document.querySelector<HTMLElement>("#keybar")!.className,
      activeAnimations: document.getAnimations().map((animation) => ({ duration: animation.effect?.getTiming().duration, playState: animation.playState })),
    }));
    console.log(`MOTION_AUDIT mobile-keybar ${JSON.stringify(mobileMotion)}`);
    const mobilePath = testInfo.outputPath("motion-audit-mobile.png");
    await mobile.screenshot({ path: mobilePath, animations: "disabled" });
    await testInfo.attach("production mobile", { path: mobilePath, contentType: "image/png" });
  } finally {
    await mobileContext.close();
  }

  // Repeat the first-run flow with pointer input to measure its approved step glide
  // and rare welcome effect separately from the keyboard path above.
  await context.request.post("/__mock/reset");
  await context.clearCookies();
  await page.evaluate(() => localStorage.clear());
  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "no-preference" });
  await page.goto("/?mock=1", { waitUntil: "commit" });
  const startupStarted = await page.evaluate(() => {
    window.__motionAudit.label = "pointer-auth-startup";
    window.__motionAudit.startSample();
    return performance.now();
  });
  await expect(page.locator("#setup-card")).toBeVisible();
  await expect(page.locator("#faulty-field")).toHaveAttribute("data-ready", "true");
  await page.waitForTimeout(320);
  const pointerStartup = await sampleAndEvents(page, "pointer-auth-startup");
  const startupLongTasks = await page.evaluate((startAt) => window.__motionAudit.longTasks
    .filter((task) => task.startTime < performance.now() && task.startTime + task.duration > startAt), startupStarted);
  const faultyWorkerWindow = await page.evaluate(() => {
    const marks = window.__faultyReadyMarks;
    const [startedAt, readyAt] = marks;
    return {
      startedAt,
      readyAt,
      longTasks: window.__motionAudit.longTasks.filter((task) => task.startTime < (readyAt ?? Infinity)
        && task.startTime + task.duration > (startedAt ?? -Infinity)),
    };
  });
  expect(faultyWorkerWindow.longTasks).toEqual([]);
  console.log(`MOTION_AUDIT pointer-auth-startup ${JSON.stringify({ ...pointerStartup, longTasks: startupLongTasks, faultyWorkerWindow, requestedFaultyWorkers })}`);

  const pointerSetup = await (await context.request.get("/__mock/setup-token")).json() as { setup_token: string };
  await page.locator("#setup-token").fill(pointerSetup.setup_token);
  await page.evaluate(() => { window.__motionAudit.label = "pointer-step-token"; window.__motionAudit.startSample(); });
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.locator("#setup-username")).toBeVisible();
  await page.waitForTimeout(280);
  const pointerToken = await sampleAndEvents(page, "pointer-step-token");
  const pointerTokenStyles = await page.evaluate(() => ({
    noMotion: document.querySelector("#setup-card")?.hasAttribute("data-no-motion"),
    viewport: getComputedStyle(document.querySelector<HTMLElement>("#setup-viewport")!).transition,
    height: document.querySelector<HTMLElement>("#setup-viewport")!.getBoundingClientRect().height,
    paneAnimation: getComputedStyle(document.querySelector<HTMLElement>(".auth-pane")!).animationName,
  }));
  expect(pointerTokenStyles.noMotion).toBe(false);
  const heightGlides = pointerToken.events.filter((event) => event.kind === "transition" && event.property === "height");
  expect(heightGlides).not.toEqual([]);
  expect(heightGlides.every((event) => event.duration === "0.24s")).toBe(true);
  console.log(`MOTION_AUDIT pointer-step-token ${JSON.stringify({ ...pointerToken, styles: pointerTokenStyles })}`);

  await page.locator("#setup-username").fill("Ada");
  await page.locator("#setup-display-name").fill("Ada Lovelace");
  await page.evaluate(() => { window.__motionAudit.label = "pointer-step-identity"; window.__motionAudit.startSample(); });
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("heading", { name: "Create your passkey" })).toBeVisible();
  await page.waitForTimeout(280);
  const pointerIdentity = await sampleAndEvents(page, "pointer-step-identity");
  console.log(`MOTION_AUDIT pointer-step-identity ${JSON.stringify(pointerIdentity)}`);

  await page.getByRole("button", { name: "Create passkey" }).click();
  await expect(page.locator("#recovery-words")).toBeVisible();
  await page.locator("label.auth-check").click();
  await expect(page.getByRole("button", { name: "Open infraternal" })).toBeEnabled();
  await page.evaluate(() => { window.__motionAudit.label = "pointer-welcome"; window.__motionAudit.startSample(); });
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await expect(page.locator("#welcome-title")).toHaveText("Welcome to infraternal");
  await page.waitForTimeout(1_200);
  const pointerWelcome = await sampleAndEvents(page, "pointer-welcome");
  const pointerWelcomeStyle = await styles(page, ["#welcome-title", ".welcome-copy p", "#faulty-field"]);
  expect(pointerWelcomeStyle.find((style) => style.selector === ".welcome-copy p")?.animationDuration).toBe("0.24s");
  const pointerWelcomePath = testInfo.outputPath("motion-audit-pointer-welcome.png");
  await page.screenshot({ path: pointerWelcomePath, fullPage: true });
  await testInfo.attach("production pointer welcome", { path: pointerWelcomePath, contentType: "image/png" });
  console.log(`MOTION_AUDIT pointer-welcome ${JSON.stringify({ pointerWelcome, pointerWelcomeStyle })}`);

  await context.request.post("/__mock/reset");
  await context.clearCookies();
  await page.evaluate(() => localStorage.clear());
  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
  await page.goto("/?mock=1", { waitUntil: "commit" });
  await page.evaluate(() => { window.__motionAudit.label = "reduced-auth"; window.__motionAudit.startSample(); });
  await expect(page.locator("#setup-card")).toBeVisible();
  await expect(page.locator("#faulty-field")).toHaveAttribute("data-ready", "true");
  await page.waitForTimeout(320);
  const reducedAuth = await sampleAndEvents(page, "reduced-auth");
  const reducedAuthStyle = await styles(page, ["#setup-card", "#faulty-field"]);
  expect(reducedAuth.events).toEqual([]);
  expect(reducedAuthStyle.find((style) => style.selector === "#setup-card")?.animationName).toBe("none");
  await page.waitForTimeout(1_300); // reduced shader mode draws one frame and leaves no work queued
  const reducedAuthIdleStart = await page.evaluate(() => window.__motionAudit.frameTimes.length);
  await page.waitForTimeout(1_100);
  const reducedAuthIdle = await page.evaluate((startFrame) => ({
    rafCallbacks: [...window.__motionAudit.rAFs.values()],
    pending: [...window.__motionAudit.timeouts.values(), ...window.__motionAudit.intervals.values()],
    idleRafFrames: window.__motionAudit.frameTimes.length - startFrame,
  }), reducedAuthIdleStart);
  expect(reducedAuthIdle.rafCallbacks).toEqual([]);
  expect(reducedAuthIdle.pending).toEqual([]);
  expect(reducedAuthIdle.idleRafFrames).toBe(0);
  console.log(`MOTION_AUDIT reduced-auth ${JSON.stringify({ reducedAuth, reducedAuthStyle, reducedAuthIdle })}`);

  await cdp.send("Emulation.setCPUThrottlingRate", { rate: 1 });
});

async function sampleAndEvents(page: Page, label: string): Promise<{ sample: MotionSample; events: MotionEvent[] }> {
  return page.evaluate((eventLabel) => {
    const probe = window.__motionAudit;
    const sample = probe.stopSample();
    return { sample, events: probe.events.filter((event) => event.label === eventLabel) };
  }, label);
}

async function styles(page: Page, selectors: string[]): Promise<Array<Record<string, string>>> {
  return page.evaluate((items) => items.map((selector) => {
    const element = document.querySelector<HTMLElement>(selector);
    if (!element) return { selector, missing: "true" };
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return {
      selector,
      animationName: style.animationName,
      animationDuration: style.animationDuration,
      animationDelay: style.animationDelay,
      transitionProperty: style.transitionProperty,
      transitionDuration: style.transitionDuration,
      transitionDelay: style.transitionDelay,
      transitionTimingFunction: style.transitionTimingFunction,
      transformOrigin: style.transformOrigin,
      transform: style.transform,
      visible: String(rect.width > 0 && rect.height > 0 && style.visibility !== "hidden"),
    };
  }), selectors);
}
