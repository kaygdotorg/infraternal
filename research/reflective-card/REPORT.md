<!-- Role: research findings and implementation guidance for issue #76; this file does not change product contracts or code. -->

# Reflective share card: research report

Research date: 2026-10-07  
Issue: `kayg/infraternal#76`  
Scope: research only; the only behavior artifact is the standalone [demo](./demo.html).

## Recommendation

Use a single reusable `packages/ui` reflective surface made from a few static CSS gradient layers and one moving highlight overlay. Drive the overlay with `transform` and the existing shared spring, then stop the animation frame loop as soon as it settles. This gives the share card a soft metallic sheen without a camera, a filter graph, a WebGL context, or a per-frame gradient repaint.

On phones, show an **Enable tilt** affordance on the card. Call `DeviceOrientationEvent.requestPermission()` directly from that tap when the browser exposes it. Do not prompt just because the share card opened. Touch drag remains available if access is declined, unavailable, or produces no sensor events. On desktop, pointer position drives the same spring. Use one static, intentionally composed reflection pose for reduced motion and PNG export.

The live [Reflective Card preview](https://sveltebits.xyz/components/reflective-card) was inspected as a visual reference: it reads as softly cloudy metallic glass, with a broad pale sheen, a few edge glints, and enough diffuse texture to keep the surface from looking flat. This report describes that appearance and the general technique family only. The preview source was not reused or paraphrased; the demo was written from scratch.

## 1. Technique and cost

| Technique | How it creates the look | Runtime cost and fit here |
| --- | --- | --- |
| CSS gradients and blend modes | A dark or themed base, a radial hotspot, a broad conic or diagonal sheen, and a restrained edge highlight. `screen`, `soft-light`, or a theme-specific blend gives the layers a glassy overlap. | **Cheapest suitable choice.** Keep the gradients static and translate one overlay. The browser may keep that overlay in a composited layer, so pointer and tilt updates can avoid layout and repaint. Blend modes still need compositing and use pixels for the overlay bounds. Verify Safari paint/compositing on a phone. |
| SVG filter (`feTurbulence`, `feSpecularLighting`, optional displacement) | Turbulence makes a procedural noise field that can act like a rough surface; specular lighting turns its surface variation into bright glints; displacement can bend the underlying image. This produces richer, less uniform reflections than CSS alone. | Filter primitives operate on image regions and can create intermediate RGBA images. The SVG spec says processing and memory scale with the filter region and `filterRes`; MDN cautions that referenced SVG filters can be slow. WebKit historically described animated SVG filters as CPU-heavy. Current Safari behavior is hardware-, filter-, and version-dependent, so this is a **profiling risk**, not a claim that every current Safari filter always runs on CPU. Avoid recomputing a turbulence/light/displacement graph on each input event. [SVG filter region and resolution](https://www.w3.org/TR/SVG11/filters/#FilterElement), [`feTurbulence`](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Element/feTurbulence), [`feSpecularLighting`](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Element/feSpecularLighting), [historical WebKit performance issue](https://bugs.webkit.org/show_bug.cgi?id=43903). |
| WebGL | A fragment shader can calculate procedural normals, colored highlights, and refraction in GPU passes. It can animate a surface with much more control than CSS. | Pixel work moves mostly to the GPU, but cost still grows with covered pixels, overdraw, passes, and texture size. A context, shader lifecycle, texture memory, and device-specific fallback are unnecessary complexity for one square card. Consider only if the owner asks for visibly warped/liquid reflections and a real-device benchmark justifies it. [WebGL API overview](https://developer.mozilla.org/en-US/docs/Web/API/WebGL_API). |

### Cheapest look that is close enough

The share card needs a moving highlight, not a physically correct reflection of the room. Use a themed base, two or three static radial/linear/conic gradient layers, a thin stationary edge treatment, and a single translated overlay. Keep the overlay modestly larger than the card so its edges do not show during movement. Avoid animating `background-position`, gradient stops, filter parameters, or a parent CSS variable on every sensor sample; those choices can trigger style recalculation or paint. Only the overlay itself needs to move.

This is an approximation: CSS gives a smooth light sweep and colored haze, but it does not refract the card's surroundings or create true view-dependent reflection. If that visual gap matters after owner review, benchmark an SVG filter against a small WebGL shader on a real iPhone. Do not add a rendering library based on a desktop-only result.

The filter cost is tied to surface area. As a rough scale example, the demo's 361 CSS-pixel card at DPR 3 covers about 1.17 million device pixels. One full-resolution RGBA8 intermediate for that area is about 4.7 MB; four simultaneous full-size buffers would be about 18.8 MB before filter padding and engine overhead. That is a raw-buffer estimate, **not** a measured Safari allocation; engines can tile, reuse buffers, or choose another resolution. It illustrates why a multi-pass filter should stay small and should not be assumed free when several cards reuse the material. [The SVG spec's region and `filterRes` guidance](https://www.w3.org/TR/SVG11/filters/#FilterElement).

## 2. Input and motion

### iOS Safari and Home Screen web apps

Safari added the device motion/orientation permission API on iOS 13. `DeviceOrientationEvent.requestPermission()` resolves to `granted` or `denied`; when the permission is still at its prompt state, the call needs transient user activation. The method is secure-context only, so the real phone test must use HTTPS. Call it in the tap handler itself, before any timer or unrelated `await`. The default argument requests relative orientation; there is no need to ask for compass/magnetometer access for a decorative tilt. [Safari 13 release notes](https://developer.apple.com/documentation/safari-release-notes/safari-13-release-notes), [MDN requestPermission reference](https://developer.mozilla.org/en-US/docs/Web/API/DeviceOrientationEvent/requestPermission_static), [W3C method steps](https://www.w3.org/TR/orientation-event/#dom-deviceorientationevent-requestpermission).

Treat the installed Home Screen web app as its own test context. Apple describes it as an app-like standalone launch, but I found no current Apple/WebKit documentation or motion-specific test matrix that establishes whether a `deviceorientation` grant persists identically between Safari and a Home Screen app for every iOS release from 17 through 27. The WebKit [2019 permission discussion](https://bugs.webkit.org/show_bug.cgi?id=197750) describes grants cached for the current session; it is useful history, not proof of behavior on current iOS releases. Reports of repeated prompts in [WebKit's PWA camera issue](https://bugs.webkit.org/show_bug.cgi?id=280394) concern `getUserMedia` camera access, not orientation. The older [WKWebView issue](https://bugs.webkit.org/show_bug.cgi?id=213468) is a native-app web view, not Safari or an installed Home Screen web app. Those reports do not verify that motion permission resets on every PWA launch.

**Finding:** the reported lack of persistence is plausible enough to design around, but it is not verified for `DeviceOrientationEvent` across iOS 17–27. Safari's API gives the page a grant/deny result rather than a reliable cross-version persistence query. Keep a clear tap-to-enable control available after each launch; if the browser retained access, the call can resolve without a new prompt. If it did not, the user can grant again. A refusal or error must leave drag and pointer input working.

There is also a [WebKit iOS 26 iframe report](https://bugs.webkit.org/show_bug.cgi?id=301294) where an accepted motion prompt did not result in events inside a cross-origin frame. It was later marked as a duplicate after a fix landed in WebKit, but the tracker does not establish which shipped OS release contains it. Keep the reflective surface in the app's top-level document instead of introducing an iframe boundary.

### Android, desktop, and fallback

Android browsers have generally delivered device orientation without a Safari-style prompt. That assumption is changing in Chromium: its [June 2026 Intent to Ship](https://groups.google.com/a/chromium.org/g/blink-dev/c/ckd2rFmT3PA) targets milestone 151 for desktop and Android. The initial rollout keeps the existing default permission as `ALLOW`, while the proposal says the longer-term plan may move it to `ASK`. In this worktree, headless Chromium 153 exposed `DeviceOrientationEvent.requestPermission` as a function. **Feature-detect the method and handle its result; do not branch on Android user-agent strings or assume that a method's presence means a prompt will appear.**

| Input | Recommended behavior |
| --- | --- |
| Desktop mouse/trackpad | Map pointer position inside the card to a clamped highlight target. Return gently toward a composed rest angle on pointer leave. |
| Touch | Allow a one-finger drag over the card as the fallback. Use pointer capture after drag begins so the gesture can finish outside the card. The demo uses `touch-action: none` on the isolated card; product code must preserve the canvas's existing scroll and gesture contract. |
| Phone orientation | Ask only after the user taps **Enable tilt**. Read relative `beta`/`gamma`, calibrate against the first event, clamp the range, and remap axes if screen orientation changes because sensor coordinates remain device-relative. If permission is denied, the device has no usable sensor, or no events arrive, keep touch drag available. [W3C coordinate model](https://www.w3.org/TR/orientation-event/#deviceorientation). |
| Keyboard and assistive technology | Expose the enable control as a real button with a pressed state. The reflective motion is decorative; it must not carry host information or be required to share the card. |

### Spring and lifecycle

The local animation standards recommend a spring for decorative mouse tracking because it preserves velocity when the user reverses direction. Reuse the package's shared spring if available; do not add a one-off spring helper. The demo uses mass 1, stiffness 150, damping 25, which is close to critical damping and gives a responsive settle without visible bounce. Those numbers are a behavior example, not a locked product contract.

An input event should update a target and schedule at most one `requestAnimationFrame`. The frame callback advances the spring and writes `transform` on the highlight element. When position and velocity are within a small threshold, stop scheduling frames. Use `visibilitychange` to cancel an in-flight frame and detach orientation listening while hidden; close does the same. On return, refresh card bounds and reattach only if the user enabled tilt. Browsers usually pause animation frames in hidden tabs, but explicit cleanup also stops sensor work and makes the component lifecycle clear. [Chrome animation guidance](https://web.dev/articles/animations-and-performance), [Page Visibility API](https://developer.mozilla.org/en-US/docs/Web/API/Page_Visibility_API), [W3C visibility requirements for sensor events](https://www.w3.org/TR/orientation-event/#deviceorientation).

While a visible card has tilt enabled, retain the minimal orientation listener so a new physical tilt can wake the effect. Do not run a polling loop. Ignore unchanged or sub-deadzone samples, and do no paint work when the target has not changed. Apple describes `DeviceOrientationEvent` as firing while the user changes device orientation. [Apple DeviceOrientationEvent reference](https://developer.apple.com/documentation/webkitjs/deviceorientationevent).

## 3. Performance evidence

The final demo was measured in Chromium **153.0.8010.12**, headless, with DevTools CPU throttling at **4×**, a **393×852 CSS viewport** and **DPR 3**. Chrome describes CPU throttling as a relative slowdown applied to the host and recommends calibrated presets when approximating a target device. This 4× run is a relative stress factor, not a mobile CPU proxy; desktop throttling cannot reproduce mobile CPU architecture. [Chrome CPU throttling guidance](https://developer.chrome.com/docs/devtools/performance/reference/#throttle-the-cpu-while-recording).

The harness swept a pointer over the card for 3.2 seconds and sampled `requestAnimationFrame` timestamps. Two runs recorded 104 pointer updates each:

| Run | Samples | Mean / p50 / p95 / p99 / max interval | Intervals over 33.3 ms | Host load |
| --- | --- | --- | ---: | --- |
| Initial run | 298 timestamps (297 intervals) | 19.18 / 16.7 / 33.4 / 66.6 / 249.9 ms | 23 | 1-minute load 9.88 after run |
| Updated demo rerun | 194 timestamps (193 intervals) | 16.67 / 16.7 / 16.7 / 16.8 / 16.8 ms | 0 | 7.68 / 7.92 / 7.08 (1 / 5 / 15-minute load before run) |

Both runs used the same spring and frame-update path. The source changes between them added screen-axis remapping and restored pointer-leave recentering; the host load also changed, so the interval difference does not isolate a code effect. The spring returned to rest in about **1,069 ms**. In the updated run, after the `data-moving` state cleared, it produced **0 spring callbacks during the next 1 second**; closing the card produced **0 more callbacks during 750 ms**. The behavior check confirmed a simulated 90° screen rotation moved a beta tilt into the horizontal axis (`translate` x **8.55 px**, y **−0.01 px**) and mouse leave returned the overlay to within **0.01 px** of rest. A separate check confirmed theme switching, zero callbacks after close, and zero animation callbacks with reduced motion enabled.

These were **loaded desktop stress observations**, not an iPhone benchmark: the host has 8 CPU cores (Intel Core i9-9900K), and concurrent Rust/C compilation and infraternal processes were visible during the initial run. The median was one 60 Hz interval in both runs; the initial run's p95 and long-tail intervals exceeded one 60 Hz interval. These are sampled `requestAnimationFrame` timestamp intervals, not rendered-frame latency, and no reflective-card frame budget has been established. The runs confirm that the demo becomes idle after settling; they do **not** prove a 60 fps iPhone result. Rerun the surface on an idle pinned perf machine and a physical iPhone before setting a product budget or approving the visual layer.

## 4. PNG and text export

CSS in the DOM does not appear automatically in a separately painted `CanvasRenderingContext2D`. If the image exporter draws the card on canvas, it must also draw the same gradient layers, blend treatment, and border itself; otherwise the exported PNG will omit the live reflection. A canvas can render radial gradients and export PNG data through `toBlob`. [Canvas radial gradients](https://developer.mozilla.org/en-US/docs/Web/API/CanvasRenderingContext2D/createRadialGradient), [`HTMLCanvasElement.toBlob`](https://developer.mozilla.org/en-US/docs/Web/API/HTMLCanvasElement/toBlob).

Freeze a deliberate, attractive reflection pose for export—such as a soft upper-left sheen—and render it into the PNG. Do not let a transient pointer or device angle determine the shared file. D126 also allows a text share; text output has no visual reflection. For image sharing, test `navigator.canShare({ files })` and call `navigator.share()` from the share-button activation. [Web Share API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Share_API), [file share support](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/share).

## 5. Accessibility and contrast

- Under `prefers-reduced-motion: reduce`, use a static highlight pose, do not request or listen to motion sensors, and do not start a spring. [MDN reduced motion](https://developer.mozilla.org/en-US/docs/Web/CSS/%40media/prefers-reduced-motion).
- No flashing, pulsing, or automatic shimmer. The only movement follows explicit pointer, drag, or tilt input.
- Keep the card's text on a stable tinted/scrim layer above the highlight. Check contrast at the brightest and darkest highlight positions in both ink and paper themes. Normal text needs at least **4.5:1** and large text at least **3:1** under WCAG AA. [WCAG 1.4.3](https://www.w3.org/WAI/WCAG21/Understanding/contrast-minimum.html).
- Preserve the existing accessible share-card labels and make the tilt control keyboard operable. Do not require tilt to read or export the Machine facts.

## 6. Reuse under D160

Make this a reusable `ReflectiveSurface` primitive in `packages/ui`, with the share-card content supplied by a slot/children. Suggested per-instance API:

```text
intensity: 0..1
highlightColor: theme token or CSS color
inputSource: auto | pointer | orientation | static
active: card-open and visible state
reducedMotion: resolved user preference
```

The primitive should own the one sheen overlay, its input-to-target mapping, spring lifecycle, and cleanup. Reuse the shared spring and shared button/control patterns; let the share card provide the label for its tilt affordance. Do not copy a surface, button, or spring per card. Keep one active overlay per visible surface and zero scheduled animation frames at rest. The current worktree does not yet contain a `packages/ui` directory, so this report specifies the destination without creating or changing product code.

## 7. Suggested implementation plan and owner questions

1. **Owner UX decision:** use a visible **Enable tilt** tap inside the share card; do not show an iOS permission prompt just because the card opened. This is the recommended choice for an optional decorative effect. Keep drag available for users who decline or cannot use motion. If a later session needs permission again, the user taps again.
2. **Surface contract:** confirm `intensity`, `highlightColor`, `inputSource`, and `active` as per-instance properties. Keep the component content-agnostic and put it in `packages/ui` when that package is available.
3. **Build the CSS version first:** static layers, one transformed highlight, shared spring, card-relative pointer mapping, opt-in relative orientation, touch drag, and complete close/hidden/reduced-motion cleanup. No camera, no WebGL context, no animated SVG filter.
4. **Implement export separately from live input:** render a frozen default reflection into the PNG. Keep text sharing separate and continue hiding IPs by default per D126.
5. **Review real production screenshots** in ink and paper themes at phone and desktop sizes. Check the resting angle and extreme highlight positions for text contrast, and verify that the mobile drag does not break the canvas's existing gestures.
6. **Test platform permission behavior on real devices:** compare Safari and installed Home Screen web app on supported iOS 17/18/26/27 devices where available; test first grant, deny, relaunch, background/foreground, and rotation. Test current Chrome Android and a non-Chromium Android browser. The current public evidence does not settle cross-launch motion permission persistence.
7. **Measure before approval:** capture a clean 4× Chromium performance trace and a real iPhone Safari trace, including spring p95/p99, idle callbacks, card-close cleanup, and visible/hidden sensor work. A GPU or filter-heavy alternative needs a measured visual/performance reason to replace CSS.

Open owner questions:

- Approve tap-to-enable tilt rather than prompting on first open? **Recommended: tap-to-enable.**
- Should a prior in-app preference resume orientation automatically when a card reopens, or should each new launch show **Enable tilt** until tapped? **Recommended: do not issue permission requests without a tap; keep an explicit control when the browser's persisted grant is uncertain.**
- Approve a fixed, attractive PNG reflection angle independent of the user's live tilt? **Recommended: yes, for consistent exports.**
- Is the CSS approximation visually close enough, or does the owner want a separate measured SVG/WebGL spike for visible refraction? **Recommended: review CSS screenshots first, then request a spike only if the visual gap matters.**
