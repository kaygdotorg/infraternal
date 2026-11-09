# UI consistency audit (2026-11-04, #345, job J195)

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

The owner asked: "do that consistency audit to see where things like text sizes, ui size, corner radius, etc differ and fix them
if consistent and document if we decided it to be different." This is the record of that audit: what was measured, every
deviation from the shared tokens, and what happened to each one.

How to read the classes:

- **(a) accidental**: no decision or TASTE row asks for it; a shared token already holds the value. Fixed.
- **(b) deliberate**: a decision, a TASTE row or a platform rule requires it. Kept, and the code says why next to the value.
- **(c) unclear**: the owner has to decide. Left alone, listed under "Owner questions".
- **deferred**: the file is changed by an open branch (see "Deferred files"). The fix exists and waits for those branches to merge.

Read the tokens first: `packages/ui/styles.css` (type roles `--ui-type-*`, `--ui-tracking`, row and control heights, `--ui-icon`,
and, since this audit, the radius scale and easing curves), `apps/tracer/style.css` (`--fw-*`), and `packages/ui/src/ui-scale.ts`
(UI size: every length is in `rem` and the root font size carries the slider).

## 1. How it was measured

1. **Source inventory.** A scan of every `.css` file and every TypeScript file under `apps/tracer` and `packages/ui`
   (tests, vendored code and fonts excluded) for each declaration of: font size, weight, line height, letter spacing; corner
   radius; padding, margin, gap, insets; heights and widths; border and outline widths; shadows and blur; z-index; transition and
   animation durations and easings. 3390 declarations. The scanner is a 60-line script kept out of the repository (it is a
   one-off); its counts are in the tables below.
2. **Browser census.** `apps/tracer/test/ui-consistency-audit.spec.ts` (run with `UI_AUDIT=1`) loads a production build of the
   tracer and, for the canvas, sidebar, palette, Settings, a window popover and sign-in, at 1440×900, 393×852 and 375×667 in ink
   and paper, takes a screenshot and counts every distinct computed font size, weight, line height, letter spacing, radius,
   transition duration and easing, plus every custom property a rule reads with no fallback that the page never defines. The
   source tells what a rule asks for; the census tells what a person sees.

## 2. The result in numbers

Counts are declarations in the source on `origin/dev` a89ebb0ae, before any change. "Fixed" means fixed on a branch of this job;
"ready" means a commit exists on `ui-consistency-j195-deferred` and waits for the open branches.

| Property | Declarations | Uses the token | (a) accidental | (b) deliberate | (c) unclear |
|---|---|---|---|---|---|
| Corner radius | 190 | 16 | 61: 35 equal a scale step (29 ready, 6 in `doc.css` turned (b) below) and 26 are `999px` (ready) | 54: circles (`50%`), nested radii, 1–2 px shapes, `doc.css` | 65 off the scale |
| Easing curve | 197 | 70 | 57: 43 pasted `cubic-bezier(0.23,1,0.32,1)` (4 fixed, 39 ready) and 14 read `--ease`, which the app does not define (ready) | 0 | 70 keywords (`ease`, `ease-out`, `linear`) and other curves |
| Letter spacing | 115 | 64 | 6 write `-0.01em`, the value of `--ui-tracking` (ready) | 22 resets (`inherit`, `normal`, `0`) | 23 other values |
| Font weight | 81 | 64 | 0 | 0 | 17 numeric literals (and two weight scales, question 1) |
| Font size | 92 | 31 | 0 | 10: `em`-relative docs type, the iOS 16 px field, canvas-measured sizes | 49 literal `rem` (question 1) |
| Spacing (padding, margin, gap) | 1275 lengths | n/a (no spacing token) | 4 px lengths in `doc.css` (fixed) | hairlines of 1–2 px | 572 lengths off the 4 px grid (question 3) |
| Control and row height | 972 | 75 | 0 | 44 px touch targets inside `pointer: coarse` blocks | four near-equal height tokens (question 4) |
| Icon size | 98 icon rules | 13 read `--ui-icon` | 0 | 0 | 85 literal sizes (question 5) |
| Border and hairline width | 200 | n/a | 0 | 57 of 62 shorthand widths are `1px` | 5 are 1.5 px or more: strokes of drawn marks |
| Shadow and blur | 96 | blur: all 4 read `--ui-overlay-blur`; shadows 12 read `--shadow` | 0 | 41 literal shadows are rings and hairlines (`0 0 0 2px`, `inset 0 0 0 1px`) | none |
| z-index | 83 | n/a | 0 | 0 | 83 numbers from −1 to 1002, no scale (question 6) |
| Duration | 293 | `--t-pop` and `--t-panel` have no users | 0 | 0 | nine values between 120 and 260 ms (question 7) |
| UI-size scaling | 3390 | rem everywhere except the lines below | `doc.css` px lengths (fixed) | hairlines, canvas geometry in px (`--gutter`), measured geometry in TypeScript | `appwin.css` (54 px declarations, deferred by name) |

Where the deviations live: 2939 of the 3390 declarations (87 %) are in files an open branch changes, so only 451 could be touched
by this job's main branch.

## 3. What was fixed

### On `ui-consistency-j195` (free files, ready to merge)

| Commit | Class | Change |
|---|---|---|
| `doc.css` reads `--ease-out` | (a) | Four pasted curves in the docs stylesheet now read the product's curve. The standalone docs pages define `--ease-out` as an alias of their `--ease`, so the stylesheet shared with the in-app reader has one name that works in both. |
| `doc.css` lengths in rem | (a) | Inline code's radius and padding and the page rows' padding and gap were pixels; the reader lives in a canvas window that follows the UI size, so they scale now. |
| `copy-feedback.ts` marker | (b) | The 16 px font of the invisible fallback copy field is required by iOS (no zoom on focus). The comment carries the `ui-literal:` marker. |
| `verify quick`: "ui literals" | guard | A change that adds a px font size, a px radius over 2 px or a pasted curve fails `verify quick` (0.07 s). See section 7. |
| `ui-consistency-audit.spec.ts` | tool | The census and the before/after captures. |

### On `ui-consistency-j195-deferred` (stacked on the branch above; do not merge before the open branches)

Every commit is pixel-identical except the second, which makes animations that were being dropped play.

| Commit | Class | Change |
|---|---|---|
| `tokens: … defined on :root` | (a) | `--r-sm/md/lg/pill`, `--ease-out`, `--ease-drawer`, `--t-pop`, `--t-panel` were declared on `.terminal-screen`, so the sign-in card, body-level popovers and the docs pages could not read them. They move to `:root` in `packages/ui/styles.css`. |
| `fix: shared components read --ease-out` | (a) | `.check`, `.swap` (the copy-tick morph, D103), `.glitch` and the sign-in pane transitions read `var(--ease)`, which only `.auth-screen` and the docs pages define. In the app that makes the whole `transition` invalid at computed time. 18 uses now read `--ease-out`. The census confirms or refutes this on the real page (section 4). |
| `radius: a corner radius equal to a scale step reads the token` | (a) | 35 `0.5rem` / `0.75rem` / `1.125rem` radii read `--r-sm` / `--r-md` / `--r-lg`. |
| `radius: the pill radius reads --r-pill` | (a) | 26 `999px` radii. |
| `motion: stylesheets read var(--ease-out)` | (a) | 46 pasted curves in CSS and in CSS text inside TypeScript. |
| `type: letter-spacing -0.01em reads --ui-tracking` | (a) | 7 rules. |
| `docs: doc.css keeps literal radii` | (b) | The standalone docs pages load `docs.css` and `doc.css` only, so the radius tokens would resolve to nothing there. `doc.css` keeps `rem` literals and says why. |

## 4. Browser census

Production build of origin/dev a89ebb0ae plus the spec, 1440×900 ink, five screens (canvas, sidebar, palette, window popover,
sign-in; Settings is captured too, but counted separately). Screenshots and the before/after contact sheets are attached to #345.

**What a person sees today (rendered, at the default 110 % base):**

| Property | Distinct values | Counts (elements) |
|---|---|---|
| Font size | 8: 15.4, 14.85, 14.3, 13.2, 12.1, 11 px (+ 23.1 and 16.5 on sign-in) | 771, 40, 275, 106, 168, 2 |
| Font weight | 5: 450, 500, 550, 600, 650 | 253, 967, 123, 2, 19 |
| Letter spacing | −0.01 em (333), −0.011 to −0.013 em (rounding of the same value), 0.02 em, 0.08–0.09 em, −0.03 em (sign-in title) | |
| Corner radius | 15: 1, 4.4, 5.5, 6, 6.6, 8.8, 11, 13.2, 15.4, 17.6, 19.8, 24.2, 30.8 px, 50 %, 999 px | |
| Floating surfaces | sign-in card 24.2 px, window and sidebar 19.8 px, palette 17.6 px, window popover 15.4 px | |

TASTE §2 lists the weights 450 / 500 / 600 and 400 for secondary text. The rendered 550 (labels, `--fw-label`) and 650 (titles,
`--fw-title`) are not on that list: owner question 1.

**The animation that the app drops (confirmed).** Shared components built in each screen's root, computed `transition`:

| Screen | `.check` | `.swap svg` (copy-tick morph, D103) |
|---|---|---|
| canvas, sidebar, palette, popover | `0s | ease` (no transition) | `0s | ease` |
| sign-in | `0.14s | cubic-bezier(0.23, 1, 0.32, 1)` | `0.15s | cubic-bezier(0.23, 1, 0.32, 1)` |
| any of them, on `ui-consistency-j195-deferred` | `0.14s | cubic-bezier(0.23, 1, 0.32, 1)` | `0.15s | cubic-bezier(0.23, 1, 0.32, 1)` |

**No regression from the fixes.** 36 screenshots per phase (6 screens × 3 sizes × ink and paper), three phases: `origin/dev` plus the
spec ("before"), the main branch, and the deferred branch.

- *Computed values.* 923 cells (a family, a value, a screen, a size and a theme: font size, weight, line height, letter spacing,
  radius, transition duration and easing, z-index). Before against the deferred branch: radius, transition duration, transition
  easing and z-index differ in 0 cells; font size 3, weight 1, line height 1 and letter spacing 3 differ by one or two elements each, in the terminal
  text on the canvas (the mock terminal prints a clock). Before against the main branch, which changes no screen in the census,
  shows the identical 8 cells: that is the noise of two runs.
- *Pixels.* A pixel differs when a channel moves by more than 8/255. Main against before: 0.00–0.13 % of the pixels in 34 images,
  1.07 % and 95 % in the two ink sign-in images at 1440×900 and 393×852 (the card's backdrop is caught at a different point of
  its fade-in). Deferred against before: 0.00–0.22 % in 35 images and the same 95 % outlier. Both bands are the capture noise
  of unchanged code, and the three sheets (`sheet-<size>-before3-vs-after-deferred3.png` on #345) look identical to the eye.
- The only intended change is the one in the table above: shared components now animate inside the app.

## 5. Deliberate differences (class b)

| Where | Value | Why | Cited |
|---|---|---|---|
| Hairlines everywhere | 1 px, 1.5 px, 2 px borders, rings and strokes | A `rem` hairline lands between device pixels and blurs; UI size is `rem` for everything else | `ui-scale.ts` ("blurs hairlines"); TASTE §1 "at most a 1 px hairline" |
| Circles | `border-radius: 50%` (33) | A circle is a shape, not a step of the radius scale | — |
| `--gutter` on the canvas | `max(20px, …)` | Canvas geometry stays in px so windows are the same width at every UI size | comment in `apps/tracer/style.css` (#283) |
| Docs type | `em` scale (1.7 / 1.3 / 1.08), `ch` measure | Long-reading scale relative to the page's body size, so the standalone page and the canvas window step the same way | `doc.css` header |
| `doc.css` radii | `0.5rem`, `0.75rem` literal | The standalone docs pages do not load the UI token file | comment in `doc.css` |
| Copy fallback field | `font-size: 16px` | iOS zooms into focused fields under 16 px | `copy-feedback.ts` |
| Web Animations API easing | `"cubic-bezier(0.23, 1, 0.32, 1)"` in TypeScript (14 `EASE` constants and `easing:` options) | The `easing` option cannot read `var()` | — (a shared `EASE_OUT` constant would be the TypeScript token; see question 8) |
| Touch targets | `2.75rem` (44 px) | iOS target size, inside `pointer: coarse` blocks | TASTE §2 "Platform-sized controls"; D174 |
| Inline text input | `--text-input` is 16 px on touch | iOS never zooms | `packages/ui/styles.css` token comment |
| Cluster frames | `border-radius: 1.75rem` on `.cl-region`, `.cl-ghost` and `.cl-chip` | A nested outer frame around windows whose corners are `--r-lg`; larger than any step of the scale, so it is kept (D372) | comments in `clusters.css` and `mesh.css` |
| Pill morph insets | `radius: 19 / 18` | Initial values; replaced by the measured pill height before the first frame | `pill-morph.ts`, `shortcuts-view.ts` |

## 6. Owner questions (class c)

Nothing here was changed. Each one is a visible decision. Captures are on #345.

1. **Two type systems.** The sign-in-derived roles (`--ui-type-name/body/label/button/eyebrow`, same size on every platform,
   weights 600/450/450/500/500) and the older tokens (`--text-body/secondary/caption/input` with `--fw-secondary/body/label/title`
   = 450/500/550/650, bigger on touch: 16/15/13/16 px). TASTE §2 says the touch text scale was superseded (D174: "touch devices get
   bigger targets, not bigger text"), and another TASTE row says phone text is 15–16 px or larger. Today 73 rules read the roles and
   55 read the old tokens, and 49 more write `rem` literals that equal the old tokens' desktop values but not their touch values
   (so the same label is 13 px on a phone in one place and 16 px in another). Recommendation: pick the roles, move the old
   tokens onto them, and decide the touch size once. Needs the owner because it changes how the phone looks.
2. **Radius steps between the scale.** 65 radii sit off `--r-sm/md/lg` (0.375, 0.625, 0.875, 0.9375, 1, 1.25, 1.375, 1.75 rem).
   Some are nested corners (outer minus padding), some are one-offs. Recommendation: add `--r-xs` (0.375 rem, 14 uses) and
   keep nested radii as `calc(var(--r-…) − padding)`; round the rest to the nearest step.
3. **The 4 px grid.** TASTE §2 says layout is on a 4 px grid. 572 of 1275 spacing and size lengths are not (6 px ×88, 10 px ×84,
   14 px ×55, 2 px ×42, 3 px ×22, 5 px ×14). Recommendation: allow a 2 px half step (6, 10, 14) in the rule, because rounding them
   changes most of the product's density.
4. **Four near-equal height tokens.** `--row` 28 px, `--ui-control-h` 30 px, `--ui-row-h` 32 px and `--pill-h` 38 px on desktop; all 44 px on
   touch. TASTE says "rows 28–32 px". Recommendation: keep `--row` (list rows) and `--pill-h` (pills), and make `--ui-control-h` and
   `--ui-row-h` one token.
5. **Icon sizes.** `--ui-icon` is 16 px desktop / 18 px touch (TASTE §2), but 85 icon rules write a size: `1rem` ×16 (right on
   desktop, 2 px small on touch), `0.875rem` ×18 (14 px, no token), `1.125rem` ×9. Recommendation: add `--ui-icon-sm` (0.875 rem) and make the
   `1rem` ones read `--ui-icon`.
6. **z-index.** 83 declarations use numbers from −1 to 1002 with no scale (popovers at 6–9, toasts at 30, tooltips at 1001–1002).
   Recommendation: a six-step layer scale (content, chrome, sidebar, overlay, toast, tooltip). Changing it risks stacking bugs, so it needs captures of every overlay pair.
7. **Durations.** Nine values between 120 and 260 ms (140 ×59, 120 ×50, 180 ×32, 240 ×29, 200 ×29, 160 ×29, 150 ×24). `--t-pop` (180 ms) and `--t-panel` (240 ms)
   exist and nothing reads them. TASTE §3 says "about 200 ms" and 180 ms when key-triggered. Recommendation: three steps (120 press, 180 pop, 240 panel).
8. **A TypeScript home for the curve.** 14 Web Animations calls repeat the literal curve. Recommendation: export `EASE_OUT` from `packages/ui`.
9. **Standalone docs type.** `docs.css` redefines `--text-body: 13px` (and the row and secondary sizes) in pixels, so the public docs page reads 13 px while the app at its default
   size reads about 14.3 px (`0.8125rem` × 17.6 px) for the same token name. Its comment still says "the product's type scale (13 px)", from before the 110 % base (2026-11-01).
   Recommendation: make the docs pages follow the same root size.
10. **Sign-in title sizes.** Titles are `1.3125rem` (sign-in, add-host), `1.4375rem` (two places) and `1.375rem`; no title role exists beside `--ui-type-name` (14 px).

## 7. The guard

`scripts/verify.d/ui-literals.py`, row "ui literals" in `scripts/verify quick`. It compares the files a change touches with the
merge base and fails when the change adds a pixel font size, a pixel corner radius over 2 px or a pasted
`cubic-bezier(0.23, 1, 0.32, 1)`. A literal a decision requires opts out with a `ui-literal: <decision>` comment on the same line or the one above.
It reads two files' text per changed file, so it takes about 0.07 s, and it needs no stored baseline.

## 8. Deferred files

Files changed by a branch with commits in the last 48 hours (excluding `wip/`, `backup/` and mockup-round branches), computed
as `git diff origin/dev...<branch>` for every `origin/*` branch and every local branch. 423 files under `apps/tracer` and
`packages/ui`. The ones that matter for style:

- Stylesheets: `account`, `addhost`, `auth`, `boot-r1`, `canvas`, `clusters`, `host-actions`, `mesh`, `proposed`, `sessions`, `style`, `version`, and `packages/ui/styles.css`.
- Free: `doc.css`, `docs.css`, `docs-reader.css`, `data-toggle.css` (and `appwin.css`, deferred by name for `appwin-ui-fixes-j193`).
- The branches the owner named: `settings-rows-j132` (Settings rows, D212; 164 files), `appearance-presets-mock-j129` (presets, D322/D338/D341; 138 files), `appwin-ui-fixes-j193` (app windows; no commits yet at the time of the audit, `appwin.css` held back by name).
- Also changing `styles.css`: `preferred-login-ui-j166`, `sidebar-292`, `toast-stack-j165`.

After they merge: rebase `ui-consistency-j195-deferred` onto dev (the commits are mechanical and re-runnable: each is a regular expression over the stylesheets),
re-run `UI_AUDIT=1 UI_AUDIT_LABEL=after bun x playwright test ui-consistency-audit`, and compare with the "before" folder.
