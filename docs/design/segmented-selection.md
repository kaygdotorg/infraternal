<!-- Role: the behavioural reference for every segmented/tab selection in infraternal (DECISIONS 120). -->
# Segmented selection: shared stretching capsule

Source: a behavioural decode of the MetalForge segmented control
(https://metalforge.xyz/interactions#component=segmented), made by Aside from
the live preview, the rendered DOM, computed styles and public parameters at the
owner's request (2026-10-07). It is **not copied source**: the downloadable
source is Pro-only. Exact spring constants, durations, blur amount and press
scale were not verified. Treat any value below that is not marked "observed"
as ours to tune, and verify it against short recordings of the reference.

## Observed
1. **One persistent shared capsule** sits behind transparent option buttons.
   It is not a per-option background crossfade, and not a rigid slide: "the
   selection stretches toward the new option, then its other edge catches up".
2. The capsule changes **position and width** to fit the selected option. The
   labels stay fixed in their cells. Reference: one indicator element with
   `translate3d(x, 5px, 0)` and a width; option widths are unequal (for
   example 61.75, 74.45, 79.8 and 67.2 px).
3. Reference geometry: item and indicator 44 px, tray inset 5 px, tray 54 px,
   inner radius 22, outer radius 27. These are reference values; use the
   infraternal tokens.
4. The selected surface is **subtly tonal**: no bright accent blob and no
   border-only state. Reference light: tray #FFFFFF, selection #EFEEE9,
   primary #1A1915, secondary #8D8A81. Dark: tray #252420, selection #3A3934,
   primary #F2F1EC, secondary #A09D93. Map these to the theme tokens. The dark
   tray has a fine highlight edge and soft layered elevation; the indicator
   has no shadow.
5. The selected label is primary colour at weight 600, and inactive labels are
   secondary. Text transitions colour and weight over 0.25 s. Labels never
   stretch.
6. Public parameters (Stretch, Speed, Bounce, Blur between states, Press
   grows) are all 1x. The underlying spring, blur, press and hover values are
   unknown.
7. Semantics: tablist and tab, `aria-selected`, roving tabindex (selected 0,
   others -1). The selected value updates immediately; the motion is only
   presentation.

## How infraternal implements it
- Two horizontal edges with **direction-aware lag**:
  - moving right, the right (leading) edge leads and the left catches up;
  - moving left, the left edge leads.
  It settles exactly on the target bounds. Use one cancellable spring per
  edge, or an equivalent x + width scheme, through the shared `spring.ts`.
- Retarget from the **current visual bounds** on interruption or reversal.
- Never remount, duplicate or snap the indicator, and never scale its
  contents.
- The first render is placed with no sweep-in.
- **Icon-only tabs** (the window info popover: Machine, Connection, Session):
  - the group is centred;
  - each button has equal, padded hit bounds, and the capsule spans those
    bounds, never a tight circle around the glyph;
  - the selected icon is primary and inactive icons secondary;
  - no weight animation;
  - warm tooltips and accessible names stay.
- The focus-visible ring is distinct from the selection.
- Arrow, Home and End keys follow the tab pattern.
- Disabled tabs are skipped.
- Touch targets are 44 px or more.
- Reduced motion: an immediate or short non-spring change.
- Measure on selection, resize, font load and content change, with batched
  reads. No per-frame layout reads. The animation stops when settled, and
  observers and rAF are cleaned up.
- Handles variable widths, RTL, scrollable groups and rapid reversals.
- **Verify with recordings:**
  - both directions, non-adjacent jumps, rapid alternation, a mid-flight
    reversal, first render;
  - all themes, mobile, keyboard and reduced motion;
  - Chromium and WebKit.
  Blur and press effects are optional pending a live comparison; never leave
  text blurred.
