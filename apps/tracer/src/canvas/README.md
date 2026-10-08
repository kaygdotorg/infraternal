<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The canvas

One canvas holds *views* (Console, Containers, Mesh, Settings, shared copies). A view is a tiled group of
*windows* (columns, each a vertical stack that scrolls by itself) or, for Mesh, a graph. The camera flies between
views, snaps to windows while the canvas lock is on, and zooms out to thumbnails when it is off. Decisions: D118,
D119, D159, D160, D177–D183, D187.

The product mounts it through `createCanvas` (`create.ts`). Mockups mount the same code with test-double adapters
(`mock/`, behind `?mock=1&proto=clusters`, left out of the production bundle by `build.ts`).

## The rule for modules

Each module is a factory `createX(cx)` that receives the **context** (`context.ts`) and returns its public
surface. Modules do not import each other's internals; they call each other through `cx.<service>` **at event
time**, never while being built. Shared mutable state is one object, `cx.state`. The composition root
(`create.ts`) builds elements, then the services in dependency order.

## Module map

| Folder / file | Owns | Public surface |
|---|---|---|
| `camera/camera.ts` | centre, zoom, springs, device-pixel snap, thumbnail and zoom-band switches, flights | `Camera`: `apply` `rest` `set` `flyTo` `keyFlight` `drive` `takeOver` `zoomAt` `fit` `toWorld` `toClient` `worldRect` |
| `camera/lock.ts` | canvas lock, stops, every way the camera is sent somewhere | `Nav`: `flyView` `focusWindow` `goStop` `setCanvasLock` `showOverview` `overviewCam` `stopsFor` `onLockChange` |
| `camera/gestures.ts` | wheel, trackpad, touch and pointer on the canvas | `installGestures(cx)` |
| `layout/geometry.ts` | cell grid, metrics, boxes, push-aside (pure) | `CELL` `metricsFor` `boxOf` `resolve` `snapToGrid` |
| `layout/stops.ts`, `columns.ts`, `flip.ts` | stops (pure), column scroll, FLIP reflow | `stopsFor` `nearestStop`, `scrollColumn` `stepWindow`, `Flip` |
| `layout/droplet.ts` | the droplet split (short-lived WebGL, only while it plays) | `dropletSplit` |
| `views/world.ts` | building a view, sizing it on the grid, settle, hover card, dragging a view | `ViewsModule` (`cx.view`) |
| `views/body.ts`, `settings*.ts`, `icons.ts` | what is inside a window by kind; Settings panels; icons | `makeBody`, `SettingsSource` |
| `windows/frame.ts`, `move.ts` | window card, activation, pill grab and move, resize | `makeWindow`, `setActive`, `beginMove` |
| `windows/visibility.ts` | which windows are live: near the screen, live level of detail, view not far, page not hidden; tells each binding `setVisible` (the only caller) | `Visibility` |
| `memory.ts` | views far from the camera are not painted; a hidden page releases big surfaces | `Memory` (reports far views and a paused page to `visibility`) |
| `windows/lifecycle.ts` | open, close (never ends the session), split | `WindowsModule` (`cx.win`) |
| `windows/float.ts`, `input-lock.ts` | floating terminal; the input lock (padlock) | `FloatModule`, `InputLock` |
| `toolbar/` | top pill + swipe, view list, tree (sidebar), canvas row + desktop buttons, shortcuts, palette | `PillModule` `ViewList` `TreeModule` `ToolbarModule` |
| `mesh/` | Mesh view, reach arrows, grant editing | `MeshModule`, adapter `MeshSource` |
| `sharing/` | share dialog, received copies, team layouts | `SharingModule`, adapter `SharingAdapter` |
| `model/` | runtime model, the **canvas document** (D180), persistence | `toDocument` `parseDocument` `columnsFromDocument`, adapter `CanvasStore`, `DocumentSync` |
| `sessions/` | binding terminal windows to sessions | adapter `SessionService` / `SessionBinding`; `live.ts` is the product one |
| `product.ts` | the product canvas: Console on real sessions + Settings with the sections that exist; a lazy chunk loaded after sign-in | `mountProductCanvas` |
| `status.ts` | a terminal's status text to the one shared toast | `createStatusRelay` |
| `addhost/` | the add-host wizard: detect-first sign-in (D183), progress from provisioning events, host key and credential pages | `createAddHost`, adapter `ProvisioningService`, hook `AddHostSink`, `FlowHost` (window kind `flow`, `cx.win.openFlow`) |
| `backdrop.ts` | the dotted canvas behind the views | `createBackdrop` |
| `mock/` | everything fake: scenes, roles, fake hosts, grants, devices, probe | `mountMockup` |

## Adapters (the seams)

| Adapter | Today | Tomorrow |
|---|---|---|
| `CanvasStore` (`model/store.ts`) | `LocalCanvasStore`: local storage per account | server sync of operations with revisions (#98, D183) |
| `SessionService` (`sessions/adapter.ts`) | `live.ts`: a `TerminalClient` per window, each a stream of the one `MuxConnection` (`src/connection.ts`, D183); mockups: previews | remote hosts as #78 lands |
| `MeshSource` (`mesh/source.ts`) | mock data; Mesh view not offered in the product | the mesh API (#108) |
| `SharingAdapter` (`sharing/adapter.ts`) | mock only; product offers no sharing | instance sharing (#93, D182) |
| `SettingsSource` (`views/settings-body.ts`) | built-in sections only | devices, account, users, grants, discovery as their APIs land |
| `ProvisioningService` (`addhost/service.ts`) | `real.ts`: `/v1/bootstrap/ws` and `/v1/bootstrap/ssh-key` of contracts/ssh-bootstrap.md, plus the endpoints proposed on #87; mockups: the same adapter against the test double | one service, no change |
| `AddHostSink` (`addhost/service.ts`) | mockups: opens a Console window for each enrolled host (`cx.win.open`), which is how the sidebar tree learns of it | the sessions service adds the host to `hosts()` and calls `onChange`, then `cx.win.open(host)` |
| `Adapters.containers` | absent in the product (view not offered) | host API |
| `Adapters.addHost` | `createAddHost(...).open` in `product.ts` (real service, flow window) and in the mockup (test double). The wizard's code is on-demand (`addhost/add-host.on-demand.ts`) | add-host flow (#78, #87) |

A feature whose adapter is missing is **not offered at all** (no view, no button, no palette row). The product
never shows mockup UI.

## Performance and memory rules

- 60 fps: a frame writes one `transform` on the world and nothing else per frame (camera). Label counter-scale,
  level of detail and zoom band change only when they cross a threshold. `will-change` only while moving.
- Instant work: handlers do a layout read and a transform write; saving, the tree and arrows are coalesced
  (timer, microtask, animation frame). Nothing runs while the camera is still.
- Memory (iOS kills a page that holds too much): the backdrop is viewport-sized tiles; windows off screen or in
  another view hold no canvas backing store (`SessionBinding.setVisible(false)`); at most one GL context exists,
  only during the droplet animation; big surfaces are released on `pagehide` and while hidden.

## Tests

- `bun test src/canvas` (pure parts: geometry, stops, the D180 document) and `bun test chunk-classes.test.ts`.
- `test/clusters*.spec.ts`, `test/canvas.spec.ts`: the mockup on the test double.
- `real/canvas.spec.ts` (`playwright.real.config.ts`, `scripts/verify integration`): the product on the real server
  binary and real PTYs: open, close (session stays alive), split, re-tile, reload, connection rotation at the
  server's 32-writer cap, frame times, memory at 393x852 DPR 3.

## Data

`model/document.ts` is the D180 document: layout and references only, windows by stable id plus readable name,
views on the cell grid, no content. `parseDocument` is the only way untrusted JSON becomes a document.

## CSS

Class names keep the `cl-` prefix and the stage attribute `data-clusters` (from the concept's first name); renaming
them is a separate mechanical change. Surfaces, pills, window cards and tooltips come from `packages/ui`.
