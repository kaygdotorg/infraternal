/**
 * The canvas context: the one object every canvas module receives.
 *
 * The canvas is built from small modules (camera, layout, views, windows, toolbar, mesh, sharing, sessions).
 * They share a little state and call each other by name. Instead of importing each other, which would make a
 * cycle of the whole canvas, each module is a factory `createX(cx)` that reads state from the context and
 * calls the other modules through it at event time (never while it is being built). The composition root
 * (`create.ts`) builds the context, fills in the services in dependency order and returns the controller.
 *
 * What lives where:
 * - Elements and infrastructure that never change are plain readonly fields.
 * - Shared mutable state is a field on `state` (one place, easy to find, easy to persist later).
 * - Services are the modules' public surfaces (`nav`, `view`, `win`, ...), typed by the interface each module
 *   exports. Optional services (`mesh`, `sharing`) exist only when their adapter is supplied.
 * - Adapters are the seams to the outside world: sessions, the mesh, sharing, devices, the document store.
 *   Product code receives real ones; mockups receive test-double ones (`mock/`).
 */
import type { WindowCard } from "../../../../packages/ui/src/window-card";
import type { ToastController } from "../../../../packages/ui/src/toast";
import type { Spring } from "../../../../packages/ui/src/spring";
import type { CoreScreen } from "../core-screen";
import type { Camera } from "./camera/camera";
import type { Metrics } from "./layout/geometry";
import type { ContainerRow, ViewId, ViewModel, WindowModel } from "./model/types";
import type { CanvasStore } from "./model/store";
import type { DocumentSync } from "./model/sync";
import type { SessionBinding, SessionService } from "./sessions/adapter";
import type { MeshModule } from "./mesh";
import type { SharingModule } from "./sharing";
import type { Nav } from "./camera/lock";
import type { Memory } from "./memory";
import type { Flip } from "./layout/flip";
import type { ViewsModule } from "./views/world";
import type { WindowsModule } from "./windows/lifecycle";
import type { FloatModule } from "./windows/float.on-demand";
import type { DetailsModule } from "./windows/details.on-demand";
import type { InputLock } from "./windows/input-lock";
import type { Visibility } from "./windows/visibility";
import type { PillModule } from "./toolbar/pill";
import type { ViewList } from "./toolbar/viewlist";
import type { TreeModule } from "./toolbar/tree";
import type { ToolbarModule } from "./toolbar/row";
import type { SessionUi } from "./windows/session-hooks";
import type { SettingsSource } from "./views/settings-body.on-demand";
import type { RecentList } from "./recency";
import type { AppWindowsAdapter } from "./appwin/adapter";
import type { AppWindowsHook } from "./appwin/hook.on-demand";

/** One window on the canvas: its card, its model and the things that must be undone when it goes. */
export interface WinRec {
  /** Closing animation may retain the card, but it must no longer be reused. */
  closing?: boolean;
  model: WindowModel;
  card: WindowCard;
  /** The view this window sits in. */
  owner: ViewRec;
  /** Header connector (terminals only): drag from it to another terminal to grant access. */
  port?: HTMLButtonElement;
  stopResize?: () => void;
  /** A body that streams text (a logs window); the stream is fed from outside. */
  stream?: HTMLElement;
  /** Appends one line to a logs window (it stays pinned to the end unless the person scrolled up). */
  pushLog?: (line: string) => void;
  /** The session this window shows (terminal windows). */
  binding?: SessionBinding;
  /** Releases what the body holds (a settings panel). */
  cleanup?: () => void;
  /** Retained host setup status shown in the machine pill (addhost/setup-pill.on-demand.ts, D255). */
  setup?: { handlePill(source: "pointer" | "keyboard"): boolean; isPending(): boolean; dispose(): void };
}

/** One view on the canvas: the elements that draw it, its position springs and its windows. */
export interface ViewRec {
  view: ViewModel;
  el: HTMLElement;
  region: HTMLElement;
  label: HTMLButtonElement;
  labelMeta: HTMLElement;
  content: HTMLElement;
  colsEl: HTMLElement;
  lift: HTMLElement;
  wins: Map<string, WinRec>;
  sx: Spring;
  sy: Spring;
  /** The animated position (the model's `view.x/y` is the committed one). */
  x: number;
  y: number;
  empty?: HTMLElement;
  /** A graph view's arrow layer. */
  graphSvg?: SVGSVGElement;
  /** Mesh bookkeeping for a graph view (the mesh module owns its shape). */
  mesh?: unknown;
}

/** Mutable state shared by the modules. */
export interface CanvasState {
  metrics: Metrics;
  activeWin: WinRec | undefined;
  currentView: ViewId;
  /** The canvas lock (D177): the camera rests only on window stops. */
  canvasLock: boolean;
  snapIdx: number;
  /** A window is being moved by its pill: no hover cards then. */
  movingWindow: boolean;
  /** Source of fresh ids for columns and split windows. */
  serial: number;
  /** Per view, the windows made active most recently (in memory, this session): the hover card's rows (#121). */
  recent: Map<ViewId, RecentList<string>>;
}

export interface Adapters {
  /** Registry-labelled removal, shared by the palette and machine popover. */
  hostRemoval?: { label(): string | undefined; remove(id: string, name: string, anchor: HTMLElement): void };
  /** Binds terminal windows to sessions (real in the product, previews in mockups). */
  sessions: SessionService;
  /** The terminal of the active window, for keyboard font size (D222); absent in mockups, where the font keys do nothing. */
  activeTerminal?(): {
    adjustFontSize(step: number | "reset"): void;
    linksOnScreen?(): readonly { target: string; openable: boolean }[];
    openLinkFromPalette?(target: string): boolean;
  } | undefined;
  /** Lists, names and ends sessions (D178, D183); absent until the lifecycle API exists, and the manager, the markers and the final-screen strip are then not offered. */
  inventory?: import("./sessions/inventory").SessionInventory;
  /** The "teach once" gate (`hints.ts`): true when an explanatory hint should show now. Absent: such hints stay quiet. */
  teach?: (hint: string) => boolean;
  /** The canvas document's home (local storage today, the server sync of #98 later). */
  store: CanvasStore;
  /** Mesh data and edits; absent until the Mesh API exists, and the Mesh view is then not offered. */
  mesh?: import("./mesh/source").MeshSource;
  /** Sharing layouts; absent when the instance cannot share. */
  sharing?: import("./sharing/adapter").SharingAdapter;
  /** What the Settings view's account-level panels show. */
  settings: SettingsSource;
  /** The Containers list; absent until the host API exists, and the Containers view is then not offered. */
  containers?: { /** The host whose containers these are. */ host: string; rows(): ContainerRow[] };
  /** Facts for the window details popover (a pill pressed without moving); absent, and the pill opens nothing. */
  details?: import("./windows/details-source").DetailsSourceLoader;
  /** Starts the add-host flow (#78); absent until it exists, and the empty-state button is then not drawn. */
  addHost?: () => void;
  /** The lock on host connections (D168, D217): its state, the palette row and Settings → Hosts; absent when the server has none. */
  authority?: import("./addhost/authority-unlock").AuthorityControl;
  /** Streams of app windows and screens from machines (D207, D208); absent in mockups, and the feature is then not offered at all. */
  appWindows?: AppWindowsAdapter;
  startupHints?: import("./sessions/startup-hints").StartupHints;
}

/** Loads the app-window runtime only after the desktop stream is wanted and supported. */
export interface AppWindowsLoader {
  load(): Promise<AppWindowsHook | undefined>;
  dispose(): void;
}

export interface Ctx {
  readonly core: CoreScreen;
  readonly stage: HTMLElement;
  readonly viewport: HTMLElement;
  /** The layer the camera transforms; views sit in it. */
  readonly world: HTMLElement;
  /** SVG layer over the views for arrows that follow the camera. */
  readonly overlay: SVGSVGElement;
  /** Edge markers for arrows that run off screen. */
  readonly edges: HTMLElement;
  readonly signal: AbortSignal;
  readonly toast: ToastController;
  readonly camera: Camera;
  readonly flip: Flip;
  readonly adapters: Adapters;
  readonly state: CanvasState;
  /** Features a canvas turns on or off. */
  readonly flags: { /** The floating terminal (needs a window that can mirror itself). */ float: boolean };
  /** Every view, in display order. */
  readonly views: Map<ViewId, ViewRec>;
  /** Schedules an overlay redraw for the next frame. */
  invalidate(): void;

  /** Saves the layout after structural changes. */
  store: DocumentSync;

  // Services, filled in by the composition root in dependency order. Call them at event time only.
  memory: Memory;
  nav: Nav;
  view: ViewsModule;
  win: WindowsModule;
  float: FloatModule;
  /** The window details popover; absent when the instance has no `DetailsSource`. */
  details?: DetailsModule;
  inputLock: InputLock;
  /** The session manager, the final-screen strip and the size badge; exists only with an inventory. */
  sessionUi?: SessionUi;
  visibility: Visibility;
  pill: PillModule;
  viewList: ViewList;
  tree: TreeModule;
  toolbar: ToolbarModule;
  mesh?: MeshModule;
  sharing?: SharingModule;
  /** Deferred loader for app-window and screen behavior; absent in mockups. */
  appWindows?: AppWindowsLoader;
}
