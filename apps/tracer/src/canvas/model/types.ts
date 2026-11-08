/**
 * The canvas's runtime model: views, columns, windows and graph nodes as the view layer draws them.
 *
 * This is the working shape. The persisted shape is the canvas document (`document.ts`, D180), which holds
 * layout and references only; `toDocument` and `fromDocument` convert between the two. Nothing here is DOM.
 */
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";

/**
 * What a window shows. A `flow` window holds a short guided task (add a host); it is never saved and closes itself when done. Only a `terminal` window is bound to a session and can split.
 * An `app` window streams one app window of a machine and a `screen` window streams a whole display (D208); neither is saved (see `WindowModel.stream`).
 * A `docs` window reads one page of the docs (the Docs view, never saved).
 */
export type WindowKind = "terminal" | "containers" | "logs" | "node" | "settings" | "flow" | "docs" | "app" | "screen";

/** The built-in views have fixed ids; a view someone shared with you gets an id of its own. */
export type ViewId = string;

/**
 * One window on the canvas as the runtime sees it: what it shows (its kind and target, such as a terminal's host and
 * session), where it sits in its column, and a few in-memory flags. `toDocument` turns the parts worth keeping into
 * the saved layout; everything else lives only in this tab.
 */
export interface WindowModel {
  id: string;
  kind: WindowKind;
  /** Host (or tag) name shown in the pill. */
  host: string;
  /** Server-owned remote host identity; absence selects the embedded host only for known local windows. */
  hostId?: string;
  address?: string;
  /** The session's readable name (D178); the stable target is `sessionId`. */
  session?: string;
  /** A manually chosen session name stays pinned across shared layout paints and reloads (#293). */
  sessionPinned?: boolean;
  /** The session this window shows (a terminal window): stable across renames and reloads (D180). */
  sessionId?: string;
  /**
   * The host refused to start this window's shell, so it has no session and none is on its way (#395). Kept in memory
   * only, never saved: such a window shows the refusal in place but is left out of the saved layout, so it does not hold
   * its birth and every later layout edit as "waiting for a session id". Cleared when a new shell in it does start.
   */
  openRefused?: boolean;
  user?: string;
  os?: HostPlatform;
  /** Fixed height in px, or a ratio of the column height when 1 or less; a window without one shares its column equally. */
  h?: number;
  /** Preview text for windows that are not bound to a live session (mockups, thumbnails). */
  lines?: string[];
  /** Set on a window made by a split: it shares its column with the window it came from and is not resized on its own. */
  splitOf?: string;
  /**
   * Columns this window covers, from its own (D212). Absent means one. A window that covers more than one column makes its
   * columns a group, drawn as one grid with the bands below.
   */
  span?: number;
  /** Row bands this window covers, from `row` (D212). Absent means one. */
  rows?: number;
  /** The band this window starts in, inside its group (D212). Only set for a window in a group; a plain column stacks its windows. */
  row?: number;
  /**
   * The window's own width in px, and the free space left of it, inside a row group (D212 amendment, D323). A window in a row group
   * has the size the person gave IT: a drag changes this window and no other, and the column (track) is as wide as its widest
   * window. Absent: the window fills its track.
   */
  w?: number;
  ml?: number;
  /** The window's host is not covered by the viewer's grants (a shared layout connects through your own access). */
  noAccess?: boolean;
  /**
   * An `app` or `screen` window: what the machine streams into it (D208). The machine's window identity lives only as long
   * as the window does, so these windows are not part of the saved layout.
   */
  stream?: {
    target: import("../appwin/inventory").AppTarget; appName: string; title: string; bundleId?: string;
    /** The machine's window or screen shape (width / height) when it was listed: the window opens in that shape. */
    aspect?: number;
  };
}

/**
 * A column. `half` names the two halves of one split (D212): closing one returns its width to the other. `group` names a row
 * group (D212, amended 2026-11-03): adjacent columns with the same name are one grid, one band for each row of windows, with no
 * window spanning columns. Both are runtime only; a generated view (Settings) declares its rows each time it is built.
 */
export interface ColumnModel { id: string; w: number; half?: string; group?: string; wins: WindowModel[] }

/** A positioned host or tag card, including restore safety when the server proves it. */
export interface NodeModel {
  id: string; kind: "host" | "tag"; label: string; x: number; y: number; detail: string; sub: string; os?: HostPlatform;
  /** Live state of a host (a tag has none): drives the card's status icon. */
  state?: "online" | "behind" | "offline";
  /** Whether this host can retire stale peers after a server authority restore. */
  restoreSafe?: boolean;
  /** A host without an address shows its tags in the detail line, as chips. */
  tagList?: string[];
  /** The person dragged this node, so it stays where it is while the rest are laid out automatically (D180). */
  pinned?: boolean;
}

/**
 * A mesh access rule, shown by name only (D180: edges reference grants by name, never the rules).
 * `id` is the stable reference; `name` is what people read (and rename). `auto` means the name still says who may
 * reach what, so the canvas renames the grant along when an end moves; a name a person chose is never touched.
 */
export interface Grant { id: string; from: string; to: string; via?: string; name?: string; auto?: boolean; /** Reaches both ways (D164: a double-headed arrow). */ both?: boolean }

export interface ViewModel {
  id: ViewId;
  name: string;
  layout: "tiled" | "graph";
  cols: ColumnModel[];
  nodes: NodeModel[];
  /** Shared pins exist even before this view has rendered its nodes (D180/D245). */
  graphPins?: Record<string, { x: number; y: number }>;
  /** Content size of a graph view. */
  graph?: { w: number; h: number };
  /** Position on the coarse cell grid, in pixels (always a multiple of `CELL`). */
  x: number;
  y: number;
  /**
   * Where the saved layout has this view (D309), set only while this device draws it somewhere else: a touch screen that
   * draws columns wider than the layout saved can push a neighbour clear. The push is display only, so saving reads this
   * (`toDocument`) and a phone never moves a view in the shared layout.
   */
  home?: { x: number; y: number };
  /** Arrived from someone: a copy that is yours (`from` only names where it came from). */
  from?: string;
  /** A published team layout you follow: read-only until you unlink it. */
  team?: { from: string; shareId: string; key: string; rev: number };
  /** Mine, and published to the team: changes to its arrangement go to the people who follow it. */
  published?: { shareId: string; key: string };
}

/** One row of the Containers list. */
export interface ContainerRow { name: string; image: string; state: "running" | "restarting" | "exited"; cpu: string }
