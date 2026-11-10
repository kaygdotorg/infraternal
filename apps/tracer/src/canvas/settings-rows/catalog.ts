// SPDX-License-Identifier: AGPL-3.0-only
/**
 * THE TABLE: which setting lives in which window of which row of Settings, and which docs heading each window's "?" opens
 * (mockup, issue #304).
 *
 * Settings is one cluster of windows. A ROW is a component (Mesh, Machines, …); a WINDOW in a row is one group of that
 * component (Mesh → Keys, Names, Access, Connections). Nothing else decides where a setting goes: the windows, the top
 * breadcrumb (Settings › Mesh › Keys), the sidebar nesting, the ⌘K rows and the "?" links are all read from this array, in
 * this order. Moving a setting to another window is a one-line edit here; so is renaming a row, reordering the windows of a row
 * or pointing a window at another docs heading.
 *
 * The map is the owner's of 2026-11-02 (names in Title Case, no brackets); the owner approved the rows on 2026-11-03 (#304). The
 * table says where a setting LIVES and what values it allows; it does not say whether the server can store it. That is
 * `backing.ts`: a setting nobody backs shows no control, and a window with nothing to show says so in one plain line
 * ("Not available yet"). The table holds no invented data: lists of facts and keys come from the source, never from here.
 * Defaults and ranges the owner gave: 7 d connection keys, 7 d machine identity, 90 d renewal grace, 30 d keys last (1–365,
 * the server's own rule), 30 d browser sign-in (1–90), 15 min add link, 10 min join code. The other ranges are my proposals.
 *
 * Plain words (TASTE): titles and explanations say what changes for the person, in one line. The technical term, where an
 * expert needs it, sits in the explanation or in `keywords` (which ⌘K searches, but nobody has to read).
 */
import type { DocsLink } from "../docs/docs-adapter";

export interface FactGroupDef { title: string; rows: Array<{ key: string; value: string }> }

/** A key a person made (a command-line or AI-tool key): what is shown, and Revoke. */
export interface KeyDef { id: string; name: string; kind: "cli" | "mcp"; lastUsed: string; expires: string }

/** What a source may fill a group with besides its settings: lists of facts and a list of keys. The table holds none (no invented data). */
export interface GroupData { facts?: FactGroupDef[]; keys?: KeyDef[] }

/**
 * An existing Settings panel reused unchanged inside a window (its id is the old section id). `only` keeps just the blocks
 * of the panel whose heading is listed, so one panel can fill several windows.
 */
export type PanelId = "windows" | "hosts" | "toolbar" | "shortcuts" | "account" | "about" | "devices";

/** The docs heading a window's "?" opens (`docs/docs-adapter.ts`). Absent on a group: no page yet. */
export type { DocsLink };

/** Describes a group of settings rows and the panel that owns them. */
export interface GroupDef {
  id: string;
  title: string;
  /** Only administrators see it. */
  admin?: boolean;
  /** The ids of the settings in this window; what each is (title, help, allowed values) is in `definitions.on-demand.ts`. */
  settings?: readonly string[];
  /** Existing Settings panels shown in this window, in order. */
  panel?: PanelId | readonly PanelId[];
  /** Keeps just the blocks of the panels whose heading is listed, so one panel can fill several windows. */
  only?: string[];
  /** The Appearance Themes window (D322, #323): the strip of theme cards and the controls that edit the selected theme (`canvas/themes/editor.on-demand.ts`). */
  themes?: boolean;
  docs?: DocsLink;
}

export interface ComponentDef {
  id: string;
  title: string;
  /** Key into `ICON_OF` (settings-rows/model.ts). */
  icon: "appearance" | "terminal" | "you" | "machines" | "mesh" | "sharing" | "about";
  admin?: boolean;
  groups: GroupDef[];
}


/** Maps product setting windows to their shared row groups. */
export const SETTINGS_MAP: readonly ComponentDef[] = [
  { id: "appearance", title: "Appearance", icon: "appearance", groups: [
    // A theme holds Colour, backgrounds, tint, blur, grain, font and UI size, so one window edits all of them (D322, D338): the Font and Size windows are part of it.
    { id: "themes", title: "Themes", themes: true },
    { id: "layout", title: "Layout", panel: "windows" },
  ] },
  { id: "terminal", title: "Terminal", icon: "terminal", groups: [
    { id: "typing", title: "Typing", panel: ["shortcuts", "toolbar"] },
    { id: "hosts", title: "Hosts", panel: "hosts" },
    { id: "scrollback", title: "Scrollback", settings: ["scrollback-lines"] },
    { id: "multiplexer", title: "Multiplexer", docs: { page: "terminal/multiplexer", heading: "offer-to-switch" }, settings: ["multiplexer-offer"] },
  ] },
  { id: "you", title: "You", icon: "you", groups: [
    { id: "profile", title: "Profile", panel: "account", only: ["This device"] },
    { id: "passkeys", title: "Passkeys", docs: { page: "reference/keys", heading: "passkey" }, panel: "account", only: ["Passkeys"] },
    { id: "recovery", title: "Recovery", docs: { page: "reference/keys", heading: "recovery-words" }, panel: "account", only: ["Recovery key"] },
    { id: "apps", title: "Apps", docs: { page: "reference/keys", heading: "keys-last" }, settings: ["app-key"] },
    { id: "devices", title: "Devices", docs: { page: "reference/keys", heading: "browsers-stay-signed-in-for" }, panel: "devices", settings: ["browser-session"] },
  ] },
  { id: "machines", title: "Machines", icon: "machines", admin: true, groups: [
    { id: "new-machines", title: "New Machines", docs: { page: "reference/keys", heading: "add-link-lasts" }, settings: ["add-link", "join-code", "install-mode", "sign-in-account", "join-mesh"] },
    { id: "updates", title: "Updates" },
  ] },
  { id: "mesh", title: "Mesh", icon: "mesh", admin: true, groups: [
    { id: "keys", title: "Keys", docs: { page: "reference/keys", heading: "connection-keys" }, settings: ["connection-keys", "machine-identity", "renewal-window"] },
    { id: "names", title: "Names", settings: ["name-suffix"] },
    { id: "access", title: "Access" },
    { id: "connections", title: "Connections" },
  ] },
  { id: "sharing", title: "Sharing", icon: "sharing", admin: true, groups: [
    { id: "published-services", title: "Published Services" },
    { id: "certificates", title: "Certificates", settings: ["renew-early"] },
  ] },
  { id: "about", title: "About", icon: "about", groups: [
    { id: "version", title: "Version", panel: "about" },
    { id: "licences", title: "Licences" },
  ] },
];
