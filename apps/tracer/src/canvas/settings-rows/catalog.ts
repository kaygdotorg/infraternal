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
import type { ValueSpec } from "../../../../../packages/ui/src/setting-value";
import type { DocsLink } from "../docs/docs-adapter";

/** One setting with a value that can be changed: it shows its default, its allowed range, a Reset and one line of help. */
export interface SettingDef {
  id: string;
  title: string;
  /** One line, plain words. */
  explain: string;
  spec: ValueSpec;
  /** Extra words ⌘K matches (technical names). */
  keywords?: string;
}

export interface FactGroupDef { title: string; rows: Array<{ key: string; value: string }> }

/** A key a person made (a command-line or AI-tool key): what is shown, and Revoke. */
export interface KeyDef { id: string; name: string; kind: "cli" | "mcp"; lastUsed: string; expires: string }

/** What a source may fill a group with besides its settings: lists of facts and a list of keys. The table holds none (no invented data). */
export interface GroupData { facts?: FactGroupDef[]; keys?: KeyDef[] }

/**
 * An existing Settings panel reused unchanged inside a window (its id is the old section id). `only` keeps just the blocks
 * of the panel whose heading is listed, so one panel can fill several windows (the Appearance panel is Theme, Font and Size).
 */
export type PanelId = "appearance" | "windows" | "hosts" | "toolbar" | "shortcuts" | "account" | "about" | "devices";

/** The docs heading a window's "?" opens (`docs/docs-adapter.ts`). Absent on a group: no page yet. */
export type { DocsLink };

export interface GroupDef {
  id: string;
  title: string;
  /** Only administrators see it. */
  admin?: boolean;
  settings?: SettingDef[];
  /** Existing Settings panels shown in this window, in order. */
  panel?: PanelId | readonly PanelId[];
  /** Keeps just the blocks of the panels whose heading is listed, so one panel can fill several windows. */
  only?: string[];
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

const days = (d: number, min: number, max: number): ValueSpec => ({ kind: "duration", unit: "d", default: d, min, max });
const minutes = (m: number, min: number, max: number): ValueSpec => ({ kind: "duration", unit: "min", default: m, min, max });

export const SETTINGS_MAP: readonly ComponentDef[] = [
  { id: "appearance", title: "Appearance", icon: "appearance", groups: [
    { id: "theme", title: "Theme", panel: "appearance", only: ["Theme", "Background", "Card transparency", "Window transparency"] },
    { id: "font", title: "Font", panel: "appearance", only: ["Font"] },
    { id: "size", title: "Size", panel: "appearance", only: ["UI size"] },
    { id: "layout", title: "Layout", panel: "windows" },
  ] },
  { id: "terminal", title: "Terminal", icon: "terminal", groups: [
    { id: "typing", title: "Typing", panel: ["shortcuts", "toolbar"] },
    { id: "hosts", title: "Hosts", panel: "hosts" },
    { id: "scrollback", title: "Scrollback", settings: [
      { id: "scrollback-lines", title: "Lines Kept", explain: "How many lines each terminal keeps for you to scroll back through.", spec: { kind: "number", unit: "lines", default: 10000, min: 1000, max: 100000 }, keywords: "scrollback history buffer" },
    ] },
    { id: "multiplexer", title: "Multiplexer", docs: { page: "terminal/multiplexer", heading: "offer-to-switch" }, settings: [
      { id: "multiplexer-offer", title: "Offer To Switch", explain: "Ask, in a new shell, whether to switch to the Infraternal Multiplexer.", spec: { kind: "switch", default: true }, keywords: "multiplexer tmux switch" },
    ] },
  ] },
  { id: "you", title: "You", icon: "you", groups: [
    { id: "profile", title: "Profile", panel: "account", only: ["This device"] },
    { id: "passkeys", title: "Passkeys", docs: { page: "reference/keys", heading: "passkey" }, panel: "account", only: ["Passkeys"] },
    { id: "recovery", title: "Recovery", docs: { page: "reference/keys", heading: "recovery-words" }, panel: "account", only: ["Recovery key"] },
    { id: "apps", title: "Apps", docs: { page: "reference/keys", heading: "keys-last" }, settings: [
      { id: "app-key", title: "Keys Last", explain: "Each use starts the time again; a key unused this long stops working.", spec: days(30, 1, 365), keywords: "cli mcp api key token sliding" },
    ] },
    { id: "devices", title: "Devices", docs: { page: "reference/keys", heading: "browsers-stay-signed-in-for" }, panel: "devices", settings: [
      { id: "browser-session", title: "Browsers Stay Signed In For", explain: "Every visit starts the time again; a browser unused this long signs out.", spec: days(30, 1, 90), keywords: "login session browser cookie sliding" },
    ] },
  ] },
  { id: "machines", title: "Machines", icon: "machines", admin: true, groups: [
    { id: "new-machines", title: "New Machines", docs: { page: "reference/keys", heading: "add-link-lasts" }, settings: [
      { id: "add-link", title: "Add Link Lasts", explain: "How long the one-time link for adding a machine works.", spec: minutes(15, 1, 60), keywords: "add host token enrol enroll link" },
      { id: "join-code", title: "Join Code Lasts", explain: "How long the short code you type after “up” works.", spec: minutes(10, 1, 30), keywords: "up code join" },
      { id: "install-mode", title: "Install For", explain: "Whether a new machine gets infraternal for the whole system or for one user.", spec: { kind: "choice", options: [{ id: "system", label: "System" }, { id: "user", label: "User" }], default: "system" }, keywords: "install mode root rootless" },
      { id: "sign-in-account", title: "Sign In As", explain: "The account used to sign in to a new machine.", spec: { kind: "choice", options: [{ id: "mine", label: "Mine" }, { id: "root", label: "Root" }], default: "mine" }, keywords: "ssh account user login" },
      { id: "join-mesh", title: "Join The Mesh", explain: "A new machine joins the mesh as soon as it is added.", spec: { kind: "switch", default: true }, keywords: "mesh automatically" },
    ] },
    { id: "updates", title: "Updates" },
  ] },
  { id: "mesh", title: "Mesh", icon: "mesh", admin: true, groups: [
    { id: "keys", title: "Keys", docs: { page: "reference/keys", heading: "connection-keys" }, settings: [
      { id: "connection-keys", title: "Connection Keys", explain: "How often every machine swaps the keys that encrypt mesh traffic (WireGuard).", spec: days(7, 1, 30), keywords: "wireguard rotation rotate encryption" },
      { id: "machine-identity", title: "Machine Identity", explain: "How often each machine replaces the key that proves who it is.", spec: days(7, 1, 90), keywords: "identity rotation rotate key" },
      { id: "renewal-window", title: "Renewal Grace Period", explain: "A machine whose certificate ran out can still renew itself for this long, then it must be added again.", spec: days(90, 1, 365), keywords: "certificate renew expiry self-renewal" },
    ] },
    { id: "names", title: "Names", settings: [
      { id: "name-suffix", title: "Machine Names End In", explain: "Machines answer to name.internal inside the mesh; change it only to avoid a clash.", keywords: "dns suffix domain internal",
        spec: { kind: "text", default: ".internal", pattern: /^\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/, rule: "Start with a dot, then lowercase letters, digits and hyphens." } },
    ] },
    { id: "access", title: "Access" },
    { id: "connections", title: "Connections" },
  ] },
  { id: "sharing", title: "Sharing", icon: "sharing", admin: true, groups: [
    { id: "published-services", title: "Published Services" },
    { id: "certificates", title: "Certificates", settings: [
      { id: "renew-early", title: "Renew Early", explain: "Certificates for published services are renewed this long before they run out.", spec: days(30, 1, 60), keywords: "proxy certificate renew acme tls" },
    ] },
  ] },
  { id: "about", title: "About", icon: "about", groups: [
    { id: "version", title: "Version", panel: "about" },
    { id: "licences", title: "Licences" },
  ] },
];
