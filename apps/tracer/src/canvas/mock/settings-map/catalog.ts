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
 * The map is the owner's of 2026-11-02 (names in Title Case, no brackets). Entries marked `// PLACEHOLDER` are my guesses
 * (a name, a range, a list's contents, which panel stands in); every number the owner gave is marked `// OWNER`.
 *
 * Plain words (TASTE): titles and explanations say what changes for the person, in one line. The technical term, where an
 * expert needs it, sits in the explanation or in `keywords` (which ⌘K searches, but nobody has to read).
 */
import type { ValueSpec } from "../../../../../../packages/ui/src/setting-value";
import type { DocsLink } from "../../docs/docs-adapter";

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

/**
 * An existing Settings panel reused unchanged inside a window (its id is the old section id). `only` keeps just the blocks
 * of the panel whose heading is listed, so one panel can fill several windows (the Appearance panel is Theme, Font and Size).
 */
export type PanelId = "appearance" | "windows" | "toolbar" | "shortcuts" | "about" | "devices";

/** The docs heading a window's "?" opens (`docs/docs-adapter.ts`). Absent on a group: no page yet. */
export type { DocsLink };

export interface GroupDef {
  id: string;
  title: string;
  /** Only administrators see it. */
  admin?: boolean;
  settings?: SettingDef[];
  facts?: FactGroupDef[];
  keys?: KeyDef[];
  panel?: PanelId;
  only?: string[];
  /** A group that does not exist yet: one plain line instead of controls. */
  later?: string;
  docs?: DocsLink;
}

export interface ComponentDef {
  id: string;
  title: string;
  /** Key into `ICON_OF` (settings-map/model.ts). */
  icon: "appearance" | "terminal" | "you" | "machines" | "mesh" | "sharing" | "about";
  admin?: boolean;
  groups: GroupDef[];
}

const days = (d: number, min: number, max: number): ValueSpec => ({ kind: "duration", unit: "d", default: d, min, max });
const minutes = (m: number, min: number, max: number): ValueSpec => ({ kind: "duration", unit: "min", default: m, min, max });

export const SETTINGS_MAP: readonly ComponentDef[] = [
  { id: "appearance", title: "Appearance", icon: "appearance", groups: [
    { id: "theme", title: "Theme", panel: "appearance", only: ["Theme", "Background", "Card transparency", "Window transparency"] }, // PLACEHOLDER: background and transparency sit with the theme
    { id: "font", title: "Font", panel: "appearance", only: ["Font"] },
    { id: "size", title: "Size", panel: "appearance", only: ["UI size"] },
    { id: "layout", title: "Layout", panel: "windows" }, // PLACEHOLDER: the old Window Sizes
  ] },
  { id: "terminal", title: "Terminal", icon: "terminal", groups: [
    { id: "typing", title: "Typing", panel: "shortcuts" }, // PLACEHOLDER: the shortcuts panel stands in
    { id: "scrollback", title: "Scrollback", settings: [
      { id: "scrollback-lines", title: "Lines Kept", explain: "How many lines each terminal keeps for you to scroll back through.", spec: { kind: "number", unit: "lines", default: 10000, min: 1000, max: 100000 } /* PLACEHOLDER */, keywords: "scrollback history buffer" },
    ] },
    { id: "multiplexer", title: "Multiplexer", docs: { page: "multiplexer", heading: "what-it-does-for-you" }, settings: [
      { id: "multiplexer-offer", title: "Offer To Switch", explain: "Ask, in a new shell, whether to switch to the Infraternal Multiplexer.", spec: { kind: "switch", default: true } /* PLACEHOLDER */, keywords: "multiplexer tmux switch" },
    ] },
  ] },
  { id: "you", title: "You", icon: "you", groups: [
    { id: "profile", title: "Profile", facts: [ // PLACEHOLDER
      { title: "Who You Are", rows: [{ key: "Name", value: "Kay G" }, { key: "Username", value: "kayg" }, { key: "Email", value: "none yet" }] },
    ] },
    { id: "passkeys", title: "Passkeys", docs: { page: "keys", heading: "passkey" }, facts: [ // PLACEHOLDER: from the account facts
      { title: "Added", rows: [{ key: "iPhone 15", value: "added 2 weeks ago" }, { key: "MacBook Pro", value: "added 3 months ago" }] },
    ] },
    { id: "recovery", title: "Recovery", docs: { page: "keys", heading: "recovery-words" }, facts: [
      { title: "Recovery Key", rows: [{ key: "Status", value: "saved" }, { key: "Last Checked", value: "6 days ago" }] },
    ] },
    { id: "apps", title: "Apps", docs: { page: "keys", heading: "cli-sign-in-api-key" }, settings: [
      { id: "app-key", title: "Keys Last", explain: "Each use starts the time again; a key unused this long stops working.", spec: days(30, 1, 365) /* OWNER 30 d sliding, 1–365 d */, keywords: "cli mcp api key token sliding" },
    ], keys: [ // PLACEHOLDER: the list of command-line and AI-tool keys (last used, expires, revoke)
      { id: "k1", name: "laptop", kind: "cli", lastUsed: "2 hours ago", expires: "in 28 days" },
      { id: "k2", name: "Claude Code", kind: "mcp", lastUsed: "yesterday", expires: "in 21 days" },
      { id: "k3", name: "build script", kind: "cli", lastUsed: "6 days ago", expires: "in 24 days" },
    ] },
    { id: "devices", title: "Devices", docs: { page: "keys", heading: "browser-sign-in" }, settings: [
      { id: "browser-session", title: "Browsers Stay Signed In For", explain: "Every visit starts the time again; a browser unused this long signs out.", spec: days(30, 1, 90) /* OWNER 30 d sliding, 1–90 d */, keywords: "login session browser cookie sliding" },
    ], panel: "devices" },
  ] },
  { id: "machines", title: "Machines", icon: "machines", admin: true, groups: [
    { id: "new-machines", title: "New Machines", docs: { page: "keys", heading: "host-join-token" }, settings: [
      { id: "add-link", title: "Add Link Lasts", explain: "How long the one-time link for adding a machine works.", spec: minutes(15, 1, 60) /* OWNER 15 min; range PLACEHOLDER */, keywords: "add host token enrol enroll link" },
      { id: "join-code", title: "Join Code Lasts", explain: "How long the short code you type after “up” works.", spec: minutes(10, 1, 30) /* OWNER 10 min; range PLACEHOLDER */, keywords: "up code join" },
      { id: "install-mode", title: "Install For", explain: "Whether a new machine gets infraternal for the whole system or for one user.", spec: { kind: "choice", options: [{ id: "system", label: "System" }, { id: "user", label: "User" }], default: "system" } /* default PLACEHOLDER */, keywords: "install mode root rootless" },
      { id: "sign-in-account", title: "Sign In As", explain: "The account used to sign in to a new machine.", spec: { kind: "choice", options: [{ id: "mine", label: "Mine" }, { id: "root", label: "Root" }], default: "mine" } /* PLACEHOLDER */, keywords: "ssh account user login" },
      { id: "join-mesh", title: "Join The Mesh", explain: "A new machine joins the mesh as soon as it is added.", spec: { kind: "switch", default: true } /* default PLACEHOLDER */, keywords: "mesh automatically" },
    ] },
    { id: "updates", title: "Updates", facts: [ // PLACEHOLDER
      { title: "Machines", rows: [{ key: "Channel", value: "stable" }, { key: "Last Checked", value: "2 hours ago" }, { key: "Behind", value: "1 machine" }] },
    ] },
  ] },
  { id: "mesh", title: "Mesh", icon: "mesh", admin: true, groups: [
    { id: "keys", title: "Keys", docs: { page: "keys", heading: "wireguard-session-keys" }, settings: [
      { id: "connection-keys", title: "Connection Keys", explain: "How often every machine swaps the keys that encrypt mesh traffic (WireGuard).", spec: days(7, 1, 30) /* OWNER 7 d; range PLACEHOLDER */, keywords: "wireguard rotation rotate encryption" },
      { id: "machine-identity", title: "Machine Identity", explain: "How often each machine replaces the key that proves who it is.", spec: days(7, 1, 90) /* OWNER 7 d; range PLACEHOLDER */, keywords: "identity rotation rotate key" },
      { id: "renewal-window", title: "Renewal Grace Period", explain: "A machine whose certificate ran out can still renew itself for this long, then it must be added again.", spec: days(90, 1, 365) /* OWNER 90 d after expiry; range PLACEHOLDER */, keywords: "certificate renew expiry self-renewal" },
    ], facts: [ // OWNER: read-only
      { title: "Machine Authority", rows: [{ key: "Expires", value: "in 9 years" }, { key: "Lock", value: "locked until an administrator confirms with a passkey" }] },
    ] },
    { id: "names", title: "Names", settings: [
      { id: "name-suffix", title: "Machine Names End In", explain: "Machines answer to name.internal inside the mesh; change it only to avoid a clash.", keywords: "dns suffix domain internal",
        spec: { kind: "text", default: ".internal" /* OWNER */, pattern: /^\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/, rule: "Start with a dot, then lowercase letters, digits and hyphens." } },
    ] },
    { id: "access", title: "Access", facts: [ // PLACEHOLDER: the real list is the Mesh view's access rules
      { title: "Who Can Reach What", rows: [{ key: "Rules", value: "14" }, { key: "Through A Relay", value: "3" }, { key: "Open To Everyone", value: "none" }] },
    ] },
    { id: "connections", title: "Connections", facts: [ // PLACEHOLDER
      { title: "Now", rows: [{ key: "Direct", value: "5" }, { key: "Through A Relay", value: "3" }, { key: "Offline", value: "1" }] },
    ] },
  ] },
  { id: "sharing", title: "Sharing", icon: "sharing", admin: true, groups: [
    { id: "published-services", title: "Published Services", facts: [ // PLACEHOLDER
      { title: "Reachable From Outside", rows: [{ key: "grafana", value: "monitor01:3000" }, { key: "docs", value: "build-01:8080" }] },
    ] },
    { id: "certificates", title: "Certificates", settings: [
      { id: "renew-early", title: "Renew Early", explain: "Certificates for published services are renewed this long before they run out.", spec: days(30, 1, 60) /* PLACEHOLDER */, keywords: "proxy certificate renew acme tls" },
    ] },
  ] },
  { id: "about", title: "About", icon: "about", groups: [
    { id: "version", title: "Version", panel: "about" },
    { id: "licences", title: "Licences", facts: [ // PLACEHOLDER
      { title: "infraternal", rows: [{ key: "Licence", value: "AGPL-3.0-only" }, { key: "Commercial Features", value: "separate licence" }] },
    ] },
  ] },
];
