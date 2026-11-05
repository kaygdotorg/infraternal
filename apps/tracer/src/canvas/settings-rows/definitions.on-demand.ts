// SPDX-License-Identifier: AGPL-3.0-only
/**
 * What each setting of the table is (issue #304): its plain title, one line of help, its allowed values and the technical names ⌘K matches.
 * On demand (D188): the sidebar, the breadcrumb and the window frames need only where a setting lives (`catalog.ts`), so the wording and
 * the rules load with the first Settings window or the first ⌘K, never with the page.
 */
import { defaultValue, type SettingValue, type ValueSpec } from "../../../../../packages/ui/src/setting-value";

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

const days = (d: number, min: number, max: number): ValueSpec => ({ kind: "duration", unit: "d", default: d, min, max });
const minutes = (m: number, min: number, max: number): ValueSpec => ({ kind: "duration", unit: "min", default: m, min, max });

export const SETTING_DEFS: Readonly<Record<string, SettingDef>> = Object.fromEntries(([
{ id: "scrollback-lines", title: "Lines Kept", explain: "How many lines each terminal keeps for you to scroll back through.", spec: { kind: "number", unit: "lines", default: 10000, min: 1000, max: 100000 }, keywords: "scrollback history buffer" },
{ id: "multiplexer-offer", title: "Offer To Switch", explain: "Ask, in a new shell, whether to switch to the Infraternal Multiplexer.", spec: { kind: "switch", default: true }, keywords: "multiplexer tmux switch" },
{ id: "app-key", title: "Keys Last", explain: "Each use starts the time again; a key unused this long stops working.", spec: days(30, 1, 365), keywords: "cli mcp api key token sliding" },
{ id: "browser-session", title: "Browsers Stay Signed In For", explain: "Every visit starts the time again; a browser unused this long signs out.", spec: days(30, 1, 90), keywords: "login session browser cookie sliding" },
{ id: "add-link", title: "Add Link Lasts", explain: "How long the one-time link for adding a machine works.", spec: minutes(15, 1, 60), keywords: "add host token enrol enroll link" },
      { id: "join-code", title: "Join Code Lasts", explain: "How long the short code you type after “up” works.", spec: minutes(10, 1, 30), keywords: "up code join" },
      { id: "install-mode", title: "Install For", explain: "Whether a new machine gets infraternal for the whole system or for one user.", spec: { kind: "choice", options: [{ id: "system", label: "System" }, { id: "user", label: "User" }], default: "system" }, keywords: "install mode root rootless" },
      { id: "sign-in-account", title: "Sign In As", explain: "The account used to sign in to a new machine.", spec: { kind: "choice", options: [{ id: "mine", label: "Mine" }, { id: "root", label: "Root" }], default: "mine" }, keywords: "ssh account user login" },
      { id: "join-mesh", title: "Join The Mesh", explain: "A new machine joins the mesh as soon as it is added.", spec: { kind: "switch", default: true }, keywords: "mesh automatically" },
{ id: "connection-keys", title: "Connection Keys", explain: "How often every machine swaps the keys that encrypt mesh traffic (WireGuard).", spec: days(7, 1, 30), keywords: "wireguard rotation rotate encryption" },
      { id: "machine-identity", title: "Machine Identity", explain: "How often each machine replaces the key that proves who it is.", spec: days(7, 1, 90), keywords: "identity rotation rotate key" },
      { id: "renewal-window", title: "Renewal Grace Period", explain: "A machine whose certificate ran out can still renew itself for this long, then it must be added again.", spec: days(90, 1, 365), keywords: "certificate renew expiry self-renewal" },
{ id: "name-suffix", title: "Machine Names End In", explain: "Machines answer to name.internal inside the mesh; change it only to avoid a clash.", keywords: "dns suffix domain internal",
        spec: { kind: "text", default: ".internal", pattern: /^\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/, rule: "Start with a dot, then lowercase letters, digits and hyphens." } },
{ id: "renew-early", title: "Renew Early", explain: "Certificates for published services are renewed this long before they run out.", spec: days(30, 1, 60), keywords: "proxy certificate renew acme tls" }
] satisfies SettingDef[]).map((d) => [d.id, d]));

/** The value a setting has until something stores another. */
export const defaultOf = (s: SettingDef): SettingValue => defaultValue(s.spec);
