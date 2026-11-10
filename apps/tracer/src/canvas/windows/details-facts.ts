/**
 * The words of the window details popover (#127), in one place for the product and the mockups: they differ in where the
 * numbers come from, never in how the facts are named. Plain wording (#112): "Connection delay", not "round trip"; the
 * technical name is a subtitle on the row. A value that is not known is left out, never shown as a dash or "unknown".
 */
import { hostPlatformFromOs, type HostPlatform } from "../../../../../packages/ui/src/host-icons";
import { ICON } from "../views/icons";
import type { DetailsFacts, HostFactsSnapshot } from "./details-source";

const OS_NAME: Record<HostPlatform, string> = { ubuntu: "Ubuntu", debian: "Debian", redhat: "Red Hat", proxmox: "Proxmox", nixos: "NixOS", apple: "macOS", unknown: "" };

const ICON_HOST = ICON.host;
const ICON_CONNECTION = '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>';
const ICON_SESSION = '<rect x="3.5" y="5" width="17" height="14" rx="2.5"/><path d="m7.5 10 2.5 2-2.5 2M12.5 14h4"/>';

/** Everything the details panel is built from: the host, the page's connection, the optional session, and whether extended info is on. */
export interface DetailsInput {
  /**
   * `unavailable` says why there are no `facts` for this host: `offline` (its infraternal agent is not connected) or `pending`
   * (not read yet, or never readable from here). The System row then says so in plain words; no other host's facts stand in.
   */
  host: { name: string; user?: string; os?: HostPlatform; address?: string; reach?: string; facts?: HostFactsSnapshot; unavailable?: "offline" | "pending" };
  connection: { state: "connected" | "connecting" | "offline"; delayMs?: number; encrypted?: boolean };
  /** Extended machine info (Settings): adds the technical facts (init, virtualization, shell, locale, how it is reached). */
  extended?: boolean;
  session?: { name?: string; lastCommand?: string; size?: string; sizedBy?: string; lastUsed?: string; started?: string };
}

const STATE_TEXT = { connected: "Connected", connecting: "Connecting…", offline: "Offline. This machine can't be reached right now." } as const;

function compactBytes(bytes: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"] as const;
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  const digits = value >= 10 || unit === 0 ? 0 : 1;
  return `${Number(value.toFixed(digits))} ${units[unit]}`;
}

function capacity(fact: { usedBytes: number; totalBytes: number } | undefined): string {
  if (!fact) return "";
  return `${compactBytes(fact.usedBytes)} of ${compactBytes(fact.totalBytes)}`;
}

function uptime(seconds: number | undefined): string {
  if (seconds === undefined) return "";
  if (seconds < 60) return "Less than a minute";
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  if (days) return `${days} ${days === 1 ? "day" : "days"}, ${hours} ${hours === 1 ? "hour" : "hours"}`;
  if (hours) return `${hours} ${hours === 1 ? "hour" : "hours"}, ${minutes} ${minutes === 1 ? "minute" : "minutes"}`;
  return `${minutes} ${minutes === 1 ? "minute" : "minutes"}`;
}

/** Turns what is known about a window's host, connection and session into the panel's header and tabs, in plain words. */
export function detailsFacts(input: DetailsInput): DetailsFacts {
  const { host, connection, session } = input;
  const facts = host.facts;
  // What the machine reports about itself wins over the platform the host list guessed; `host.os` is the fallback
  // before the facts arrive. Title, mark and subtitle must agree with the System row.
  const platform = facts ? hostPlatformFromOs(facts.os) : host.os;
  const os = platform && platform !== "unknown" ? platform : undefined;
  const osName = (platform ? OS_NAME[platform] : "") || (facts ? facts.os : "");
  // D126: the default facts always show, under titled sections (no "More" control, TASTE). The rest are cheap but
  // technical, so only the device-local extended switch adds them (D156: opt-in for the noisier facts). A fact the
  // host did not report has an empty value and the popover omits the row.
  const row = (group: string, core: boolean, key: string, value: string) => ({ key, value, group, core });
  const allHostRows = [
    row("System", true, "Name", host.name),
    row("System", true, "System", facts ? `${facts.os}${facts.version ? ` ${facts.version}` : ""}` : host.unavailable === "offline" ? "Can't be read while this machine is offline" : host.unavailable === "pending" ? "Not known yet" : osName),
    row("System", true, "Kernel", facts?.kernel ?? ""),
    row("System", true, "Architecture", facts?.architecture ?? ""),
    row("System", true, "Model", facts?.model ?? ""),
    row("System", false, "Init", facts?.init ?? ""),
    row("System", false, "Virtualization", facts?.virtualization ?? ""),
    row("Resources", true, "CPU", facts ? `${facts.logicalCpus} logical ${facts.logicalCpus === 1 ? "core" : "cores"}${facts.cpuModel ? ` · ${facts.cpuModel}` : ""}` : ""),
    row("Resources", true, "Memory", capacity(facts?.memory)),
    row("Resources", true, "Disk used on /", capacity(facts?.rootDisk)),
    row("Resources", true, "Uptime", uptime(facts?.uptimeSeconds)),
    row("Resources", true, "Load average", facts?.loadAverage?.map((value) => value.toFixed(2)).join(", ") ?? ""),
    row("Access", true, "Infraternal agent", facts ? `${facts.mode === "embedded" ? "Embedded" : "Remote"} · ${facts.executionUid === 0 ? "root" : "user"}` : ""),
    row("Access", true, "Engines", facts ? facts.engines.length ? facts.engines.join(", ") : "None detected" : ""),
    row("Access", true, "Login", host.user ?? ""),
    row("Access", true, "Address", host.address ?? ""),
    row("Access", false, "How it is reached", host.reach ?? ""),
    row("Access", false, "Shell", facts?.shell ?? ""),
    row("Access", false, "Locale", facts?.locale ?? ""),
  ];
  const hostRows = allHostRows.filter((r) => r.core || input.extended).map(({ key, value, group }) => ({ key, value, group }));
  const section = (id: string, label: string, icon: string, rows: DetailsFacts["sections"][number]["rows"]) => ({ id, label, icon, rows });
  return {
    ...(os ? { os } : {}),
    title: osName || host.name,
    subtitle: osName ? `${host.user ? `${host.user}@` : ""}${host.name}` : host.user ? `${host.user}@${host.name}` : "",
    sections: [
      section("host", "Host", ICON_HOST, hostRows),
      section("connection", "Connection", ICON_CONNECTION, [
        { key: "Status", value: STATE_TEXT[connection.state] },
        { key: "Connection delay", value: connection.delayMs === undefined ? "" : `${Math.round(connection.delayMs)} ms`, hint: "Round-trip time to the server" },
        { key: "Encrypted", value: connection.encrypted === undefined ? "" : connection.encrypted ? "Yes" : "No, this page is not on HTTPS" },
      ]),
      section("session", "Session", ICON_SESSION, [
        { key: "Name", value: session?.name ?? "" },
        { key: "Started", value: session?.started ?? "" },
        { key: "Last used", value: session?.lastUsed ?? "" },
        { key: "Running now", value: session?.lastCommand ?? "" },
        { key: "Size", value: session?.size ?? "" },
        { key: "Sized by", value: session?.sizedBy ?? "" },
      ]),
    ],
  };
}
