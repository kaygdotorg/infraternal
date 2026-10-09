/**
 * The words of the window details popover (#127), in one place for the product and the mockups: they differ in where the
 * numbers come from, never in how the facts are named. Plain wording (#112): "Connection delay", not "round trip"; the
 * technical name is a subtitle on the row. A value that is not known is left out, never shown as a dash or "unknown".
 */
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";
import type { DetailsFacts } from "./details-source";

const OS_NAME: Record<HostPlatform, string> = { ubuntu: "Ubuntu", debian: "Debian", redhat: "Red Hat", proxmox: "Proxmox", nixos: "NixOS", apple: "macOS", unknown: "" };

const ICON_HOST = '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>';
const ICON_CONNECTION = '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>';
const ICON_SESSION = '<rect x="3.5" y="5" width="17" height="14" rx="2.5"/><path d="m7.5 10 2.5 2-2.5 2M12.5 14h4"/>';

export interface DetailsInput {
  host: { name: string; user?: string; os?: HostPlatform; address?: string; reach?: string };
  connection: { state: "connected" | "connecting" | "offline"; delayMs?: number; encrypted?: boolean };
  session?: { name?: string; lastCommand?: string; size?: string; sizedBy?: string; lastUsed?: string; started?: string };
}

const STATE_TEXT = { connected: "Connected", connecting: "Connecting…", offline: "Offline. This machine can't be reached right now." } as const;

export function detailsFacts(input: DetailsInput): DetailsFacts {
  const { host, connection, session } = input;
  const os = host.os && host.os !== "unknown" ? host.os : undefined;
  const osName = host.os ? OS_NAME[host.os] : "";
  const section = (id: string, label: string, icon: string, rows: DetailsFacts["sections"][number]["rows"]) => ({ id, label, icon, rows });
  return {
    ...(os ? { os } : {}),
    title: osName || host.name,
    subtitle: osName ? `${host.user ? `${host.user}@` : ""}${host.name}` : host.user ? `${host.user}@${host.name}` : "",
    sections: [
      section("host", "Host", ICON_HOST, [
        { key: "Name", value: host.name },
        { key: "System", value: osName },
        { key: "Login", value: host.user ?? "" },
        { key: "Address", value: host.address ?? "" },
        { key: "How it is reached", value: host.reach ?? "" },
      ]),
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
