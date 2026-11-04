/** The old windows prototype's facts for the shared details popover (windows/details.on-demand.ts): invented machine data. */
import type { DetailsFacts } from "../../windows/details-source";
import type { KeyValueRow } from "../../../../../../packages/ui/src/kv-list";
import type { CanvasHost, CanvasSession } from "./canvas";

/** Builds the details popover's facts for a prototype window. The numbers are invented test data. */
export function prototypeFacts(host: CanvasHost, session: CanvasSession, hostLabel: string, icons: { machine: string; connection: string; session: string }): DetailsFacts {
  const machine: KeyValueRow[] = [
    { key: "Kernel", value: host.kernel },
    { key: "Architecture", value: host.architecture },
    { key: "Model", value: host.model },
    { key: "CPU", value: host.cores ? `${host.cpu} · ${host.cores} cores` : host.cpu },
    { key: "Memory", value: host.memory ? `${host.memory}% used` : "", meter: host.memory },
    { key: "Disk", value: host.disk ? `${host.disk}% used` : "", meter: host.disk },
    { key: "Uptime", value: host.uptime },
    { key: "Load", value: host.load },
    { key: "Init", value: host.init },
    { key: "Virtualization", value: host.virtualization },
    { key: "Shell", value: host.shell },
    { key: "Locale", value: host.locale },
    { key: "IP addresses", value: host.ips.join(" · ") },
    { key: "Engines", value: host.engines.join(" · ") },
    { key: "infraternal agent", value: host.mode },
  ];
  const connection: KeyValueRow[] = [
    { key: "Route", value: host.connection.route },
    { key: "Transport", value: host.connection.transport },
    { key: "Mesh", value: host.connection.mesh },
    { key: "Certificate", value: host.connection.certificate },
    { key: "Connection delay", value: host.connection.roundTrip, hint: "Round-trip time to the server" },
    { key: "Traffic", value: host.connection.bytes },
    { key: "Reconnects", value: String(host.connection.reconnects) },
  ];
  const sess: KeyValueRow[] = [
    { key: "Session", value: session.name },
    { key: "Started", value: session.started },
    { key: "Age", value: session.age },
    { key: "Viewers", value: String(session.viewers) },
    { key: "Size", value: session.size },
    { key: "Scrollback", value: session.scrollback },
    { key: "Last output", value: session.lastOutput },
  ];
  return {
    os: host.os,
    title: [host.osName, host.version].filter(Boolean).join(" ") || hostLabel,
    subtitle: [`${host.user ? `${host.user}@` : ""}${hostLabel}`, host.architecture].filter(Boolean).join(" · "),
    sections: [
      { id: "machine", label: "Machine", icon: icons.machine, rows: machine },
      { id: "connection", label: "Connection", icon: icons.connection, rows: connection },
      { id: "session", label: "Session", icon: icons.session, rows: sess },
    ],
  };
}
