// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The add-host wizard's pure rules: nothing here touches the DOM or the network, so specs can pin them.
 *
 * - `stagesOf` turns a target's folded provisioning events into the five stages the person sees
 *   (detect, connect, install, enrol, first session). Stage status comes only from events; nothing is
 *   guessed from time.
 * - `guideFor` turns a failure into what happened, what to do next and which action fixes it. The server's
 *   own text is shown beside it and is never matched on (contracts/ssh-bootstrap.md).
 * - `parseTarget` and `parseSshConfig` read what the person types or pastes into the host field.
 */
import type { AuthenticationInfo, FailureDetail, FailureKind, NetworkProvider, TargetView } from "../../provisioning-client";

export type StageId = "detect" | "connect" | "install" | "enrol" | "session";
export type StageState = "pending" | "running" | "done" | "failed";

export const STAGES: ReadonlyArray<{ id: StageId; label: string }> = [
  { id: "detect", label: "Detect how to sign in" },
  { id: "connect", label: "Connect and check the system" },
  { id: "install", label: "Install the infraternal agent" },
  { id: "enrol", label: "Enrol the host" },
  { id: "session", label: "Open the first session" },
];

export interface StageView { id: StageId; label: string; state: StageState; detail: string }

const NETWORK_NAMES: Record<NetworkProvider, string> = { netbird: "NetBird", tailscale: "Tailscale", twingate: "Twingate", other: "your network" };

/** The words for how the server signed in, e.g. "network access (NetBird)". */
export function authLabel(info: AuthenticationInfo): string {
  if (info.method === "network") return info.network && info.network !== "other" ? `network access (${NETWORK_NAMES[info.network]})` : "network access";
  if (info.method === "server-key") return "this server's key";
  if (info.method === "user-key") return "your saved key";
  return "your password";
}

/** The failure kinds that stop before any login succeeded. */
const BEFORE_LOGIN: readonly FailureKind[] = ["unreachable", "mesh-policy", "host-key", "auth"];

/**
 * Index of the stage a target is in. Contract steps are check, install, facts, connect; the sign-in report
 * splits `check` in two: until the server reports how it signed in the host is still being detected.
 */
export function currentStage(view: TargetView): number {
  const failedBeforeLogin = view.state === "failed" && !view.authentication && !!view.failure && BEFORE_LOGIN.includes(view.failure.kind);
  if (view.phase === 0) return view.authentication && !failedBeforeLogin ? 1 : 0;
  // `unsupported` is reported by the system check, which runs after sign-in.
  return view.phase + 1;
}

export function stagesOf(view: TargetView): StageView[] {
  const at = currentStage(view);
  return STAGES.map((stage, index): StageView => {
    let state: StageState = "pending";
    if (view.state === "done") state = "done";
    else if (view.state !== "pending") {
      if (index < at) state = "done";
      else if (index === at) state = view.state === "failed" ? "failed" : "running";
    }
    let detail = "";
    if (stage.id === "detect" && view.authentication && state === "done") detail = `Signed in with ${authLabel(view.authentication)}`;
    // A running stage's text is the server's latest message, which the host's header line already shows;
    // repeating it under the stage name would say everything twice.
    else if (index === at && view.state === "failed") detail = view.failure?.message ?? view.message;
    return { id: stage.id, label: stage.label, state, detail };
  });
}

/** What fixes a failure; the wizard shows the matching page or button. */
export type FixAction = "choose-method" | "host-key" | "install-command" | "retry" | "none";

export interface Guide { title: string; happened: string; next: string; fix: FixAction }

/** Plain-language account of a failed host. `name` is what the person typed or picked. */
export function guideFor(name: string, failure: FailureDetail | undefined): Guide {
  const kind = failure?.kind ?? "install";
  if (kind === "unreachable") return {
    title: `${name} didn't answer`,
    happened: `Nothing answered over SSH at ${name}.`,
    next: "Check that the host is on and reachable from this server, then retry. If it can't be reached from here, install from the host instead.",
    fix: "install-command",
  };
  if (kind === "mesh-policy") return {
    title: "Blocked, possibly by the mesh policy",
    happened: `${name} is a mesh peer that answers elsewhere on the mesh, but SSH from this server looks blocked. That can be a mesh access policy.`,
    next: "Ask a mesh admin to allow SSH (TCP 22) from this server, then retry.",
    fix: "retry",
  };
  if (kind === "host-key") return {
    title: `${name} has a key this server doesn't trust`,
    happened: `${name} answered with an SSH host key that isn't in this server's known hosts.`,
    next: "Compare the fingerprint with the one on the host before you trust it.",
    fix: failure?.fingerprints?.length ? "host-key" : "retry",
  };
  if (kind === "auth") return failure?.choose_method ? {
    title: `${name} didn't accept any sign-in`,
    happened: "Network access, this server's key and your saved key were all tried or unavailable.",
    next: "Choose how to sign in this once, or add this server's key to the host.",
    fix: "choose-method",
  } : {
    title: `${name} refused the sign-in`,
    happened: `${name} answered but refused the way this server signed in.`,
    next: "Retry, or choose another way to sign in.",
    fix: "choose-method",
  };
  if (kind === "unsupported") return {
    title: `${name} isn't supported yet`,
    happened: `${name} doesn't have what the infraternal agent needs.`,
    next: "Use a Linux host (x86_64 or aarch64) with systemd, then add it again.",
    fix: "none",
  };
  return {
    title: `${name} could not be set up`,
    happened: `The installation on ${name} didn't finish, and it was rolled back.`,
    next: "Read the details, then retry.",
    fix: "retry",
  };
}

export interface ParsedTarget { user: string | undefined; host: string; port: number | undefined }

/** Parses `user@host[:port]`; undefined for text that cannot name a host. */
export function parseTarget(raw: string): ParsedTarget | undefined {
  const match = /^(?:([a-z_][a-z0-9_.-]*)@)?([a-z0-9][a-z0-9.-]*|\[[0-9a-f:]+\])(?::(\d{1,5}))?$/i.exec(raw.trim());
  if (!match) return undefined;
  const port = match[3] ? Number(match[3]) : undefined;
  if (port !== undefined && (port < 1 || port > 65535)) return undefined;
  return { user: match[1], host: match[2]!.toLowerCase(), port };
}

/**
 * Reads hosts out of pasted `ssh_config` text and returns them as `user@host[:port]` strings. Wildcard and
 * negated patterns are skipped, `Match` blocks are ignored, and only HostName, User and Port are read:
 * the server's own OpenSSH applies the rest of the person's configuration when it connects.
 */
export function parseSshConfig(text: string): string[] {
  const hosts: string[] = [];
  let aliases: string[] = [];
  let hostName: string | undefined;
  let user: string | undefined;
  let port: string | undefined;
  const flush = (): void => {
    for (const alias of aliases) {
      const target = `${user ? `${user}@` : ""}${hostName ?? alias}${port ? `:${port}` : ""}`;
      if (parseTarget(target)) hosts.push(target);
    }
    aliases = []; hostName = undefined; user = undefined; port = undefined;
  };
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*([A-Za-z]+)(?:\s*=\s*|\s+)(.+?)\s*$/.exec(line);
    if (!match || line.trimStart().startsWith("#")) continue;
    const key = match[1]!.toLowerCase();
    const value = match[2]!.replace(/\s+#.*$/, "").replace(/^"(.*)"$/, "$1");
    if (key === "host") { flush(); aliases = value.split(/\s+/).filter((item) => item && !/[*?!]/.test(item)); }
    else if (key === "match") { flush(); }
    else if (!aliases.length) continue;
    else if (key === "hostname") hostName = value;
    else if (key === "user") user = value;
    else if (key === "port") port = /^\d{1,5}$/.test(value) ? value : undefined;
  }
  flush();
  return [...new Set(hosts)];
}

/** True when the text looks like ssh_config rather than a host name. */
export const looksLikeSshConfig = (text: string): boolean => /^\s*Host\s+\S/im.test(text);
