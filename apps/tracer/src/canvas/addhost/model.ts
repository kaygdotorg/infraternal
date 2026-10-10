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
  { id: "detect", label: "Find a way to sign in" },
  { id: "connect", label: "Connect and check the host" },
  { id: "install", label: "Install the infraternal agent" },
  { id: "enrol", label: "Let the host join" },
  { id: "session", label: "Open a terminal on the host" },
];

/** What is happening in each stage, in the words the person sees. The server's own text is never the headline. */
export const RUNNING_TEXT: Record<StageId, string> = {
  detect: "Finding a way to sign in",
  connect: "Checking the host",
  install: "Installing on the host",
  enrol: "Waiting for the host to join",
  session: "Opening a terminal on the host",
};

/** One plain sentence for a failure. An unknown or missing failure gets the generic one; the raw text stays in the details. */
export function failureLine(failure: FailureDetail | undefined): string {
  switch (failure?.kind) {
    case "unreachable": return "Couldn't reach this host";
    case "mesh-policy": return "This server can't connect to this host";
    case "host-key": return "This host's key needs your OK";
    case "auth": return "Couldn't sign in to this host";
    case "unsupported": return "This host can't run the infraternal agent yet";
    case "install": return "Setting up this host didn't finish";
    default: return "Something went wrong while setting up this host. Try again.";
  }
}

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
    else if (index === at && view.state === "failed") detail = failureLine(view.failure);
    return { id: stage.id, label: stage.label, state, detail };
  });
}

/** What fixes a failure; the wizard shows the matching page or button. */
export type FixAction = "choose-method" | "host-key" | "install-command" | "retry" | "none";

export interface Guide { title: string; happened: string; next: string; fix: FixAction }

/** Plain-language account of a failed host. `name` is what the person typed or picked. */
export function guideFor(name: string, failure: FailureDetail | undefined): Guide {
  switch (failure?.kind) {
    case "unreachable": return {
      title: `${name} isn't answering`,
      happened: `We couldn't reach ${name} to sign in.`,
      next: "Check that it is turned on and on the network, then try again. If this server can't reach it, install from the host instead.",
      fix: "install-command",
    };
    case "mesh-policy": return {
      title: `This server can't connect to ${name}`,
      happened: `${name} is on your network, but this server can't open a connection to it. A network access rule may be blocking it.`,
      next: "Ask whoever manages your network to let this server connect to it, then try again.",
      fix: "retry",
    };
    case "host-key": return {
      title: `${name} needs your OK`,
      happened: `${name} showed a security key this server hasn't seen before.`,
      next: "Compare the fingerprint with the one on the host before you trust it.",
      fix: failure.fingerprints?.length ? "host-key" : "retry",
    };
    case "auth": return failure.choose_method ? {
      title: `Couldn't sign in to ${name}`,
      happened: "Your network access, this server's key and your saved key didn't get in.",
      next: "Choose another way to sign in, or give this server's key to the host.",
      fix: "choose-method",
    } : {
      title: `${name} turned the sign-in down`,
      happened: `${name} answered but wouldn't accept how this server signed in.`,
      next: "Try again, or choose another way to sign in.",
      fix: "choose-method",
    };
    case "unsupported": return {
      title: `${name} can't run the infraternal agent yet`,
      happened: "This host is missing something the infraternal agent needs.",
      next: "Use a Linux host (Intel, AMD or ARM) with systemd, then add it again.",
      fix: "none",
    };
    case "install": return {
      title: `Setting up ${name} didn't finish`,
      happened: "Installation stopped before this host was ready. Automatic cleanup may still need to finish.",
      next: "Open the details, restore access to the host if needed, then try again to finish cleanup before another attempt.",
      fix: "retry",
    };
    default: return {
      title: `Something went wrong with ${name}`,
      happened: "Something went wrong while setting up this host.",
      next: "Try again.",
      fix: "retry",
    };
  }
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
