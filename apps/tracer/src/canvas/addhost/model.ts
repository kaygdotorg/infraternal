// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The add-host wizard's pure rules: nothing here touches the DOM or the network, so specs can pin them.
 *
 * - `stagesOf` turns a target's folded provisioning events into the five stages the person sees
 *   (detect, connect, install, enrol, first session). Stage status comes only from events; nothing is
 *   guessed from time.
 * - `guideFor` turns a failure into what happened, what to do next and which action fixes it. The server's
 *   diagnostic text stays in Details and never determines the failure category (contracts/ssh-bootstrap.md).
 * - `parseTarget` and `parseSshConfig` read what the person types or pastes into the host field.
 */
import { shortcutLabel } from "../../../../../packages/ui/src/platform";
import { awaitingFresh } from "../../provisioning-client";
import type { AuthenticationInfo, FailureDetail, FailureKind, NetworkProvider, TargetView } from "../../provisioning-client";

export type StageId = "detect" | "connect" | "install" | "enrol" | "session";
export type StageState = "pending" | "running" | "done" | "failed";

export const STAGES: ReadonlyArray<{ id: StageId; label: string }> = [
  { id: "detect", label: "Find a way to sign in" },
  { id: "connect", label: "Connect and check the host" },
  { id: "install", label: "Install the infraternal agent" },
  { id: "enrol", label: "Connect the host to this server" },
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
    case "stale_previous_attempt": return "Leftovers from an earlier setup";
    case "setup_running": return "Setup is already running on this host";
    case "install":
      if (failure.failed_step === "get-arm64-binary" || failure.failed_step === "get-x86-64-binary") {
        return `Download infraternal (${failure.failed_step === "get-arm64-binary" ? "arm64" : "x86_64"}): ${failure.message}`;
      }
      if (failure.already_added) return failure.message;
      if (failure.missing_binary) return `The ${failure.missing_binary.architecture} static infraternal binary is unavailable. Put it at ${failure.missing_binary.path} on the server, then try again.`;
      if (failure.failed_step === "connect") return "Connecting to the host failed.";
      return failure.failed_step ? [failure.message, ...failure.log_tail.filter((line) => !line.startsWith("Remote command returned"))].join(" ") : "Setting up this host didn't finish";
    default: return "Something went wrong while setting up this host. Try again.";
  }
}

/** What confirming a stuck-install replacement ends; empty when the server did not say (#305, D13). */
function sessionsLine(lock: NonNullable<FailureDetail["setup_lock"]>): string {
  if (lock.sessions === undefined) return "";
  if (lock.sessions === 0) return "No terminal sessions are open on it.";
  return lock.sessions === 1 ? "1 open terminal session will end." : `${lock.sessions} open terminal sessions will end.`;
}

/** Turn the validated host lease coordinates into the message shown in the flow. */
function setupLockLine(lock: NonNullable<FailureDetail["setup_lock"]>, active: boolean): string {
  const owner = lock.pid === undefined ? "an unidentified process" : `process ${lock.pid}`;
  return active
    ? `${owner[0]?.toUpperCase()}${owner.slice(1)} on ${lock.machine} holds the setup lock since ${lock.since}.`
    : `The failed install on ${lock.machine} was last held by ${owner} since ${lock.since}.`;
}

export interface StageView { id: StageId; label: string; state: StageState; detail: string }

const NETWORK_NAMES: Record<NetworkProvider, string> = { netbird: "NetBird", tailscale: "Tailscale", twingate: "Twingate", other: "your network" };

/** The words for how the server signed in, e.g. "network access (NetBird)". */
export function authLabel(info: AuthenticationInfo): string {
  if (info.method === "network") return info.network && info.network !== "other" ? `network access (${NETWORK_NAMES[info.network]})` : "network access";
  if (info.method === "server-key") return "this server's key";
  if (info.method === "user-key") return "your key";
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
      // A pause on leftovers waits for the person; it is not a spinner.
      else if (index === at) state = view.state === "failed" || awaitingFresh(view) ? "failed" : "running";
    }
    let detail = "";
    if (stage.id === "detect" && view.authentication && state === "done") detail = `Signed in with ${authLabel(view.authentication)}`;
    // A running stage's text is the server's latest message, which the host's header line already shows;
    // repeating it under the stage name would say everything twice.
    else if (index === at && (view.state === "failed" || awaitingFresh(view))) detail = failureLine(view.failure);
    return { id: stage.id, label: stage.label, state, detail };
  });
}

/** What fixes a failure; the wizard shows the matching page or button. */
export type FixAction = "choose-method" | "host-key" | "install-command" | "retry" | "start-fresh" | "replace-stuck-install" | "none";

/**
 * `tone` is the news, not the severity: "info" for a host that needs a decision or a wait (leftovers, a setup still
 * running), "danger" for a real failure. The icon follows it (TASTE: the icon matches the news).
 */
export interface Guide { title: string; happened: string; next: string; fix: FixAction; tone: "info" | "danger" }

/** What to do after an install failure, by the step that stopped. Without a step nothing more is known. */
export const STEP_ADVICE: Record<NonNullable<FailureDetail["failed_step"]>, string> = {
  "get-arm64-binary": "Check this server’s release channel and signed arm64 binary, then try again.",
  "get-x86-64-binary": "Check this server’s release channel and signed x86_64 binary, then try again.",
  connect: "Check SSH access and the host service, then try again.",
  upload: "Copying the infraternal agent to the host didn't finish. Try again.",
  install: "Installing the infraternal agent stopped partway. Try again, or open the details to see where.",
  join: "The host couldn't join this server. Try again in a moment.",
  start: "The infraternal agent was installed but didn't start. Try again, or open the details to see why.",
  readiness: "The host joined, but its terminal wasn't ready yet. Try again in a moment.",
};
const GENERIC_ADVICE = "Try again, or open the details to see where it stopped.";

/** Plain-language account of a failed host. `name` is what the person typed or picked. */
export function guideFor(name: string, failure: FailureDetail | undefined, canOpen = false): Guide {
  // Without a button to open its terminal (an older server sends no host id; the page may not list the host) the
  // copy carries the route itself, so the page is never a dead end. Keys follow the platform (⌘ only on Apple keyboards).
  if (failure?.already_added) return { title: `${name} is already added`, happened: "It's already in Console.", next: canOpen ? "" : `Find its terminal with ${shortcutLabel({ mac: "⌘K", other: "Ctrl K" })}.`, fix: "none", tone: "info" };
  switch (failure?.kind) {
    case "unreachable": return {
      title: `${name} isn't answering`,
      happened: `We couldn't reach ${name} to sign in.`,
      next: "Check that it is turned on and on the network, then try again. If this server can't reach it, install from the host instead.",
      fix: "install-command", tone: "danger",
    };
    case "mesh-policy": return {
      title: `This server can't connect to ${name}`,
      happened: `${name} is on your network, but this server can't open a connection to it. A network access rule may be blocking it.`,
      next: "Ask whoever manages your network to let this server connect to it, then try again.",
      fix: "retry", tone: "danger",
    };
    case "host-key": return {
      title: `${name} needs your OK`,
      happened: `${name} showed a security key this server hasn't seen before.`,
      next: "Compare the fingerprint with the one on the host before you trust it.",
      fix: failure.fingerprints?.length ? "host-key" : "retry", tone: "danger",
    };
    case "auth": return failure.choose_method ? {
      title: `Couldn't sign in to ${name}`,
      happened: "The sign-in methods tried so far didn't get in.",
      next: "Choose another way to sign in, or give this server's key to the host.",
      fix: "choose-method", tone: "danger",
    } : {
      title: `${name} turned the sign-in down`,
      happened: `${name} answered but wouldn't accept how this server signed in.`,
      next: "Try again, or choose another way to sign in.",
      fix: "choose-method", tone: "danger",
    };
    case "unsupported": return {
      title: `${name} can't run the infraternal agent yet`,
      happened: "This host is missing something the infraternal agent needs.",
      next: "Use a Linux host (Intel, AMD or ARM) with systemd, then add it again.",
      fix: "none",
      tone: "danger",
    };
    case "stale_previous_attempt":
      if (failure.setup_lock?.active === false) {
        const lock = failure.setup_lock;
        // D335: another server enrolled this machine; it can join this one as a new host.
        if (lock.enrolled_with !== undefined) return {
          title: `${name} is enrolled with another server`,
          happened: `${lock.enrolled_with ? `It belongs to ${lock.enrolled_with}. ` : ""}Join it to this server as a new host with a new key. Its old infraternal agent is stopped and set aside, not deleted.`,
          next: sessionsLine(lock),
          fix: "replace-stuck-install",
          tone: "info",
        };
        return {
          title: "A stuck infraternal agent was found on " + name,
          happened: setupLockLine(lock, false),
          next: sessionsLine(lock),
          fix: "replace-stuck-install",
          tone: "info",
        };
      }
      return {
        title: "This host has leftovers from an earlier setup",
        happened: "infraternal didn't finish setting up here before. Start fresh to remove what it left behind and continue.",
        next: "",
        fix: "start-fresh",
        tone: "info",
      };
    case "setup_running": return {
      title: failure.setup_lock ? "Setup is running on " + failure.setup_lock.machine : "Setup is already running on this host",
      happened: failure.setup_lock ? setupLockLine(failure.setup_lock, true) : failure.message,
      next: failure.setup_lock ? "Wait for it to finish. If it stays stuck, replace the stuck install." : "Another setup for this host hasn't finished. Wait for it, or try again in a moment.",
      fix: "retry",
      tone: "info",
    };
    case "install": return {
      title: `Setting up ${name} didn't finish`,
      happened: failure.failed_step ? failureLine(failure) : "Setup stopped before this host was ready.",
      next: failure.missing_binary ? "Add the file on the server, then try again." : failure.failed_step ? STEP_ADVICE[failure.failed_step] : GENERIC_ADVICE,
      fix: "retry", tone: "danger",
    };
    default: return {
      title: `Something went wrong with ${name}`,
      happened: "Something went wrong while setting up this host.",
      next: "Try again.",
      fix: "retry", tone: "danger",
    };
  }
}

export interface ParsedTarget { user: string | undefined; host: string; port: number | undefined }

/**
 * Parses `user@host[:port]`; undefined for text that cannot name a host. A pasted `ssh://user@host:port` address or
 * `ssh [-p port] [-l user] [user@]host` command is normalised into the same fields. Only those two options are
 * read: any other option (`-o…`, `-J`, `-i`) or trailing remote command is refused rather than guessed at.
 */
export function parseTarget(raw: string): ParsedTarget | undefined {
  const text = raw.trim();
  if (/^ssh:\/\//i.test(text)) return parseDestination(text.slice(6).replace(/\/$/, ""));
  if (!/^ssh\s/i.test(text)) return parseDestination(text);
  let port: string | undefined;
  let login: string | undefined;
  const rest: string[] = [];
  const words = text.split(/\s+/).slice(1);
  for (let i = 0; i < words.length; i++) {
    const word = words[i]!;
    const flag = /^-([pl])(.*)$/.exec(word);
    if (flag) {
      const value = flag[2] || words[++i];
      if (value === undefined) return undefined;
      if (flag[1] === "p") port = value; else login = value;
    } else if (word.startsWith("-")) return undefined;
    else rest.push(word);
  }
  if (rest.length !== 1) return undefined;
  const target = parseDestination(rest[0]!);
  if (!target) return undefined;
  if (port !== undefined) {
    if (target.port !== undefined || !/^\d{1,5}$/.test(port)) return undefined;
    target.port = Number(port);
    if (target.port < 1 || target.port > 65535) return undefined;
  }
  if (login !== undefined) {
    if (target.user !== undefined || !parseDestination(`${login}@x`)) return undefined;
    target.user = login;
  }
  return target;
}

function parseDestination(raw: string): ParsedTarget | undefined {
  const match = /^(?:([a-z_][a-z0-9_.-]*)@)?([a-z0-9][a-z0-9.-]*|\[[0-9a-f:]+\])(?::(\d{1,5}))?$/i.exec(raw);
  if (!match) return undefined;
  const port = match[3] ? Number(match[3]) : undefined;
  if (port !== undefined && (port < 1 || port > 65535)) return undefined;
  const host = match[2]!.toLowerCase();
  if (host.startsWith("[")) {
    // Validate the complete IPv6 address using the browser's URL parser. A
    // hexadecimal-looking bracketed string alone is insufficient proof.
    try { new URL(`http://${host}/`); } catch { return undefined; }
  }
  return { user: match[1], host, port };
}

/**
 * How a typed target relates to the listed hosts. `named` is the listed host it names (by id or address). `prefixed`
 * is true when other hosts' names start with the same text: while the person is still typing, such a token waits
 * for a delimiter instead of chipping at the first match.
 */
export function matchListed<T extends { id: string; address: string }>(target: ParsedTarget, hosts: readonly T[]): { named: T | undefined; prefixed: boolean } {
  const named = hosts.find((host) => host.id === target.host || host.address === target.host);
  return { named, prefixed: hosts.some((host) => host !== named && host.id.startsWith(target.host)) };
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

/** Details retain diagnostic evidence once, excluding sentences already displayed in the failure card. */
export function failureDiagnostics(failure: FailureDetail | undefined, guide: Guide): string[] {
  // The server's sentence for a duplicate says what the page already says; there is nothing more to show.
  if (!failure || failure.already_added) return [];
  const visible = `${guide.happened} ${guide.next}`;
  const evidence = [failure.kind !== "stale_previous_attempt" ? failure.message : "", ...failure.log_tail];
  return [...new Set(evidence.filter((line) => line && !visible.includes(line)))];
}
