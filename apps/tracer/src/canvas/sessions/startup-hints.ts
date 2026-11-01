/**
 * D315 startup offer and its saved switches; file changes always go through confirmation.
 *
 * When a multiplexer (tmux, Zellij) starts by itself in a new terminal, one quiet notice asks whether to switch
 * to the Infraternal Multiplexer instead (owner wording, #251). Three icon choices: ✓ switch (after a
 * confirmation, with a restoring undo), ✗ keep the other multiplexer, ? the docs page. Switching adds the
 * guard line `[ -n "$INFRATERNAL_SESSION" ] || <command>` to the startup file; the copy never says "guard".
 * The server shows the offer once per host, so ✗ needs no write of its own; the switches live in Settings.
 */
import type { ToastController, ToastMessage } from "../../../../../packages/ui/src/toast";
import { mountConfirmTip } from "../../../../../packages/ui/src/tooltip";
import { ICON_CHECK, ICON_HELP, ICON_X, ICONS } from "../../../../../packages/ui/src/icons";
import type { SwitchPref } from "../../../../../packages/ui/src/settings-panels";

interface Connection {
  call(action: string, input: Record<string, unknown>): Promise<Record<string, unknown>>;
  onWelcome(listener: () => void): () => void;
  readonly isWelcomed: boolean;
}

/** The page about our multiplexer on the public docs site (D44, D223: infraternal.com/docs). Source: docs/multiplexer.md. */
export const MULTIPLEXER_DOCS_URL = "https://infraternal.com/docs/multiplexer";
const MULTIPLEXER_NAMES: Record<string, string> = { tmux: "tmux", zellij: "Zellij" };
/** The name people know the program by; an unknown future one shows as the server reports it. */
export const multiplexerName = (id: string): string => MULTIPLEXER_NAMES[id] ?? id;

export interface StartupHintOptions {
  /** Where ? goes; a mockup points it at its own rendered copy of the page. */
  docsUrl?: string;
  /** Opens the docs; the default is a new tab that cannot reach back into this one. */
  openDocs?: (url: string) => void;
}
export function createStartupHints(connection: Connection, toast: ToastController, confirm = mountConfirmTip, options: StartupHintOptions = {}) {
  const docsUrl = options.docsUrl ?? MULTIPLEXER_DOCS_URL;
  const openDocs = options.openDocs ?? ((url: string) => { window.open(url, "_blank", "noopener,noreferrer"); });
  let disposed = false;
  let globalEnabled = true;
  let revision = 0;
  let pendingWrites = 0;
  let writes = Promise.resolve();
  let tip: ReturnType<typeof mountConfirmTip> | undefined;
  const hosts = new Map<string, { name: string; override?: boolean }>();
  const listeners = new Set<() => void>();
  const publish = () => { if (!disposed) for (const listener of listeners) listener(); };
  const call = (input: Record<string, unknown>) => connection.call("terminal.startup", input);
  const failure = () => { if (!disposed) toast.show({ message: "Could not change the startup file. It may have changed; try again.", tone: "error" }); };
  const refresh = async (): Promise<void> => {
    const at = revision;
    const entries = [...hosts];
    try {
      const [account, ...values] = await Promise.all([call({ op: "get" }), ...entries.map(([id]) => call({ op: "get", ...(id ? { host_id: id } : {}) }))]);
      if (disposed || at !== revision || pendingWrites) return;
      if (typeof account?.global_enabled === "boolean") globalEnabled = account.global_enabled;
      entries.forEach(([, host], i) => { const value = values[i]?.host_override; if (typeof value === "boolean") host.override = value; else delete host.override; });
      publish();
    } catch { /* Welcome and the next Settings visit retry; terminals never wait on hints. */ }
  };
  const set = (on: boolean, host?: string, global = true): Promise<void> => {
    revision++;
    pendingWrites++;
    const saved = writes.then(async () => { await call({ op: "set", global, enabled: on, ...(host ? { host_id: host } : {}) }); });
    writes = saved.catch(() => {}).then(async () => { if (--pendingWrites === 0) await refresh(); });
    return writes.then(() => saved);
  };
  const offWelcome = connection.onWelcome(() => { void refresh(); });
  if (connection.isWelcomed) void refresh();
  return {
    async inspect(session: string, host?: string, name = "This host"): Promise<void> {
      if (disposed) return;
      if (!hosts.has(host ?? "")) { hosts.set(host ?? "", { name }); publish(); void refresh(); }
      try {
        const result = await call({ op: "inspect", session });
        if (disposed || !["tmux", "zellij"].includes(String(result.multiplexer))) return;
        const proposal = result.proposal as { file: string; guard: string } | undefined;
        const other = multiplexerName(String(result.multiplexer));
        const line = proposal?.guard ?? `[ -n "$INFRATERNAL_SESSION" ] || ${result.multiplexer}`;
        const change = async (op: "apply" | "undo"): Promise<void> => {
          try {
            await call({ op, session, proposal, confirmed: true });
            if (!disposed) toast.show(op === "apply"
              ? { message: `Switched. ${other} no longer starts in Infraternal terminals (changed ${proposal?.file}).`,
                  action: { label: `Restore ${proposal?.file}`, onSelect: () => { void change("undo"); } }, duration: 0, dismissible: true }
              : { message: `${proposal?.file} restored. ${other} starts automatically again.` });
          } catch { failure(); }
        };
        // ✓: with a recognised startup line the file is edited after a confirmation; otherwise the person gets the line to place themselves.
        const switchChoice = (event?: MouseEvent): void => {
          if (!proposal) {
            void navigator.clipboard.writeText(line).then(() => { if (!disposed) toast.show({ message: `Copied the line that switches. Add it before ${other} starts in your startup file.` }); }, failure);
            return;
          }
          const anchor = event?.currentTarget as HTMLElement | undefined;
          if (disposed || !anchor) return;
          const sentence = `${other} will stop starting in Infraternal terminals. This terminal keeps running, and you can undo it.`;
          tip = confirm(anchor, { label: "Switch to the Infraternal Multiplexer", title: `Switch to the Infraternal Multiplexer in ${proposal.file}?`,
            // The line sits on its own row: the confirmation keeps a line break in its effect text.
            effect: `${proposal.guard}\n${sentence}`,
            confirmLabel: "Switch", cancelLabel: "Keep as is", onConfirm: () => { void change("apply"); },
            onCancel: () => { if (!disposed) toast.show(notice); },
          });
        };
        const notice: ToastMessage = { message: `${other} started automatically. Would you like to switch to the Infraternal Multiplexer instead?`,
          icon: ICONS.terminal, duration: 0, actionGroupLabel: "Switch to the Infraternal Multiplexer?",
          iconActions: [
            { label: proposal ? "Switch to the Infraternal Multiplexer" : "Copy the line that switches", icon: ICON_CHECK, onSelect: switchChoice },
            { label: `Keep ${other}, don't ask again on this host`, icon: ICON_X, onSelect() {} },
            { label: "About the Infraternal Multiplexer", icon: ICON_HELP, keepOpen: true, onSelect: () => { openDocs(docsUrl); } },
          ],
        };
        toast.show(notice);
      } catch { /* Detection fails open: shell startup is always the person's own startup. */ }
    },
    set,
    enabled: () => globalEnabled,
    switches(): SwitchPref[] {
      const save = (on: boolean, host?: string, global = true) => { void set(on, host, global).catch(() => { if (!disposed) toast.show({ message: "Could not save startup hints. Try again.", tone: "error" }); }); };
      return [{ id: "startup-hints", title: "Multiplexer", label: "Offer the Infraternal Multiplexer", hint: "When tmux or Zellij starts by itself in a terminal", get: () => globalEnabled, set: (on) => save(on), onChange: this.onChange },
        ...[...hosts].map(([id, host]) => ({ id: `startup-${id || "local"}`, title: host.name, label: "Offer the Infraternal Multiplexer", hint: "Only for this host", get: () => host.override ?? globalEnabled, set: (on: boolean) => save(on, id || undefined, false), onChange: this.onChange }))];
    },
    refresh,
    onChange(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    dispose() { disposed = true; offWelcome(); tip?.close(false); listeners.clear(); },
  };
}

export type StartupHints = ReturnType<typeof createStartupHints>;
