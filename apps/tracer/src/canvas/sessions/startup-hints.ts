/** D315 startup notices and saved hint switches; file changes always go through confirmation. */
import type { ToastController, ToastMessage } from "../../../../../packages/ui/src/toast";
import { mountConfirmTip } from "../../../../../packages/ui/src/tooltip";
import { ICON_INFO } from "../../../../../packages/ui/src/icons";
import type { SwitchPref } from "../../../../../packages/ui/src/settings-panels";

interface Connection {
  call(action: string, input: Record<string, unknown>): Promise<Record<string, unknown>>;
  onWelcome(listener: () => void): () => void;
  readonly isWelcomed: boolean;
}
export function createStartupHints(connection: Connection, toast: ToastController, confirm = mountConfirmTip) {
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
        const guard = proposal?.guard ?? `[ -n "$INFRATERNAL_SESSION" ] || ${result.multiplexer}`;
        const copy = { label: "Copy guard", onSelect: () => { void navigator.clipboard.writeText(guard).then(() => { if (!disposed) toast.show({ message: "Guard copied." }); }, failure); } };
        const change = async (op: "apply" | "undo"): Promise<void> => {
          try {
            await call({ op, session, proposal, confirmed: true });
            if (!disposed) toast.show({ message: op === "apply" ? `Guard added to ${proposal?.file}.` : `Guard removed from ${proposal?.file}.`,
              ...(op === "apply" ? { action: { label: "Remove guard", onSelect: () => { void change("undo"); } }, duration: 0, dismissible: true } : {}),
            });
          } catch { failure(); }
        };
        const notice: ToastMessage = { message: `${result.multiplexer} started${proposal ? ` from ${proposal.file}` : " during shell startup"}.`,
          icon: ICON_INFO, duration: 0, dismissible: true,
          action: proposal ? { label: "Add guard", onSelect: (event) => {
            const anchor = event?.currentTarget as HTMLElement | undefined;
            if (disposed || !anchor) return;
            tip = confirm(anchor, { label: "Guard terminal startup", title: `Add this guard to ${proposal.file}?`,
              effect: `${proposal.guard}\n${result.multiplexer} will start only outside infraternal. This session keeps running.`,
              confirmLabel: "Add guard", cancelLabel: "Keep file", onConfirm: () => { void change("apply"); },
              onCancel: () => { if (!disposed) toast.show(notice); },
            });
          } } : copy,
          ...(proposal ? { secondaryAction: copy } : {}),
        };
        toast.show(notice);
      } catch { /* Detection fails open: shell startup is always the person's own startup. */ }
    },
    set,
    enabled: () => globalEnabled,
    switches(): SwitchPref[] {
      const save = (on: boolean, host?: string, global = true) => { void set(on, host, global).catch(() => { if (!disposed) toast.show({ message: "Could not save startup hints. Try again.", tone: "error" }); }); };
      return [{ id: "startup-hints", title: "Startup hints", label: "Show hints", hint: "Offer a guard when tmux or zellij starts with a shell", get: () => globalEnabled, set: (on) => save(on), onChange: this.onChange },
        ...[...hosts].map(([id, host]) => ({ id: `startup-${id || "local"}`, title: host.name, label: "Show startup hints", hint: "Only for this host", get: () => host.override ?? globalEnabled, set: (on: boolean) => save(on, id || undefined, false), onChange: this.onChange }))];
    },
    refresh,
    onChange(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    dispose() { disposed = true; offWelcome(); tip?.close(false); listeners.clear(); },
  };
}

export type StartupHints = ReturnType<typeof createStartupHints>;
