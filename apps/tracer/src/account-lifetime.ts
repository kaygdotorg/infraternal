/** Session-owned callbacks stay in RAM and can be frozen during logout, then permanently forgotten (D312). */
interface Work { pause(value: boolean): void; dispose(): void }
const accounts = new Map<string, Set<Work>>();
export function registerAccountWork(account: string, work: Work): () => void {
  let set = accounts.get(account); if (!set) accounts.set(account, set = new Set());
  set.add(work);
  return () => { set.delete(work); if (!set.size) accounts.delete(account); };
}
export function pauseAccountWork(account: string | undefined, value: boolean): void {
  if (account) for (const work of accounts.get(account) ?? []) work.pause(value);
}
export function forgetAccountWork(account: string | undefined): void {
  for (const [id, set] of accounts) if (account === undefined || id === account) {
    for (const work of [...set]) work.dispose(); accounts.delete(id);
  }
}

/** Accelerate confirmed logout/re-login teardown without a durable marker or any cross-tab queue adoption. */
export function sessionNotifications(onForget: (account: string, before: number) => void) {
  let channel: BroadcastChannel | undefined;
  try { channel = new BroadcastChannel("infraternal.session-lifetime"); }
  catch { /* Server revocation and foreground authentication remain authoritative. */ }
  if (channel) channel.onmessage = (event: MessageEvent<unknown>) => {
    const value = event.data;
    if (!value || typeof value !== "object") return;
    const row = value as { account?: unknown; before?: unknown; type?: unknown };
    if (row.type === "forget" && typeof row.account === "string" && typeof row.before === "number" && Number.isFinite(row.before)) onForget(row.account, row.before);
  };
  return {
    forget(account: string) {
      try { channel?.postMessage({ type: "forget", account, before: performance.timeOrigin + performance.now() }); }
      catch { /* Notification is best effort; confirmed revocation must still tear down this tab. */ }
    },
    dispose() { if (channel) { channel.onmessage = null; channel.close(); channel = undefined; } },
  };
}
