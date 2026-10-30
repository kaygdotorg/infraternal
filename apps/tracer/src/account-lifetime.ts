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
