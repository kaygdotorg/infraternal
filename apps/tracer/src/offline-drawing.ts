/** Validates the public drawing cache before an offline screen reuses its labels (D245). */
import { canvasKey, drawingIdentityKey, lastAccountKey, readStoredJson } from "./account-storage";
import { isCanonicalUuid } from "./identifiers";
import { readLayoutCache } from "./canvas/model/cache";
export interface DrawingIdentity { user_id: string; username?: string; display_name?: string; hostname?: unknown; recovery_pending?: { ready_at: number } | null }

export async function cachedDrawingIdentity(): Promise<DrawingIdentity | undefined> {
  try {
    const account = localStorage.getItem(lastAccountKey);
    if (!isCanonicalUuid(account)) return undefined;
    const canvas = readStoredJson(canvasKey(account));
    if (!readLayoutCache(canvas)) return undefined;
    const value = readStoredJson(drawingIdentityKey(account));
    if (!value || typeof value !== "object") return undefined;
    const row = value as Record<string, unknown>;
    if (row.user_id !== account || typeof row.hostname !== "string" || !row.hostname.trim() || row.hostname.length > 200) return undefined;
    return { user_id: account, hostname: row.hostname, ...(typeof row.username === "string" ? { username: row.username } : {}), ...(typeof row.display_name === "string" ? { display_name: row.display_name } : {}) };
  } catch { return undefined; }
}
