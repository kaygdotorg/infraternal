/** Authenticated display identity stays in RAM; cold offline startup never reads private drawing caches (D312). */
export interface DrawingIdentity { user_id: string; username?: string; display_name?: string; hostname?: unknown; recovery_pending?: { ready_at: number } | null }
