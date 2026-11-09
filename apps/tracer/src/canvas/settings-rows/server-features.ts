// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The server-feature switches in Settings (#146, D349): today one, "App Windows" (the server's `desktop` feature), under
 * Settings › Machines › App Windows.
 *
 * It uses the server's own feature switch, the owner actions `plugins.list` and `plugins.set_enabled`, over the canvas
 * connection, so the Settings row and any other caller change the same stored setting. The server lets the owner switch a
 * feature only within 15 minutes of a passkey sign-in. When it refuses, the row asks for the passkey once, reconnects so
 * the connection carries the fresh sign-in, and tries again; a second refusal is final and the row says so.
 */
import type { SettingBacking } from "../views/settings-outline";

/** What the switch needs from the canvas: the connection's action call and a way to reconnect after a fresh sign-in. */
export interface FeatureLink {
  call(actionId: string, input: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** Signs in again with a passkey (the server wants a recent one) and resolves once the connection is back. */
  confirmAndReconnect(): Promise<void>;
}

/** The server's name for the app-windows feature. */
const DESKTOP = "desktop";

/** The words the row shows when the switch could not be changed. */
export const SWITCH_REFUSED = "Only the owner can switch this, with a passkey. Still using the old value.";

/** Reads whether `plugin` is on, or `undefined` when this build has no such feature or the list could not be read. */
async function readFeature(link: FeatureLink, plugin: string): Promise<boolean | undefined> {
  const list = await link.call("plugins.list", {}).catch(() => undefined);
  const plugins = Array.isArray(list?.plugins) ? list.plugins as unknown[] : [];
  for (const entry of plugins) {
    if (!entry || typeof entry !== "object") continue;
    const row = entry as { descriptor?: { id?: unknown }; enabled?: unknown };
    if (row.descriptor?.id === plugin && typeof row.enabled === "boolean") return row.enabled;
  }
  return undefined;
}

/** The backing of the "App Windows" switch: on means people can open windows of a Mac's apps on the canvas. */
export function appWindowsBacking(link: FeatureLink): SettingBacking {
  const set = (enabled: boolean): Promise<unknown> => link.call("plugins.set_enabled", { plugin: DESKTOP, enabled });
  return {
    read: () => readFeature(link, DESKTOP),
    write: async (value) => {
      if (typeof value !== "boolean") return SWITCH_REFUSED;
      try {
        await set(value);
        return;
      } catch { /* most often a sign-in older than 15 minutes: confirm once, below */ }
      try {
        await link.confirmAndReconnect();
        await set(value);
      } catch {
        return SWITCH_REFUSED;
      }
    },
  };
}
