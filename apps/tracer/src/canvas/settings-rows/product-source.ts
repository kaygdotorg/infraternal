// SPDX-License-Identifier: AGPL-3.0-only
/**
 * What the product backs in the Settings rows (issue #304), and nothing else. A setting appears in the table (`catalog.ts`) before
 * the server can store it; it gets a control here only once something real stands behind it. Today that is one server setting,
 * how long an API key may go unused (`api_key_lifetime_days`, 1 to 365, owner only, changed with a fresh passkey), plus the
 * client-side panels (Appearance, Window sizes, Shortcuts, ...), which the table reuses and which need no backing here.
 *
 * The settings that wait for a server setting, each to be an issue of its own: connection-keys, machine-identity, renewal-window,
 * name-suffix, browser-session, add-link, join-code, install-mode, sign-in-account, join-mesh, renew-early, scrollback-lines,
 * multiplexer-offer; and the lists behind Updates, Access, Connections, Published Services and the Devices window.
 */
import { UNIT_MINUTES } from "../../../../../packages/ui/src/setting-value";
import type { SettingsSource } from "../views/settings-body.on-demand";
import { onDemand } from "../../on-demand";
import { createRowsSource } from "./source";

const DAY = UNIT_MINUTES.d;
const auth = () => onDemand(() => import("../../auth"));

const backing: NonNullable<SettingsSource["backing"]> = (id) => id !== "app-key" ? undefined : {
  read: async () => { const days = await (await auth()).readKeyLifetime(); return days === undefined ? undefined : days * DAY; },
  write: async (value) => {
    const days = Number(value) / DAY;
    // The server stores whole days; the row has already checked the range.
    if (!Number.isInteger(days)) return "Use whole days. Still using the old value.";
    const { writeKeyLifetime } = await auth();
    const { deviceName } = await onDemand(() => import("../../onboarding"));
    await writeKeyLifetime(days, deviceName());
  },
};

/** The licences are facts of the product itself, not of a server. */
const data: NonNullable<SettingsSource["data"]> = (component, group) => component === "about" && group === "licences"
  ? { facts: [{ title: "infraternal", rows: [{ key: "Licence", value: "AGPL-3.0-only" }, { key: "Commercial Features", value: "separate licence" }] }] }
  : undefined;

/** The rows of Settings with what the product can store. `admin` is whether the viewer sees the administrator rows. */
export const createProductRows = (admin: () => boolean) => createRowsSource({ admin, backing, data });
