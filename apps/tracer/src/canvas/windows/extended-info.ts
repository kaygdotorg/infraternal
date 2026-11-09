/**
 * "Extended machine info" (Settings -> Appearance): whether the details popover's machine tab adds the technical facts
 * (init, virtualization, shell, locale, how it is reached) to the default ones (D126, D156). Off by default. It belongs to the account's canvas look
 * (D352); it applies the next time a tab is shown, so a popover that is already open follows on its next tab press.
 */
import { readLocal, writeLocal } from "../../../../../packages/ui/src/local-pref";
import { lookBridge } from "../themes/controller";

/** Dispatched on `window` by `writeExtendedInfo`, so open details can follow. */
export const EXTENDED_INFO_EVENT = "tracer:extended-info";
/** The local-storage key of the setting. */
const KEY = "tracer.extended-info";

/** True when the account turned extended machine info on. Off by default. */
export const readExtendedInfo = (): boolean => lookBridge()?.extendedInfo() ?? readLocal(KEY) === "1";

/** Saves through the account look when active, then fires `EXTENDED_INFO_EVENT`. */
export function writeExtendedInfo(on: boolean): void {
  const bridge = lookBridge();
  if (bridge) bridge.setExtendedInfo(on);
  else writeLocal(KEY, on ? "1" : "0");
  window.dispatchEvent(new CustomEvent(EXTENDED_INFO_EVENT));
}
