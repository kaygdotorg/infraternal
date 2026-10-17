/**
 * "Extended machine info" (Settings -> Appearance): whether the details popover's machine tab adds the technical facts
 * (init, virtualization, shell, locale, how it is reached) to the default ones (D126, D156). Off by default. A device-local preference like the theme and the
 * window sizes; it applies the next time a tab is shown, so a popover that is already open follows on its next tab press.
 */
import { readLocal, writeLocal } from "../../../../../packages/ui/src/local-pref";

export const EXTENDED_INFO_EVENT = "tracer:extended-info";
const KEY = "tracer.extended-info";

export const readExtendedInfo = (): boolean => readLocal(KEY) === "1";

export function writeExtendedInfo(on: boolean): void {
  writeLocal(KEY, on ? "1" : "0");
  window.dispatchEvent(new CustomEvent(EXTENDED_INFO_EVENT));
}
