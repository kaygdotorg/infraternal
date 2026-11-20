/**
 * "Programs can copy to your clipboard" (Settings -> Terminal -> Hosts, D373): whether a copy that a program in the
 * terminal asks for (OSC 52, for example from a remote editor or a multiplexer) may land on the clipboard by itself
 * when its terminal is the one in use. On by default. When off, every such copy is offered behind a Copy action instead.
 * A device-local preference, stored like the other client preferences (`local-pref.ts`); the terminal reads it at the
 * moment of each copy, so a change applies to the very next one.
 */
import { readLocal, writeLocal } from "../../../packages/ui/src/local-pref";

/** Dispatched on `window` by `writeProgramCopy`, so an open Settings switch can follow. */
export const PROGRAM_COPY_EVENT = "tracer:program-copy";
/** The local-storage key of the setting. */
export const PROGRAM_COPY_KEY = "tracer.program-copy";

/** True unless the person turned program copies off in this browser. On by default. */
export const readProgramCopy = (): boolean => readLocal(PROGRAM_COPY_KEY) !== "0";

/** Saves the setting for this browser and fires `PROGRAM_COPY_EVENT`. */
export function writeProgramCopy(on: boolean): void {
  writeLocal(PROGRAM_COPY_KEY, on ? "1" : "0");
  window.dispatchEvent(new CustomEvent(PROGRAM_COPY_EVENT));
}
