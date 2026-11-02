/**
 * The seam between the canvas and the desktop streams (D207, D208): the canvas knows nothing of the wire. The product
 * supplies one adapter over its single `MuxConnection`; mockups supply none, and then the feature is simply not offered
 * (the rule of the canvas: a feature whose adapter is missing is not drawn at all).
 *
 * `available()` is the whole gate. It is true only when the browser wants app windows (the preview door or the Settings
 * switch, `flag.ts`) and the server has said it can stream (the desktop bit of its Hello). Both can change while the page
 * is open, so `onChange` tells the canvas, which then loads the feature's code (only then; D188) or lets it go quiet.
 */
import type { MuxConnection } from "../../connection";
import { DESKTOP_VIDEO_CAP } from "../../connection";
import { APPWIN_EVENT, appWindowsWanted, readAppWindowsPref, writeAppWindowsPref } from "./flag";

/** The part of the connection a stream uses. */
export type StreamConnection = Pick<MuxConnection, "call" | "openStream" | "closeStream" | "send" | "isWelcomed" | "onWelcome">;

export interface AppWindowsAdapter {
  readonly connection: StreamConnection;
  /** Wanted here and supported by the server. */
  available(): boolean;
  /** The server says it can stream, whether or not this browser wants it (the Settings switch is shown on this). */
  serverCan(): boolean;
  /** The Settings switch: remembered on this browser. Turning it on reconnects once, because the capability is declared when a socket opens. */
  setWanted(on: boolean): void;
  /** The Settings switch's value. */
  readonly pref: boolean;
  /** Runs when either side of `available()` may have changed; returns the remover. */
  onChange(listener: () => void): () => void;
}

export function createAppWindowsAdapter(connection: MuxConnection): AppWindowsAdapter {
  const serverCan = (): boolean => ((connection.serverCaps ?? 0n) & DESKTOP_VIDEO_CAP) !== 0n;
  return {
    connection,
    serverCan,
    get pref() { return readAppWindowsPref(); },
    setWanted(on) {
      const before = appWindowsWanted();
      writeAppWindowsPref(on);
      // A socket declares its capabilities in its Hello. One opened before the switch did not, so it reconnects once (a resume:
      // the terminals keep their screens), and only when the feature was not already wanted for another reason.
      if (on && !before && serverCan()) connection.forceDrop();
    },
    available: () => appWindowsWanted() && serverCan(),
    onChange(listener) {
      const offCaps = connection.onServerCaps(listener);
      window.addEventListener(APPWIN_EVENT, listener);
      return () => { offCaps(); window.removeEventListener(APPWIN_EVENT, listener); };
    },
  };
}
