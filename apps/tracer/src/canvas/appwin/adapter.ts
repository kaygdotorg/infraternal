/**
 * The seam between the canvas and the desktop streams (D207, D208): the canvas knows nothing of the wire. The product
 * supplies an adapter with a desktop-only `MuxConnection`; mockups supply none, and then the feature is simply not offered
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

/** What the canvas asks of the desktop streams. The product builds one with `createAppWindowsAdapter`; without one, app windows are not offered. */
export interface AppWindowsAdapter {
  readonly connection: StreamConnection;
  /** Wanted here and supported by the server. */
  available(): boolean;
  /** The server says it can stream, whether or not this browser wants it (the Settings switch is shown on this). */
  serverCan(): boolean;
  /** The Settings switch, remembered on this browser. */
  setWanted(on: boolean): void;
  /** The Settings switch's value. */
  readonly pref: boolean;
  /** Runs when either side of `available()` may have changed; returns the remover. */
  onChange(listener: () => void): () => void;
  /** Releases the desktop transport when the signed-in canvas goes away. */
  dispose(): void;
}

/**
 * Uses the terminal connection to learn the server's capability. The desktop connection opens on first use so a queued
 * WebSocket video message or icon reply cannot hold up terminal bytes on the same TCP connection. The desktop connection
 * stays available through preference changes so closing an app window can finish its source Stop.
 * `serverCan` reads the desktop-video bit of the capabilities the server sent in
 * its Hello (unknown counts as no). `available()` needs both that and the browser's wish (`appWindowsWanted`). `onChange` fires
 * when either may have changed.
 */
export function createAppWindowsAdapter(primary: MuxConnection, openDesktop: () => MuxConnection): AppWindowsAdapter {
  let desktop: MuxConnection | undefined;
  const serverCan = (): boolean => ((primary.serverCaps ?? 0n) & DESKTOP_VIDEO_CAP) !== 0n;
  return {
    get connection() { return desktop ??= openDesktop(); },
    serverCan,
    get pref() { return readAppWindowsPref(); },
    setWanted: writeAppWindowsPref,
    available: () => appWindowsWanted() && serverCan(),
    onChange(listener) {
      const offCaps = primary.onServerCaps(listener);
      window.addEventListener(APPWIN_EVENT, listener);
      return () => { offCaps(); window.removeEventListener(APPWIN_EVENT, listener); };
    },
    dispose() { desktop?.dispose(); },
  };
}
