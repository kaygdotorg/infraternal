/**
 * The session mockup scenes' list: what the palette shows for them. It is a plain list so the palette never loads the scenes' code.
 */

/** The sessions scenes' names and hints, for the palette; their code (session-scenes.on-demand.ts) loads when one runs. */
export const SESSION_SCENES: Array<{ title: string; hint: string }> = [
  { title: "Session manager", hint: "grouped by state, by frecency" },
  { title: "Sidebar inventory", hint: "open, detached, exited · markers" },
  { title: "Exited session", hint: "final screen · Run again · Dismiss" },
  { title: "Close keeps it running", hint: "detached · toast · Reopen" },
  { title: "End a session", hint: "names what is running" },
  { title: "Splits", hint: "right, then down · a fade" },
  { title: "Sized for another device", hint: "scaled to fit · type to take over" },
  { title: "Only one session", hint: "empty manager" },
  { title: "Loading sessions", hint: "slow host" },
  { title: "Sessions unavailable", hint: "error · Try again" },
];
