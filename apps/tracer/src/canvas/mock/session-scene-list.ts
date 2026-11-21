/**
 * The session mockup scenes' list: what the palette shows for them. It is a plain list so the palette never loads the scenes' code.
 */

/** The sessions scenes' names and hints, for the palette; their code (session-scenes.on-demand.ts) loads when one runs. */
/** The numbers are the owner's review numbers (#104), not positions: a scene that shipped as real product leaves a gap. */
export const SESSION_SCENES: Array<{ n: number; title: string; hint: string }> = [
  { n: 1, title: "Session manager", hint: "grouped by state, by frecency" },
  { n: 2, title: "Sidebar inventory", hint: "open, detached, exited · markers" },
  { n: 3, title: "Exited session", hint: "final screen · Run again · Dismiss" },
  { n: 4, title: "Close keeps it running", hint: "detached · toast · Reopen" },
  { n: 5, title: "End a session", hint: "names what is running" },
  { n: 6, title: "Splits", hint: "right, then down · a fade" },
  { n: 7, title: "Sized for another device", hint: "scaled to fit · type to take over" },
  { n: 8, title: "Only one session", hint: "empty manager" },
  { n: 9, title: "Loading sessions", hint: "slow host" },
  { n: 10, title: "Sessions unavailable", hint: "error · Try again" },
  // Scene 11 (the D315 guard line) shipped as real product, so it has no mock; the numbers stay the ones the owner reviewed.
  { n: 12, title: "Opened by an AI tool", hint: "window with the tool's note (D304)" },
];
