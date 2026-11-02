// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Stand-ins for the quick facts the docs build will put in `index.json` (issue #304; the build is the docs job's, #302). The contract is
 * `> [!FACTS]` under a heading: a few short sentences (the first is the lead, the rest are bullets), at most 320 characters, and optionally a small table.
 * The mockup's own docs build does not read that block yet, so the headings the windows point at are filled in here, in that shape, with
 * what the page says today. The preview uses the index's `facts` when it has them and these only when it has not: once the docs build
 * ships quick facts, this file is deleted and nothing else changes.
 */
export interface StandIn { facts: string; factsTable?: { head: string[]; rows: string[][] } }

export const STAND_IN: Readonly<Record<string, StandIn>> = {
  "keys#browser-sign-in": { facts: "Lasts 30 days. Using Infraternal renews the server's copy. The cookie in your browser ends 30 days after you signed in." },
  "keys#passkey": { facts: "A key pair on your device. The private half never leaves it, and Infraternal never sees it. It does not expire, and you can have two." },
  "keys#recovery-words": { facts: "24 words that bring you back in if you lose your passkeys. They do not expire, and only you hold them. A finished recovery signs out everything and gives you new words." },
  "keys#cli-sign-in-api-key": { facts: "Lasts 30 days without use, from 1 to 365 days. Using it renews it silently. An expired key needs a new sign-in, and revoking one works at once." },
  "keys#host-join-token": { facts: "Lasts 15 minutes and works once. A faulty request does not use it up. Adding the host again replaces it." },
  "keys#host-certificate": { facts: "Lasts 7 days. Renewed by itself at 3.5 days while the host is online. A host that stays offline for more than 7 days must be added again." },
  "keys#wireguard-session-keys": {
    facts: "A new session key about every 2 minutes, made by WireGuard itself. You do nothing. Two nodes that cannot reach each other have no session until they can.",
    factsTable: { head: ["Key", "Lasts", "Renewed"], rows: [["Session keys", "About 2 minutes", "By WireGuard"], ["Static key", "7 days (planned)", "With overlap"], ["Identity key", "7 days (planned)", "Signed by the old one"]] },
  },
  "keys#at-a-glance": {
    facts: "Most keys renew by themselves while a host is online. The ones you handle yourself are your passkey, your recovery words and the short codes.",
    factsTable: { head: ["Key", "Lasts", "Renewed"], rows: [["Browser sign-in", "30 days", "With use"], ["Host join token", "15 minutes", "No, one use"], ["Host certificate", "7 days", "At 3.5 days"]] },
  },
  "multiplexer#what-it-does-for-you": { facts: "Every terminal is a session that keeps running on its host. Close the tab, lose the connection or upgrade Infraternal: the shell goes on." },
};
