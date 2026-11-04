// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Stand-ins for the quick facts the docs build will put in `index.json` (issue #304; the build is the docs job's, #302). The contract is
 * `> [!FACTS]` under a heading: a few short sentences (the first is the lead, the rest are bullets), at most 320 characters, and optionally a small table.
 * The docs build reads that block now, but a few headings the windows point at have none yet, so those are filled in here, in that shape, with
 * what the page says today. The preview uses the index's `facts` when it has them and these only when it has not: once the docs build
 * ships quick facts, this file is deleted and nothing else changes.
 */
export interface StandIn { facts: string; factsTable?: { head: string[]; rows: string[][] } }

export const STAND_IN: Readonly<Record<string, StandIn>> = {
  "reference/keys#passkey": { facts: "A key pair on your device. The private half never leaves it, and Infraternal never sees it. It does not expire, and you can have two." },
  "reference/keys#recovery-words": { facts: "24 words that bring you back in if you lose your passkeys. They do not expire, and only you hold them. A finished recovery signs out everything and gives you new words." },
  "reference/keys#host-join-token": { facts: "Lasts 15 minutes and works once. A faulty request does not use it up. Adding the host again replaces it." },
  "reference/keys#all-keys-at-a-glance": {
    facts: "Most keys renew by themselves while a host is online. The ones you handle yourself are your passkey, your recovery words and the short codes.",
    factsTable: { head: ["Key", "Lasts", "Renewed"], rows: [["Browser sign-in", "30 days", "With use"], ["Host join token", "15 minutes", "No, one use"], ["Host certificate", "7 days", "At 3.5 days"]] },
  },
};
