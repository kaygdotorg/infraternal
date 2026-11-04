// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Extra waiting items for the test double (`?inbox=3`): they exist to show that the inbox card is generic. Each is
 * only an icon, a title, a body and actions; the card draws all of them with the same row.
 */
import { ICONS } from "../../../../../packages/ui/src/icons";
import type { InboxItem } from "../../../../../packages/ui/src/inbox";

/** Two example waiting items for the inbox card (`?inbox=3`). Their buttons do nothing. */
export function mockInboxItems(): InboxItem[] {
  const noop = (): void => undefined;
  return [
    {
      id: "mock-approve-host", icon: ICONS.plus, title: "Approve build-02",
      body: "A new machine asked to join. Approving lets it connect to your other hosts.",
      actions: [{ label: "Dismiss", run: noop }, { label: "Approve", primary: true, run: noop }],
    },
    {
      id: "mock-update", icon: ICONS.overview, title: "Update available",
      body: "A newer infraternal agent is ready for 3 hosts. Updating restarts each host's agent once.",
      actions: [{ label: "Update", primary: true, run: noop }],
    },
  ];
}
