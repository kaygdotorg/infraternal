// SPDX-License-Identifier: AGPL-3.0-only
/** Break-it review of the already-added outcome (#189): the page must still hand over a next step when no id arrives. */
import { expect, test } from "bun:test";
import { failureDiagnostics, guideFor } from "./model";

test("an already-added failure without a host id (older server) still says how to reach the terminal", () => {
  // A web-only deploy can run this page against a server that predates `host_id`: no "Open a terminal" button
  // renders, Details are hidden and the only control is Back, so the copy must carry the route itself.
  const failure = { kind: "install" as const, message: "This host is already added. Open its terminal from Console.", log_tail: [], already_added: true };
  const guide = guideFor("worker", failure);
  expect(failureDiagnostics(failure, guide)).toEqual([]);
  expect(`${guide.happened} ${guide.next}`).toMatch(/terminal/i);
});
