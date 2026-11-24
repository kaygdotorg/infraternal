/** Tests of the Inbox item an update raises. */
import { describe, expect, test } from "bun:test";
import { createUpdatesDouble } from "../mock/updates/double";
import { inboxItemFor } from "./notices";

describe("the Inbox item", () => {
  test("is titled Update ready · <version> and its one action is Update now", async () => {
    const double = createUpdatesDouble("ready");
    const item = inboxItemFor("0.5.0", 5, double, () => undefined);
    expect(item.title).toBe("Update ready · 0.5.0");
    expect(item.body).toContain("5 min");
    expect(item.actions.map((a) => a.label)).toEqual(["Update now"]);
    expect(item.actions[0]!.primary).toBe(true);
    item.actions[0]!.run();
    await Promise.resolve();
    expect(double.facts().state.kind).toBe("applying");
  });

  test("a refusal is said, not thrown", async () => {
    const double = createUpdatesDouble("ready");
    double.refuseNext("Only the owner can do this.");
    const said: string[] = [];
    inboxItemFor("0.5.0", 5, double, (m) => said.push(m)).actions[0]!.run();
    await new Promise((r) => setTimeout(r, 0));
    expect(said).toEqual(["Only the owner can do this."]);
  });
});
