/** Tests of the names the canvas gives the grants it draws: the server must accept them as they are (#580). */
import { describe, expect, test } from "bun:test";
import { derivedGrantName, grantSentence } from "./source";

/** The server's own rule (`validate_name` in crates/plugins/mesh/src/api.rs). */
const SERVER_NAME = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

describe("derived grant names", () => {
  test("are names the server accepts, for hosts, tags and networks", () => {
    for (const [from, to] of [["build-01", "edge-arm"], ["tag:ops", "nix-cache"], ["tag:ci", "net:12"], ["Studio_Mac.local", "tag:ops"], ["a".repeat(60), "b".repeat(60)]] as const) {
      expect(derivedGrantName(from, to)).toMatch(SERVER_NAME);
    }
    expect(derivedGrantName("tag:ops", "build-01")).toBe("ops-to-build-01");
    expect(derivedGrantName("tag:ci", "net:12")).toBe("ci-to-net-12");
  });

  test("an arrow nobody named still reads as a sentence", () => {
    expect(grantSentence({ id: "g1", from: "build-01", to: "edge-arm", name: derivedGrantName("build-01", "edge-arm"), auto: true })).toBe("build-01 can reach edge-arm");
  });
});
