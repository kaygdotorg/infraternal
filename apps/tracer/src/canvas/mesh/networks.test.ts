/** The words of subnet routes (D197 M3, #580): every sentence says what happens, in plain words, with no route numbers. */
import { describe, expect, test } from "bun:test";
import { networkSub, refusalWords, revokeConfirm, type MeshNetwork } from "./networks";

/** An approved network the word tests ask about. */
const approved: MeshNetwork = { id: "net:4", routeId: 4, nodeId: 1, cidr: "192.168.10.0/24", router: "build-01", state: "approved", advertised: true, keepSource: false };

describe("networks", () => {
  test("the server's refusals become the owner's words, without route numbers", () => {
    const overlap = refusalWords("192.168.0.0/16 overlaps 192.168.10.0/24, which is already approved (route 4); revoke that one first or pick a network that does not overlap");
    expect(overlap).toEqual({ short: "Overlaps 192.168.10.0/24", sentence: "192.168.0.0/16 overlaps 192.168.10.0/24, which is already approved. Revoke that one first, or have the machine advertise a network that does not overlap." });
    expect(refusalWords("10.0.0.0/8 overlaps the mesh's own range 10.254.0.0/16; pick a network outside it").short).toBe("Overlaps the mesh");
    expect(refusalWords("127.0.0.0/8 is loopback and is never routed through the mesh")).toEqual({ short: "Never routed", sentence: "127.0.0.0/8 is loopback and is never routed through the mesh." });
    expect(refusalWords("something new (route 9)").sentence).toBe("Something new.");
  });

  test("the revoke question names the network and says how many arrows go", () => {
    expect(revokeConfirm(approved, 3).title).toBe("Stop routing 192.168.10.0/24?");
    expect(revokeConfirm(approved, 3).effect).toContain("The 3 arrows that end on it are deleted.");
    expect(revokeConfirm(approved, 1).effect).toContain("The 1 arrow that ends on it is deleted.");
    expect(revokeConfirm(approved, 0).effect).toContain("No arrow ends on it.");
  });

  test("a card says what the network's machines see, or why it waits", () => {
    expect(networkSub(approved)).toBe("Appears as build-01");
    expect(networkSub({ ...approved, keepSource: true })).toBe("Keeps each machine's own address");
    expect(networkSub({ ...approved, advertised: false })).toBe("build-01 stopped offering it");
    expect(networkSub({ ...approved, state: "pending", refusal: { short: "Overlaps 10.0.0.0/8", sentence: "" } })).toBe("Overlaps 10.0.0.0/8");
  });
});
