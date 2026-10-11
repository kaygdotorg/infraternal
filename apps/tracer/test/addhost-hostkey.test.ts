/** Checks that host-key instructions name the same family the connection pins (#87). */
import { expect, test } from "bun:test";
import { hostKeyPresentation } from "../src/canvas/addhost/host-key";

test("the selected host-key family determines its label and comparison command", () => {
  for (const [type, label, file] of [
    ["ssh-ed25519", "ED25519", "ed25519"],
    ["ssh-rsa", "RSA", "rsa"],
    ["ecdsa-sha2-nistp256", "ECDSA", "ecdsa"],
  ] as const) {
    expect(hostKeyPresentation(type)).toEqual({ label, command: `ssh-keygen -lf /etc/ssh/ssh_host_${file}_key.pub` });
  }
});

test("unknown key metadata cannot invent a comparison command", () => {
  expect(hostKeyPresentation(undefined)).toEqual({ label: "Host key", command: undefined });
});
