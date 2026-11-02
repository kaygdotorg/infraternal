// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The docs' demo dataset (docs-dataset.ts, #302): plain names replace the internal ones everywhere in the mock world, nothing
 * else changes, and what is left over can be found. The mock world's files are scanned for real, so a name added to a mock
 * tomorrow either gets a rule or fails here.
 */
import { expect, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { findLeaks, renameDataset } from "./docs-dataset";

test("hosts, people and private addresses are renamed as whole words", () => {
  expect(renameDataset("kayg@build-01:~$ ssh nix-cache")).toBe("maya@home-server:~$ ssh media-server");
  expect(renameDataset("Kay G, Asha Verma and Ravi Menon")).toBe("Maya Patel, Sam Lee and Alex Kim");
  expect(renameDataset("ops→build-01 via fra-relay")).toBe("ops→home-server via cloud-relay");
  expect(renameDataset("10.0.4.17 and 192.168.1.20 and 172.16.9.3")).toBe("192.0.2.17 and 192.0.2.20 and 192.0.2.3");
});

test("a name inside a longer word is left alone", () => {
  expect(renameDataset("build-011 pre-kayg kayger asha_ nix-cache-2 ravine")).toBe("build-011 pre-kayg kayger asha_ nix-cache-2 ravine");
});

test("the renaming is stable: running it twice changes nothing more", () => {
  const once = renameDataset("kayg@studio-mac 10.1.2.3 Kay G");
  expect(renameDataset(once)).toBe(once);
});

test("what must not appear in a figure is found", () => {
  expect(findLeaks("maya@home-server")).toEqual([]);
  expect(findLeaks("203.0.113.9 and 192.0.2.4 and 127.0.0.1")).toEqual([]);
  expect(findLeaks("kayg@monitor01")).toEqual(["kayg", "monitor01"]);
  expect(findLeaks("ssh.kayg.org")).toContain("ssh.kayg.org");
  expect(findLeaks("reach 10.20.30.40")).toEqual(["10.20.30.40"]);
  expect(findLeaks("reach 8.8.4.4")).toEqual(["8.8.4.4"]);
  expect(findLeaks("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl")).not.toEqual([]);
});

/** Every `.ts` file under a directory. */
async function sources(dir: string): Promise<string[]> {
  const found: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...await sources(path));
    else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) found.push(path);
  }
  return found;
}

test("after the rewrite, no internal name or address is left in the mock world or in the test double's fixtures", async () => {
  const here = import.meta.dirname;
  const files = [...await sources(resolve(here, "src/canvas/mock")), resolve(here, "src/add-host-prototype.ts"), resolve(here, "src/add-host-contract.ts"), resolve(here, "test/prototype-fixtures.ts"), resolve(here, "test/session-fixtures.ts")];
  const leftover: string[] = [];
  for (const file of files) {
    const found = findLeaks(renameDataset(await readFile(file, "utf8")));
    if (found.length > 0) leftover.push(`${file.replace(`${here}/`, "")}: ${[...new Set(found)].join(", ")}`);
  }
  expect(leftover).toEqual([]);
});
