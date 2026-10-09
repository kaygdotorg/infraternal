/** Tests plain-language host fact rows used by the live and mock details sources. */
import { expect, test } from "bun:test";
import { detailsFacts } from "./details-facts";

test("host facts become plain-language details rows", () => {
  const facts = detailsFacts({
    host: {
      name: "build-01",
      os: "debian",
      facts: {
        os: "Debian GNU/Linux",
        version: "13",
        kernel: "6.12.0-test",
        architecture: "x86_64",
        model: "Test board",
        cpuModel: "Example CPU",
        logicalCpus: 8,
        memory: { usedBytes: 3.1 * 1024 ** 3, totalBytes: 8 * 1024 ** 3 },
        rootDisk: { usedBytes: 4 * 1024 ** 3, totalBytes: 20 * 1024 ** 3 },
        uptimeSeconds: 90_061,
        loadAverage: [0.1, 0.2, 0.3],
        mode: "embedded",
        executionUid: 1000,
        engines: ["Docker"],
        init: "systemd",
        virtualization: "KVM",
        shell: "/bin/zsh",
        locale: "de_DE.UTF-8",
      },
    },
    connection: { state: "connected" },
  });
  const rows = new Map(facts.sections[0]!.rows.map(({ key, value }) => [key, value]));

  expect(rows.get("System")).toBe("Debian GNU/Linux 13");
  expect(rows.get("Kernel")).toBe("6.12.0-test");
  expect(rows.get("Architecture")).toBe("x86_64");
  expect(rows.get("CPU")).toBe("8 logical cores · Example CPU");
  expect(rows.get("Memory")).toBe("3.1 GB of 8 GB");
  expect(rows.get("Disk used on /")).toBe("4 GB of 20 GB");
  expect(rows.get("Uptime")).toBe("1 day, 1 hour");
  expect(rows.get("Infraternal agent")).toBe("Embedded · user");
  expect(rows.get("Engines")).toBe("Docker");
  expect(new Map(facts.sections.find((section) => section.id === "more")!.rows.map(({ key, value }) => [key, value])).get("Virtualization")).toBe("KVM");
});

test("unknown optional host facts stay absent instead of appearing as placeholders", () => {
  const facts = detailsFacts({
    host: {
      name: "remote-01",
      facts: {
        os: "Linux",
        version: "",
        kernel: "6.12.0-test",
        architecture: "x86_64",
        logicalCpus: 1,
        mode: "remote",
        executionUid: 0,
        engines: [],
        uptimeSeconds: 59,
      },
    },
    connection: { state: "connected" },
  });
  const rows = new Map(facts.sections[0]!.rows.map(({ key, value }) => [key, value]));
  expect(rows.get("System")).toBe("Linux");
  expect(rows.get("Memory")).toBe("");
  expect(rows.get("Model")).toBe("");
  expect(rows.get("Uptime")).toBe("Less than a minute");
  expect(rows.get("Infraternal agent")).toBe("Remote · root");
  expect(rows.get("Engines")).toBe("None detected");
});

// D126 and #144 keep secondary identity fields behind the explicit more control.
test("default Host rows keep secondary facts behind more", () => {
  const facts = detailsFacts({
    host: {
      name: "build-01",
      facts: {
        os: "Linux", version: "", kernel: "6.12", architecture: "x86_64",
        logicalCpus: 8, mode: "embedded", executionUid: 1000, engines: [],
        init: "systemd", virtualization: "KVM", shell: "/bin/zsh", locale: "en_US.UTF-8",
      },
    },
    connection: { state: "connected" },
  });
  const visibleKeys = facts.sections[0]!.rows.filter((row) => row.value.trim() !== "").map((row) => row.key);
  expect(visibleKeys).not.toContain("Init");
  expect(visibleKeys).not.toContain("Virtualization");
  expect(visibleKeys).not.toContain("Shell");
  expect(visibleKeys).not.toContain("Locale");
  const more = facts.sections.find((section) => section.id === "more");
  expect(more?.label).toBe("More");
  expect(more?.rows.filter((row) => row.value.trim() !== "").map((row) => row.key)).toEqual([
    "Init", "Virtualization", "Shell", "Locale",
  ]);
});
