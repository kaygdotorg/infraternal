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
    extended: true,
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
  expect(rows.get("Virtualization")).toBe("KVM");
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
    extended: true,
  });
  const rows = new Map(facts.sections[0]!.rows.map(({ key, value }) => [key, value]));
  expect(rows.get("System")).toBe("Linux");
  expect(rows.get("Memory")).toBe("");
  expect(rows.get("Model")).toBe("");
  expect(rows.get("Uptime")).toBe("Less than a minute");
  expect(rows.get("Infraternal agent")).toBe("Remote · root");
  expect(rows.get("Engines")).toBe("None detected");
});

// "No More tab": the extra facts live in titled sections of the machine tab, shown only with extended info.
const FULL = {
  host: {
    name: "build-01",
    user: "kayg",
    address: "10.0.0.7",
    facts: {
      os: "Linux", version: "", kernel: "6.12", architecture: "x86_64",
      logicalCpus: 8, uptimeSeconds: 7_200, mode: "embedded" as const, executionUid: 1000, engines: [],
      init: "systemd", virtualization: "KVM", shell: "/bin/zsh", locale: "en_US.UTF-8",
    },
  },
  connection: { state: "connected" as const },
};

test("extended info off: the machine tab shows only the essentials, ungrouped, and there is no More section", () => {
  const facts = detailsFacts(FULL);
  expect(facts.sections.map((section) => section.id)).toEqual(["host", "connection", "session"]);
  const rows = facts.sections[0]!.rows.filter((row) => row.value.trim() !== "");
  expect(rows.map((row) => row.key)).toEqual(["Name", "System", "Uptime", "Login", "Address"]);
  expect(rows.some((row) => row.group)).toBe(false);
});

test("extended info on: every fact sits under System, Resources or Access", () => {
  const rows = detailsFacts({ ...FULL, extended: true }).sections[0]!.rows.filter((row) => row.value.trim() !== "");
  const groups = new Map<string, string[]>();
  for (const row of rows) groups.set(row.group!, [...(groups.get(row.group!) ?? []), row.key]);
  expect([...groups.keys()]).toEqual(["System", "Resources", "Access"]);
  expect(groups.get("System")).toEqual(["Name", "System", "Kernel", "Architecture", "Init", "Virtualization"]);
  expect(groups.get("Resources")).toEqual(["CPU", "Uptime"]);
  expect(groups.get("Access")).toEqual(["Infraternal agent", "Engines", "Login", "Address", "Shell", "Locale"]);
});
