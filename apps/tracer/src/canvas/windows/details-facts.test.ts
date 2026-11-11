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

// D126/D156: the default facts always show under titled sections; extended info only adds the technical ones.
const FULL = {
  host: {
    name: "build-01",
    user: "kayg",
    address: "10.0.0.7",
    facts: {
      os: "Linux", version: "", kernel: "6.12", architecture: "x86_64", model: "Test board", cpuModel: "Example CPU",
      logicalCpus: 8, memory: { usedBytes: 2 * 1024 ** 3, totalBytes: 8 * 1024 ** 3 }, rootDisk: { usedBytes: 4 * 1024 ** 3, totalBytes: 20 * 1024 ** 3 },
      uptimeSeconds: 7_200, loadAverage: [0.1, 0.2, 0.3] as [number, number, number], mode: "embedded" as const, executionUid: 1000, engines: ["Docker"],
      init: "systemd", virtualization: "KVM", shell: "/bin/zsh", locale: "en_US.UTF-8",
    },
  },
  connection: { state: "connected" as const },
};

const grouped = (extended: boolean) => {
  const rows = detailsFacts({ ...FULL, extended }).sections[0]!.rows.filter((row) => row.value.trim() !== "");
  const groups = new Map<string, string[]>();
  for (const row of rows) groups.set(row.group!, [...(groups.get(row.group!) ?? []), row.key]);
  return groups;
};

test("by default the machine tab shows the D126 facts under System, Resources and Access, with no More section", () => {
  const facts = detailsFacts(FULL);
  expect(facts.sections.map((section) => section.id)).toEqual(["host", "connection"]); // D385: two tabs
  const groups = grouped(false);
  expect([...groups.keys()]).toEqual(["System", "Resources", "Access"]);
  expect(groups.get("System")).toEqual(["Name", "System", "Kernel", "Architecture", "Model"]);
  expect(groups.get("Resources")).toEqual(["CPU", "Memory", "Disk used on /", "Uptime", "Load average"]);
  expect(groups.get("Access")).toEqual(["Infraternal agent", "Engines", "Login"]);
});

test("the Connection tab holds the link and the session's own facts, under their own headings (D385)", () => {
  const facts = detailsFacts({ ...FULL, extended: true, session: { name: "deploy", started: "10:02", size: "120×32" } });
  const connection = facts.sections.find((section) => section.id === "connection")!;
  expect(facts.sections.map((section) => section.label)).toEqual(["Machine", "Connection"]);
  const keys = connection.rows.filter((row) => row.value.trim() !== "");
  expect(keys.map((row) => row.group)).toEqual([...keys.map((row) => row.group)].sort((a, b) => ["Link", "Session"].indexOf(a!) - ["Link", "Session"].indexOf(b!))); // Link rows first, then Session
  expect(keys.filter((row) => row.group === "Link").map((row) => row.key)).toContain("Address");
  expect(keys.filter((row) => row.group === "Session").map((row) => row.key)).toEqual(["Name", "Started", "Size"]);
});

test("extended info adds only init, virtualization, how it is reached, shell and locale", () => {
  const base = [...grouped(false).values()].flat();
  const extended = [...grouped(true).values()].flat();
  expect(extended.filter((key) => !base.includes(key)).sort()).toEqual(["Init", "Locale", "Shell", "Virtualization"]);
  expect(grouped(true).get("Access")).toContain("Shell");
});

test("facts the host did not report are omitted by default, not shown as unknown", () => {
  const sparse = detailsFacts({
    host: { name: "bare", facts: { os: "Linux", version: "", kernel: "6.1", architecture: "arm64", logicalCpus: 2, mode: "remote", executionUid: 0, engines: [] } },
    connection: { state: "connected" },
  }).sections[0]!.rows.filter((row) => row.value.trim() !== "").map((row) => row.key);
  expect(sparse).not.toContain("Memory");
  expect(sparse).not.toContain("Model");
  expect(sparse).not.toContain("Uptime");
});

test("the header follows the machine's own facts, not the platform the host list guessed", () => {
  const facts = detailsFacts({
    host: { name: "build-01", user: "kayg", os: "ubuntu", facts: { ...FULL.host.facts, os: "Debian GNU/Linux", version: "13" } },
    connection: { state: "connected" },
  });
  expect(facts.os).toBe("debian");
  expect(facts.title).toBe("Debian");
  expect(facts.subtitle).toBe("kayg@build-01");
  expect(facts.sections[0]!.rows.find((row) => row.key === "System")!.value).toBe("Debian GNU/Linux 13");
});

test("before facts arrive the host's platform names the header", () => {
  const facts = detailsFacts({ host: { name: "build-01", os: "ubuntu" }, connection: { state: "connected" } });
  expect(facts.os).toBe("ubuntu");
  expect(facts.title).toBe("Ubuntu");
});

test("a reported system with no platform mark still names the header and shows no mark", () => {
  const facts = detailsFacts({ host: { name: "box", facts: { ...FULL.host.facts, os: "Alpine Linux" } }, connection: { state: "connected" } });
  expect(facts.os).toBeUndefined();
  expect(facts.title).toBe("Alpine Linux");
});
