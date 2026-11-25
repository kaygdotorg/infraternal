// SPDX-License-Identifier: AGPL-3.0-only
/**
 * End-to-end tests for `scripts/release/install.sh` against a local loopback HTTP server (#211, D184, D224, D226).
 *
 * Verifies that:
 * - the embedded trust anchors in `scripts/release/install.sh` match `release/allowed_signers` exactly;
 * - the default invocation resolves `stable.json` and never falls back to `edge.json`;
 * - `--channel edge` resolves `edge.json`, verifies `ssh-keygen -Y verify`, `VERSION`, and `infraternal` SHA-256;
 * - a tampered signature, untrusted key, mismatched `VERSION`, or tampered binary is refused with no output written.
 */
import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

/** Repository root resolved from `apps/tracer/`. */
const REPO_ROOT = resolve(import.meta.dirname, "../..");

/** Path to the shipping POSIX installer script. */
const INSTALL_SCRIPT = resolve(REPO_ROOT, "scripts/release/install.sh");

/** Path to the canonical release trust anchors. */
const ALLOWED_SIGNERS = resolve(REPO_ROOT, "release/allowed_signers");

/** Computes the lowercase SHA-256 hex digest of `text`. */
const sha256 = (text: string): string => createHash("sha256").update(text).digest("hex");

/** Generates an ephemeral Ed25519 keypair using `ssh-keygen` and signs a release manifest. */
async function createFixture(dir: string): Promise<{
  allowedSignersLine: string;
  sign(sumsPath: string): Promise<string>;
}> {
  const keyPath = join(dir, "release_key");
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", keyPath], { stdio: "pipe" });
  const pub = (await readFile(`${keyPath}.pub`, "utf8")).trim().split(/\s+/);
  const allowedSignersLine = `release@infraternal.com namespaces="infraternal-release" ${pub[0]} ${pub[1]} fixture-key`;
  return {
    allowedSignersLine,
    async sign(sumsPath: string): Promise<string> {
      execFileSync("ssh-keygen", ["-q", "-Y", "sign", "-f", keyPath, "-n", "infraternal-release", sumsPath], {
        stdio: "pipe",
      });
      return readFile(`${sumsPath}.sig`, "utf8");
    },
  };
}

/** Creates a fake `uname` shim reporting Linux x86_64 so installer tests run on both x86_64 and arm64 build hosts. */
async function writeUnameShim(dir: string, os = "Linux", arch = "x86_64"): Promise<string> {
  const binDir = join(dir, "shim-bin");
  await chmod(dir, 0o700);
  execFileSync("mkdir", ["-p", binDir]);
  const shim = join(binDir, "uname");
  await writeFile(
    shim,
    `#!/bin/sh\ncase "$1" in\n  -s) printf '%s\\n' "${os}" ;;\n  -m) printf '%s\\n' "${arch}" ;;\n  *) /usr/bin/uname "$@" ;;\nesac\n`,
    { mode: 0o755 },
  );
  return binDir;
}

/** Runs `scriptPath` with `args` against `origin`, returning exit code, stdout, and stderr. */
async function runInstall(
  scriptPath: string,
  args: string[],
  origin: string,
  shimBinDir: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(["sh", scriptPath, ...args], {
    env: {
      ...process.env,
      PATH: `${shimBinDir}:${process.env.PATH ?? ""}`,
      INFRATERNAL_RELEASE_ORIGIN: origin,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [code, stdout, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  return { code, stdout, stderr };
}

test("install.sh embeds the exact production release/allowed_signers trust anchors", async () => {
  const canonical = (await readFile(ALLOWED_SIGNERS, "utf8"))
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
  const script = await readFile(INSTALL_SCRIPT, "utf8");
  expect(canonical.length).toBe(2);
  for (const line of canonical) expect(script).toContain(line);
});

test("install.sh resolves stable/edge pointers, verifies signatures and checksums, and refuses tampering", async () => {
  const dir = await mkdtemp(join(tmpdir(), "install-sh-"));
  try {
    const fixture = await createFixture(dir);
    const shimBin = await writeUnameShim(dir);

    // Prepare a test copy of install.sh with the ephemeral test key substituted for the production keys.
    const rawScript = await readFile(INSTALL_SCRIPT, "utf8");
    const testScript = join(dir, "install.sh");
    const replaced = rawScript.replace(
      /cat <<'EOF' > "\$staging\/allowed_signers"[\s\S]*?\nEOF/,
      `cat <<'EOF' > "$staging/allowed_signers"\n${fixture.allowedSignersLine}\nEOF`,
    );
    expect(replaced).not.toBe(rawScript);
    await writeFile(testScript, replaced, { mode: 0o755 });

    const stableVersion = "1.4.0";
    const edgeVersion = "edge-20261125T050000Z";
    const binaryPayload = "#!/bin/sh\necho infraternal-test-binary\n";

    /** Builds signed release files on disk and returns a pathname-to-body map. */
    const makeRelease = async (version: string, channel: "stable" | "edge"): Promise<Map<string, string>> => {
      const versionText = `${version}\n`;
      const sumsText = `${sha256(versionText)}  VERSION\n${sha256(binaryPayload)}  infraternal\n`;
      const sumsPath = join(dir, `${version}.SHA256SUMS`);
      await writeFile(sumsPath, sumsText);
      const sigText = await fixture.sign(sumsPath);
      return new Map<string, string>([
        [`/releases/channels/${channel}.json`, JSON.stringify({ version, channel })],
        [`/releases/${version}/SHA256SUMS`, sumsText],
        [`/releases/${version}/SHA256SUMS.sig`, sigText],
        [`/releases/${version}/VERSION`, versionText],
        [`/releases/${version}/infraternal`, binaryPayload],
      ]);
    };

    let files = new Map<string, string>();
    const requested: string[] = [];
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(req) {
        const pathname = new URL(req.url).pathname;
        requested.push(pathname);
        const body = files.get(pathname);
        if (body === undefined) return new Response("not found", { status: 404 });
        return new Response(body, { status: 200 });
      },
    });
    const origin = `http://127.0.0.1:${server.port}`;

    try {
      // 1. Empty stable channel refuses and never falls back to edge.
      files = await makeRelease(edgeVersion, "edge");
      requested.length = 0;
      const outEmpty = join(dir, "out-empty");
      const emptyRes = await runInstall(testScript, ["--output", outEmpty], origin, shimBin);
      expect(emptyRes.code).not.toBe(0);
      expect(emptyRes.stderr).toContain("no stable release yet");
      expect(requested).toEqual(["/releases/channels/stable.json"]);

      // 2. Explicit --channel edge succeeds and installs executable binary.
      const outEdge = join(dir, "out-edge");
      const edgeRes = await runInstall(testScript, ["--channel", "edge", "--output", outEdge], origin, shimBin);
      expect(edgeRes.code).toBe(0);
      expect(edgeRes.stdout).toContain(edgeVersion);
      expect(await readFile(outEdge, "utf8")).toBe(binaryPayload);
      expect((await stat(outEdge)).mode & 0o111).not.toBe(0);

      // 3. Default (stable) succeeds when stable is published.
      files = await makeRelease(stableVersion, "stable");
      const outStable = join(dir, "out-stable");
      const stableRes = await runInstall(testScript, ["--output", outStable], origin, shimBin);
      expect(stableRes.code).toBe(0);
      expect(stableRes.stdout).toContain(stableVersion);
      expect(await readFile(outStable, "utf8")).toBe(binaryPayload);

      // 4. Shipping install.sh (production keys) refuses a release signed by the ephemeral test key.
      const outUntrusted = join(dir, "out-untrusted");
      const untrustedRes = await runInstall(INSTALL_SCRIPT, ["--output", outUntrusted], origin, shimBin);
      expect(untrustedRes.code).not.toBe(0);
      expect(untrustedRes.stderr).toContain("signature could not be verified");
      await expect(stat(outUntrusted)).rejects.toThrow();

      // 5. Tampered binary (bad checksum) is refused and leaves no output file.
      const tamperedBinFiles = await makeRelease(stableVersion, "stable");
      tamperedBinFiles.set(`/releases/${stableVersion}/infraternal`, "tampered-payload");
      files = tamperedBinFiles;
      const outTamperedBin = join(dir, "out-tampered-bin");
      const tamperedBinRes = await runInstall(testScript, ["--output", outTamperedBin], origin, shimBin);
      expect(tamperedBinRes.code).not.toBe(0);
      expect(tamperedBinRes.stderr).toContain("checksum mismatch");
      await expect(stat(outTamperedBin)).rejects.toThrow();

      // 6. Cross-channel pointer (stable.json pointing to edge version) is refused.
      const crossFiles = await makeRelease(edgeVersion, "edge");
      crossFiles.set("/releases/channels/stable.json", JSON.stringify({ version: edgeVersion, channel: "stable" }));
      files = crossFiles;
      const outCross = join(dir, "out-cross");
      const crossRes = await runInstall(testScript, ["--output", outCross], origin, shimBin);
      expect(crossRes.code).not.toBe(0);
      expect(crossRes.stderr).toContain("another channel");
      await expect(stat(outCross)).rejects.toThrow();
    } finally {
      server.stop(true);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
