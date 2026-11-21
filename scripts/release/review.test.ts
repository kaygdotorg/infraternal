/** Verifies publication admission and fail-closed storage response parsing (#157, D184). */
import { expect, test } from "bun:test";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

const root = join(import.meta.dir, "../..");

test("publication with two build directories admits only one writer", async () => {
  const scratch = join(process.env.HOME!, ".cache/codex-scratch/release-pipeline-review");
  await mkdir(scratch, { recursive: true });
  const directory = await mkdtemp(join(scratch, "publication-"));
  const manifest = await Bun.file(join(root, "Cargo.toml")).text();
  const version = manifest.match(/\[workspace\.package\][\s\S]*?^version = "([^"]+)"/m)![1]!;
  const names = ["VERSION", "infraternal", "infraternal-x86_64-musl", "infraternal-aarch64-musl", "infraternal-x86_64-session-musl", "infraternal-aarch64-session-musl"];
  let releaseAdmission!: () => void;
  const admission = new Promise<void>((resolve) => { releaseAdmission = resolve; });
  let lists = 0;
  let uploads = 0;
  let replacements = 0;
  const stored = new Map<string, string>();
  // The local lock is the same-host guard even though R2 honours If-None-Match. Keep
  // both empty-prefix checks ahead of writes to exercise its claimed local lock.
  const server = Bun.serve({
    hostname: "127.0.0.1", port: 0,
    async fetch(request) {
      const path = new URL(request.url).pathname;
      if (request.method === "GET" && path === "/s3/infraternal-builds") {
        lists += 1;
        if (lists === 2) releaseAdmission();
        await admission;
        return new Response('<ListBucketResult><Name>infraternal-builds</Name><Prefix>releases/x/</Prefix><KeyCount>0</KeyCount><MaxKeys>10</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>');
      }
      if (request.method === "PUT") {
        uploads += 1;
        const body = await request.text();
        if (stored.has(path)) replacements += 1;
        stored.set(path, body);
        return new Response("");
      }
      // No signer/trust fixture is necessary: admission must happen before any
      // publication mutation, independently of downstream signing availability.
      return new Response("", { status: 503 });
    },
  });
  const children: ReturnType<typeof Bun.spawn>[] = [];
  const timeout = setTimeout(() => {
    releaseAdmission();
    for (const child of children) child.kill();
  }, 20_000);
  try {
    for (const label of ["first", "second"]) {
      const target = join(directory, label);
      const bundle = join(target, "releases", version);
      await mkdir(bundle, { recursive: true });
      for (const name of names) {
        await writeFile(join(bundle, name), name === "VERSION" ? `${version}\n` : `${label}-${name}\n`);
      }
      const child = Bun.spawn(["bash", join(root, "scripts/release/publish"), version], {
        env: {
          ...process.env,
          CARGO_TARGET_DIR: target,
          CLOUDFLARE_ACCOUNT_ID: "fixture",
          R2_ACCESS_KEY_ID: "FIXTUREACCESSKEY",
          R2_SECRET_ACCESS_KEY: "fixture-secret",
          RELEASE_CALLER_TOKEN: "fixture-publication",
          RELEASE_TEST_ORIGIN: `http://127.0.0.1:${server.port}`,
        },
        stdout: "ignore", stderr: "ignore",
      });
      children.push(child);
      // A correctly shared lock can refuse the second process before its GET;
      // release the first process in that case so the test never waits on it.
      void child.exited.then(releaseAdmission);
    }
    const exits = await Promise.all(children.map((child) => child.exited));
    expect(exits.every((code) => code !== 0)).toBe(true);
    console.log(`PUBLICATION_ADMISSION same_host=true build_directories=2 list_requests=${lists} uploads=${uploads} replaced_objects=${replacements}`);
    // At least one writer must reach the mutation boundary; a fixture timeout
    // must not count as successful serialization.
    expect(uploads).toBeGreaterThanOrEqual(names.length);
    expect(uploads).toBeLessThanOrEqual(names.length);
    expect(replacements).toBe(0);
  } finally {
    clearTimeout(timeout);
    for (const child of children) { if (child.exitCode === null) child.kill(); }
    await Promise.all(children.map((child) => child.exited));
    server.stop(true);
    await rm(directory, { recursive: true, force: true });
  }
}, 30_000);

// An existing-object entry hidden behind a zero count is ambiguous. The
// preflight must refuse that state before the publisher receives write permission.
test("storage preflight refuses ambiguous existing-object results", async () => {
  const child = Bun.spawn(["python3", join(root, "scripts/release/response.py"), "s3-empty-prefix", "infraternal-builds", "releases/0.1.0/"], {
    stdin: "pipe", stdout: "pipe", stderr: "pipe",
  });
  child.stdin.write('<ListBucketResult><Name>infraternal-builds</Name><Prefix>releases/0.1.0/</Prefix><KeyCount>0</KeyCount><MaxKeys>10</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>releases/0.1.0/infraternal</Key></Contents></ListBucketResult>');
  child.stdin.end();
  const [exit, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  console.log(`STORAGE_PREFLIGHT hidden_existing_object=true existing_objects=1 exit=${exit} stdout_bytes=${stdout.length} stderr_bytes=${stderr.length}`);
  expect(exit).not.toBe(0);
});
