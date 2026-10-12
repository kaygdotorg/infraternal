/** Independently checks remote artifact admission with real signatures (#188, D250). */
import { expect, test } from "bun:test";
import { join } from "node:path";

test("remote admission refuses an x86 payload outside the signed manifest", async () => {
  const child = Bun.spawn(["python3", "-c", `
import hashlib
from pathlib import Path
import subprocess
import tempfile
from staging_artifacts_test import proof
from deploy_remote import checksums, verify_signed

scratch = Path.home() / ".cache/codex-scratch/deploy-pipeline-review/fixtures"
scratch.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(dir=scratch) as temporary:
    root = Path(temporary)
    key = root / "signer"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    fields = key.with_suffix(".pub").read_text().split()
    trust = root / "allowed_signers"
    trust.write_text('release@infraternal.com namespaces="infraternal-release" ' + fields[0] + " " + fields[1] + " fixture\\n")
    image = root / "image"
    image.write_bytes(b"signed-server-image")
    release = root / "release"
    proof.bundle(release, image, key, "edge-20261012T000001Z")
    key.unlink()
    checksums(release)
    verify_signed(release, trust, release / "infraternal", complete=True)
    # A reused remote directory has its own unsigned integrity list. Keep the
    # authenticated server intact while replacing only the installed payload.
    (release / "infraternal-x86_64-musl").write_bytes(b"superseded-payload")
    (release / "SHA256SUMS").write_text("".join(
        hashlib.sha256(file.read_bytes()).hexdigest() + "  " + str(file.relative_to(release)) + "\\n"
        for file in sorted(release.rglob("*")) if file.is_file()
        and file.name not in {"SHA256SUMS", "MANIFEST", "MANIFEST.sig"}))
    checksums(release)
    refused = False
    try:
        verify_signed(release, trust, release / "infraternal", complete=True)
    except ValueError:
        refused = True
    print("REMOTE_ADMISSION unsigned_x86_payload=true refused=" + str(refused).lower())
    assert refused, "remote signed-bundle admission accepted an unsigned x86 payload"
`], {
    cwd: import.meta.dir,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    stdout: "pipe", stderr: "pipe",
  });
  const [exit, stdout, stderr] = await Promise.all([
    child.exited, new Response(child.stdout).text(), new Response(child.stderr).text(),
  ]);
  await Bun.write(join(process.env.HOME!, ".cache/codex-scratch/deploy-pipeline-review/artifact-admission.log"), stdout + stderr);
  console.log(stdout.trim());
  expect(exit).toBe(0);
});

test("alias restoration failure still requests the retained warm rollback", async () => {
  const child = Bun.spawn(["python3", "-c", `
import errno
from pathlib import Path
from unittest.mock import patch
from deploy_test import DeploymentTests, remote

fixture = DeploymentTests()
fixture.setUp()
try:
    config, old = fixture.setup_apply()
    release = fixture.root / "releases" / config["sha"]
    for name in ("infraternal", "infraternal-x86_64-musl", "infraternal-aarch64-musl"):
        (release / name).write_bytes(b"new-image")
    fixture.sums(release)
    swap = remote.swap_link
    def full_directory(path, target):
        # The server alias is published, then allocation for the next alias
        # and for restoration fails. Retained rollback bytes remain readable.
        if path.name != "infraternal" or path.is_symlink():
            raise OSError(errno.ENOSPC, "directory allocation refused")
        swap(path, target)
    with patch.object(remote.os, "geteuid", return_value=0), \\
         patch.object(remote, "healthy", return_value=True), \\
         patch.object(remote, "same_image", return_value=True), \\
         patch.object(remote, "verify_signed"), \\
         patch.object(remote, "endpoint", return_value=(1, 2)), \\
         patch.object(remote, "backup", side_effect=lambda data, saved: saved.mkdir()), \\
         patch.object(remote, "restart") as restart, \\
         patch.object(remote, "wait_for_success"), \\
         patch.object(remote, "swap_link", side_effect=full_directory):
        try:
            remote.apply(config)
        except (OSError, ValueError):
            pass
        print("ALIAS_RECOVERY restart_requests=" + str(restart.call_count))
        assert restart.call_count == 2, "alias restoration error skipped the warm rollback request"
        assert restart.call_args_list[1].args[1].read_bytes() == b"old binary"
finally:
    fixture.tearDown()
`], {
    cwd: import.meta.dir,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1", INFRATERNAL_RELEASE_TEST_SCRATCH: join(process.env.HOME!, ".cache/codex-scratch/deploy-pipeline-review/fixtures") },
    stdout: "pipe", stderr: "pipe",
  });
  const [exit, stdout, stderr] = await Promise.all([
    child.exited, new Response(child.stdout).text(), new Response(child.stderr).text(),
  ]);
  await Bun.write(join(process.env.HOME!, ".cache/codex-scratch/deploy-pipeline-review/alias-recovery.log"), stdout + stderr);
  console.log(stdout.trim());
  expect(exit).toBe(0);
});
