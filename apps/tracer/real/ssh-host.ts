// SPDX-License-Identifier: AGPL-3.0-only
/**
 * A throwaway SSH host for real-server Add host specs: a key-only `sshd` run as the current user on a free loopback port.
 * Its sessions get a private HOME and the user's runtime directory, so the host check sees a working user systemd
 * manager while whatever setup writes lands in the host's own temporary directory and never in the real account.
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** A throwaway key-only `sshd` for the current user on a free loopback port; `stop()` removes everything it made. */
export async function startHost(): Promise<{ port: number; privateKey: string; stop(): void }> {
  // sshd gives its sessions a clean environment: without this the host's user systemd manager cannot be reached and
  // the host check (rightly) reports the host unsupported.
  const runtimeDir = process.env.XDG_RUNTIME_DIR ?? `/run/user/${process.getuid?.() ?? 1000}`;
  const dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), "h"));
  const port = await new Promise<number>((resolve) => { const probe = createServer(); probe.listen(0, "127.0.0.1", () => { const p = (probe.address() as { port: number }).port; probe.close(() => resolve(p)); }); });
  for (const type of ["ed25519"]) spawnSync("ssh-keygen", ["-q", "-t", type, "-N", "", "-f", join(dir, `host_${type}`)], { stdio: "ignore" });
  spawnSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", join(dir, "user")], { stdio: "ignore" });
  // The host's sessions get a private HOME: the install this spec lets begin writes its setup state under $HOME, and it
  // must not touch the real account's home (a shared account, and a second run would then meet "leftovers").
  mkdirSync(join(dir, "home"), { mode: 0o700 });
  writeFileSync(join(dir, "authorized_keys"), readFileSync(join(dir, "user.pub")), { mode: 0o600 });
  writeFileSync(join(dir, "sshd_config"), [
    `Port ${port}`, "ListenAddress 127.0.0.1", `HostKey ${join(dir, "host_ed25519")}`, `AuthorizedKeysFile ${join(dir, "authorized_keys")}`,
    "PasswordAuthentication no", "KbdInteractiveAuthentication no", "UsePAM no", "StrictModes no", `SetEnv XDG_RUNTIME_DIR=${runtimeDir} HOME=${join(dir, "home")}`, `PidFile ${join(dir, "pid")}`, "LogLevel ERROR",
  ].join("\n"));
  // A transient user unit, so the daemon is owned by the user's manager and stops with `systemctl --user stop`.
  const unit = `j510-host-${port}`;
  const child: ChildProcess = spawn("systemd-run", ["--user", "--quiet", "--collect", "--unit", unit, "/usr/sbin/sshd", "-D", "-e", "-f", join(dir, "sshd_config")], { stdio: "ignore" });
  const privateKey = readFileSync(join(dir, "user"), "utf8");
  await new Promise((resolve) => setTimeout(resolve, 500)); // sleep: give sshd time to bind its port before the first connection
  return { port, privateKey, stop: () => { spawnSync("systemctl", ["--user", "stop", unit], { stdio: "ignore", timeout: 10_000 }); child.kill(); rmSync(dir, { recursive: true, force: true }); } };
}

