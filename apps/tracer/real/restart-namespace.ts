/** Require an isolated private runtime for destructive restart fixtures; support mapped-root build-host checks. */
import { readFile, readlink } from "node:fs/promises";

export function privateRuntimeMount(mountinfo: string): boolean {
  return mountinfo.split("\n").some((line) => {
    const [mount, filesystem] = line.split(" - ");
    const fields = mount?.split(" ") ?? [];
    return fields[4] === "/run/infraternal" && filesystem?.startsWith("tmpfs ") === true
      && !fields.slice(6).some((field) => field.startsWith("shared:") || field.startsWith("master:"));
  });
}
export async function requirePrivateRuntime(): Promise<void> {
  if (!privateRuntimeMount(await readFile("/proc/self/mountinfo", "utf8"))) throw Error("restart fixture requires a private tmpfs on /run/infraternal");
  const current = await readlink("/proc/self/ns/mnt");
  try {
    if (current === await readlink("/proc/1/ns/mnt")) throw Error("restart fixture requires a private mount namespace");
  } catch (error) {
    // Mapped root cannot inspect host init. Its single-entry uid map plus the
    // verified private tmpfs establish the supported unprivileged fixture path.
    if (!(error instanceof Error && "code" in error && error.code === "EACCES")) throw error;
    const map = (await readFile("/proc/self/uid_map", "utf8")).trim().split(/\s+/);
    if (process.getuid?.() !== 0 || map.length !== 3 || map[0] !== "0" || map[2] !== "1") throw error;
  }
}
