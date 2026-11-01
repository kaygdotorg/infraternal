/** A real-server restart waits for every fixture process in its detached group before relaunch (#250). */
import { mkdtemp, readFile, rm, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { expect, test } from "playwright/test";
import { startRealServer, type RealServer } from "./server";

const textAt = async (path: string): Promise<string> => readFile(path, "utf8").catch(() => "");
const processGroupExists = (group: number): boolean => {
  try { process.kill(-group, 0); return true; }
  catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ESRCH") return false;
    throw error;
  }
};

test("restart waits for a delayed child in the fixture's process group", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "infraternal-process-group-"));
  const wrapper = resolve(root, "server-with-child");
  const pidFile = resolve(root, "child.pid");
  const stoppedFile = resolve(root, "child.stopped");
  const realBinary = process.env.INFRATERNAL_BIN ?? resolve(import.meta.dirname, "../../../target/x86_64-unknown-linux-musl/release/infraternal");
  const previous = new Map<string, string | undefined>([
    ["INFRATERNAL_BIN", process.env.INFRATERNAL_BIN],
    ["INFRATERNAL_GROUP_BINARY", process.env.INFRATERNAL_GROUP_BINARY],
    ["INFRATERNAL_GROUP_PID_FILE", process.env.INFRATERNAL_GROUP_PID_FILE],
    ["INFRATERNAL_GROUP_STOPPED_FILE", process.env.INFRATERNAL_GROUP_STOPPED_FILE],
  ]);
  const source = `#!/bin/sh
if [ "$1" = "server" ] && [ "$2" = "--listen" ]; then
python3 -c '
import os,signal,sys,time
pid_file, stopped_file = sys.argv[1:3]
with open(pid_file, "w", encoding="utf-8") as output: output.write(str(os.getpid()))
def stop(*_):
 time.sleep(3)
 with open(stopped_file, "w", encoding="utf-8") as output: output.write("stopped")
 raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
while True: time.sleep(1)
' "$INFRATERNAL_GROUP_PID_FILE" "$INFRATERNAL_GROUP_STOPPED_FILE" &
fi
exec "$INFRATERNAL_GROUP_BINARY" "$@"
`;
  let server: RealServer | undefined;
  let childPid = 0;
  try {
    await writeFile(wrapper, source, { mode: 0o700 });
    await chmod(wrapper, 0o700);
    process.env.INFRATERNAL_BIN = wrapper;
    process.env.INFRATERNAL_GROUP_BINARY = realBinary;
    process.env.INFRATERNAL_GROUP_PID_FILE = pidFile;
    process.env.INFRATERNAL_GROUP_STOPPED_FILE = stoppedFile;
    server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4456) });
    await expect.poll(() => textAt(pidFile), { timeout: 10_000 }).toMatch(/^[1-9][0-9]*$/);
    childPid = Number(await textAt(pidFile));
    const oldGroup = server.pid;

    await server.restart(async () => {
      expect(processGroupExists(oldGroup), "the old detached group must exit before the replacement starts").toBe(false);
      expect(await textAt(stoppedFile), "the old process group must finish before the replacement starts").toBe("stopped");
    });
  } finally {
    await server?.dispose();
    if (childPid > 0) { try { process.kill(childPid, "SIGKILL"); } catch { /* the fixture child already exited */ } }
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await rm(root, { recursive: true, force: true });
  }
});
