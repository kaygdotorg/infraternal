/** Namespace guard controls keep restart fixtures away from shared host runtimes. */
import { expect, test } from "bun:test";
import { privateRuntimeMount } from "./restart-namespace";
test("only an explicit private tmpfs runtime qualifies", () => {
  const mount = "55 24 0:53 / /run/infraternal rw,nosuid - tmpfs tmpfs rw,size=1024k";
  expect(privateRuntimeMount(mount)).toBe(true);
  for (const line of ["", mount.replace("/run/infraternal", "/run"), mount.replace(" - tmpfs ", " - ext4 "), mount.replace(" - tmpfs", " shared:1 - tmpfs"), mount.replace(" - tmpfs", " master:1 - tmpfs")]) expect(privateRuntimeMount(line)).toBe(false);
});
