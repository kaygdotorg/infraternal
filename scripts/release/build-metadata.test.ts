/** Verifies static compiler path normalization, cache-visible flags and native metadata. */
import { expect, test } from "bun:test";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const repository = resolve(import.meta.dir, "../..");
const scratch = process.env.CARGO_TARGET_DIR ?? resolve(repository, "target");

/** The workspace config already supplies this static target feature. */
function withoutWorkspaceStaticFeature(flags: string[]): string[] {
  const result: string[] = [];
  for (let index = 0; index < flags.length; index++) {
    if (flags[index] === "-C" && flags[index + 1] === "target-feature=+crt-static") {
      index++;
      continue;
    }
    if (flags[index] !== "-Ctarget-feature=+crt-static") result.push(flags[index]);
  }
  return result;
}

test("native metadata canonicalization retains version fields and refuses changed syntax", () => {
  const result = Bun.spawnSync(["python3", join(repository, "scripts/test-native-metadata.py")]);
  expect(result.exitCode).toBe(0);
});

test("Rust and cached target compiles receive every environment remap", () => {
  mkdirSync(scratch, { recursive: true });
  const root = mkdtempSync(join(scratch, "static-recipe-test-"));
  try {
    const bin = join(root, "bin");
    const cargoHome = join(root, "cargo home with spaces");
    const target = join(root, "target with spaces");
    const rustupHome = join(root, "rustup home with spaces");
    const registryRoots = [join(cargoHome, "registry/src/index-one"), join(cargoHome, "registry/src/index two")];
    mkdirSync(bin);
    for (const registry of registryRoots) mkdirSync(registry, { recursive: true });
    const compiler = join(rustupHome, "toolchains/pinned/bin/rustc");
    mkdirSync(join(rustupHome, "toolchains/pinned/bin"), { recursive: true });
    writeFileSync(compiler, '#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n');
    chmodSync(compiler, 0o755);
    writeFileSync(join(bin, "rustup"), '#!/usr/bin/env sh\nprintf "%s\\n" "' + compiler + '"\n');
    chmodSync(join(bin, "rustup"), 0o755);
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      CARGO_HOME: cargoHome,
      CARGO_TARGET_DIR: target,
      RUSTUP_HOME: rustupHome,
    };
    const result = Bun.spawnSync([
      join(repository, ".cargo/rustc.sh"), "--cfg", 'a_value="with spaces"', "-C", "panic=unwind",
    ], { env });
    expect(result.exitCode).toBe(0);
    const rustcFlags = JSON.parse(result.stdout.toString()) as string[];
    expect(rustcFlags.slice(0, 4)).toEqual(["--cfg", 'a_value="with spaces"', "-C", "panic=unwind"]);
    const expectedRemaps = [
      ...registryRoots.map((registry) => `--remap-path-prefix=${registry}=/cargo`),
      `--remap-path-prefix=${target}=/build`,
      `--remap-path-prefix=${cargoHome}=/cargo`,
      `--remap-path-prefix=${rustupHome}=/rustup`,
      `--remap-path-prefix=${repository}=/infraternal`,
    ];
    const expectedStaticRemaps = [
      `--remap-path-prefix=${repository}=/infraternal`,
      `--remap-path-prefix=${cargoHome}=/cargo`,
      `--remap-path-prefix=${target}=/build`,
      ...[...registryRoots].sort().map((registry) => `--remap-path-prefix=${registry}=/cargo`),
      `--remap-path-prefix=${rustupHome}=/rustup`,
    ];
    for (const flag of expectedRemaps) expect(rustcFlags).toContain(flag);

    const cargo = join(bin, "cargo");
    writeFileSync(cargo, '#!/usr/bin/env python3\nimport json,os,shlex,sys\nprint(json.dumps({"encoded":os.environ.get("CARGO_ENCODED_RUSTFLAGS"),"plain":os.environ.get("RUSTFLAGS"),"args":sys.argv[1:],"cflags":shlex.split(os.environ.get("CFLAGS","")),"cxxflags":shlex.split(os.environ.get("CXXFLAGS","")),"shellEscaped":os.environ.get("CC_SHELL_ESCAPED_FLAGS"),"targetCflags":{name:shlex.split(os.environ.get(name,"")) for name in ("CFLAGS_x86_64-unknown-linux-musl","CFLAGS_aarch64-unknown-linux-musl","CFLAGS_x86_64_unknown_linux_musl","CFLAGS_aarch64_unknown_linux_musl","CXXFLAGS_x86_64_unknown_linux_musl","CXXFLAGS_aarch64_unknown_linux_musl")}}))\n');
    chmodSync(cargo, 0o755);
    const cases = [
      {
        targetName: "x86_64-unknown-linux-musl",
        targetArgs: ["--target", "x86_64-unknown-linux-musl"],
        inherited: ["-C", "panic=unwind", "--cfg", 'a_value="with spaces"'],
        inheritedEnv: { RUSTFLAGS: `-C panic=unwind --cfg 'a_value="with spaces"'` },
      },
      {
        targetName: "x86_64-unknown-linux-musl",
        targetArgs: ["--target", "x86_64-unknown-linux-musl"],
        inherited: ["-C", "target-feature=+crt-static", "--cfg", 'a_value="with spaces"'],
        inheritedEnv: { RUSTFLAGS: `-C target-feature=+crt-static --cfg 'a_value="with spaces"'` },
      },
      {
        targetName: "aarch64-unknown-linux-musl",
        targetArgs: ["--target=aarch64-unknown-linux-musl"],
        inherited: ["--cfg", 'a_value="with spaces"'],
        inheritedEnv: { RUSTFLAGS: "-C panic=abort", CARGO_ENCODED_RUSTFLAGS: '--cfg\x1fa_value="with spaces"' },
      },
      {
        targetName: "x86_64-unknown-linux-musl",
        targetArgs: [],
        inherited: ["--cfg", 'a_value="with spaces"'],
        inheritedEnv: { CARGO_BUILD_TARGET: "x86_64-unknown-linux-musl", CARGO_ENCODED_RUSTFLAGS: '--cfg\x1fa_value="with spaces"' },
      },
    ];
    for (const item of cases) {
      const childEnv: NodeJS.ProcessEnv = { ...env };
      delete childEnv.RUSTFLAGS;
      delete childEnv.CARGO_ENCODED_RUSTFLAGS;
      delete childEnv.CARGO_BUILD_TARGET;
      for (const key of Object.keys(childEnv)) {
        if (/^(CFLAGS|CXXFLAGS)(_|$)/.test(key) || /^(HOST|TARGET)_(CFLAGS|CXXFLAGS)$/.test(key)) delete childEnv[key];
      }
      delete childEnv.CC_SHELL_ESCAPED_FLAGS;
      childEnv.CFLAGS = "-DGLOBAL=1 -DLEGACY='two words'";
      childEnv["CFLAGS_x86_64-unknown-linux-musl"] = "-DARCH_X=1";
      childEnv["CFLAGS_aarch64-unknown-linux-musl"] = "-DARCH_A=1";
      Object.assign(childEnv, item.inheritedEnv);
      const invocationResult = Bun.spawnSync([
        join(repository, "scripts/static-cargo"), "build", "--release", ...item.targetArgs,
      ], { env: childEnv });
      expect(invocationResult.exitCode).toBe(0);
      const invocation = JSON.parse(invocationResult.stdout.toString()) as {
        encoded: string | null;
        plain: string | null;
        args: string[];
        cflags: string[];
        cxxflags: string[];
        shellEscaped: string | undefined;
        targetCflags: Record<string, string[]>;
      };
      expect(invocation.encoded).toBeNull();
      expect(invocation.plain).toBeNull();
      expect(invocation.args.slice(-item.targetArgs.length - 2)).toEqual([
        "build", "--release", ...item.targetArgs,
      ]);
      const configs = invocation.args.flatMap((argument, index) => {
        const next = invocation.args[index + 1];
        return argument === "--config" && next !== undefined ? [next] : [];
      });
      expect(invocation.shellEscaped).toBe("1");
      expect(invocation.cflags).toContain("-DGLOBAL=1");
      expect(invocation.cflags).toContain("-DLEGACY='two");
      expect(invocation.cflags).toContain("words'");
      expect(invocation.targetCflags["CFLAGS_x86_64-unknown-linux-musl"]).toContain("-DARCH_X=1");
      expect(invocation.targetCflags["CFLAGS_aarch64-unknown-linux-musl"]).toContain("-DARCH_A=1");
      const expectedNativeRemaps = [
        ...registryRoots.map((registry) => `-ffile-prefix-map=${registry}=/cargo`),
        `-ffile-prefix-map=${target}=/build`,
        `-ffile-prefix-map=${cargoHome}=/cargo`,
        `-ffile-prefix-map=${repository}=/infraternal`,
      ];
      const targetSuffix = item.targetName.replaceAll("-", "_");
      const targetCflags = invocation.targetCflags[`CFLAGS_${targetSuffix}`];
      const targetCxxflags = invocation.targetCflags[`CXXFLAGS_${targetSuffix}`];
      for (const flag of expectedNativeRemaps) {
        expect(targetCflags).toContain(flag);
        expect(targetCxxflags).toContain(flag);
      }
      const selected = configs.find((config) => config.startsWith(`target.${item.targetName}.rustflags=`));
      expect(selected).toBeDefined();
      const targetFlags = JSON.parse(selected!.slice(selected!.indexOf("=") + 1)) as string[];
      const expectedInherited = withoutWorkspaceStaticFeature(item.inherited);
      expect(targetFlags.slice(0, expectedInherited.length)).toEqual(expectedInherited);
      expect(targetFlags.slice(-expectedStaticRemaps.length)).toEqual(expectedStaticRemaps);
      expect(targetFlags).not.toContain("target-feature=+crt-static");
      expect(targetFlags).not.toContain("-Ctarget-feature=+crt-static");
      const workspaceConfig = readFileSync(join(repository, ".cargo/config.toml"), "utf8");
      expect(workspaceConfig.match(/rustflags = \["-C", "target-feature=\+crt-static"\]/g)).toHaveLength(2);
      const otherTarget = item.targetName === "x86_64-unknown-linux-musl"
        ? "aarch64-unknown-linux-musl"
        : "x86_64-unknown-linux-musl";
      const otherConfig = configs.find((config) => config.startsWith(`target.${otherTarget}.rustflags=`));
      expect(otherConfig).toBeDefined();
      const otherFlags = JSON.parse(otherConfig!.slice(otherConfig!.indexOf("=") + 1)) as string[];
      const uniqueInherited = item.inherited.filter((flag) => flag !== "-C");
      expect(otherFlags.some((flag) => uniqueInherited.includes(flag))).toBe(false);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
