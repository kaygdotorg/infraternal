/** Exercises the common compiler driver and packaging flag ownership (D243, #201, #229). */
import { expect, test } from "bun:test";
import { chmodSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const repository = resolve(import.meta.dir, "../..");
const scratch = process.env.CARGO_TARGET_DIR ?? resolve(repository, "target");

test("native metadata canonicalization retains version fields and refuses changed syntax", () => {
  const result = Bun.spawnSync(["python3", join(repository, "scripts/test-native-metadata.py")]);
  expect(result.exitCode).toBe(0);
});

test("one compiler driver remaps all source roots and preserves argument boundaries", () => {
  mkdirSync(scratch, { recursive: true });
  const root = mkdtempSync(join(scratch, "static-recipe-test-"));
  try {
    const bin = join(root, "bin"), cargoHome = join(root, "cargo"), target = join(root, "target with spaces");
    mkdirSync(bin);
    mkdirSync(join(cargoHome, "registry/src/index-one"), { recursive: true });
    mkdirSync(join(cargoHome, "registry/src/index two"));
    const compiler = join(bin, "compiler");
    writeFileSync(compiler, '#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n');
    chmodSync(compiler, 0o755);
    writeFileSync(join(bin, "rustup"), '#!/usr/bin/env sh\nprintf "%s\\n" "' + compiler + '"\n');
    chmodSync(join(bin, "rustup"), 0o755);
    const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, CARGO_HOME: cargoHome, CARGO_TARGET_DIR: target };
    const result = Bun.spawnSync([join(repository, ".cargo/rustc.sh"), "--cfg", 'a_value="with spaces"', "-C", "panic=unwind"], { env });
    expect(result.exitCode).toBe(0);
    const flags = JSON.parse(result.stdout.toString()) as string[];
    expect(flags.slice(0, 4)).toEqual(["--cfg", 'a_value="with spaces"', "-C", "panic=unwind"]);
    for (const [source, destination] of [[repository, "/infraternal"], [target, "/build"], [cargoHome, "/cargo"],
      [join(cargoHome, "registry/src/index-one"), "/cargo"], [join(cargoHome, "registry/src/index two"), "/cargo"]]) {
      expect(flags).toContain(`--remap-path-prefix=${source}=${destination}`);
    }
    writeFileSync(join(bin, "cargo"), '#!/usr/bin/env python3\nimport json,os,sys\nprint(json.dumps({"flags":os.environ.get("CARGO_ENCODED_RUSTFLAGS"),"plain":os.environ.get("RUSTFLAGS"),"args":sys.argv[1:]}))\n');
    chmodSync(join(bin, "cargo"), 0o755);
    for (const encoded of [false, true]) {
      const inherited = encoded ? '--cfg\x1fa_value="with spaces"' : "";
      const plain = encoded ? "" : "-C panic=unwind";
      const cargo = Bun.spawnSync([join(repository, "scripts/static-cargo"), "build", "--release", "--target", "x86_64-unknown-linux-musl"], {
        env: { ...env, RUSTFLAGS: plain, CARGO_ENCODED_RUSTFLAGS: inherited },
      });
      expect(cargo.exitCode).toBe(0);
      expect(JSON.parse(cargo.stdout.toString())).toEqual({ flags: inherited, plain,
        args: ["build", "--release", "--target", "x86_64-unknown-linux-musl"] });
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});
