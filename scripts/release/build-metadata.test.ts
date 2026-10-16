/** Exercises compiler metadata and source path canonicalization before shipping builds (D243, #229). */
import { expect, test } from "bun:test";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const repository = resolve(import.meta.dir, "../..");
const scratch = process.env.CARGO_TARGET_DIR ?? resolve(repository, "target");

test("compiler metadata retains flags and wrapper identity across checkout locations", () => {
  mkdirSync(scratch, { recursive: true });
  const root = mkdtempSync(join(scratch, "metadata-test-"));
  try {
    mkdirSync(join(root, "util"));
    const generator = join(root, "util/mkbuildinf.pl");
    writeFileSync(generator, 'my $cflags = join(" ", @ARGV);\n$cflags = "compiler: $cflags";\nprint $cflags;\n');
    chmodSync(generator, 0o755);
    for (let attempt = 0; attempt < 2; attempt++) {
      const patch = Bun.spawnSync(["python3", join(repository, "scripts/patch-openssl-build-metadata.py"), root]);
      expect(patch.exitCode).toBe(0);
    }
    expect(readFileSync(generator, "utf8").match(/compiler:/g)).toHaveLength(1);
    expect(statSync(generator).mode & 0o777).toBe(0o755);
    for (const wrapper of ["musl-cc.sh", "musl-cc-avx512.sh"]) {
      for (const checkout of ["/a/short", "/a much longer/checkout"]) {
        for (const quoted of [false, true]) {
          const compiler = `${checkout}/.cargo/${wrapper}`;
          const options = "-O2 -fPIC -DVALUE=1 -DWRAPPER=/other/.cargo/musl-cc.sh";
          const command = quoted ? `cache-launcher "${compiler}"` : compiler;
          const result = Bun.spawnSync(["perl", generator, `${command} ${options}`]);
          expect(result.exitCode).toBe(0);
          expect(result.stdout.toString()).toBe(`compiler: .cargo/${wrapper} ${options}`);
        }
      }
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});


test("static Cargo remaps source paths and preserves encoded flags and arguments", () => {
  mkdirSync(scratch, { recursive: true });
  const root = mkdtempSync(join(scratch, "static-recipe-test-"));
  try {
    const bin = join(root, "bin"), cargoHome = join(root, "cargo"), target = join(root, "target with spaces");
    mkdirSync(bin);
    mkdirSync(join(cargoHome, "registry/src/index-one"), { recursive: true });
    mkdirSync(join(cargoHome, "registry/src/index two"));
    const cargo = join(bin, "cargo");
    writeFileSync(cargo, '#!/usr/bin/env python3\nimport json,os,sys\nprint(json.dumps({"flags":os.environ["CARGO_ENCODED_RUSTFLAGS"].split("\\x1f"),"args":sys.argv[1:]}))\n');
    chmodSync(cargo, 0o755);
    for (const encoded of [false, true]) {
      const result = Bun.spawnSync([join(repository, "scripts/static-cargo"), "build", "--release", "--target", "x86_64-unknown-linux-musl"], {
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, CARGO_HOME: cargoHome, CARGO_TARGET_DIR: target,
          RUSTFLAGS: encoded ? "" : "-C panic=unwind", CARGO_ENCODED_RUSTFLAGS: encoded ? "--cfg\x1fa_value=\"with spaces\"" : "" },
      });
      expect(result.exitCode).toBe(0);
      const value = JSON.parse(result.stdout.toString()) as {flags: string[]; args: string[]};
      expect(value.args).toEqual(["build", "--release", "--target", "x86_64-unknown-linux-musl"]);
      expect(value.flags.slice(0, 2)).toEqual(["-C", "target-feature=+crt-static"]);
      expect(value.flags).toContain(`--remap-path-prefix=${repository}=/infraternal`);
      expect(value.flags).toContain(`--remap-path-prefix=${target}=/build`);
      expect(value.flags).toContain(`--remap-path-prefix=${cargoHome}/registry/src/index-one=/cargo`);
      expect(value.flags).toContain(`--remap-path-prefix=${cargoHome}/registry/src/index two=/cargo`);
      expect(value.flags).toContain(encoded ? 'a_value="with spaces"' : "panic=unwind");
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});
