// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The demo dataset of the docs' figures (#302): the same mock world the mockups use, with plain, friendly names.
 *
 * A figure in the user docs is a picture of the real product, and the product's mock world carries the names of the people
 * who build it: their machines, their account, their addresses. A documentation page must show a home server, a NAS and a
 * person called Maya Patel. So the pictures are captured from a build of the same mock world in which those names are
 * replaced, and nowhere else:
 *
 * - It is a build-time transform (`docsDatasetPlugin`, used only when `TRACER_DATASET=docs`; build.ts). The normal build, the
 *   product and the other specs never see it, and there is no flag in any shipped code that could switch it on.
 * - The mock world's text is rewritten by name, whole words only (`renameDataset`): hosts, people, and private addresses.
 *   Because it rewrites the source text, every place a name appears changes together, including ones nobody remembers.
 * - The capture refuses to take a picture while any internal name is on the page (`LEAKS`, figures/capture.ts), so a name the
 *   rewrite misses is a failed capture, not a published screenshot.
 *
 * The test double's fixtures (hosts, sessions) are rewritten the same way when it runs for the docs (test/docs-fixtures.ts).
 */
import type { BunPlugin } from "bun";

/** Machines: the internal names on the left, what a reader of the docs sees on the right. */
export const DOCS_HOSTS: ReadonlyArray<readonly [string, string]> = [
  ["build-01", "home-server"], ["edge-arm", "raspberry-pi"], ["nix-cache", "media-server"], ["studio-mac", "work-laptop"],
  ["fra-relay", "cloud-relay"], ["monitor01", "garage-pi"], ["db-01", "database"], ["ci-02", "build-box"], ["gpu-01", "gaming-pc"],
  ["lab-01", "lab-pc-1"], ["lab-02", "lab-pc-2"], ["lab-03", "lab-pc-3"], ["infraternal-dev", "home-server"],
];
/** People, longest first so "Kay G" is not caught by a shorter rule. */
export const DOCS_PEOPLE: ReadonlyArray<readonly [string, string]> = [
  ["Kay G", "Maya Patel"], ["Asha Verma", "Sam Lee"], ["Ravi Menon", "Alex Kim"],
  ["kayg", "maya"], ["asha", "sam"], ["ravi", "alex"], ["mira", "sam"],
];

/** A pattern that matches `name` only as a whole word (not part of a longer word or a hyphenated name), with special characters escaped. */
const WORD = (name: string): RegExp => new RegExp(`(?<![\\w-])${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w-])`, "g");
/** The name replacements in the order they are applied: people first, then machines. */
const RULES: ReadonlyArray<readonly [RegExp, string]> = [...DOCS_PEOPLE, ...DOCS_HOSTS].map(([from, to]) => [WORD(from), to] as const);
/** Private addresses become the documentation range (RFC 5737), keeping the last number so two hosts stay two addresses. */
const PRIVATE_ADDRESS = /\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.(\d{1,3})\b/g;
/** The mesh's own addresses (100.64.0.0/10, shared address space) become a second documentation range. */
const MESH_ADDRESS = /\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.(\d{1,3})\b/g;

/** Rewrites the mock world's names in a piece of text. Pure; the same text always gives the same result. */
export function renameDataset(text: string): string {
  let out = text.replace(PRIVATE_ADDRESS, "192.0.2.$1").replace(MESH_ADDRESS, "198.51.100.$1");
  for (const [pattern, to] of RULES) out = out.replace(pattern, to);
  return out;
}

/**
 * What must not be on a page that is about to become a figure: the internal names (as whole words), a private or loopback address,
 * a public address outside the documentation ranges, and anything shaped like a key.
 */
export const LEAKS: ReadonlyArray<RegExp> = [
  ...[...DOCS_PEOPLE, ...DOCS_HOSTS].map(([from]) => WORD(from)),
  /\bcompute0\d\b|\bssh\.kayg\.org\b|\bkayg\.org\b|\bmonitor0\d\b/,
  /\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b/,
  /\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b/,
  /\b(?!192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.0\.0\.1\b|0\.0\.0\.0\b)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
  /ssh-(?:ed25519|rsa) [A-Za-z0-9+/]{20,}|-----BEGIN [A-Z ]*KEY-----|\bAAAA[A-Za-z0-9+/]{30,}/,
];

/** Names found in `text` that must not appear in a figure; empty when it is clean. */
export function findLeaks(text: string): string[] {
  return [...new Set(LEAKS.flatMap((pattern) => [...text.matchAll(new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`))].map((match) => match[0])))];
}

/**
 * A fixture as the test double serves it: unchanged normally, with the docs' names when the double runs for the docs
 * (`TRACER_DATASET=docs`). It is applied where the fixtures are defined, not where they are sent, so every lookup the double
 * makes by id (a host the person picks, a session they open) finds what the page was told.
 */
export function forDocs<T>(fixture: T): T {
  return process.env.TRACER_DATASET === "docs" ? JSON.parse(renameDataset(JSON.stringify(fixture))) as T : fixture;
}

/** Where the mock world lives in the app's source: the only files the transform touches. */
const MOCK_WORLD = /[\\/](?:canvas[\\/]mock[\\/].*|add-host-prototype|add-host-contract)\.ts$/;

/** The build-time transform for `TRACER_DATASET=docs` (build.ts). */
export const docsDatasetPlugin: BunPlugin = {
  name: "docs-dataset",
  setup(builder) {
    builder.onLoad({ filter: MOCK_WORLD }, async (args) => {
      const text = await Bun.file(args.path).text();
      const renamed = renameDataset(text);
      return renamed === text ? undefined : { contents: renamed, loader: "ts" };
    });
  },
};
