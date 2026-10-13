/** Resolves browser review artifacts to a process-specific evidence directory outside the checkout. */
import { homedir } from "node:os";
import { mkdirSync } from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const configuredRoot = process.env.INFRATERNAL_EVIDENCE_DIR;
const evidenceRoot = resolve(
  configuredRoot ?? resolve(homedir(), ".cache", "codex-scratch", `tracer-${process.pid}`, "evidence"),
);
const repositoryRelativeRoot = relative(repositoryRoot, evidenceRoot);
if (repositoryRelativeRoot === "" || (repositoryRelativeRoot !== ".." && !repositoryRelativeRoot.startsWith(`..${sep}`))) {
  throw new Error("browser evidence output must stay outside the repository checkout");
}

export function tracerEvidencePath(...segments: string[]): string {
  const path = resolve(evidenceRoot, ...segments);
  const relativePath = relative(evidenceRoot, path);
  if (relativePath === ".." || relativePath.startsWith(`..${sep}`)) {
    throw new Error("browser evidence path must stay within its external evidence directory");
  }
  mkdirSync(dirname(path), { recursive: true });
  return path;
}
