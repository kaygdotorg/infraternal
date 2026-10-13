/** Resolves verification artifacts to a job-owned directory outside the checkout. */
import { homedir } from "node:os";
import { join, relative, resolve, sep } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "..");

export function evidencePath(job, ...segments) {
  const configuredRoot = process.env.INFRATERNAL_EVIDENCE_DIR;
  const evidenceRoot = resolve(configuredRoot ?? join(homedir(), ".cache", "codex-scratch", `${job}-${process.pid}`, "evidence"));
  const repositoryRelativeRoot = relative(repositoryRoot, evidenceRoot);
  if (repositoryRelativeRoot === "" || (repositoryRelativeRoot !== ".." && !repositoryRelativeRoot.startsWith(`..${sep}`))) {
    throw new Error("evidence output must stay outside the repository checkout");
  }
  const path = resolve(evidenceRoot, ...segments);
  const relativePath = relative(evidenceRoot, path);
  if (relativePath === ".." || relativePath.startsWith(`..${sep}`)) {
    throw new Error("evidence output path must stay inside its external evidence directory");
  }
  return path;
}
