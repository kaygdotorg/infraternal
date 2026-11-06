// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Guards the mock-backed browser suite (`playwright.config.ts`) against running with more than one worker.
 *
 * Every spec in `test/` talks to one shared test double, and each spec starts with `/__mock/reset`. A second worker's reset
 * ends the first worker's session, so its page shows the sign-in card ("Your session ended") for reasons that have nothing to
 * do with the code under test (#377). The config pins `workers: 1`, but `--workers` on the command line overrides that, so the
 * config asks this module first and refuses to start with a plain message.
 */
import { availableParallelism } from "node:os";

/** What the person asked for on the command line or in the environment, or `undefined` when they said nothing. */
export function requestedWorkers(argv: readonly string[], env: Readonly<Record<string, string | undefined>>): string | undefined {
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    const inline = /^(?:--workers|-j)=?(.+)$/.exec(arg);
    if (inline && arg !== "--workers" && arg !== "-j") return inline[1];
    if ((arg === "--workers" || arg === "-j") && argv[i + 1] !== undefined) return argv[i + 1];
  }
  return env.PW_WORKERS;
}

/** The worker count a request resolves to: a number as given, a percentage of this machine's cores (at least 1). */
export function resolvedWorkers(request: string, cores = availableParallelism()): number {
  const percent = /^(\d+(?:\.\d+)?)%$/.exec(request);
  if (percent) return Math.max(1, Math.floor((cores * Number(percent[1])) / 100));
  const count = Number(request);
  return Number.isFinite(count) ? Math.floor(count) : 1;
}

/**
 * The message to fail with when the request resolves to more than one worker, otherwise `undefined`.
 * Call it from the config of the project that uses the shared test double.
 */
export function sharedDoubleWorkersError(argv: readonly string[], env: Readonly<Record<string, string | undefined>>, cores?: number): string | undefined {
  const request = requestedWorkers(argv, env);
  if (request === undefined) return undefined;
  const workers = resolvedWorkers(request, cores);
  if (workers <= 1) return undefined;
  return `The browser specs in apps/tracer/test run with one worker, but ${workers} were requested (${request}). They share one test double, `
    + "and every spec starts with the same /__mock/reset, so a second worker's reset ends the first worker's session and its page falls back "
    + "to the sign-in card. Run without --workers (or with --workers=1) and unset PW_WORKERS.";
}
