// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The name the browser test double gives as "this host" (`mock-server.ts`) and that specs expect to see (`core-screen.spec.ts`).
 *
 * It is a constant and not the build machine's `os.hostname()` because the name is drawn in the machine pill and in the Views
 * tree: a long machine name (compute01's is 28 characters) widened the pill past its panel and made layout specs fail on one
 * build host and pass on another. Keep it short.
 */
export const DOUBLE_HOSTNAME = "test-host";
