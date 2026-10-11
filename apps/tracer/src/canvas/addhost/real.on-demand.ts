/**
 * The on-demand entry for the real provisioning glue (#87, D188). The product canvas imports this only when the
 * add-host wizard first opens, so the glue never weighs on the canvas's deferred load. It re-exports `real.ts`, which
 * the mock canvas also imports statically.
 */
export { createRealProvisioning } from "./real";
