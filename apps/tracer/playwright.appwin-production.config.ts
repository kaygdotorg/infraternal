/** Exercises capability and preference gating in the actual production bundle; no preview define or UI test hooks [D208]. */
import { defineConfig } from "playwright/test";
import base from "./playwright.config";

/** The base config's shared test server; this config reuses it with the clusters preview turned off. */
const server = base.webServer;
if (!server || Array.isArray(server)) throw new Error("app-window production checks need the shared single test server");
/** The shared config limited to the app-window production spec, with the clusters preview turned off so the real capability gating runs. */
export default defineConfig({
  ...base,
  testMatch: "appwin-production.spec.ts",
  webServer: { ...server, env: { ...server.env, INFRATERNAL_CLUSTERS_PREVIEW: "0" } },
});
