/** Replays the functional merge checks against the existing production-build harness with an IPv4 loopback URL. */
import { resolve } from "node:path";
import base from "../../apps/tracer/playwright.config.ts";
const app = resolve(import.meta.dirname, "../../apps/tracer");
const port = Number(process.env.TRACER_TEST_PORT);
const server = base.webServer;
if (!server || Array.isArray(server)) throw new Error("Expected the repository’s single tracer test server");
export default {
  ...base,
  testDir: resolve(app, "test"),
  outputDir: resolve(app, "test-results"),
  use: { ...base.use, baseURL: `http://127.0.0.1:${port}` },
  webServer: { ...server, cwd: app, url: `http://127.0.0.1:${port}/health` },
};
