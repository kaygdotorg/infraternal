/**
 * TEST DOUBLE: receives the frame meter's incident batches (`POST /__perf`, issue #116) and appends them to a file
 * the orchestrator can read, so a stutter on a real device reaches the person fixing it without being described.
 *
 * The file is `$XDG_STATE_HOME/infraternal-preview/perf/<port>.jsonl` (default `~/.local/state/...`;
 * `INFRATERNAL_PERF_DIR` replaces the directory, for tests). One JSON line per incident:
 *
 *   {"t":"incident","recv":"<ISO time the server received it>","recvMs":<epoch ms>,"sid":"<tab session id>",
 *    "page":"/?mock=1&proto=clusters...","kind":"drop|freeze","at":<epoch ms of the late frame>,"worstMs":..,
 *    "drops":..,"refreshHz":..,"activity":"pan|zoom|...","animations":{..},"ctx":{..},"intervals":[..],
 *    "loaf":[..],"longtasks":[..],"slowEvents":[..],"diag":{"stalls":[..],"ws":{..},"heap":{..}|null,"events":[..],
 *    "action":{..}|null,"support":{..}}}
 *
 * and, the first time a tab session is seen, one `{"t":"session",...,"session":{ua, platform, dpr, refreshHz, ...}}`
 * line before its incidents. A tab that hit its hourly cap sends `suppressed`, written as `{"t":"suppressed",...}`.
 *
 * Safety: same-origin posts only (a page on another origin cannot fill the disk through the visitor's browser),
 * bodies over 64 KiB are refused, an incident line over 16 KiB is dropped, and the file rotates at 20 MB (the old one
 * becomes `<port>.jsonl.1`). Nothing in a record is a secret: counts, timings, names of animations and scripts.
 */
import { appendFile, mkdir, rename, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { IncomingMessage, ServerResponse } from "node:http";

const MAX_BODY = 64 * 1024;
const MAX_LINE = 16 * 1024;
const ROTATE_AT = 20 * 1024 * 1024;

export function perfDir(): string {
  return process.env.INFRATERNAL_PERF_DIR ?? join(process.env.XDG_STATE_HOME || join(homedir(), ".local", "state"), "infraternal-preview", "perf");
}

export function createPerfSink(port: number): (request: IncomingMessage, response: ServerResponse) => Promise<void> {
  const file = join(perfDir(), `${port}.jsonl`);
  const seen = new Set<string>();
  let size: number | undefined;
  let queue: Promise<void> = Promise.resolve();

  const sameOrigin = (request: IncomingMessage): boolean => {
    const site = request.headers["sec-fetch-site"];
    if (typeof site === "string" && site !== "same-origin" && site !== "none") return false;
    const origin = request.headers.origin;
    if (origin === undefined) return true;
    try { return new URL(origin).host === request.headers.host; } catch { return false; }
  };
  const append = async (lines: string[]): Promise<void> => {
    await mkdir(perfDir(), { recursive: true });
    if (size === undefined) size = await stat(file).then((s) => s.size).catch(() => 0);
    const text = lines.join("\n") + "\n";
    if (size + text.length > ROTATE_AT) { await rename(file, `${file}.1`).catch(() => undefined); size = 0; }
    await appendFile(file, text);
    size += text.length;
  };

  return async (request, response) => {
    const reply = (status: number): void => { response.statusCode = status; response.setHeader("Cache-Control", "no-store"); response.end(); };
    if (request.method !== "POST") return reply(405);
    if (!sameOrigin(request)) return reply(403);
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const chunk of request) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += bytes.byteLength;
      if (total > MAX_BODY) { request.destroy(); return reply(413); }
      chunks.push(bytes);
    }
    let body: { sid?: unknown; page?: unknown; session?: unknown; suppressed?: unknown; incidents?: unknown };
    try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return reply(400); }
    if (typeof body !== "object" || body === null || typeof body.sid !== "string" || !Array.isArray(body.incidents)) return reply(400);
    const sid = body.sid.slice(0, 64);
    const page = typeof body.page === "string" ? body.page.slice(0, 300) : "";
    const now = Date.now();
    const base = { recv: new Date(now).toISOString(), recvMs: now, sid, page };
    const lines: string[] = [];
    if (!seen.has(sid) && typeof body.session === "object" && body.session !== null) {
      seen.add(sid);
      lines.push(JSON.stringify({ t: "session", ...base, session: body.session }));
    }
    if (typeof body.suppressed === "number" && body.suppressed > 0) lines.push(JSON.stringify({ t: "suppressed", ...base, count: body.suppressed }));
    for (const incident of body.incidents.slice(0, 50)) {
      if (typeof incident !== "object" || incident === null) continue;
      const line = JSON.stringify({ t: "incident", ...base, ...incident });
      if (line.length <= MAX_LINE) lines.push(line);
    }
    if (lines.length) {
      queue = queue.then(() => append(lines)).catch(() => undefined);
      await queue;
    }
    reply(204);
  };
}
