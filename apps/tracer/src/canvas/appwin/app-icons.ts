/**
 * App icons, fetched one at a time by content hash and kept by hash (#146, D349).
 *
 * A window row names its app's icon by the SHA-256 of the PNG (`iconHash`). The first time a hash is shown, `AppIcons` asks the
 * server for it once (`desktop.icon`), checks what comes back, and keeps it: the same hash is always the same image, so it is never
 * asked for again while the page lives, whichever machine lists it. Until it arrives, or if it never does, the row keeps its letter
 * tile.
 *
 * The bytes come from another machine through the server, so they are checked here too: at most 16 KiB, the PNG signature, and a
 * SHA-256 equal to the name asked for. The image is shown from a `blob:` URL, never as HTML.
 */

/** The largest icon accepted, as the host and server also enforce. */
export const MAX_ICON_BYTES = 16 * 1024;
/** How many icons are kept; the least recently used goes first. */
const MAX_ICONS = 64;
/** A content hash: 64 lowercase hex digits. */
const HASH = /^[0-9a-f]{64}$/;
/** The first eight bytes of every PNG. */
const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

/** True when `value` is a content hash as window rows carry it. */
export const isIconHash = (value: unknown): value is string => typeof value === "string" && HASH.test(value);

/** How icons are fetched: one server action call. */
export type IconCall = (actionId: string, input: Record<string, unknown>) => Promise<Record<string, unknown>>;

/** Decodes base64 to bytes, or `undefined` for text that is not base64 or decodes past the size limit. */
function decode(base64: unknown): Uint8Array<ArrayBuffer> | undefined {
  if (typeof base64 !== "string" || base64.length > Math.ceil(MAX_ICON_BYTES / 3) * 4) return undefined;
  try {
    const text = atob(base64);
    const bytes = new Uint8Array(text.length);
    for (let i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i);
    return bytes;
  } catch {
    return undefined;
  }
}

/** The lowercase hex SHA-256 of `bytes`. */
async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Checks one fetched icon and returns its bytes, or `undefined` when it is not the PNG named `hash`. */
export async function checkedIcon(reply: Record<string, unknown>, hash: string): Promise<Uint8Array<ArrayBuffer> | undefined> {
  const bytes = decode(reply.png);
  if (!bytes || bytes.length < PNG_SIGNATURE.length || bytes.length > MAX_ICON_BYTES) return undefined;
  if (!PNG_SIGNATURE.every((byte, i) => bytes[i] === byte)) return undefined;
  return await sha256(bytes) === hash ? bytes : undefined;
}

/**
 * The page's icons by hash. `url(hash)` answers at once with a `blob:` URL when the icon is here; `load(host, hash)` fetches it
 * (concurrent loads of one hash share one call) and resolves to the URL, or `undefined` when the host had none or sent something
 * that failed the checks. `onChange` fires when an icon arrives, so a list can redraw its rows.
 */
export class AppIcons {
  private readonly urls = new Map<string, string>();
  private readonly loading = new Map<string, Promise<string | undefined>>();
  /** The previous fetch must settle before more icon bytes enter the connection. */
  private tail: Promise<unknown> = Promise.resolve();
  /** Queued loads are dropped and late replies cannot create URLs after disposal. */
  private disposed = false;
  /** Hashes that failed once: they are not asked for again while the page lives. */
  private readonly failed = new Set<string>();
  private readonly listeners = new Set<() => void>();

  /** `call` runs one server action; icons are asked for with `desktop.icon`. */
  constructor(private readonly call: IconCall) {}

  /** The icon's URL if it is here (and marks it recently used), else `undefined`. */
  url(hash: string): string | undefined {
    const url = this.urls.get(hash);
    if (url === undefined) return undefined;
    this.urls.delete(hash);
    this.urls.set(hash, url);
    return url;
  }

  /** Runs `listener` whenever an icon arrives. Returns the unsubscribe function. */
  onChange(listener: () => void): () => void { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; }

  /** Fetches icon `hash` from machine `hostId`, once. */
  load(hostId: string, hash: string): Promise<string | undefined> {
    const here = this.url(hash);
    if (here !== undefined) return Promise.resolve(here);
    if (this.disposed || !isIconHash(hash) || this.failed.has(hash)) return Promise.resolve(undefined);
    const running = this.loading.get(hash);
    if (running) return running;
    const job = this.tail.then(async () => {
      if (this.disposed) return undefined;
      const reply = await this.call("desktop.icon", { host_id: hostId, sha256: hash });
      return checkedIcon(reply, hash);
    })
      .then((bytes) => {
        if (this.disposed) return undefined;
        if (!bytes) { this.failed.add(hash); return undefined; }
        const url = URL.createObjectURL(new Blob([bytes], { type: "image/png" }));
        this.urls.set(hash, url);
        this.trim();
        for (const listener of [...this.listeners]) listener();
        return url;
      }, () => undefined)
      .finally(() => { this.loading.delete(hash); });
    this.loading.set(hash, job);
    this.tail = job;
    return job;
  }

  /** Lets go of every icon (and its blob URL). */
  dispose(): void {
    this.disposed = true;
    for (const url of this.urls.values()) URL.revokeObjectURL(url);
    this.urls.clear();
    this.listeners.clear();
  }

  /** Drops the least recently used icons beyond the cap. */
  private trim(): void {
    while (this.urls.size > MAX_ICONS) {
      const [oldest, url] = this.urls.entries().next().value as [string, string];
      URL.revokeObjectURL(url);
      this.urls.delete(oldest);
    }
  }
}
