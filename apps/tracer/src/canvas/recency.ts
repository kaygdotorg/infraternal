/**
 * The most recently used windows of a view (the view's hover card lists the first five, #121).
 *
 * A window counts as used when it becomes the active window (`setActive`), which is also how a focus or a
 * typed keystroke reaches it: typing goes to the active window. Nothing is recorded per keystroke, and nothing
 * is persisted: the list is rebuilt from what the person does in this session, and it is capped, so it stays a
 * few entries per view however long the canvas is open.
 *
 * Items are window ids, not window records. A closed window keeps its id here until the list is capped out, but
 * it keeps no DOM or session alive; readers look each id up in the view and skip the ones that are gone.
 */
export class RecentList<T> {
  private items: T[] = [];
  constructor(private readonly cap = 16) {}

  /** Moves `item` to the front (most recent). A repeat of the front item costs one comparison. */
  touch(item: T): void {
    if (this.items[0] === item) return;
    const at = this.items.indexOf(item);
    if (at >= 0) this.items.splice(at, 1);
    this.items.unshift(item);
    if (this.items.length > this.cap) this.items.length = this.cap;
  }

  /** The most recent items that `live` accepts, at most `n`, most recent first. */
  top(n: number, live: (item: T) => boolean): T[] {
    const out: T[] = [];
    for (const item of this.items) {
      if (out.length >= n) break;
      if (live(item)) out.push(item);
    }
    return out;
  }

  get size(): number {
    return this.items.length;
  }
}

/**
 * The rows a view's hover card shows: the used windows first (most recent first), then the rest in the view's own
 * order, up to `n`. A view that has not been used yet lists its first windows in order; a view with three windows
 * always shows three. `all` is the view's windows in order.
 */
export function recentRows<W>(recent: RecentList<string> | undefined, all: Map<string, W>, n: number): W[] {
  const used = recent?.top(n, (id) => all.has(id)) ?? [];
  const rows: W[] = used.map((id) => all.get(id) as W);
  for (const win of all.values()) {
    if (rows.length >= n) break;
    if (!rows.includes(win)) rows.push(win);
  }
  return rows;
}
