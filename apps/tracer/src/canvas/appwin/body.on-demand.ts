/** Mounts an app-window stream after this window kind crosses the on-demand boundary. */
import { el } from "../dom";
import type { Ctx, WinRec } from "../context";

/** Resolves the runtime and binds the stream only while the window still belongs to a live canvas. */
export function mountAppWindowBody(cx: Ctx, rec: WinRec): void {
  const body = rec.card.body;
  const unavailable = (): void => {
    const box = el("div", "cl-noaccess");
    box.innerHTML = '<p class="cl-noaccess-title">App windows are off</p><p class="cl-noaccess-hint">Turn them on in Settings, Hosts, then open this window again.</p>';
    body.replaceChildren(box);
  };
  if (cx.signal.aborted || rec.closing || rec.owner.wins.get(rec.model.id) !== rec) return;
  const adapter = cx.adapters.appWindows;
  const loading = cx.appWindows?.load();
  if (!adapter || !loading) { unavailable(); return; }
  void loading.then((runtime) => {
    if (cx.signal.aborted || rec.closing || rec.owner.wins.get(rec.model.id) !== rec) return;
    const binding = adapter.available() ? runtime?.bindingFor(rec) : undefined;
    if (!binding) { unavailable(); return; }
    rec.binding = binding;
    // A window opened from the picker is made the active one before its binding exists, so nothing has told the binding yet:
    // without this its first press would look like "already active" to the canvas and never be treated as the one that acts.
    if (cx.state.activeWin === rec) binding.setActive(true);
    binding.mount(body);
    cx.visibility.watch(rec);
  }).catch(() => { if (!cx.signal.aborted && !rec.closing) unavailable(); });
}
