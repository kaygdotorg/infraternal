// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The inside of Settings › Machines › Updates (#211, S5): what this server's automatic update is doing, the two settings that
 * steer it, the buttons the owner can press, and the history. It is drawn from an `UpdatesSource` and repaints when the source
 * says something changed, so the window needs nothing else.
 *
 *   Status       ✓ Up to date                       one row, the value is the state; pressing it checks now
 *   Running      0.4.2 · stable
 *   Last checked 2 minutes ago
 *   [Update now] [Check now] [Roll back]            only the buttons that can act are enabled
 *   Channel      ( Stable | Edge )                  the shared settings rows
 *   Quiet window  5 min
 *   History      0.5.0 installed · from 0.4.2 · 2 hours ago
 *
 * Roll back asks first and says what is lost (D295). Every call needs the owner and a fresh sign-in; the server says no in a
 * sentence and the window shows it as a toast, never a second place of its own. On demand (D188): Settings loads this with the window.
 */
import { createKeyValueList, type KeyValueRow } from "../../../../../packages/ui/src/kv-list";
import { createSettingRow } from "../../../../../packages/ui/src/setting-row";
import { heading } from "../../../../../packages/ui/src/settings-panels";
import type { SettingValue, ValueSpec } from "../../../../../packages/ui/src/setting-value";
import { mountConfirmTip } from "../../../../../packages/ui/src/tooltip";
import { el } from "../dom";
import type { Ctx } from "../context";
import type { Channel, UpdatesSource } from "./source";
import { ago, buttons, historyLine, rollbackConfirm, statusLine } from "./words";

/** The channel: stable by default, edge opt-in and "may break" (D185, D186). */
const CHANNEL: ValueSpec = { kind: "choice", default: "stable", options: [{ id: "stable", label: "Stable" }, { id: "edge", label: "Edge" }] };
/** How long nothing may be typed before an update applies (the quiet window of the plan: 5 minutes). */
const QUIET: ValueSpec = { kind: "duration", unit: "min", default: 5, min: 1, max: 120 };

/** How many history lines the window shows before "older ones are kept". */
const HISTORY_SHOWN = 8;

/** Makes a button of the shared button style with a plain verb as its label. */
function button(label: string, kind: "primary" | "secondary"): HTMLButtonElement {
  const b = el("button", "ui-button cl-up-button");
  b.type = "button";
  b.dataset.button = kind;
  b.textContent = label;
  return b;
}

/** Draws the Updates window into `pane`. Returns the cleanup. */
export function renderUpdates(cx: Ctx, pane: HTMLElement, source: UpdatesSource): () => void {
  const root = el("div", "ui-sp cl-up");
  const status = createKeyValueList("Updates");
  const detail = el("p", "cl-up-detail");
  const actions = el("div", "cl-up-actions");
  const apply = button("Update now", "primary");
  const check = button("Check now", "secondary");
  const back = button("Roll back", "secondary");
  actions.append(apply, check, back);

  const settings = el("div", "ui-setting-list");
  const refuse = (error: unknown): string => (error instanceof Error ? error.message : "That did not work. Try again.");
  const channel = createSettingRow({
    id: "update-channel", title: "Channel", spec: CHANNEL, value: source.facts().channel,
    explain: "Stable is the tested release. Edge gets every build first and may break.",
    onSave: (v: SettingValue) => source.setChannel(v as Channel).then(() => undefined, refuse),
  });
  const quiet = createSettingRow({
    id: "update-quiet", title: "Quiet Window", spec: QUIET, value: source.facts().quietMinutes,
    explain: "An update installs only after nobody has typed or opened a session for this long.",
    onSave: (v: SettingValue) => source.setQuietMinutes(Number(v)).then(() => undefined, refuse),
  });
  settings.append(channel.root, quiet.root);

  const historyHead = heading("History");
  const history = createKeyValueList("Update history");
  const older = el("p", "cl-settings-later");
  root.append(status.root, detail, actions, settings, historyHead, history.root, older);
  pane.append(root);

  /** Runs one owner action; a refusal (not the owner, no fresh sign-in, nothing to do) is said once as a toast. */
  const run = (work: () => Promise<void>): void => { void work().catch((error: unknown) => cx.toast.show({ message: refuse(error), tone: "error" })); };

  apply.addEventListener("click", () => run(() => source.apply()));
  check.addEventListener("click", () => run(() => source.check()));
  back.addEventListener("click", () => {
    const { rollback } = source.facts();
    if (!rollback.available) return;
    mountConfirmTip(back, { ...rollbackConfirm(rollback.to, rollback.lost), named: true, onConfirm: () => run(() => source.rollback()) });
  });

  const paint = (): void => {
    const facts = source.facts();
    const now = Date.now();
    const line = statusLine(facts.state, facts.quietMinutes);
    const can = buttons(facts);
    const rows: KeyValueRow[] = [
      { key: "Status", value: line.value, ...(line.mark ? { mark: line.mark } : {}), ...(line.meter !== undefined ? { meter: line.meter } : {}),
        ...(can.check ? { press: { tip: "Check for updates now", run: () => run(() => source.check()) } } : {}) },
      { key: "Running", value: `${facts.running} · ${facts.channel}` },
    ];
    if (facts.checkedAt !== undefined) rows.push({ key: "Last Checked", value: ago(facts.checkedAt, now) });
    status.set(rows);
    detail.textContent = line.detail ?? "";
    detail.toggleAttribute("hidden", !line.detail);
    detail.dataset.tone = line.mark ?? "";
    apply.disabled = !can.apply;
    check.disabled = !can.check;
    back.disabled = !can.rollback;
    back.dataset.tip = facts.rollback.available ? `Go back to ${facts.rollback.to}` : "No earlier version is kept yet";
    // A value the owner is typing is left alone: only a different stored value is put on screen.
    if (channel.value() !== facts.channel) channel.set(facts.channel);
    if (quiet.value() !== facts.quietMinutes) quiet.set(facts.quietMinutes);
    history.set(facts.history.slice(0, HISTORY_SHOWN).map((entry): KeyValueRow => {
      const text = historyLine(entry, now);
      return { key: text.title, value: ago(entry.at, now), hint: text.sub.split("\n").slice(1).join(" ") || `from ${entry.from}` };
    }));
    historyHead.hidden = history.root.hidden = facts.history.length === 0;
    older.textContent = facts.history.length > HISTORY_SHOWN ? `${facts.history.length - HISTORY_SHOWN} older updates are kept.` : "";
    older.toggleAttribute("hidden", !older.textContent);
  };
  paint();
  const stop = source.onChange(paint);
  return () => { stop(); channel.dispose(); quiet.dispose(); status.dispose(); history.dispose(); root.remove(); };
}
