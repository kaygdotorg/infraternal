/** Holds unapproved recovery presentation [D162, #45/#83]; backend and crypto stay enabled.
 * Builds default to off. INFRATERNAL_RECOVERY_UI=preview permits only the explicit
 * mock prototype URL; =1 is the deliberate production build opt-in after approval.
 */
declare const __RECOVERY_UI_MODE__: "off" | "preview" | "1";

/**
 * Whether the recovery screens may be shown. The build decides: `off` never, `1` always, and `preview` only on the mock
 * address `?mock=1&proto=recovery`. Pass a query string to test a different address.
 */
export function recoveryUiEnabled(search = location.search): boolean {
  if (__RECOVERY_UI_MODE__ === "1") return true;
  if (__RECOVERY_UI_MODE__ !== "preview") return false;
  const query = new URLSearchParams(search);
  return query.get("mock") === "1" && query.get("proto") === "recovery";
}
