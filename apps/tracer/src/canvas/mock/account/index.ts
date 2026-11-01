/**
 * The person's card on the test double (`?mock=1&proto=clusters&account=1`): the card is the product's (`canvas/account`),
 * fed by a double that knows everything the server cannot say yet, with the review scaffolding around it: palette rows that open
 * every state at once, and the dev-only data toggle (Demo data / Worst case / Empty / One). Loaded on demand with the mockup; the
 * product has none of this file.
 */
import { ICON_INFO, ICONS } from "../../../../../../packages/ui/src/icons";
import type { CoreScreen, PaletteEntry } from "../../../core-screen";
import { mountAccountCard, type AccountMount } from "../../account";
import type { DataMode } from "../data-mode";
import { SCENARIOS, type AccountDouble } from "./double";
import { accountDouble } from "./store";

export interface AccountMock {
  double: AccountDouble;
  mount: AccountMount | undefined;
  entries(): PaletteEntry[];
  run(action: string): void;
  dispose(): void;
}

export function createAccountMock(core: CoreScreen, data: DataMode): AccountMock {
  const double = accountDouble();
  const mount = mountAccountCard({
    core, model: double,
    openSettings: (section) => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: `canvas:settings:${section}`, source: "pointer" } })),
  });
  // The toggle's data set replaces the person at the double (never in the markup).
  const stopData = data.subscribe((id) => { if (double.scenario() !== `data:${id}` && !(id === "demo" && double.scenario() === "community")) double.setData(id); });
  return {
    double, mount,
    entries: () => [
      { group: "Account", glyph: "◇", icon: ICON_INFO, label: "Your account", hint: "name · picture · email · sign-in", action: "proto:acct:open" },
      { group: "Account", glyph: "◇", icon: ICON_INFO, label: "Add or change email", hint: "optional · never part of sign-in", action: "proto:acct:email" },
      { group: "Account", glyph: "◇", icon: ICONS.lock, label: "Passkeys and recovery key", hint: "sign-in health · devices", action: "proto:acct:signin" },
      { group: "Account", glyph: "◇", icon: ICON_INFO, label: "Where you log in", hint: "accounts · machines · tags", action: "proto:acct:logins" },
      ...SCENARIOS.map((s): PaletteEntry => ({ group: "Mockup", glyph: "◇", label: `Mockup: account – ${s.label}`, hint: s.hint, action: `proto:acct:s:${s.id}` })),
      ...(["demo", "worst", "empty", "one"] as const).map((id): PaletteEntry => ({ group: "Mockup", glyph: "◇", label: `Mockup: account – data: ${id === "worst" ? "worst case" : id}`, hint: "the regression fixture", action: `proto:acct:d:${id}` })),
    ],
    run(action) {
      if (action === "open") { mount?.show(); return; }
      if (action === "email") { mount?.show((p) => p.editEmail()); return; }
      if (action === "signin") { mount?.show((p) => p.showSignIn()); return; }
      if (action === "logins") { mount?.show((p) => p.showLogins()); return; }
      if (action.startsWith("d:")) { data.set(action.slice(2) as "demo" | "worst" | "empty" | "one"); mount?.show(); return; }
      if (action.startsWith("s:")) { double.setScenario(action.slice(2)); mount?.show(); }
    },
    dispose() { stopData(); mount?.dispose(); },
  };
}
