// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The palette rows that act on a host (#215, #259), built by an on-demand module (D188) the palette loads at idle: "Remove
 * host: <host>" where the instance offers removal, "Allow full access on <host>" where it has a privilege service, and
 * "Rename <host>" for the Mesh's hosts. An owner can Forget an expired pending removal on its existing row (D369). Rows are computed each time the palette opens, like the rest.
 */
import { ICON_KEY } from "../../../../../packages/ui/src/icons";
import type { PaletteEntry } from "../../core-screen";
import type { Ctx } from "../context";
import { isFreeView } from "../layout/stops";
import { SESSION_ICON } from "../views/icons";

/** Builds the palette rows that act on hosts. Rows are made fresh each time the palette opens, and only for what this instance offers. */
export function hostEntries(cx: Ctx): PaletteEntry[] {
  const out: PaletteEntry[] = [];
  const removal = cx.adapters.hostRemoval;
  for (const host of cx.adapters.sessions.hosts()) {
    if (host.state) {
      const canForget = host.state === "retired-unreachable" && removal?.label() && removal.forget;
      out.push({ group: "Hosts", glyph: canForget ? "×" : "…", label: canForget ? `Forget ${host.name}` : host.name, ...(canForget ? { action: `canvas:forgethost:${host.id}` } : {}), hint: canForget ? "unreachable" : host.state === "pending" ? "removal pending · access revoked" : "retired-unreachable · cleanup certificate expired" });
      continue;
    }
    if (host.id !== "embedded" && removal?.label()) out.push({ group: "Hosts", glyph: "×", label: `${removal.label()}: ${host.name}`, hint: "revoke access · uninstall", action: `canvas:removehost:${host.id}` });
    // The consent for full access: found by typing, like every action; it opens the machine's details on the row.
    if (cx.adapters.privilege && !cx.adapters.privilege.isFull(host.name)) out.push({ group: "Hosts", glyph: "✓", icon: ICON_KEY, label: `Allow full access on ${host.name}`, hint: "host · privileged access", action: `canvas:access:${encodeURIComponent(host.name)}`, queryOnly: true });
  }
  // Mesh hosts by name, so "rename build-01" finds the way to the host's name field (the palette reaches everything). Only
  // while the Mesh draws each host as a card; a big mesh has no card to put the field on.
  const meshView = cx.views.get("mesh");
  if (cx.mesh && cx.adapters.mesh?.status() === "ready" && meshView && !isFreeView(meshView.view)) {
    for (const name of cx.adapters.mesh.data().nodes.keys()) out.push({ group: "Mesh", glyph: "✎", icon: SESSION_ICON.rename, label: `Rename ${name}`, hint: "mesh · host · name", action: `canvas:rename:${encodeURIComponent(name)}` });
  }
  return out;
}
