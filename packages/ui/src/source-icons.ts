/** Shared source marks for host discovery rows and their accessible source labels. */

/** Where a discovered host came from; each has one mark. `already-added` marks a host that is already in the list. */
export type HostSource = "netbird" | "tailscale" | "known-hosts" | "ssh-config" | "already-added";

/** The SVG body (24 by 24 viewBox, stroke only) of each source's mark. */
const SOURCE_MARKS: Record<HostSource, string> = {
  netbird: '<circle cx="6" cy="12" r="2.2"/><circle cx="18" cy="6" r="2.2"/><circle cx="18" cy="18" r="2.2"/><path d="m8 11 7.8-4M8 13l7.8 4"/>',
  tailscale: '<circle cx="6" cy="6" r="2.2"/><circle cx="18" cy="6" r="2.2"/><circle cx="12" cy="18" r="2.2"/><path d="M8.2 7.2 10.9 16m4.9 0 2.7-8.8M8.3 6h7.4"/>',
  "known-hosts": '<path d="M5 4.5h14a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-11a2 2 0 0 1 2-2Z"/><path d="M7 9h4m-4 4h10m-10 4h7"/>',
  "ssh-config": '<rect x="3.5" y="4.5" width="17" height="15" rx="2"/><path d="m7 10 2.5 2L7 14m5.5 0H17"/>',
  "already-added": '<circle cx="12" cy="12" r="8.5"/><path d="m8 12 2.5 2.5L16 9"/>',
};

/** Returns the one shared, non-interactive source glyph used beside its visible label. */
export function hostSourceIconMarkup(source: HostSource): string {
  return `<svg class="ui-source-icon" data-source-icon="${source}" viewBox="0 0 24 24" aria-hidden="true">${SOURCE_MARKS[source]}</svg>`;
}
