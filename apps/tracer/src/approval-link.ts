/**
 * Reads a device-approval link out of the address bar, once, before the first request (D311, #263).
 *
 * Two link forms exist and they are kept apart on purpose:
 * - `?device_code=<code>` is the CLI sign-in link (unchanged);
 * - `#join=<code>` is the "add this machine" link that `infraternal up` shows as a QR code. The code sits in the
 *   fragment because a browser never sends the fragment to the server: it cannot reach an access log, a proxy or a
 *   Referer header. The page reads it, takes it out of the address bar, and keeps it in memory only.
 *
 * The caller replaces the URL with `cleaned` before it issues any request; a link that cannot be cleared is refused.
 */

export type ApprovalKind = "sign_in" | "join_machine";

/** An error still names the kind of link it came from, so the failure screen speaks about the right thing. */
export type ApprovalLink = { code: string; kind: ApprovalKind } | { error: string; kind: ApprovalKind } | undefined;

export interface ApprovalLinkRead {
  link: ApprovalLink;
  /** The address to put back (path, query and fragment without the approval code), or undefined when there was none. */
  cleaned: string | undefined;
}

const MORE_THAN_ONE_SIGN_IN = "This sign-in link has more than one code. Ask the person who started it to run infraternal sign-in again.";
const MORE_THAN_ONE_JOIN = "This link has more than one code. Run infraternal up again on the machine you want to add.";

export function readApprovalLink(location: Pick<URL, "pathname" | "search" | "hash">): ApprovalLinkRead {
  const query = new URLSearchParams(location.search);
  const fragment = new URLSearchParams(location.hash.startsWith("#") ? location.hash.slice(1) : location.hash);
  const signIn = query.getAll("device_code");
  const join = fragment.getAll("join");
  if (signIn.length === 0 && join.length === 0) return { link: undefined, cleaned: undefined };

  query.delete("device_code");
  fragment.delete("join");
  const search = query.size > 0 ? `?${query}` : "";
  const hash = fragment.size > 0 ? `#${fragment}` : "";
  const cleaned = `${location.pathname}${search}${hash}`;

  if (join.length > 1) return { link: { error: MORE_THAN_ONE_JOIN, kind: "join_machine" }, cleaned };
  if (signIn.length > 1) return { link: { error: MORE_THAN_ONE_SIGN_IN, kind: "sign_in" }, cleaned };
  if (join.length === 1 && signIn.length === 1) return { link: { error: MORE_THAN_ONE_JOIN, kind: "join_machine" }, cleaned };
  if (join.length === 1) return { link: { code: join[0] ?? "", kind: "join_machine" }, cleaned };
  return { link: { code: signIn[0] ?? "", kind: "sign_in" }, cleaned };
}
