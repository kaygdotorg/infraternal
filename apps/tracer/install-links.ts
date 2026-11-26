// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Browser entrypoint for `/install/` (`/docs/install-links.js`, lazy-imported by `doc.js` only on the install page).
 *
 * Reads release files from the page’s own origin. Reads the requested channel from `location.search` (`stable` by default; `edge` only when `?channel=edge` is set),
 * updates the curl one-liner, and resolves the signed channel pointer against the embedded `release/allowed_signers`
 * trust anchors before populating any download link. Refuses unverified releases and never falls back from stable to edge.
 */
import {
  DEFAULT_SITE_ORIGIN,
  installCommandFor,
  resolveChannelRelease,
  selectChannel,
  SERVER_IMAGE_NAME,
  type ReleaseChannel,
} from "./install-release";

/** Contents of `release/allowed_signers`, injected at build time by `site-build.ts`. */
declare const __INFRATERNAL_ALLOWED_SIGNERS__: string;

/** Renders the verified download links (binary, checksums, signature) into `container` without raw HTML injection. */
function renderVerifiedLinks(container: HTMLElement, binaryUrl: string, sumsUrl: string, signatureUrl: string): void {
  const link = (href: string, label: string): HTMLAnchorElement => {
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.textContent = label;
    return anchor;
  };
  container.replaceChildren(
    link(binaryUrl, "Download"),
    document.createTextNode(" · "),
    link(sumsUrl, "Checksums"),
    document.createTextNode(" · "),
    link(signatureUrl, "Signature"),
  );
}

/** Shows the edge-channel warning banner when `channel` is `edge`; hides it for `stable`. */
function updateChannelNotice(root: HTMLElement, channel: ReleaseChannel): void {
  const notice = root.querySelector<HTMLElement>("[data-install-notice]");
  if (!notice) return;
  if (channel !== "edge") {
    notice.hidden = true;
    notice.replaceChildren();
    return;
  }
  const p = document.createElement("p");
  const strong = document.createElement("strong");
  strong.textContent = "Edge channel.";
  p.append(strong, document.createTextNode(" Edge builds are for update testing and may break."));
  notice.replaceChildren(p);
  notice.hidden = false;
}

/**
 * Enhances the `/install/` page root element: selects the channel, updates the curl one-liner, and resolves
 * the signed channel pointer into verified download links or a fail-closed status message.
 */
export async function enhanceInstallPage(
  root: HTMLElement,
  options?: { search?: string; allowedSigners?: string; fetchFn?: typeof fetch },
): Promise<void> {
  const origin = window.location.origin;
  const siteOrigin = root.dataset.siteOrigin || DEFAULT_SITE_ORIGIN;
  const channel = selectChannel(options?.search ?? window.location.search);
  const allowedSigners = options?.allowedSigners ?? __INFRATERNAL_ALLOWED_SIGNERS__;

  updateChannelNotice(root, channel);

  const cmdEl = root.querySelector<HTMLElement>("[data-install-cmd]");
  if (cmdEl) cmdEl.textContent = installCommandFor(siteOrigin, channel);

  const versionEl = root.querySelector<HTMLElement>("[data-install-version]");
  const linksEl = root.querySelector<HTMLElement>("[data-install-links]");
  const statusEl = root.querySelector<HTMLElement>("[data-install-status]");

  const result = await resolveChannelRelease({
    origin,
    channel,
    allowedSigners,
    ...(options?.fetchFn ? { fetchFn: options.fetchFn } : {}),
  });

  if (result.state === "verified") {
    if (versionEl) versionEl.textContent = `${SERVER_IMAGE_NAME} · ${result.version}`;
    if (linksEl) renderVerifiedLinks(linksEl, result.binaryUrl, result.sumsUrl, result.signatureUrl);
    if (statusEl) {
      delete statusEl.dataset.state;
      const prefix = channel === "edge"
        ? `Signed edge release ${result.version} verified · sha256 `
        : `Signed release ${result.version} verified · sha256 `;
      const code = document.createElement("code");
      code.textContent = result.binarySha256;
      statusEl.replaceChildren(document.createTextNode(prefix), code);
    }
    return;
  }

  if (versionEl) versionEl.textContent = SERVER_IMAGE_NAME;
  if (result.state === "empty") {
    if (linksEl) linksEl.textContent = result.message;
    if (statusEl) {
      delete statusEl.dataset.state;
      statusEl.textContent = "";
    }
    return;
  }

  if (linksEl) linksEl.textContent = "Verification failed";
  if (statusEl) {
    statusEl.dataset.state = "error";
    statusEl.textContent = `Could not verify the release: ${result.message}.`;
  }
}
