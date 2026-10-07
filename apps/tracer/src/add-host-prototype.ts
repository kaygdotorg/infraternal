/** Mounts the mock-only host discovery and SSH bootstrap window on the tracer canvas. */
import {
  enhanceSwitch,
  createSpinner,
  hostSourceIconMarkup,
  installStretchingCapsule,
  mountConfirmTip,
  mountStepStatus,
  mountToast,
  showTip,
  Spring,
  springCheckbox,
  type ConfirmTipController,
  type HostSource,
  type StepStatus,
  type StepStatusController,
  type StretchingCapsule,
  type ToastController,
  type UiSwitch,
} from "../../../packages/ui/src/index";
import type { AddHostFixture } from "./add-host-contract";
import type { CoreScreen } from "./core-screen";

const FIXTURES_URL = "/__mock/proto/addhost";
const SOURCE_LABELS: Record<HostSource, string> = {
  netbird: "NetBird",
  tailscale: "Tailscale",
  "known-hosts": "Known hosts",
  "ssh-config": "SSH config",
  "already-added": "Already added",
};
const ALL_SOURCES: HostSource[] = ["netbird", "tailscale", "known-hosts", "ssh-config"];
const BOOTSTRAP_STEPS = [
  { id: "sniff", label: "Read-only system check" },
  { id: "install", label: "Install infraternal agent" },
  { id: "facts", label: "Gather host facts" },
  { id: "connect", label: "Connect to server" },
] as const;

type AddHostStep = "entry" | "discovery" | "manual" | "credentials" | "root-consent" | "bootstrap" | "failure" | "success";
type FailureKind = "unreachable" | "authentication" | "mesh-policy";
type AddHostFailure = { kind: FailureKind; host: AddHostFixture };
type ProtoActionDetail = { action?: unknown; source?: unknown };

const escapeHtml = (value: string): string => value.replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;",
}[char]!));

function one<T extends HTMLElement>(root: ParentNode, selector: string): T {
  const element = root.querySelector<T>(selector);
  if (!element) throw new Error(`The add-host window is missing ${selector}`);
  return element;
}

function failureFor(host: AddHostFixture): AddHostFailure | undefined {
  if (host.reachability === "unreachable") {
    return { kind: "unreachable", host };
  }
  if (host.reachability === "mesh-policy") {
    return { kind: "mesh-policy", host };
  }
  if (host.authentication === "refused") {
    return { kind: "authentication", host };
  }
  return undefined;
}

/** Loads the test-double inventory and binds the window to existing app entry points. */
export async function mountAddHostPrototype(core: CoreScreen): Promise<{ dispose(): void }> {
  const response = await fetch(FIXTURES_URL, { cache: "no-store" });
  if (!response.ok) throw new Error("The add-host test-double inventory is unavailable");
  const payload = await response.json() as { hosts?: unknown };
  if (!Array.isArray(payload.hosts) || payload.hosts.length !== 6) throw new Error("The add-host test-double needs six discovery fixtures");
  const hosts = payload.hosts as AddHostFixture[];
  const stage = core.stage;
  const panes = one<HTMLElement>(stage, ".panes");
  const originalCard = core.terminalHost.closest<HTMLElement>(".pane-card");
  if (!originalCard) throw new Error("The existing terminal pane is missing");

  stage.classList.add("has-windows-prototype", "has-addhost-prototype");
  panes.dataset.windowCanvas = "true";
  originalCard.setAttribute("aria-hidden", "true");

  const group = document.createElement("section");
  group.className = "window-group addhost-window-group";
  group.setAttribute("aria-label", "Add-host window on the canvas");
  const card = document.createElement("section");
  card.className = "pane-card window-card addhost-window";
  card.setAttribute("role", "group");
  card.setAttribute("aria-label", "Add hosts");
  card.tabIndex = -1;
  card.innerHTML = `
    <header class="window-header addhost-window-header">
      <div class="window-host-pill ui-pill ui-overlay-surface" hidden><span class="addhost-window-title"></span></div>
      <div class="window-header-actions">
        <button class="window-header-action ui-icon-button ui-overlay-surface" type="button" data-addhost-action="close" aria-label="Close add hosts" data-tip="Close add hosts">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
        </button>
      </div>
    </header>
    <div class="addhost-window-body"><div class="addhost-content"></div></div>
    <footer class="addhost-footer" hidden></footer>`;
  group.append(card);
  panes.append(group);

  const body = one<HTMLElement>(card, ".addhost-content");
  const footer = one<HTMLElement>(card, ".addhost-footer");
  const title = one<HTMLElement>(card, ".addhost-window-title");
  const hostPill = one<HTMLElement>(card, ".addhost-window-header .window-host-pill");
  const toast: ToastController = mountToast(stage);
  const query = new URLSearchParams(location.search);
  const emptyEntry = query.get("empty") === "1";
  let step: AddHostStep = emptyEntry ? "entry" : "discovery";
  let selectedHosts: AddHostFixture[] = [];
  let installHosts: AddHostFixture[] = [];
  let priorFailures: AddHostFailure[] = [];
  let failure: AddHostFailure | undefined;
  let rootConsent = false;
  let installAsRoot = false;
  let activeSources = new Set<HostSource>(ALL_SOURCES);
  let discoveryQuery = "";
  let extendedInformation = false;
  let tabs: StretchingCapsule | undefined;
  let confirmTip: ConfirmTipController | undefined;
  let sourceSwitches: UiSwitch[] = [];
  let timerIds: number[] = [];
  let progressMarks = new Map<string, StepStatusController[]>();
  let terminalWindows: Array<{ group: HTMLElement; card: HTMLElement; host: AddHostFixture }> = [];
  let disposed = false;

  const disposeControls = (): void => {
    tabs?.dispose();
    tabs = undefined;
    for (const control of sourceSwitches) control.dispose();
    sourceSwitches = [];
  };
  const clearTimers = (): void => {
    for (const timer of timerIds) window.clearTimeout(timer);
    timerIds = [];
  };
  const setStep = (next: AddHostStep): void => {
    step = next;
    card.dataset.step = next;
    render();
  };
  const activeHosts = (): AddHostFixture[] => hosts.filter((host) =>
    host.sources.some((source) => activeSources.has(source)) || host.alreadyAdded,
  );
  const visibleHosts = (): AddHostFixture[] => {
    const needle = discoveryQuery.trim().toLocaleLowerCase();
    return activeHosts().filter((host) => !needle ||
      `${host.user}@${host.id} ${host.address} ${host.operatingSystem} ${host.architecture}`.toLocaleLowerCase().includes(needle),
    );
  };
  const hostByName = (name: string): AddHostFixture | undefined =>
    hosts.find((host) => host.id.toLocaleLowerCase() === name.toLocaleLowerCase() || host.address === name);

  function setFooter(markup: string): void {
    footer.innerHTML = markup;
    footer.hidden = markup.length === 0;
  }

  function updateDiscoveryHostList(): void {
    const list = body.querySelector<HTMLElement>(".addhost-host-list");
    if (!list) return;
    const rows = visibleHosts().map(hostRowMarkup).join("");
    list.innerHTML = rows || `<li class="addhost-list-empty">No hosts match. Try Manual to check another host.</li>`;
    for (const input of list.querySelectorAll<HTMLInputElement>("[data-host-choice]")) springCheckbox(input);
  }

  function sourceMarkup(source: HostSource): string {
    return `<span class="addhost-source-chip" data-source="${source}"><span class="addhost-source-separator" aria-hidden="true">·</span>${hostSourceIconMarkup(source)}<span>${SOURCE_LABELS[source]}</span></span>`;
  }

  function hostRowMarkup(host: AddHostFixture): string {
    const selected = selectedHosts.some((candidate) => candidate.id === host.id);
    const status = host.alreadyAdded
      ? "Already added"
      : host.reachability === "ready"
        ? "SSH ready · port 22"
        : host.reachability === "mesh-policy"
          ? "SSH blocked · mesh policy"
          : "No SSH response on port 22";
    const sourceChips = host.sources.map(sourceMarkup).join("");
    return `<li class="addhost-host-row" data-host-row data-host-id="${escapeHtml(host.id)}" data-unavailable="${String(host.alreadyAdded)}">
      <label class="addhost-host-select" data-touch-target>
        <input type="checkbox" data-host-choice aria-label="Select ${escapeHtml(host.id)}" value="${escapeHtml(host.id)}" ${host.alreadyAdded ? "disabled" : ""} ${selected ? "checked" : ""} />
      </label>
      <span class="addhost-host-copy">
        <span class="addhost-host-name">${escapeHtml(host.id)}</span>
        <span class="addhost-host-secondary"><span class="addhost-host-system">${escapeHtml(host.operatingSystem)} · ${escapeHtml(host.architecture)}</span>${sourceChips}</span>
      </span>
      <span class="addhost-host-trailing">
        <span class="addhost-host-status" data-ssh-status data-status="${host.alreadyAdded ? "added" : host.reachability}">${status}</span>
        <button type="button" class="addhost-ip-action" data-addhost-action="show-ip" data-host-id="${escapeHtml(host.id)}" aria-label="Show IP for ${escapeHtml(host.id)}">Show IP</button>
      </span>
    </li>`;
  }

  function sourceSwitchMarkup(source: HostSource): string {
    const checked = activeSources.has(source);
    return `<label class="addhost-toggle-row"><span>${SOURCE_LABELS[source]}</span><input class="ui-switch" type="checkbox" data-source-toggle="${source}" aria-label="${SOURCE_LABELS[source]}" ${checked ? "checked" : ""} /></label>`;
  }

  function renderEntry(): void {
    body.innerHTML = `<section class="addhost-empty-state" aria-label="No hosts yet">
      <div class="addhost-heading"><h1>No hosts yet</h1><p>Add a host to open its terminal on the canvas.</p></div>
      <button type="button" data-addhost-action="begin">Add hosts</button>
    </section>`;
    setFooter("");
  }

  function renderDiscovery(manual = false): void {
    const tabsMarkup = `<div class="segmented-tabs ui-pill addhost-tabs" role="tablist" aria-label="Add-host method">
      <span class="segmented-capsule ui-overlay-surface" aria-hidden="true"></span>
      <button type="button" role="tab" data-tab="discovered" aria-selected="${String(!manual)}">Discovered</button>
      <button type="button" role="tab" data-tab="manual" aria-selected="${String(manual)}">Manual</button>
    </div>`;
    if (manual) {
      body.innerHTML = `<div class="addhost-heading"><h1>Add hosts</h1><p>Enter a user and host, an IP address, or a name.</p></div>
        ${tabsMarkup}
        <label class="addhost-field"><span>Host</span><input class="addhost-host-input" type="text" autocomplete="off" spellcheck="false" placeholder="user@host, IP or name" aria-label="Host" /></label>
        <p class="addhost-note">The first check reads SSH reachability only. No login starts until you continue.</p>`;
      setFooter(`<button type="button" class="addhost-primary" data-addhost-action="manual-add">Add host</button>`);
    } else {
      const rows = visibleHosts().map(hostRowMarkup).join("") || `<li class="addhost-list-empty">No hosts match. Try Manual to check another host.</li>`;
      body.innerHTML = `<div class="addhost-heading"><h1>Add hosts</h1><p>Choose a host the server can already reach. Discovery checks SSH without logging in.</p></div>
        ${tabsMarkup}
        <label class="addhost-field"><span>Find a host</span><input class="addhost-host-input" type="search" autocomplete="off" spellcheck="false" placeholder="user@host, IP or name" aria-label="Find a host" value="${escapeHtml(discoveryQuery)}" /></label>
        <ul class="addhost-host-list">${rows}</ul>
        <div class="addhost-options"><button type="button" class="addhost-options-toggle" data-addhost-action="toggle-sources" aria-expanded="false">Discovery sources</button><div class="addhost-source-options" hidden>
          ${ALL_SOURCES.map(sourceSwitchMarkup).join("")}
        </div></div>
        <div class="addhost-toggle-row addhost-extended-row"><label for="addhost-extended"><span>Gather extended information</span><small>Read-only host facts such as IP addresses, listeners, and workloads.</small></label>
          <input class="ui-switch" id="addhost-extended" type="checkbox" aria-label="Gather extended information" ${extendedInformation ? "checked" : ""} />
        </div>`;
      setFooter(`<button type="button" class="addhost-primary" data-addhost-action="continue" ${selectedHosts.length ? "" : "disabled"}>Continue</button>`);
      for (const input of body.querySelectorAll<HTMLInputElement>("[data-source-toggle]")) {
        sourceSwitches.push(enhanceSwitch(input));
      }
      const extended = body.querySelector<HTMLInputElement>("#addhost-extended");
      if (extended) sourceSwitches.push(enhanceSwitch(extended));
      for (const input of body.querySelectorAll<HTMLInputElement>("[data-host-choice]")) springCheckbox(input);
    }
    const tablist = body.querySelector<HTMLElement>("[role='tablist']");
    if (tablist) {
      tabs = installStretchingCapsule(tablist, manual ? "manual" : "discovered", (id) => {
        if (id === "manual") setStep("manual");
        else setStep("discovery");
      });
    }
  }

  function renderCredentials(): void {
    const credentialHosts = selectedHosts.filter((host) => host.credentialRequired);
    const primary = credentialHosts[0] ?? selectedHosts[0];
    if (!primary) { setStep("discovery"); return; }
    body.innerHTML = `<div class="addhost-heading"><h1>SSH identity</h1><p>The server's own key is used in place and never copied. Mesh SSH needs no secret.</p></div>
      <article class="addhost-access-card">
        ${credentialHosts.map((host) => `<div class="addhost-access-host"><strong>${escapeHtml(host.user)}@${escapeHtml(host.id)}</strong><span>${escapeHtml(host.operatingSystem)} · ${escapeHtml(host.architecture)}</span></div>
          <label class="addhost-field"><span>SSH key or password for ${escapeHtml(host.id)}</span><input type="password" autocomplete="off" aria-label="SSH key or password for ${escapeHtml(host.id)}" /></label>`).join("")}
        <div class="addhost-identity">
          <label class="addhost-identity-option"><input type="radio" name="addhost-identity" checked />Server SSH key · used in place</label>
          <label class="addhost-identity-option"><input type="radio" name="addhost-identity" />Paste a key · encrypted with your passkey</label>
          <p class="addhost-note">Pasted keys are encrypted with your passkey. No credential is sent by this preview.</p>
          ${selectedHosts.length > 1 ? `<label class="addhost-identity-option"><input type="checkbox" data-use-all />Use for all selected</label>` : ""}
        </div>
      </article>`;
    if (selectedHosts.length > 1) {
      const useAll = body.querySelector<HTMLInputElement>("[data-use-all]");
      if (useAll) springCheckbox(useAll);
    }
    setFooter(`<button type="button" class="addhost-secondary" data-addhost-action="back">Back</button><button type="button" class="addhost-primary" data-addhost-action="credentials-continue">Continue</button>`);
    void primary;
  }

  function eligibleHosts(): AddHostFixture[] {
    return selectedHosts.filter((host) => host.reachability === "ready" && host.authentication === "accepted" && !host.alreadyAdded);
  }

  function continueAfterCredentials(): void {
    const rejected = selectedHosts.filter((host) => host.authentication === "refused");
    priorFailures = [...priorFailures, ...rejected.map((host) => failureFor(host)!).filter(Boolean)];
    selectedHosts = eligibleHosts();
    if (selectedHosts.length === 0) {
      failure = priorFailures[0] ?? failureFor(hosts[2]!);
      setStep("failure");
      return;
    }
    openRootChoice();
  }

  function renderRootConsent(): void {
    const roots = selectedHosts.filter((host) => host.rootAvailable);
    const rootNames = roots.map((host) => host.id).join(", ");
    body.innerHTML = `<div class="addhost-heading"><h1>Root access</h1><p>Passwordless sudo is available on this host. That does not grant permission.</p></div>
      <article class="addhost-consent-card">
        ${roots.map((host) => `<div class="addhost-consent-host"><strong>${escapeHtml(host.user)}@${escapeHtml(host.id)}</strong><span>${escapeHtml(host.operatingSystem)} · ${escapeHtml(host.architecture)}</span></div>`).join("")}
        <p class="addhost-consent-copy">Installing the infraternal agent as root gives it access to every file on the host. <strong>Trust is one thing we can't get back once lost.</strong></p>
        <label class="addhost-consent-label"><input type="checkbox" data-root-consent aria-label="I trust ${escapeHtml(rootNames)} with root access" /><span>I trust infraternal with root access on ${escapeHtml(rootNames)}.</span></label>
        ${roots.length > 1 ? `<label class="addhost-consent-label"><input type="checkbox" data-consent-all aria-label="Apply to all ${roots.length} hosts that allow sudo" /><span>Apply to all ${roots.length} hosts that allow sudo</span></label>` : ""}
      </article>`;
    const consentInput = body.querySelector<HTMLInputElement>("[data-root-consent]");
    if (consentInput) springCheckbox(consentInput);
    const applyAll = body.querySelector<HTMLInputElement>("[data-consent-all]");
    if (applyAll) springCheckbox(applyAll);
    setFooter(`<button type="button" class="addhost-secondary" data-addhost-action="install-user">Install as a user</button><button type="button" class="addhost-primary" data-addhost-action="install-root" ${rootConsent ? "" : "disabled"}>Install as root</button>`);
  }

  function renderBootstrap(): void {
    body.innerHTML = `<div class="addhost-heading"><h1>Installing infraternal agent</h1><p>The system check is read-only. Host facts are gathered after installation.</p></div>
      <ul class="addhost-progress-list" aria-live="polite">${installHosts.map((host) => `<li class="addhost-progress-host" data-progress-host="${escapeHtml(host.id)}">
        <h2>${escapeHtml(host.id)} · ${escapeHtml(host.operatingSystem)} · ${escapeHtml(host.architecture)}</h2>
        <ol class="addhost-progress-steps">${BOOTSTRAP_STEPS.map((item) => `<li class="addhost-progress-step" data-bootstrap-step="${item.id}" data-state="pending"><span class="addhost-progress-mark"></span><span>${item.label}</span></li>`).join("")}</ol>
      </li>`).join("")}</ul>
      ${priorFailures.map((item) => `<p class="addhost-policy-evidence">${escapeHtml(item.host.id)} could not connect. The other hosts continue independently.</p>`).join("")}`;
    setFooter("");
    progressMarks = new Map();
    for (const host of installHosts) {
      const row = one<HTMLElement>(body, `[data-progress-host="${CSS.escape(host.id)}"]`);
      const markers = [...row.querySelectorAll<HTMLElement>(".addhost-progress-mark")];
      progressMarks.set(host.id, markers.map((marker) => mountStepStatus(marker)));
    }
    const advance = (completed: number): void => {
      for (const host of installHosts) {
        const row = one<HTMLElement>(body, `[data-progress-host="${CSS.escape(host.id)}"]`);
        const hostMarks = progressMarks.get(host.id) ?? [];
        const rows = [...row.querySelectorAll<HTMLElement>("[data-bootstrap-step]")];
        rows.forEach((stepRow, index) => {
          const done = index < completed;
          const running = index === completed && completed < BOOTSTRAP_STEPS.length;
          const state: StepStatus = done ? "done" : running ? "running" : "pending";
          stepRow.dataset.state = state;
          hostMarks[index]?.set(state);
        });
      }
      if (completed >= BOOTSTRAP_STEPS.length) {
        timerIds.push(window.setTimeout(finishBootstrap, 260));
      } else {
        timerIds.push(window.setTimeout(() => advance(completed + 1), 520));
      }
    };
    advance(0);
  }

  function makeTerminalWindow(host: AddHostFixture, rootless: boolean): { group: HTMLElement; card: HTMLElement; host: AddHostFixture } {
    const terminalGroup = document.createElement("section");
    terminalGroup.className = "window-group addhost-result-group";
    // Keep the first host window wholly outside the success view until the toast opens it.
    if (!panes.querySelector(".addhost-result-group")) terminalGroup.classList.add("addhost-result-first");
    terminalGroup.setAttribute("aria-label", `Canvas window for ${host.id}`);
    const terminalCard = document.createElement("section");
    terminalCard.className = "pane-card window-card addhost-result-window";
    terminalCard.dataset.hostId = host.id;
    terminalCard.setAttribute("role", "group");
    terminalCard.setAttribute("aria-label", `Terminal window for ${host.id}`);
    terminalCard.tabIndex = -1;
    const header = document.createElement("header");
    header.className = "window-header";
    const pill = document.createElement("div");
    pill.className = "window-host-pill ui-pill ui-overlay-surface";
    const hostLabel = document.createElement("span");
    hostLabel.className = "window-pill-host";
    hostLabel.textContent = `${host.user}@${host.id}`;
    const systemLabel = document.createElement("span");
    systemLabel.className = "addhost-terminal-system";
    systemLabel.textContent = `${host.operatingSystem} · ${host.architecture}`;
    pill.append(hostLabel, systemLabel);
    const actions = document.createElement("div");
    actions.className = "window-header-actions";
    if (rootless && host.rootAvailable) {
      const rootPill = document.createElement("button");
      rootPill.type = "button";
      rootPill.className = "addhost-root-available";
      rootPill.dataset.addhostAction = "root-available";
      rootPill.dataset.hostId = host.id;
      rootPill.textContent = "Root available";
      actions.append(rootPill);
    }
    const status = document.createElement("span");
    status.className = "dot live";
    status.setAttribute("aria-label", "Connected");
    actions.append(status);
    header.append(pill, actions);
    const terminal = document.createElement("div");
    terminal.className = "window-fake-terminal";
    terminal.setAttribute("role", "application");
    terminal.setAttribute("aria-label", `Terminal on ${host.id}`);
    const output = document.createElement("pre");
    output.className = "window-fake-output";
    output.textContent = `${host.operatingSystem} · ${host.architecture}\n\n${host.user}@${host.id}:~$ `;
    terminal.append(output);
    terminalCard.append(header, terminal);
    terminalGroup.append(terminalCard);
    panes.append(terminalGroup);
    const result = { group: terminalGroup, card: terminalCard, host };
    if (rootless && host.rootAvailable) {
      const rootPill = one<HTMLButtonElement>(terminalCard, ".addhost-root-available");
      rootPill.addEventListener("click", () => {
        confirmTip?.close(false);
        confirmTip = mountConfirmTip(rootPill, {
          label: "Root access confirmation",
          message: `Install the infraternal agent as root on ${host.id}?`,
          confirmLabel: "Yes",
          cancelLabel: "No",
          onConfirm: () => {
            const original = rootPill.textContent ?? "Root available";
            const spinner = createSpinner();
            rootPill.prepend(spinner);
            showTip(rootPill, "Starting root agent", 1800);
            window.setTimeout(() => {
              spinner.remove();
              rootPill.textContent = "Root active";
              showTip(rootPill, "Root agent ready");
            }, 1250);
          },
        });
      });
    }
    return result;
  }

  function renderSuccess(): void {
    const ready = installHosts;
    const first = ready[0];
    if (!first) { setStep("discovery"); return; }
    body.innerHTML = `<div class="addhost-success">
      <div class="addhost-heading"><h1>${escapeHtml(first.id)} is ready</h1><p>Its terminal window is open on the canvas.</p></div>
      <p class="addhost-ready-line"><span aria-hidden="true">✓</span> Connected · ${escapeHtml(first.operatingSystem)} · ${escapeHtml(first.architecture)}</p>
      ${priorFailures.map((item) => `<p class="addhost-policy-evidence">${escapeHtml(item.host.id)} could not be added. Other selected hosts continued.</p>`).join("")}
      <button type="button" class="addhost-success-next" data-addhost-action="back">Add another host</button>
      <pre class="addhost-terminal-output" aria-label="Terminal output">${escapeHtml(`${first.operatingSystem} · ${first.architecture}\n\n${first.user}@${first.id}:~$ `)}</pre>
    </div>`;
    setFooter("");
    clearTerminalWindows();
    terminalWindows = ready.map((host) => makeTerminalWindow(host, !installAsRoot));
    const firstWindow = terminalWindows[0];
    if (firstWindow) {
      toast.show({
        message: `${first.id} is ready`,
        action: {
          label: "Go to window",
          onSelect: () => {
            group.hidden = true;
            firstWindow.group.classList.remove("addhost-result-first");
            panes.scrollLeft = 0;
            firstWindow.card.focus({ preventScroll: true });
          },
        },
      });
    }
  }

  function clearTerminalWindows(): void {
    for (const windowView of terminalWindows) windowView.group.remove();
    terminalWindows = [];
  }

  function finishBootstrap(): void {
    if (disposed || step !== "bootstrap") return;
    clearTimers();
    setStep("success");
  }

  function showFailure(next: AddHostFailure): void {
    clearTimers();
    failure = next;
    setStep("failure");
  }

  function retryFailure(): void {
    if (!failure) return;
    if (failure.kind === "authentication") {
      selectedHosts = [failure.host];
      setStep("credentials");
      return;
    }
    const next = failureFor(failure.host);
    if (next) showFailure(next);
  }

  function renderFailure(): void {
    if (!failure) { setStep("discovery"); return; }
    const copy = failure.kind === "unreachable"
      ? {
          heading: "Host unreachable",
          happened: `SSH to ${failure.host.id} got no response on TCP 22.`,
          next: "Check that the host is online and SSH is listening, then retry.",
        }
      : failure.kind === "authentication"
        ? {
            heading: "SSH key refused",
            happened: `SSH to ${failure.host.id} reached the host, but the selected identity was refused.`,
            next: "Choose another SSH identity or correct its access, then retry.",
          }
        : {
            heading: "SSH blocked by mesh policy",
            happened: `SSH to ${failure.host.id} is blocked by the mesh access policy (TCP 22).`,
            next: "Ask a mesh admin to allow TCP 22 from this server, then retry.",
          };
    body.innerHTML = `<div class="addhost-heading"><h1>${copy.heading}</h1></div>
      <article class="addhost-error" data-failure="${failure.kind}">
        <p>${escapeHtml(copy.happened)}</p>
        <p class="addhost-policy-note">${escapeHtml(copy.next)}</p>
      </article>`;
    setFooter(`<button type="button" class="addhost-secondary" data-addhost-action="back">Back to hosts</button><button type="button" class="addhost-primary" data-addhost-action="retry">Retry</button>`);
  }

  function openRootChoice(): void {
    rootConsent = false;
    const roots = selectedHosts.some((host) => host.rootAvailable);
    if (roots) setStep("root-consent");
    else startBootstrap(false);
  }

  function startBootstrap(asRoot: boolean): void {
    installAsRoot = asRoot;
    installHosts = [...selectedHosts];
    if (installHosts.length === 0) {
      setStep("discovery");
      return;
    }
    clearTimers();
    setStep("bootstrap");
  }

  function continueSelection(): void {
    selectedHosts = selectedHosts.filter((host) => !host.alreadyAdded);
    priorFailures = [];
    if (!selectedHosts.length) return;
    const blocked = selectedHosts.filter((host) => host.reachability !== "ready");
    const ready = selectedHosts.filter((host) => host.reachability === "ready");
    if (!ready.length) {
      showFailure(failureFor(blocked[0]!)!);
      return;
    }
    priorFailures = blocked.map((host) => failureFor(host)!).filter(Boolean);
    selectedHosts = ready;
    if (selectedHosts.some((host) => host.credentialRequired)) setStep("credentials");
    else openRootChoice();
  }

  function manualHost(): AddHostFixture | undefined {
    const raw = body.querySelector<HTMLInputElement>(".addhost-host-input")?.value.trim() ?? "";
    if (!raw) return undefined;
    const at = raw.lastIndexOf("@");
    const user = at >= 0 ? raw.slice(0, at).trim() : "kayg";
    const name = at >= 0 ? raw.slice(at + 1).trim() : raw;
    const found = hostByName(name);
    if (found) return { ...found, user: user || found.user };
    return {
      id: name,
      user: user || "kayg",
      address: name,
      operatingSystem: "Unknown Linux host",
      architecture: "Unknown architecture",
      sources: [],
      reachability: "unreachable",
      evidence: "A TCP connection to port 22 timed out; no login was attempted.",
      alreadyAdded: false,
      rootAvailable: false,
      credentialRequired: false,
      authentication: "accepted",
    };
  }

  function addManualHost(): void {
    const host = manualHost();
    if (!host) return;
    selectedHosts = [host];
    priorFailures = [];
    if (host.reachability !== "ready") {
      showFailure(failureFor(host)!);
    } else if (host.credentialRequired) {
      setStep("credentials");
    } else {
      openRootChoice();
    }
  }

  function updateFooterState(): void {
    if (step === "discovery") {
      const button = footer.querySelector<HTMLButtonElement>("[data-addhost-action='continue']");
      if (button) button.disabled = selectedHosts.length === 0;
    } else if (step === "root-consent") {
      const button = footer.querySelector<HTMLButtonElement>("[data-addhost-action='install-root']");
      if (button) button.disabled = !rootConsent;
    } else if (step === "manual") {
      const button = footer.querySelector<HTMLButtonElement>("[data-addhost-action='manual-add']");
      if (button) button.disabled = !(body.querySelector<HTMLInputElement>(".addhost-host-input")?.value.trim());
    }
  }

  function setWindowTitle(): void {
    const host = step === "success" ? installHosts[0] : step === "failure" ? failure?.host : undefined;
    hostPill.hidden = !host;
    if (host) title.textContent = `${host.user}@${host.id}`;
  }

  function render(): void {
    disposeControls();
    card.dataset.step = step;
    card.dataset.kind = step === "success" ? "flow-success" : "flow";
    setWindowTitle();
    if (step === "entry") renderEntry();
    else if (step === "discovery") renderDiscovery(false);
    else if (step === "manual") renderDiscovery(true);
    else if (step === "credentials") renderCredentials();
    else if (step === "root-consent") renderRootConsent();
    else if (step === "bootstrap") renderBootstrap();
    else if (step === "failure") renderFailure();
    else renderSuccess();
  }

  function openWindow(animate: boolean): void {
    const sidebarToggle = stage.querySelector<HTMLButtonElement>("#sidebar-toggle");
    if (sidebarToggle?.getAttribute("aria-expanded") === "true") sidebarToggle.click();
    group.hidden = false;
    if (animate) {
      windowSpring.set(0, true);
      requestAnimationFrame(() => windowSpring.set(1));
    } else windowSpring.set(1, true);
  }

  function closeWindow(): void {
    group.hidden = true;
  }

  function onClick(event: MouseEvent): void {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest<HTMLElement>("[data-addhost-action]");
    if (!button) return;
    const action = button.dataset.addhostAction;
    if (action === "close") closeWindow();
    else if (action === "begin") setStep("discovery");
    else if (action === "toggle-sources") {
      const options = body.querySelector<HTMLElement>(".addhost-source-options");
      const expanded = button.getAttribute("aria-expanded") !== "true";
      button.setAttribute("aria-expanded", String(expanded));
      if (options) options.hidden = !expanded;
    }
    else if (action === "continue") continueSelection();
    else if (action === "manual-add") addManualHost();
    else if (action === "credentials-continue") continueAfterCredentials();
    else if (action === "install-root") startBootstrap(true);
    else if (action === "install-user") startBootstrap(false);
    else if (action === "back") {
      if (step === "success") {
        selectedHosts = [];
        priorFailures = [];
        clearTerminalWindows();
        toast.dismiss();
        setStep("discovery");
      } else if (step === "credentials" && selectedHosts.length === 1 && selectedHosts[0]?.id !== "nix-cache") setStep("discovery");
      else setStep("discovery");
    } else if (action === "retry") retryFailure();
    else if (action === "show-ip") revealIp(button);
    else if (action === "root-available") {
      const hostId = button.dataset.hostId;
      const windowView = terminalWindows.find((entry) => entry.host.id === hostId);
      windowView?.card.focus({ preventScroll: true });
    }
  }

  function revealIp(button: HTMLElement): void {
    const host = hostByName(button.dataset.hostId ?? "");
    if (!host || button.dataset.revealed === "true") return;
    button.dataset.revealed = "true";
    button.setAttribute("aria-label", `IP address for ${host.id}`);
    button.replaceChildren();
    const value = document.createElement("span");
    value.className = "addhost-ip-value";
    value.dataset.hostIp = "true";
    value.textContent = host.address;
    button.append(value);
  }

  function onChange(event: Event): void {
    const target = event.target;
    if (!(target instanceof HTMLInputElement)) return;
    if (target.matches("[data-host-choice]")) {
      const host = hosts.find((candidate) => candidate.id === target.value && !candidate.alreadyAdded);
      if (target.checked && host && !selectedHosts.some((candidate) => candidate.id === host.id)) selectedHosts.push(host);
      else if (!target.checked) selectedHosts = selectedHosts.filter((candidate) => candidate.id !== target.value);
      updateFooterState();
    } else if (target.matches("[data-source-toggle]")) {
      const source = target.dataset.sourceToggle as HostSource | undefined;
      if (!source) return;
      if (target.checked) activeSources.add(source);
      else activeSources.delete(source);
      // Keep the focused switch and disclosure mounted while only the filtered rows change.
      updateDiscoveryHostList();
      updateFooterState();
    } else if (target.id === "addhost-extended") {
      extendedInformation = target.checked;
    } else if (target.matches("[data-root-consent]")) {
      rootConsent = target.checked;
      updateFooterState();
    } else if (target.matches(".addhost-host-input")) updateFooterState();
  }

  function onInput(event: Event): void {
    if (!(event.target instanceof HTMLInputElement) || !event.target.matches(".addhost-host-input")) return;
    if (step === "discovery") {
      discoveryQuery = event.target.value;
      updateDiscoveryHostList();
    }
    updateFooterState();
  }

  function onKeyDown(event: KeyboardEvent): void {
    if (step === "manual" && event.key === "Enter" && event.target instanceof HTMLInputElement && event.target.matches(".addhost-host-input")) {
      event.preventDefault();
      addManualHost();
    }
  }

  function onProtoAction(event: Event): void {
    const detail = (event as CustomEvent<ProtoActionDetail>).detail;
    if (detail?.action === "proto:addhost") openWindow(detail.source !== "keyboard");
  }

  const sidebar = stage.querySelector<HTMLElement>("#sidebar");
  const sidebarButton = document.createElement("button");
  sidebarButton.type = "button";
  sidebarButton.className = "ui-button addhost-sidebar-button";
  sidebarButton.textContent = "Add hosts";
  const openFromSidebar = (): void => openWindow(true);
  sidebarButton.addEventListener("click", openFromSidebar);
  sidebar?.append(sidebarButton);

  card.addEventListener("click", onClick);
  card.addEventListener("change", onChange);
  card.addEventListener("input", onInput);
  card.addEventListener("keydown", onKeyDown);
  window.addEventListener("tracer:proto-action", onProtoAction);
  const windowSpring = new Spring(0, (value) => {
    card.style.opacity = String(value);
    card.style.transform = `translateY(${(1 - value) * 6}px) scale(${0.975 + value * 0.025})`;
  }, { visualDuration: 0.22, bounce: 0.12 });
  render();
  requestAnimationFrame(() => windowSpring.set(1));
  requestAnimationFrame(() => { if (!disposed) panes.scrollLeft = 0; });

  return {
    dispose() {
      disposed = true;
      clearTimers();
      disposeControls();
      confirmTip?.close(false);
      toast.dispose();
      card.removeEventListener("click", onClick);
      card.removeEventListener("change", onChange);
      card.removeEventListener("input", onInput);
      card.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("tracer:proto-action", onProtoAction);
      sidebarButton.removeEventListener("click", openFromSidebar);
      sidebarButton.remove();
      clearTerminalWindows();
      group.remove();
      originalCard.removeAttribute("aria-hidden");
      panes.removeAttribute("data-window-canvas");
      stage.classList.remove("has-addhost-prototype", "has-windows-prototype");
    },
  };
}
