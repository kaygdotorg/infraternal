/**
 * The one window card (D160): the framed surface every terminal, flow or tool lives in on
 * the canvas. It looks exactly like the core screen's pane card (same fill, hairline,
 * radius and shadow) and adds a quiet header: a title pill (host mark, `user@host`,
 * session, status dot) on the left and optional icon actions on the right.
 *
 * Consumers own the body: a live terminal host, a static preview or a wizard. The card
 * never measures or animates its body, so it costs nothing while idle.
 *
 * API (stable; the add-host flow uses the same card):
 *   const card = createWindowCard({ id, title, icon, status, actions, label });
 *   card.root     → mount it anywhere (canvas layer, panes)
 *   card.body     → put content here; it fills the card under the header
 *   card.pill     → the title pill button (anchor popovers to it)
 *   card.setActive(active)   → accent hairline, `aria-current`
 *   card.setTitle(title) / card.setStatus(status) / card.setIcon(svgMarkup)
 *   card.dispose()
 */

/** `none` hides the dot: a window that is not a connection yet (a flow in progress). */
export type WindowStatus = "live" | "connecting" | "offline" | "none";

export interface WindowTitle {
  host: string;
  user?: string;
  session?: string;
}

export interface WindowAction {
  id: string;
  label: string;
  icon: string; // inner SVG markup on a 24×24 grid, stroked
  onSelect(event: MouseEvent): void;
}

export interface WindowCardOptions {
  id: string;
  title: WindowTitle;
  icon?: string; // full <svg> markup for the host mark
  status?: WindowStatus;
  actions?: WindowAction[];
  label?: string; // accessible name of the whole window
}

export interface WindowCard {
  readonly root: HTMLElement;
  readonly header: HTMLElement;
  readonly pill: HTMLButtonElement;
  readonly body: HTMLElement;
  setActive(active: boolean): void;
  setTitle(title: WindowTitle): void;
  setStatus(status: WindowStatus): void;
  setIcon(svg: string): void;
  dispose(): void;
}

const STATUS_LABEL: Record<WindowStatus, string> = { live: "connected", connecting: "reconnecting", offline: "offline", none: "" };

/** Builds a window card; nothing is attached to the document until the caller mounts `root`. */
export function createWindowCard(options: WindowCardOptions): WindowCard {
  const root = document.createElement("section");
  root.className = "ui-window";
  root.dataset.windowId = options.id;

  const header = document.createElement("header");
  header.className = "ui-window-head";

  const pill = document.createElement("button");
  pill.type = "button";
  pill.className = "ui-window-pill";
  pill.setAttribute("aria-haspopup", "dialog");
  pill.innerHTML = `<span class="ui-window-mark"></span><span class="ui-window-title"><span class="ui-window-user"></span><span class="ui-window-host"></span></span><span class="ui-window-session"></span><span class="ui-window-dot" aria-hidden="true"></span>`;
  const mark = pill.querySelector<HTMLElement>(".ui-window-mark")!;
  const user = pill.querySelector<HTMLElement>(".ui-window-user")!;
  const host = pill.querySelector<HTMLElement>(".ui-window-host")!;
  const session = pill.querySelector<HTMLElement>(".ui-window-session")!;

  const actions = document.createElement("div");
  actions.className = "ui-window-actions";
  const handlers: Array<[HTMLButtonElement, (event: MouseEvent) => void]> = [];
  for (const action of options.actions ?? []) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "ui-window-action";
    button.dataset.action = action.id;
    button.setAttribute("aria-label", action.label);
    button.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${action.icon}</svg>`;
    const handler = (event: MouseEvent): void => action.onSelect(event);
    button.addEventListener("click", handler);
    handlers.push([button, handler]);
    actions.append(button);
  }
  header.append(pill, actions);

  const body = document.createElement("div");
  body.className = "ui-window-body";
  root.append(header, body);

  let title = options.title;
  let status: WindowStatus = options.status ?? "live";
  const label = (): void => {
    const name = `${title.user ? `${title.user}@` : ""}${title.host}${title.session ? `, ${title.session}` : ""}`;
    root.setAttribute("aria-label", options.label ?? name);
    pill.setAttribute("aria-label", status === "none" ? name : `${name}, ${STATUS_LABEL[status]}. Show details`);
  };
  const setTitle = (next: WindowTitle): void => {
    title = next;
    user.textContent = next.user ? `${next.user}@` : "";
    host.textContent = next.host;
    session.textContent = next.session ?? "";
    session.hidden = !next.session;
    label();
  };
  const setStatus = (next: WindowStatus): void => {
    status = next;
    root.dataset.status = next;
    label();
  };
  const setIcon = (svg: string): void => { mark.innerHTML = svg; mark.hidden = !svg; };

  setTitle(title);
  setStatus(status);
  setIcon(options.icon ?? "");

  return {
    root,
    header,
    pill,
    body,
    setActive(active) {
      root.toggleAttribute("data-active", active);
      if (active) root.setAttribute("aria-current", "true");
      else root.removeAttribute("aria-current");
    },
    setTitle,
    setStatus,
    setIcon,
    dispose() {
      for (const [button, handler] of handlers) button.removeEventListener("click", handler);
      root.remove();
    },
  };
}
