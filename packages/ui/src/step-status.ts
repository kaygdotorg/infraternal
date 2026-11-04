/** Builds a non-interactive progress mark from the shared dot, spinner, tick, and danger cross. */
import { createSpinner } from "./spinner";
import { tick } from "./tick";

/** The four states of a step: not started, in progress (spinner), finished (tick), or failed (cross). */
export type StepStatus = "pending" | "running" | "done" | "failed";

/** The handle returned by {@link mountStepStatus}. */
export interface StepStatusController {
  /** Updates the glyph while keeping it out of the interaction and focus order. */
  set(status: StepStatus): void;
}

/** Mounts the shared status glyph in a host and returns its visual state controller. */
export function mountStepStatus(host: HTMLElement, initial: StepStatus = "pending"): StepStatusController {
  const pending = document.createElement("span");
  pending.className = "ui-step-status-pending";

  const tickHost = document.createElement("span");
  tickHost.className = "ui-step-status-tick";
  const tickController = tick(tickHost, false);

  const failed = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  failed.classList.add("ui-step-status-failed");
  failed.setAttribute("viewBox", "0 0 24 24");
  failed.setAttribute("aria-hidden", "true");
  const cross = document.createElementNS("http://www.w3.org/2000/svg", "path");
  cross.setAttribute("d", "m6 6 12 12M18 6 6 18");
  failed.append(cross);

  const spinner = createSpinner();
  host.replaceChildren(pending, tickHost, failed, spinner);
  host.classList.add("ui-step-status");
  host.setAttribute("aria-hidden", "true");
  host.dataset.state = initial;
  tickController.set(initial === "done", true);
  spinner.hidden = initial !== "running";

  return {
    set(status) {
      host.dataset.state = status;
      tickController.set(status === "done");
      spinner.hidden = status !== "running";
    },
  };
}
