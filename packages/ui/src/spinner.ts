/** Creates the shared, theme-aware spinner mark for short in-place progress. */
export function createSpinner(): HTMLSpanElement {
  const spinner = document.createElement("span");
  spinner.className = "ui-spinner";
  spinner.setAttribute("aria-hidden", "true");
  return spinner;
}
