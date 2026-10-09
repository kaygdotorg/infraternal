/**
 * Static text previews of a terminal window: what a window shows when it has no live renderer (a thumbnail,
 * a window on a host the mockup only simulates). Lines are escaped before they become markup; the prompt and
 * the command get their own classes so a preview is coloured like a shell.
 */
export const escapeHtml = (value: string): string => value.replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
})[char]!);

/** Italic (`ESC[3m`) and bold (`ESC[1m`) runs of a fixture line, closed by `ESC[0m`, become <i> and <b>. */
const sgr = (html: string): string => html.replace(/\u001b\[3m(.*?)\u001b\[0m/g, "<i>$1</i>").replace(/\u001b\[1m(.*?)\u001b\[0m/g, "<b>$1</b>").replace(/\u001b\[[0-9;]*m/g, "");

/** Splits a prompt line into its prompt and command so previews colour them like a shell. */
export function previewLine(line: string): string {
  const match = /^(\S+@\S+:[^$#]*[$#])(.*)$/.exec(line);
  if (!match) return `<span class="canvas-out">${sgr(escapeHtml(line)) || " "}</span>`;
  return `<span class="canvas-prompt">${escapeHtml(match[1]!)}</span><span class="canvas-cmd">${sgr(escapeHtml(match[2]!))}</span>`;
}

