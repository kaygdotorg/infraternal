/** Compares raw repaint syntax with complete painted rows using the shipping renderer and reader (#189). */
import { init, Terminal as Renderer } from "../../../apps/tracer/vendor/ghostty-web";
import { TerminalClient } from "../../../apps/tracer/src/terminal";

Object.assign(window, { snapshotWitness: async (bytes: number[]) => {
  await init();
  const host = document.createElement("div");
  host.style.cssText = "width:800px;height:480px";
  document.body.append(host);
  const terminal = new Renderer({ cols: 80, rows: 24, scrollback: 0 });
  try {
    terminal.open(host);
    const snapshot = new Uint8Array(bytes);
    await new Promise<void>((resolve) => terminal.write(snapshot, resolve));
    const raw = new TextDecoder().decode(snapshot);
    const lines = TerminalClient.prototype.readScreenText.call({ terminal } as unknown as TerminalClient).split("\n");
    return {
      rawWitness: raw.includes("BEFORE_HANDOVER\r\n") && raw.includes("AFTER_HANDOVER\r\n"),
      completeRows: lines.includes("BEFORE_HANDOVER") && lines.includes("AFTER_HANDOVER"),
    };
  } finally { terminal.dispose(); host.remove(); }
} });
