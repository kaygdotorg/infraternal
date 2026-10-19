/** Models the server's bounded query arbitration for production-browser regressions [307]. */
import { TerminalQueries } from "../src/terminal-queries";
export class QueryReplies {
  private readonly scanner = new TerminalQueries();
  private next = 0n;
  private readonly pending = new Map<bigint, { started: number; request: string }>();
  dropped = 0;
  attempts = 0;
  output(offset: bigint, bytes: Uint8Array): void {
    if (offset > this.next) { this.scanner.reset(); this.next = offset; }
    const skip = Number(this.next - offset);
    if (skip >= bytes.length) return;
    this.scanner.scan(bytes.subarray(skip), offset + BigInt(skip), (_, sequence, started, request) => {
      if (this.pending.size === 64) this.pending.delete(this.pending.keys().next().value!);
      this.pending.set(sequence, { started, request });
    });
    this.next = offset + BigInt(bytes.length);
  }
  accept(sequence: bigint, bytes: Uint8Array): boolean {
    this.attempts++;
    const query = this.pending.get(sequence);
    const response = new TextDecoder().decode(bytes);
    const valid = bytes.length > 0 && bytes.length <= 1024 && query && performance.now() - query.started < 1000 && matchesReply(query.request, response);
    if (!valid) { this.dropped++; return false; }
    this.pending.delete(sequence);
    return true;
  }
}
function matchesReply(query: string, response: string): boolean {
  if (query.endsWith("6n")) return /^\u001b\[\??[0-9]{1,6};[0-9]{1,6}R$/.test(response);
  if (query.endsWith("5n")) return response === "\u001b[0n";
  if (query.endsWith("c")) return /^\u001b\[[?>][0-9;]+c$/.test(response);
  if (query.endsWith("$p")) return /^\u001b\[\??[0-9]+;[0-4]\$y$/.test(response);
  if (query.endsWith("q")) return /^\u001bP>\|[\x20-\x7e]+\u001b\\$/.test(response);
  if (query.endsWith("u")) return /^\u001b\[\?[0-9]+u$/.test(response);
  if (query.startsWith("\u001b]")) return /^\u001b\](?:1[012]|4;[0-9]+);rgb:[a-fA-F0-9]{1,4}\/[a-fA-F0-9]{1,4}\/[a-fA-F0-9]{1,4}(?:\u0007|\u001b\\)$/.test(response);
  return false;
}
