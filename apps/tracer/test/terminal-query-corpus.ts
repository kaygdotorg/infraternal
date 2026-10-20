/** Generates equivalent request forms for shipping-renderer and three-viewer PTY properties [307]. */
export const terminalQueryCorpus = [
  "\u001bZ", "\u001b[c", "\u001b[0c", "\u001b[>c", "\u001b[=c", "\u001b[5n", "\u001b[?6n",
  "\u001b[?2004$p", "\u001b[>q", "\u001b[?u", "\u001bP$qm\u001b\\", "\u001bP$qbad\u001b\\",
  ...Array.from({ length: 8 }, (_, zeros) => `\u001b[${"0".repeat(zeros)}6n`),
  ...[0, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 19, 127].map((ignored) => `\u001b[${String.fromCharCode(ignored)}6n`),
  "\u001b[" + "\u0000".repeat(300) + "6n",
  "\u001b]0;cancelled\u001b[6n", "\u001bP$qcancelled\u001b[6n", "\u001b[6\u001bZ",
];
