/** Identifies the pinned renderer crash and full-load fixtures used by browser tests. */
export interface TerminalFixture {
  name: string;
  path: string;
  bytes: number;
  sha256: string;
  encoding: "identity" | "gzip";
}

export const terminalFixtures: readonly TerminalFixture[] = [
  { name: "minimal-combining-5679.bin", path: "reproducers/minimal-combining-5679.bin", bytes: 5_679, sha256: "0047de6d657e0a1f69e16b9cdf8c6dc9343c98086c8b44df9276223f4bf3428f", encoding: "identity" },
  { name: "behemoth-prefix-82541.bin", path: "reproducers/behemoth-prefix-82541.bin", bytes: 82_541, sha256: "480f7026f1494e79fc62492439bf99c0449b6c4262cf641039ba3a94bc733741", encoding: "identity" },
  { name: "mixed-prefix-82144.bin", path: "reproducers/mixed-prefix-82144.bin", bytes: 82_144, sha256: "9d3575c83d09f5129461dc3c4406b04add00c01f23a6999c3a4c2bb26b1dc192", encoding: "identity" },
  { name: "binary-prefix-106342.bin", path: "reproducers/binary-prefix-106342.bin", bytes: 106_342, sha256: "519b244ff5ec90ef21cd0eeb017ed2bfc6655afc9b14424029a183a4b826ceca", encoding: "identity" },
  { name: "browser-text-binary-prefix-192253.bin", path: "reproducers/browser-text-binary-prefix-192253.bin", bytes: 192_253, sha256: "be3734effe07068d44594d261fbab86725528dd9cee1320880b89a58844fb55e", encoding: "identity" },
  { name: "binary-one-esc-context.bin", path: "reproducers/binary-one-esc-context.bin", bytes: 192_253, sha256: "7a07d190be76e63a521385fb69abf043e21b94aa73951ba340526d477951ce89", encoding: "identity" },
  { name: "binary-no-esc-context.bin", path: "reproducers/binary-no-esc-context.bin", bytes: 192_253, sha256: "bfc8c9fe72b76270cfb7c32ca576db69d21dd762b3845487c2c1667a29678434", encoding: "identity" },
  { name: "behemoth.txt", path: "behemoth.txt.gz", bytes: 50_000_000, sha256: "e436d35a872e85acd7ea95431e365fe876147576e13d0438db0093647ccae06d", encoding: "gzip" },
  { name: "mixed.txt", path: "mixed.txt.gz", bytes: 20_000_000, sha256: "29e8a2ca5d93956b9678ece3ba6ef2037c671d6fb423e9368ba00c42ff6e950f", encoding: "gzip" },
  { name: "binary.bin", path: "binary.bin.gz", bytes: 20_000_000, sha256: "c923c6d07a407ebc6a5003fe58ff94326c1834e0b34fc5567c9f46bc1c21f1f7", encoding: "gzip" },
];
