/**
 * On-demand loader for BIP-39 mnemonic conversion and the 2048-word English wordlist (#573, D188).
 * Only first-run owner setup and account recovery generate or parse recovery phrases; keeping the wordlist
 * out of `auth.ts`'s static closure removes ~20 KB identity (~8 KB brotli) from every sign-in and signed-in load.
 */
export { entropyToMnemonic, mnemonicToEntropy } from "@scure/bip39";
export { wordlist } from "@scure/bip39/wordlists/english.js";
