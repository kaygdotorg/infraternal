/** Browser BIP-39 decoding for native recovery-envelope WebCrypto verification [25]. */
import { mnemonicToEntropy } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
globalThis.authRecoveryEntropy = words => mnemonicToEntropy(words, wordlist);
