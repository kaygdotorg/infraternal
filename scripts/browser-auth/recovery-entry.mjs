/** Bundles the production auth/recovery adapter for port-free native browser verification. */
import { registerOwner, loginWithPasskey, recoveryAuth } from '../../apps/tracer/src/auth.ts';
import { startRecovery, replacePasskey } from '../../apps/tracer/src/recovery-auth.ts';
import { mnemonicToEntropy } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
globalThis.recoveryBrowser = { registerOwner, loginWithPasskey, startRecovery, replacePasskey, recoveryAuth,
  entropy: words => mnemonicToEntropy(words, wordlist) };
