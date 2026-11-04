/**
 * The short form of a machine key fingerprint that a person compares by eye (#263).
 *
 * `infraternal up` prints the same short form beside its code, so the person can check that the browser and the
 * terminal talk about the same key. Sixteen base64 characters are 96 bits: far more than a look-alike attack can
 * search for in the minutes a code lives, and it fits a phone line. The full fingerprint is what a click copies.
 */

/** `SHA256:AbCd-…` becomes `AbCd EfGh IjKl MnOp`: the first sixteen characters, in groups of four. */
export function shortFingerprint(fingerprint: string): string {
  const digest = fingerprint.startsWith("SHA256:") ? fingerprint.slice("SHA256:".length) : fingerprint;
  return (digest.slice(0, 16).match(/.{1,4}/g) ?? []).join(" ");
}
