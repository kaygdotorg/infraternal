/**
 * Pins the keyboard attributes of every field a person types a token, word or secret into (#510).
 * iOS capitalises the first letter and "corrects" words unless told not to, which turns a lowercase setup
 * token into one that no longer matches. The fields are template strings, so the check reads the source.
 */
import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";

/** The text of a tracer source file, relative to this test. */
const source = (file: string): string => readFileSync(new URL(file, import.meta.url), "utf8");

/** The opening tag of the first element whose `id` or `data-secret` marker is `marker`. */
function tag(file: string, marker: string): string {
  const text = source(file);
  const at = text.indexOf(marker);
  expect(at).toBeGreaterThan(-1);
  return text.slice(text.lastIndexOf("<", at), text.indexOf(">", at));
}

/** The attributes that stop iOS capitalising, correcting or spell-checking what is typed. */
const NO_KEYBOARD_HELP = [/autocapitalize="(none|off)"/, /autocorrect="off"/, /spellcheck="false"/];

/** Every token, word, username and secret field: its name, the file that draws it and a marker inside its opening tag. */
const FIELDS: ReadonlyArray<[string, string, string]> = [
  ["setup token", "./onboarding-setup.on-demand.ts", 'id="setup-token"'],
  ["setup username", "./onboarding-setup.on-demand.ts", 'id="setup-username"'],
  ["recovery username", "./recovery.ts", 'id="recovery-username"'],
  ["recovery word", "./recovery.ts", 'aria-label="Word ${i + 1}"'],
  ["private key", "./canvas/addhost/wizard.ts", 'data-secret="key"'],
  ["add-host prototype secret", "./add-host-prototype.ts", 'aria-label="SSH key or password"'],
];

for (const [name, file, marker] of FIELDS) {
  test(`${name} field turns off capitalising, correcting and spellcheck`, () => {
    const opening = tag(file, marker);
    for (const attribute of NO_KEYBOARD_HELP) expect(opening).toMatch(attribute);
  });
}

test("one-off secret inputs share the same attributes", () => {
  const text = source("./canvas/addhost/wizard.ts");
  const line = text.split("\n").find((l) => l.startsWith("const ONE_OFF_SECRET_ATTRS"))!;
  for (const attribute of NO_KEYBOARD_HELP) expect(line).toMatch(attribute);
});
