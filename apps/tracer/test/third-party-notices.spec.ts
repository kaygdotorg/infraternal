// SPDX-License-Identifier: AGPL-3.0-only
/** Checks that a production web build serves its complete third-party notices and the full MIT and Apache-2.0 texts. */
import { expect, test } from "playwright/test";

test("the production build serves complete theme and font license notices", async ({ request }) => {
  const mitResponse = await request.get("/licenses/MIT.txt");
  expect(mitResponse.status()).toBe(200);
  const mit = await mitResponse.text();
  const mitText = mit.replace(/\s+/g, " ");
  expect(mitText).toContain("Copyright (c) 2021 Catppuccin");
  expect(mitText).toContain(
    "The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.",
  );
  expect(mitText).toContain('THE SOFTWARE IS PROVIDED "AS IS"');

  const apacheResponse = await request.get("/licenses/Apache-2.0.txt");
  expect(apacheResponse.status()).toBe(200);
  const apache = await apacheResponse.text();
  const apacheText = apache.replace(/\s+/g, " ");
  expect(apacheText).toContain("Apache License Version 2.0, January 2004");
  expect(apacheText).toContain("4. Redistribution.");
  expect(apacheText).toContain("9. Accepting Warranty or Additional Liability.");
  expect(apacheText).toContain("END OF TERMS AND CONDITIONS");
  expect(apacheText).toContain("APPENDIX: How to apply the Apache License to your work.");

  const noticeResponse = await request.get("/THIRD_PARTY_NOTICES.md");
  expect(noticeResponse.status()).toBe(200);
  const notices = await noticeResponse.text();
  for (const asset of [
    "Catppuccin Latte", "Rosé Pine Dawn", "Geist Mono", "Maple Mono NF", "Nerd Symbols", "Source Code Pro",
  ]) {
    expect(notices, `the shipped notice includes ${asset}`).toContain(asset);
  }
});

test("the Nerd Symbols subset credits each carried source range and serves its full licence text", async ({ request }) => {
  const noticeResponse = await request.get("/THIRD_PARTY_NOTICES.md");
  expect(noticeResponse.status()).toBe(200);
  const notices = await noticeResponse.text();
  const sourceRows = notices.split("\n");
  const credited: Array<[string, string, string]> = [
    ["Pomicons", "U+E000–U+E00A", "SIL OFL 1.1"],
    ["Powerline Symbols", "U+E0A0–U+E0D7", "MIT"],
    ["Powerline Extra Symbols", "U+E0A0–U+E0D7", "MIT"],
    ["Seti UI", "U+E5FA–U+E6B7", "MIT"],
    ["Devicons", "U+E700–U+E7C5", "MIT"],
    ["Font Awesome Free", "U+F000–U+F2E0", "CC BY 4.0"],
    ["Font Logos", "U+F300–U+F381", "Unlicense"],
    ["Octicons", "U+F400–U+F532", "MIT"],
  ];
  for (const [source, range, license] of credited) {
    expect(sourceRows.some((row) => row.includes(source) && row.includes(range) && row.includes(license)),
      `the notice maps ${source} ${range} to its licence`).toBe(true);
  }
  expect(notices, "the Maple base font keeps its OFL terms").toContain("Maple Mono NF v7.9");
  expect(notices, "the separate glyph licences permit AGPL-compatible distribution").toContain("AGPL-compatible for\ndistribution alongside this AGPL-3.0-only application");

  const licenses = [
    ["/licenses/MIT.txt", "Copyright (c) 2021 Catppuccin"],
    ["/licenses/Nerd-Symbols-MIT.txt", "Copyright (c) 2013 Kim Silkebækken and other contributors"],
    ["/licenses/Nerd-Symbols-MIT.txt", "Copyright (c) 2016 Ryan L McIntyre"],
    ["/licenses/Nerd-Symbols-MIT.txt", "Copyright (c) 2014 Jesse Weed"],
    ["/licenses/Nerd-Symbols-MIT.txt", "Copyright (c) 2015 konpa"],
    ["/licenses/Nerd-Symbols-MIT.txt", "Copyright (c) 2023 GitHub Inc."],
    ["/licenses/Nerd-Symbols-MIT.txt", "The above copyright notice and this permission notice shall be included"],
    ["/licenses/CC-BY-4.0.txt", "Creative Commons Attribution 4.0 International Public License"],
    ["/licenses/CC-BY-4.0.txt", "Creative Commons may be contacted at creativecommons.org."],
    ["/licenses/Unlicense.txt", "This is free and unencumbered software released into the public domain."],
    ["/licenses/Unlicense.txt", "For more information, please refer to <http://unlicense.org>"],
    ["/licenses/Pomicons-OFL-1.1.txt", "with Reserved Font Name Pomicons."],
    ["/licenses/Pomicons-OFL-1.1.txt", "OTHER DEALINGS IN THE FONT SOFTWARE."],
    ["/licenses/Font-Awesome-Free.txt", "with Reserved Font Name: \"Font Awesome\"."],
    ["/licenses/Font-Awesome-Free.txt", "The Font Awesome Free download is licensed under a Creative Commons"],
    ["/licenses/Font-Awesome-Free.txt", "SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007"],
    ["/licenses/Font-Awesome-Free.txt", "OTHER DEALINGS IN THE FONT SOFTWARE."],
    ["/fonts/maple-mono-nf/OFL.txt", "Copyright 2022 The Maple Mono Project Authors"],
    ["/fonts/maple-mono-nf/OFL.txt", "OTHER DEALINGS IN THE FONT SOFTWARE."],
  ] as const;
  for (const [path, requiredText] of licenses) {
    const response = await request.get(path);
    expect(response.status(), `${path} is served by the production build`).toBe(200);
    expect((await response.text()).replace(/\s+/g, " "), `${path} contains its complete source licence`).toContain(requiredText);
  }
});
