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
