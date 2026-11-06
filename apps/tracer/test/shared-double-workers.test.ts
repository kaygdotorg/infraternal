// SPDX-License-Identifier: AGPL-3.0-only
/** The mock-backed browser suite refuses more than one worker, and says why (#377). */
import { expect, test } from "bun:test";
import { sharedDoubleWorkersError } from "./shared-double-workers";

test("--workers=2 is refused with the cause named", () => {
  const message = sharedDoubleWorkersError(["test", "--workers=2"], {}, 8);
  expect(message).toContain("/__mock/reset");
  expect(message).toContain("2 were requested");
});

test("every way of asking for more than one worker is refused", () => {
  expect(sharedDoubleWorkersError(["--workers", "3"], {}, 8)).toBeDefined();
  expect(sharedDoubleWorkersError(["-j", "2"], {}, 8)).toBeDefined();
  expect(sharedDoubleWorkersError(["-j2"], {}, 8)).toBeDefined();
  expect(sharedDoubleWorkersError([], { PW_WORKERS: "4" }, 8)).toBeDefined();
  expect(sharedDoubleWorkersError(["--workers=50%"], {}, 8)).toBeDefined();
});

test("one worker, or nothing asked, starts normally", () => {
  expect(sharedDoubleWorkersError([], {}, 8)).toBeUndefined();
  expect(sharedDoubleWorkersError(["--workers=1"], {}, 8)).toBeUndefined();
  expect(sharedDoubleWorkersError([], { PW_WORKERS: "1" }, 8)).toBeUndefined();
  expect(sharedDoubleWorkersError(["--workers=50%"], {}, 2)).toBeUndefined();
});
