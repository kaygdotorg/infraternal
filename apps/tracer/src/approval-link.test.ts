/** The approval link is read from the right place, once, and cleaned without disturbing anything else (D311, #263). */
import { expect, test } from "bun:test";
import { readApprovalLink } from "./approval-link";

const at = (path: string) => {
  const url = new URL(`https://infra.example${path}`);
  return readApprovalLink(url);
};

test("a join link carries its code in the fragment and the fragment is cleared", () => {
  const read = at("/#join=AbCdEfGhIjKlMnOp");
  expect(read.link).toEqual({ code: "AbCdEfGhIjKlMnOp", kind: "join_machine" });
  expect(read.cleaned).toBe("/");
});

test("the CLI sign-in link keeps working from the query string", () => {
  const read = at("/?device_code=AbCdEfGhIjKlMnOp");
  expect(read.link).toEqual({ code: "AbCdEfGhIjKlMnOp", kind: "sign_in" });
  expect(read.cleaned).toBe("/");
});

test("unrelated query and fragment parts survive the cleaning", () => {
  const read = at("/app?mock=1&device_code=AbCdEfGhIjKlMnOp#keep=1");
  expect(read.cleaned).toBe("/app?mock=1#keep=1");
  expect(at("/app?mock=1#join=AbCdEfGhIjKlMnOp&keep=1").cleaned).toBe("/app?mock=1#keep=1");
});

test("a code in the query is never taken for a join code, and a fragment is never taken for a sign-in code", () => {
  expect(at("/?join=AbCdEfGhIjKlMnOp").link).toBeUndefined();
  expect(at("/#device_code=AbCdEfGhIjKlMnOp").link).toBeUndefined();
});

test("a page without a link is left alone", () => {
  const read = at("/?mock=1#top");
  expect(read.link).toBeUndefined();
  expect(read.cleaned).toBeUndefined();
});

test("two codes of any kind are refused and still cleared", () => {
  for (const path of [
    "/#join=AbCdEfGhIjKlMnOp&join=QwErTyUiOpAsDfGh",
    "/?device_code=AbCdEfGhIjKlMnOp&device_code=QwErTyUiOpAsDfGh",
    "/?device_code=AbCdEfGhIjKlMnOp#join=QwErTyUiOpAsDfGh",
  ]) {
    const read = at(path);
    expect(read.link).toHaveProperty("error");
    expect(read.link && "error" in read.link ? read.link.error : "").toContain("more than one code");
    expect(read.cleaned).toBe("/");
  }
});
