/** Predictive echo is on by default only once the host's echo-off signal exists (#569, D130). */
import { expect, test } from "bun:test";
import { HOST_ECHO_SIGNAL_SHIPPED, predictiveEchoEnabled } from "./host-echo-signal";

test("without the host echo signal, only an explicit ?predict=1 turns prediction on", () => {
  expect(predictiveEchoEnabled(null, false)).toBe(false);
  expect(predictiveEchoEnabled("1", false)).toBe(true);
  expect(predictiveEchoEnabled("0", false)).toBe(false);
});

test("with the signal, prediction is on by default and ?predict=0 still turns it off", () => {
  expect(predictiveEchoEnabled(null, true)).toBe(true);
  expect(predictiveEchoEnabled("0", true)).toBe(false);
  expect(predictiveEchoEnabled("1", true)).toBe(true);
});

test("the shipped default follows the signal flag", () => {
  expect(predictiveEchoEnabled(null)).toBe(HOST_ECHO_SIGNAL_SHIPPED);
});
