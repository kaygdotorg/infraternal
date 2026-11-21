/**
 * Unit tests for predictive echo's host-echo matching and its secret-prompt rule (#569, D130).
 *
 * The overlay is mounted on a stand-in document without a 2D context, so nothing is drawn; the tests read the
 * prediction queue (`state.pendingText`) and the misprediction count, which is what the matching decides.
 */
import { afterAll, beforeAll, expect, test } from "bun:test";
import { isSecretPrompt, PredictiveEcho, type PredictionPosition } from "./predictive-echo";

/** The globals the overlay and the scheduler touch, saved so the stand-ins are removed afterwards. */
const stubbed = ["document", "window", "requestAnimationFrame", "cancelAnimationFrame", "getComputedStyle"] as const;
const saved = new Map<string, PropertyDescriptor | undefined>();
beforeAll(() => {
  for (const name of stubbed) saved.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
  const element = () => ({ style: {}, width: 0, height: 0, getContext: () => null, append() {}, remove() {}, setAttribute() {} });
  Object.assign(globalThis, {
    document: { createElement: element },
    window: globalThis,
    requestAnimationFrame: () => 0,
    cancelAnimationFrame: () => {},
    getComputedStyle: () => ({ getPropertyValue: () => "" }),
  });
});
afterAll(() => {
  for (const name of stubbed) {
    const descriptor = saved.get(name);
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else Reflect.deleteProperty(globalThis, name);
  }
});

/** A prediction at a 100 ms round trip whose host cursor the test moves by hand, with an optional prompt row. */
function predictor(prompt = "$ ") {
  const position = {
    canvas: {}, x: prompt.length, y: 0, visible: true, alternate: false, viewportY: 0, columns: 80, rows: 24,
    cellWidth: 9, cellHeight: 18, baseline: 14, fontFamily: "monospace", fontSize: 14,
  } as unknown as PredictionPosition;
  const echo = new PredictiveEcho({
    host: { append() {} } as unknown as HTMLElement,
    optedIn: true,
    getPosition: () => position,
    onVisible: () => {},
    textBeforeCursor: () => prompt,
  });
  echo.setRoundTrip(100);
  let sequence = 0n;
  const type = (key: string) => {
    const bytes = new TextEncoder().encode(key);
    echo.input(key, sequence, bytes, true);
    sequence += BigInt(bytes.byteLength);
  };
  /** The host's output: written to the (imagined) renderer, then painted. */
  const host = (text: string, cursorX: number) => {
    position.x = cursorX;
    echo.hostWritten(new TextEncoder().encode(text));
    echo.paintedOutput();
  };
  return { echo, type, host };
}

test("a line editor's erase echo (backspace, erase to end of line) confirms a predicted backspace", () => {
  for (const erase of ["\b \b", "\b\x1b[K", "\b\x1b[0K"]) {
    const { echo, type, host } = predictor();
    type("a");
    host("a", 3);
    type("\x7f");
    type("b");
    expect(echo.state.pendingText).toBe("b");
    host(erase, 2);
    host("b", 3);
    expect(echo.state.mispredictions).toBe(0);
    expect(echo.state.pendingText).toBe("");
  }
});

test("a backspace followed by another sequence is a cursor move, not an erase", () => {
  const { echo, type, host } = predictor();
  type("a");
  host("a", 3);
  type("\x7f");
  host("\b\x1b[1C", 3);
  type("b");
  host("b", 4);
  expect(echo.state.mispredictions).toBe(1);
});

test("keys at a password prompt are never predicted, even when the host still echoes", () => {
  const { echo, type } = predictor("[sudo] password for kayg: ");
  type("h");
  expect(echo.state.pendingText).toBe("");
  expect(echo.state.fallbacks["secret-prompt"]).toBe(1);
});

test("the secret-prompt rule matches prompts for secrets and nothing else", () => {
  for (const prompt of ["Password: ", "[sudo] password for kayg: ", "Enter passphrase for key '/home/k/.ssh/id_ed25519': ",
    "Password for 'https://kayg@example.com': ", "Verifying - Password:", "PIN: ", "Verification code: ", "Token? ",
    "Contraseña: ", "Senha: ", "Пароль: ", "パスワード: ", "密码：", "Kennwort:", "Mot de passe : ", "API key: ",
    "Enter password> ", "Recovery words: ", "[sudo] Passwort für kayg: "]) {
    expect(isSecretPrompt(prompt)).toBe(true);
  }
  for (const prompt of ["kayg@box:~$ ", "% ", ">>> ", "Username for 'https://example.com': ", "~/passwords$ ",
    "pinhead:~$ ", "$ echo password: hello", "kayg@box ~/src/token-service> ", "> ", "kayg@secret-box:~/x% "]) {
    expect(isSecretPrompt(prompt)).toBe(false);
  }
});
