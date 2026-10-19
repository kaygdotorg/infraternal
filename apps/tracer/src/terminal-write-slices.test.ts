/** Checks scoped renderer input ownership, range validation and equivalence to bulk VT writes [307]. */
import { expect, test } from "bun:test";
import { Ghostty, type GhosttyTerminal } from "../vendor/ghostty-web";

const engine = await Ghostty.load(new URL("../vendor/ghostty-web/dist/ghostty-vt.wasm", import.meta.url).pathname);
const encoder = new TextEncoder();
function screen(terminal: GhosttyTerminal): number[] {
  // The raw API requires a RenderState update before reading its viewport.
  terminal.update();
  return terminal.getViewport().map((cell) => cell.codepoint);
}
function responses(terminal: GhosttyTerminal): string {
  let result = "";
  for (let next = terminal.readResponse(); next !== null; next = terminal.readResponse()) result += next;
  return result;
}

test("every slice split preserves cells, cursor and all renderer answers", () => {
  const bytes = encoder.encode("preé界\u001b[31mred\u001b[0m\u001b[6n\u001bZ\u001b[06n");
  const reference = engine.createTerminal(80, 24);
  try {
    reference.write(bytes);
    const expected = responses(reference);
    for (let split = 0; split <= bytes.length; split++) {
      const terminal = engine.createTerminal(80, 24);
      try {
        let actual = "";
        terminal.writeSlices(bytes, (write) => {
          if (split > 0) { write(split); actual += responses(terminal); }
          if (split < bytes.length) { write(bytes.length); actual += responses(terminal); }
        });
        expect(actual).toBe(expected);
        expect(terminal.getCursor()).toEqual(reference.getCursor());
        terminal.update(); reference.update();
        expect(terminal.getViewport().map((cell) => ({ ...cell }))).toEqual(reference.getViewport().map((cell) => ({ ...cell })));
      } finally { terminal.free(); }
    }
  } finally { reference.free(); }
});

test("invalid or incomplete ranges never feed unexpected bytes and leave later writes usable", () => {
  for (const end of [-1, 0, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 4]) {
    const terminal = engine.createTerminal(80, 24);
    try {
      expect(() => terminal.writeSlices(encoder.encode("abc"), (write) => write(end))).toThrow(RangeError);
      expect(terminal.getCursor().x).toBe(0);
      terminal.write("ok");
      expect(terminal.getCursor().x).toBe(2);
    } finally { terminal.free(); }
  }
  const terminal = engine.createTerminal(80, 24);
  try {
    expect(() => terminal.writeSlices(encoder.encode("abc"), () => undefined)).toThrow(RangeError);
    expect(terminal.getCursor().x).toBe(0);
  } finally { terminal.free(); }
});

test("escaped writers cannot access released input and callback failure releases the scope", () => {
  const terminal = engine.createTerminal(80, 24);
  let escaped: ((end: number) => void) | undefined;
  try {
    terminal.writeSlices(encoder.encode("abc"), (write) => { escaped = write; write(3); });
    expect(() => escaped?.(4)).toThrow(RangeError);
    expect(terminal.getCursor().x).toBe(3);
    expect(() => terminal.writeSlices(encoder.encode("def"), (write) => { escaped = write; write(1); throw new Error("end scope"); })).toThrow("end scope");
    // End 2 is inside the old range: only scope lifetime makes it invalid.
    expect(() => escaped?.(2)).toThrow(RangeError);
    terminal.write("z");
    expect(screen(terminal).slice(0, 5)).toEqual([97, 98, 99, 100, 122]);
  } finally { terminal.free(); }
});

test("nested writes and memory growth cannot replace borrowed input", () => {
  const terminal = engine.createTerminal(80, 24);
  const memory = (terminal as unknown as { memory: WebAssembly.Memory }).memory;
  try {
    terminal.writeSlices(encoder.encode("ab"), (write) => {
      write(1);
      terminal.write("C");
      memory.grow(1);
      write(2);
    });
    expect(screen(terminal).slice(0, 3)).toEqual([97, 67, 98]);
  } finally { terminal.free(); }
});

test("allocation refusal never writes or frees unowned memory", () => {
  const terminal = engine.createTerminal(80, 24);
  const native = (terminal as unknown as { exports: Record<string, unknown> }).exports;
  const memory = (terminal as unknown as { memory: WebAssembly.Memory }).memory;
  let writes = 0; let frees = 0;
  try {
    Reflect.set(terminal, "memory", new WebAssembly.Memory({ initial: 1 }));
    Reflect.set(terminal, "exports", {
      ...native,
      ghostty_wasm_alloc_u8_array: () => 0,
      ghostty_terminal_write: () => { writes++; },
      ghostty_wasm_free_u8_array: () => { frees++; },
    });
    expect(() => terminal.writeSlices(encoder.encode("abc"), (write) => write(3))).toThrow("allocation failed");
    expect(writes).toBe(0); expect(frees).toBe(0);
  } finally {
    Reflect.set(terminal, "exports", native);
    Reflect.set(terminal, "memory", memory);
    terminal.free();
  }
});

test("empty scopes accept no input and reject later writer use", () => {
  const terminal = engine.createTerminal(80, 24);
  let escaped: ((end: number) => void) | undefined;
  try {
    terminal.writeSlices(new Uint8Array(), (write) => { escaped = write; });
    expect(() => escaped?.(0)).toThrow(RangeError);
    expect(terminal.getCursor().x).toBe(0);
  } finally { terminal.free(); }
});

test("input views of native memory survive allocation-driven memory growth", () => {
  const terminal = engine.createTerminal(80, 24);
  const memory = (terminal as unknown as { memory: WebAssembly.Memory }).memory;
  const native = (terminal as unknown as { exports: {
    ghostty_wasm_alloc_u8_array(length: number): number;
    ghostty_wasm_free_u8_array(ptr: number, length: number): void;
  } }).exports;
  const ptr = native.ghostty_wasm_alloc_u8_array(3);
  expect(ptr).not.toBe(0);
  const input = new Uint8Array(memory.buffer, ptr, 3);
  input.set(encoder.encode("XYZ"));
  try {
    Reflect.set(terminal, "exports", { ...native, ghostty_wasm_alloc_u8_array: (length: number) => {
      memory.grow(1);
      return native.ghostty_wasm_alloc_u8_array(length);
    } });
    terminal.writeSlices(input, (write) => write(3));
    expect(terminal.getCursor().x).toBe(3);
  } finally {
    Reflect.set(terminal, "exports", native);
    native.ghostty_wasm_free_u8_array(ptr, 3);
    terminal.free();
  }
});

test("throwing callbacks release exactly their owned input allocation", () => {
  const terminal = engine.createTerminal(80, 24);
  const native = (terminal as unknown as { exports: {
    ghostty_wasm_alloc_u8_array(length: number): number;
    ghostty_wasm_free_u8_array(ptr: number, length: number): void;
  } }).exports;
  let allocations = 0; let releases = 0;
  try {
    Reflect.set(terminal, "exports", { ...native,
      ghostty_wasm_alloc_u8_array: (length: number) => { allocations++; return native.ghostty_wasm_alloc_u8_array(length); },
      ghostty_wasm_free_u8_array: (ptr: number, length: number) => { releases++; native.ghostty_wasm_free_u8_array(ptr, length); },
    });
    expect(() => terminal.writeSlices(encoder.encode("abc"), (write) => { write(1); throw new Error("end scope"); })).toThrow("end scope");
    expect(allocations).toBe(1); expect(releases).toBe(1);
  } finally {
    Reflect.set(terminal, "exports", native);
    terminal.free();
  }
});
