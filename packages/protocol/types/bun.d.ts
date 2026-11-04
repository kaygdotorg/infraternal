/**
 * Minimal Bun declarations used to type-check the dependency-free test package.
 * They cover only what the protocol tests call; add a declaration here when a test needs
 * another Bun API, instead of adding a types dependency.
 */
declare module "bun:test" {
  /** The assertion methods the tests use on the value passed to `expect`. */
  interface Matchers {
    toBe(expected: unknown): void;
    toEqual(expected: unknown): void;
    toHaveLength(expected: number): void;
    toMatchObject(expected: unknown): void;
    toBeInstanceOf(expected: Function): void;
    toThrow(expected?: unknown): void;
  }

  export function describe(name: string, callback: () => void): void;
  export function test(name: string, callback: () => void | Promise<void>): void;
  export function expect<Value>(actual: Value): Matchers;
}

/** The part of Bun's file handle the tests read. */
interface BunFile {
  arrayBuffer(): Promise<ArrayBuffer>;
  text(): Promise<string>;
}

/** The Bun globals the tests call: run a process synchronously, and open a file. */
declare const Bun: {
  spawnSync(command: string[], options: { cwd: string; stdin: Uint8Array; maxBuffer: number }): {
    exitCode: number; stdout: Uint8Array; stderr: Uint8Array;
  };
  file(path: URL | string): BunFile;
};
