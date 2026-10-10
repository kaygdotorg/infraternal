/** Minimal Bun declarations used to type-check the dependency-free test package. */
declare module "bun:test" {
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

interface BunFile {
  arrayBuffer(): Promise<ArrayBuffer>;
  text(): Promise<string>;
}

declare const Bun: {
  spawnSync(command: string[], options: { cwd: string; stdin: Uint8Array; maxBuffer: number }): {
    exitCode: number; stdout: Uint8Array; stderr: Uint8Array;
  };
  file(path: URL | string): BunFile;
};
