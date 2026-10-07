/** Checks the compiled D162 flag boundary, including production URLs attempting opt-in. */
import { expect, test } from "bun:test";

for (const mode of ["off", "preview", "1"] as const) {
  test(`compiled recovery UI mode ${mode} obeys its URL boundary`, async () => {
    const result = await Bun.build({
      entrypoints: ["src/recovery-ui.ts"], target: "browser",
      define: { __RECOVERY_UI_MODE__: JSON.stringify(mode) },
    });
    expect(result.success).toBe(true);
    const source = await result.outputs[0]!.text();
    const flag = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`) as {
      recoveryUiEnabled: (search: string) => boolean;
    };
    for (const search of ["", "?mock=1", "?proto=recovery", "?mock=0&proto=recovery", "?mock=1&proto=other", "?mock=1&proto=recovery"]) {
      expect(flag.recoveryUiEnabled(search)).toBe(mode === "1" || (mode === "preview" && search === "?mock=1&proto=recovery"));
    }
  });
}
