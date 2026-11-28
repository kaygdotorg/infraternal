/**
 * On-demand loader for the sign-in screen's WebGL backdrop (`packages/ui/src/faulty-terminal.ts`).
 * The backdrop only begins its intro reveal 600 ms after sign-in renders and never runs on signed-in visits,
 * so keeping it out of the first-screen static closure saves a request and ~3.2 KB brotli on every cold load (#573, D188).
 */
export { mountFaultyTerminal, type FaultyTerminal } from "../../../packages/ui/src/faulty-terminal";
