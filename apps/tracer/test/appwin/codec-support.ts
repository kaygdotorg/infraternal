/** Checks whether this browser can decode the H.264 app-window fixtures before starting a streaming browser case. */
import { test, type Page } from "playwright/test";

const CODEC = "avc1.640028";

/** Skip only streaming cases when the browser reports either fixture shape unsupported, with the reason in the test report. */
export async function requireFixtureH264(page: Page): Promise<void> {
  const capability = await page.evaluate(async () => {
    if (typeof VideoDecoder === "undefined" || typeof VideoDecoder.isConfigSupported !== "function") {
      return { supported: false, reason: "WebCodecs VideoDecoder.isConfigSupported is unavailable" };
    }

    const failures: string[] = [];
    for (const [codedWidth, codedHeight] of [[1280, 800], [800, 1280]] as const) {
      try {
        const result = await VideoDecoder.isConfigSupported({
          codec: "avc1.640028",
          codedWidth,
          codedHeight,
          optimizeForLatency: true,
          hardwareAcceleration: "no-preference",
        });
        if (!result.supported) failures.push(`${codedWidth}x${codedHeight} is unsupported`);
      } catch (error) {
        failures.push(`${codedWidth}x${codedHeight}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    return failures.length === 0
      ? { supported: true, reason: "" }
      : { supported: false, reason: failures.join("; ") };
  });

  test.skip(!capability.supported, `H.264 ${CODEC} fixture decode is unavailable: ${capability.reason}`);
}
