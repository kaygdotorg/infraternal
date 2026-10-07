/** Adds the default high-latency test link around browser requests fulfilled by the private auth fixture [#55, D122, D130]. */

const configuredRtt = Number(process.env.INFRATERNAL_TEST_RTT ?? "300");
if (!Number.isInteger(configuredRtt) || configuredRtt < 0 || configuredRtt > 60_000) {
  throw new Error("INFRATERNAL_TEST_RTT must be an integer from 0 to 60000 milliseconds");
}
const jitter = configuredRtt === 0 ? 0 : 30;

/** Routes a mocked HTTP request through independently delayed upload and download halves. */
export function routeWithLatency(routeOwner, url, handler) {
  return routeOwner.route(url, async (route) => {
    await wait(oneWayDelay());
    const delayed = new Proxy(route, {
      get(target, property) {
        if (property === "fulfill") {
          return async (...arguments_) => {
            await wait(oneWayDelay());
            return target.fulfill(...arguments_);
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    await handler(delayed);
  });
}

function oneWayDelay() {
  const halfRtt = configuredRtt / 2;
  const halfJitter = jitter / 2;
  return Math.max(0, halfRtt + (Math.random() * 2 - 1) * halfJitter);
}

function wait(milliseconds) {
  return milliseconds === 0 ? Promise.resolve() : new Promise((resolve) => setTimeout(resolve, milliseconds));
}
