/**
 * The Next.js adapter.
 *
 * App Router: export `route` as the route's method handlers, unchanged.
 *
 * ```ts
 * // app/api/spicy/proxy/route.ts
 * export const { GET, POST, PUT, DELETE } = route;
 * export const runtime = "nodejs"; // see below
 * ```
 *
 * `runtime` must be set to `nodejs` explicitly: the edge runtime cannot read the server-only
 * values in `process.env`, and the key lives precisely there. A project that defaults to the edge
 * discovers this only after deploying - at which point the proxy answers 500 "no key configured"
 * while everything works locally.
 */
import { createProxyHandler, type ProxyOptions } from "./core.js";

/** App Router: `export const { POST } = route` is all it takes. */
export function createRoute(options: ProxyOptions = {}) {
  const handle = createProxyHandler(options);
  return { GET: handle, POST: handle, PUT: handle, PATCH: handle, DELETE: handle };
}

/** An App Router route with default configuration, taking its key from `SPICY_API_KEY`. */
export const route = createRoute();
