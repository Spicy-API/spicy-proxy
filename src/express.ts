/**
 * The Express adapter.
 *
 * ```ts
 * app.all("/api/spicy/proxy", createExpressHandler());
 * ```
 *
 * Express req/res are Node streams rather than fetch's `Request` and `Response`, so all this layer
 * does is convert between the two; the decision and the forwarding stay in core.
 *
 * Do not mount body-parsing middleware ahead of this route (`express.json()` and friends): it
 * consumes the request body, so what gets forwarded is a request with an empty body, and the error
 * surfaces upstream as "missing parameter" - which points nowhere near middleware ordering. Either
 * mount the proxy before the parser, or skip the parser for this path.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";

import { createProxyHandler, type ProxyOptions } from "./core.js";

type ExpressLike = IncomingMessage & { originalUrl?: string; body?: unknown };

export function createExpressHandler(options: ProxyOptions = {}) {
  const handle = createProxyHandler(options);

  return async function middleware(
    req: ExpressLike,
    res: ServerResponse,
    next?: (error?: unknown) => void,
  ): Promise<void> {
    try {
      const headers = new Headers();
      for (const [name, value] of Object.entries(req.headers)) {
        if (value === undefined) continue;
        headers.set(name, Array.isArray(value) ? value.join(", ") : value);
      }

      const hasBody = req.method !== "GET" && req.method !== "HEAD";
      const response = await handle(
        new Request(`http://proxy.invalid${req.originalUrl ?? req.url ?? "/"}`, {
          method: req.method,
          headers,
          ...(hasBody ? { body: Readable.toWeb(req) as ReadableStream, duplex: "half" } : {}),
        } as RequestInit),
      );

      res.statusCode = response.status;
      response.headers.forEach((value, name) => res.setHeader(name, value));
      if (response.body) {
        const nodeStream = Readable.fromWeb(
          response.body as Parameters<typeof Readable.fromWeb>[0],
        );
        nodeStream.pipe(res);
      } else {
        res.end();
      }
    } catch (error) {
      if (next) next(error);
      else {
        res.statusCode = 500;
        res.end();
      }
    }
  };
}
