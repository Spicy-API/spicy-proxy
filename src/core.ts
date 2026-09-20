/**
 * A server-side proxy that lets client applications call SpicyAPI without ever holding an API key.
 *
 * JavaScript in a browser, an iOS or Android app, a desktop app - none of these can keep a secret.
 * A key shipped inside a bundle is a public key: an attacker decompiles it, or captures one
 * request, and then spends until the balance is gone, while all we see on our side is "this account
 * is rather busy today".
 *
 * The right shape is for the client to call the caller's own server, and for that layer to add the
 * key and forward the request. This module is that layer, mounted inside the caller's Next.js,
 * Express or any other fetch runtime.
 *
 * ## The protocol
 *
 * The client puts the destination in an `x-spicy-target-url` header and calls whichever route its
 * own backend agreed on (`/api/spicy/proxy` by convention). The proxy validates the target, adds
 * `Authorization`, forwards the request and passes the response straight back.
 *
 * ## Why the destination must be allow-listed rather than "forward to whatever the header says"
 *
 * This is the one place in the design where getting it wrong is catastrophic. Without validation,
 * anyone can put `https://attacker.example` in that header and have your server send them your key
 * - one request leaks it, and the traffic looks entirely normal, because your own server sent it.
 *
 * So `allowedOrigins` defaults to `https://api.spicyapi.ai` alone, and the comparison is on the
 * exact origin rather than a prefix: `https://api.spicyapi.ai.attacker.example` starts with our
 * domain too.
 */

/** The header carrying the destination. Lower-case throughout, as HTTP/2 accepts nothing else. */
export const TARGET_URL_HEADER = "x-spicy-target-url";

/** The conventional route. Not mandatory, but keeping it consistent lets front-end configuration
 * be copied as-is. */
export const DEFAULT_PROXY_ROUTE = "/api/spicy/proxy";

/** The platform's only production entry point. */
const DEFAULT_ALLOWED_ORIGIN = "https://api.spicyapi.ai";

/**
 * Hop-by-hop headers: they describe this particular connection rather than the message, so
 * forwarding them is meaningless and possibly harmful. See RFC 9110 section 7.6.1. `host` is a
 * separate case - it has to be recomputed for the destination, and copying it confuses the origin.
 */
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);

/**
 * These headers are dropped whatever the client sends, so that it cannot influence the
 * authentication decision made on its behalf.
 *
 * `authorization` matters most: without dropping it, a client could supply its own and override the
 * one we add, turning the proxy into an open relay that forwards on behalf of any key at all.
 */
const CLIENT_CONTROLLED = new Set(["authorization", "cookie", "x-api-key"]);

export interface ProxyOptions {
  /**
   * The API key. Read from `SPICY_API_KEY` by default.
   *
   * Passing a function supports rotation: it is consulted on every request, so no restart is
   * needed.
   */
  apiKey?: string | (() => string | undefined);
  /** Origins this proxy may forward to. The production entry point alone by default; only local
   * development needs it widened. */
  allowedOrigins?: string[];
  /** Forwarding timeout, 120 seconds by default - submitting a media task is fast; what takes time
   * is the polling afterwards. */
  timeoutMs?: number;
  /** An injected fetch, for tests. */
  fetch?: typeof fetch;
}

export class ProxyConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProxyConfigurationError";
  }
}

/** The proxy's decision: either allow, with the request to send, or refuse, with the status to
 * answer. */
export type ProxyDecision =
  { ok: true; request: Request } | { ok: false; status: number; message: string };

function resolveKey(options: ProxyOptions): string | undefined {
  const raw = typeof options.apiKey === "function" ? options.apiKey() : options.apiKey;
  const key = (raw ?? process.env.SPICY_API_KEY)?.trim();
  return key || undefined;
}

function allowed(options: ProxyOptions): string[] {
  const list = options.allowedOrigins ?? [DEFAULT_ALLOWED_ORIGIN];
  if (list.length === 0) {
    throw new ProxyConfigurationError(
      "allowedOrigins must not be empty; an empty list would forward your API key anywhere",
    );
  }
  return list;
}

/**
 * Turns an incoming request into either "forward this" or "refuse".
 *
 * This function never touches the network, so every framework adapter shares it and tests can
 * assert on the decision directly without standing up a real HTTP server.
 */
export function decide(incoming: Request, options: ProxyOptions = {}): ProxyDecision {
  const target = incoming.headers.get(TARGET_URL_HEADER);
  if (!target) {
    return { ok: false, status: 400, message: `missing ${TARGET_URL_HEADER} header` };
  }

  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return { ok: false, status: 400, message: `${TARGET_URL_HEADER} is not a valid absolute URL` };
  }

  // Exact origin comparison. A prefix match would admit https://api.spicyapi.ai.attacker.example.
  if (!allowed(options).includes(url.origin)) {
    return { ok: false, status: 403, message: `target origin is not allowed: ${url.origin}` };
  }

  const key = resolveKey(options);
  if (!key) {
    // This is a deployment problem rather than the caller's mistake, so it must not be a 4xx.
    return { ok: false, status: 500, message: "the proxy has no SpicyAPI key configured" };
  }

  const headers = new Headers();
  for (const [name, value] of incoming.headers) {
    const lower = name.toLowerCase();
    if (lower === TARGET_URL_HEADER) continue;
    if (HOP_BY_HOP.has(lower)) continue;
    if (CLIENT_CONTROLLED.has(lower)) continue;
    headers.set(name, value);
  }
  headers.set("authorization", `Bearer ${key}`);

  return {
    ok: true,
    request: new Request(url, {
      method: incoming.method,
      headers,
      body: incoming.body,
      // What is forwarded is a new request and must not inherit the caller's redirect policy.
      redirect: "manual",
      // Node's undici requires duplex to be declared explicitly for a streaming body. It is not
      // part of the standard RequestInit, so only this fragment is asserted rather than the whole
      // literal - asserting the literal would switch off type checking for every field above.
      ...(incoming.body ? ({ duplex: "half" } as RequestInit) : {}),
    }),
  };
}

/** Answers with a refusal shaped like the platform's error envelope, so a client needs no separate
 * parsing path for the proxy. */
function refuse(status: number, message: string): Response {
  return new Response(JSON.stringify({ code: status, msg: message, request_id: null }), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

/**
 * The generic handler: takes a `Request` and returns a `Response`.
 *
 * Framework adapters are responsible only for converting their own request object into a `Request`;
 * the decision and the forwarding both happen here.
 */
export function createProxyHandler(options: ProxyOptions = {}) {
  const doFetch = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 120_000;

  return async function handle(incoming: Request): Promise<Response> {
    const decision = decide(incoming, options);
    if (!decision.ok) return refuse(decision.status, decision.message);

    let upstream: Response;
    try {
      upstream = await doFetch(decision.request, { signal: AbortSignal.timeout(timeoutMs) });
    } catch {
      // Do not return the upstream error verbatim: it may carry an internal hostname.
      return refuse(504, "the upstream request did not complete in time");
    }

    const headers = new Headers();
    for (const [name, value] of upstream.headers) {
      if (HOP_BY_HOP.has(name.toLowerCase())) continue;
      headers.set(name, value);
    }
    return new Response(upstream.body, { status: upstream.status, headers });
  };
}
