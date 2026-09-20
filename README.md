# @spicyapi/proxy

Let a browser, mobile or desktop app call SpicyAPI **without ever holding an API key**.

A key compiled into a client is a public key. Anyone can decompile the app or watch one request, and
then spend your balance until it runs out — while your dashboard just shows a busy day. The fix is
not obfuscation. It is to never put the key there: the app calls **your** server, and your server
adds the credential.

This package is that server-side hop.

## Install

```bash
npm install @spicyapi/proxy
```

Set `SPICY_API_KEY` in the server environment. It is never sent to the client.

## Next.js (App Router)

```ts
// app/api/spicy/proxy/route.ts
export { GET, POST, PUT, PATCH, DELETE } from "@spicyapi/proxy/nextjs";
export const runtime = "nodejs";
```

`runtime = "nodejs"` is not optional. Edge runtimes do not see server-only environment variables, so
the proxy would answer 500 in production while working perfectly on your machine.

## Express

```ts
import { createExpressHandler } from "@spicyapi/proxy/express";

app.all("/api/spicy/proxy", createExpressHandler());
```

Mount it **before** any body parser. `express.json()` consumes the request body, and the proxy would
then forward an empty one — which surfaces upstream as a missing-parameter error that points nowhere
near your middleware order.

## Any fetch runtime

```ts
import { createProxyHandler } from "@spicyapi/proxy";

const handle = createProxyHandler();
// handle(request: Request) => Promise<Response>
```

## How a client uses it

Point the client at your own route and put the real target in `x-spicy-target-url`:

```ts
await fetch("/api/spicy/proxy", {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "x-spicy-target-url": "https://api.spicyapi.ai/api/v1/jobs/createTask",
    "idempotency-key": crypto.randomUUID(),
  },
  body: JSON.stringify({ model, input }),
});
```

## What it refuses

| Situation                       | Answer |
| ------------------------------- | ------ |
| No `x-spicy-target-url`         | `400`  |
| Target origin not allow-listed  | `403`  |
| No key configured on the server | `500`  |
| Upstream did not answer in time | `504`  |

**The allow-list is the whole point.** Forwarding to whatever the header says would mean a stranger
can make your server hand your key to a host they control — one request, and the traffic looks
entirely normal because it came from you. The comparison is on the exact origin, never a prefix:
`https://api.spicyapi.ai.attacker.example` starts with our domain too.

Client-supplied `authorization`, `x-api-key` and `cookie` headers are dropped before forwarding, so
the proxy cannot be turned into an open relay for someone else's credentials.

## Limits

This hop authenticates to SpicyAPI. It does **not** authenticate your users — anyone who can reach
the route can spend your balance. Put your own session check, rate limit and per-user quota in front
of it, exactly as you would for any endpoint that costs money.
