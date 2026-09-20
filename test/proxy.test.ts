import assert from "node:assert/strict";
import test from "node:test";

import { createProxyHandler, decide, TARGET_URL_HEADER } from "../src/core.js";

const KEY = "sk-spicy-test-key";
const TARGET = "https://api.spicyapi.ai/api/v1/models";

function incoming(headers: Record<string, string>, method = "GET"): Request {
  return new Request("https://app.example/api/spicy/proxy", { method, headers });
}

void test("forwards with the server's key and always drops a client-supplied Authorization", () => {
  // Without dropping it the proxy becomes an open relay forwarding on behalf of any key: anyone can
  // use it as a jump host, and the bill lands on whoever deployed the proxy.
  const decision = decide(
    incoming({
      [TARGET_URL_HEADER]: TARGET,
      authorization: "Bearer sk-spicy-someone-elses-key",
      "x-api-key": "another-attempt",
    }),
    { apiKey: KEY },
  );
  assert.equal(decision.ok, true);
  if (!decision.ok) return;
  assert.equal(decision.request.headers.get("authorization"), `Bearer ${KEY}`);
  assert.equal(decision.request.headers.get("x-api-key"), null);
});

void test("refuses a target origin that is not allow-listed, leaking no byte of the key", () => {
  // This is the one catastrophic failure in the design: allowing an arbitrary target means your own
  // server sends your key to a host the attacker chose, and the traffic looks entirely normal.
  for (const hostile of [
    "https://attacker.example/collect",
    "http://api.spicyapi.ai/api/v1/models",
    "https://api.spicyapi.ai.attacker.example/api/v1/models",
    "https://evil.example/?x=https://api.spicyapi.ai",
  ]) {
    const decision = decide(incoming({ [TARGET_URL_HEADER]: hostile }), { apiKey: KEY });
    assert.equal(decision.ok, false, `must refuse ${hostile}`);
    if (decision.ok) return;
    assert.equal(decision.status, 403);
  }
});

void test("a host that merely starts with our domain is refused - the comparison is on the exact origin", () => {
  // `startsWith("https://api.spicyapi.ai")` would admit api.spicyapi.ai.attacker.example, and this
  // test exists to pin down that the comparison must never become a prefix match.
  const decision = decide(
    incoming({ [TARGET_URL_HEADER]: "https://api.spicyapi.ai.attacker.example/steal" }),
    { apiKey: KEY },
  );
  assert.equal(decision.ok, false);
});

void test("a missing target header is a 400, a missing key is a 500", () => {
  // The two must stay apart: the first is the caller's mistake, the second the deployer's. Collapsed
  // into one status code, whoever investigates goes and edits the client while the problem is on the
  // server.
  const missingTarget = decide(incoming({}), { apiKey: KEY });
  assert.equal(missingTarget.ok, false);
  if (!missingTarget.ok) assert.equal(missingTarget.status, 400);

  const missingKey = decide(incoming({ [TARGET_URL_HEADER]: TARGET }), { apiKey: () => undefined });
  assert.equal(missingKey.ok, false);
  if (!missingKey.ok) assert.equal(missingKey.status, 500);
});

void test("hop-by-hop headers are not forwarded, nor is the target header itself", () => {
  const decision = decide(
    incoming({
      [TARGET_URL_HEADER]: TARGET,
      connection: "keep-alive",
      "transfer-encoding": "chunked",
      host: "app.example",
      "content-type": "application/json",
    }),
    { apiKey: KEY },
  );
  assert.equal(decision.ok, true);
  if (!decision.ok) return;
  for (const dropped of ["connection", "transfer-encoding", TARGET_URL_HEADER]) {
    assert.equal(decision.request.headers.get(dropped), null, `${dropped} must not be forwarded`);
  }
  // Business headers stay - stripping too much breaks content negotiation and idempotency keys.
  assert.equal(decision.request.headers.get("content-type"), "application/json");
  assert.equal(new URL(decision.request.url).host, "api.spicyapi.ai");
});

void test("the idempotency key is forwarded verbatim: it is the caller's lock against paying twice", () => {
  const decision = decide(
    incoming({ [TARGET_URL_HEADER]: TARGET, "idempotency-key": "abc-123" }, "POST"),
    { apiKey: KEY },
  );
  assert.equal(decision.ok, true);
  if (!decision.ok) return;
  assert.equal(decision.request.headers.get("idempotency-key"), "abc-123");
});

void test("passes the upstream response straight back, and refuses in the platform's envelope shape", async () => {
  const handle = createProxyHandler({
    apiKey: KEY,
    fetch: () =>
      Promise.resolve(
        new Response(JSON.stringify({ code: 200, msg: "success", data: { items: [] } }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      ),
  });

  const ok = await handle(incoming({ [TARGET_URL_HEADER]: TARGET }));
  assert.equal(ok.status, 200);
  assert.equal(((await ok.json()) as { code: number }).code, 200);

  const refused = await handle(incoming({ [TARGET_URL_HEADER]: "https://attacker.example" }));
  assert.equal(refused.status, 403);
  // A client needs no separate parsing path for the proxy: the shape matches the platform's.
  const body = (await refused.json()) as { code: number; msg: string };
  assert.equal(body.code, 403);
  assert.match(body.msg, /not allowed/);
});

void test("an empty allowedOrigins array throws rather than meaning allow-everything", () => {
  // An implementation where an empty list means "no restriction" would silently open the gates the
  // moment somebody writes `allowedOrigins: []`.
  assert.throws(
    () => decide(incoming({ [TARGET_URL_HEADER]: TARGET }), { apiKey: KEY, allowedOrigins: [] }),
    /must not be empty/,
  );
});
