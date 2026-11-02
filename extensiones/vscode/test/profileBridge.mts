/**
 * The VS Code side of the browser bridge, run for real in plain Node:
 * ProfileStore (SecretStorage persistence and reload) and the local token
 * server (`POST /token`, `GET /health`) — what the browser extension talks to.
 * Synthetic tokens only.
 *
 * Run: node --experimental-strip-types --import ./test/register.mjs test/profileBridge.mts
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import { ProfileStore } from "../src/secrets.ts";
import { TokenAutoRefreshServer } from "../src/tokenServer.ts";
import { setLocale } from "../src/i18n.ts";
import { createServer } from "node:http";
import {
  chatEndpointDiagnostics,
  chatEndpointOf,
  initLogger,
  isTokenUsable,
  streamCopilotTurn,
  tokenFingerprint,
  type CopilotProfile,
} from "@m365copilot/core/bizchat";

const logged: string[] = [];
initLogger({ appendLine: (line) => logged.push(line) });
setLocale("en");

/** SecretStorage in memory, shared by every ProfileStore built on it (like two windows). */
function fakeSecrets() {
  const values = new Map<string, string>();
  const listeners = new Set<(e: { key: string }) => void>();
  return {
    values,
    async get(key: string) {
      return values.get(key);
    },
    async store(key: string, value: string) {
      values.set(key, value);
      for (const listener of listeners) listener({ key });
    },
    async delete(key: string) {
      values.delete(key);
      for (const listener of listeners) listener({ key });
    },
    onDidChange(listener: (e: { key: string }) => void) {
      listeners.add(listener);
      return { dispose: () => listeners.delete(listener) };
    },
  };
}

const b64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const rand = (bytes: number) => randomBytes(bytes).toString("base64url");
const jwe = () =>
  `${b64url({ alg: "RSA-OAEP-256", enc: "A256GCM" })}.${rand(256)}.${rand(12)}.${rand(1600)}.${rand(16)}`;
const jwt = () =>
  `${b64url({ alg: "none" })}.${b64url({
    aud: "https://substrate.office.com/sydney",
    oid: "work-oid",
    tid: "work-tid",
    upn: "someone@contoso.com",
    exp: Math.floor(Date.now() / 1000) + 3600,
  })}.sig`;
const identity = {
  oid: "00000000-0000-0000-1234-56789abcdef0",
  tid: "9188040d-6c67-4c5b-b112-36a304b66dad",
  endpointBase: "wss://substrate.office.com/m365Copilot/Chathub",
};
/** What the browser extension's background POSTs (profileFromCapture). */
const browserProfile = (accessToken: string, extra: Record<string, unknown> = {}) =>
  JSON.stringify({
    version: 1,
    capturedAt: new Date().toISOString(),
    accessToken,
    endpoint: `${identity.endpointBase}/${identity.oid}@${identity.tid}?scenario=OfficeWebConsumerCopilot`,
    origin: "https://m365.cloud.microsoft",
    userAgent: "UA",
    invocationTemplate: null,
    invocationType: 4,
    claims: null,
    identity,
    ...extra,
  });

async function testPersistenceAndReload() {
  const secrets = fakeSecrets();
  const store = new ProfileStore(secrets as never);
  const token = jwe();
  const saved = await store.setFromPaste(browserProfile(token));
  assert.equal(saved.identity?.oid, identity.oid);

  // Another window / a restart: a new store reads it back from SecretStorage.
  const reloaded = await new ProfileStore(secrets as never).get();
  assert.equal(reloaded?.accessToken, token);
  assert.deepEqual(reloaded?.identity, identity);
  assert.equal(reloaded?.claims, null);
  assert.equal(isTokenUsable(reloaded!), true);

  // Rejected by M365: persisted, and only for that very token.
  await store.markRejected("some-other-token");
  assert.equal((await store.get())?.rejectedAt, undefined);
  await store.markRejected(token);
  const rejected = await new ProfileStore(secrets as never).get();
  assert.ok(rejected?.rejectedAt);
  assert.equal(isTokenUsable(rejected!), false);
  // The browser resends the same token (a new model seen…): still rejected.
  await store.setFromPaste(browserProfile(token, { observedTones: ["Gpt_5_6_Reasoning"] }));
  assert.ok((await store.get())?.rejectedAt);
  assert.deepEqual((await store.get())?.observedTones, ["Gpt_5_6_Reasoning"]);
  // A new token replaces it, usable again.
  await store.setFromPaste(browserProfile(jwe()));
  assert.equal((await store.get())?.rejectedAt, undefined);

  // JWT profiles persist exactly as before.
  const work = await store.setFromPaste(jwt());
  assert.equal((await new ProfileStore(secrets as never).get())?.claims?.upn, work.claims?.upn);
  // Nothing in the secret but the profile itself.
  assert.equal(secrets.values.size, 1);
  store.dispose();
  console.log(
    "  ✓ ProfileStore: un perfil JWE se guarda, se recarga y recuerda el rechazo de su token",
  );
}

async function testLocalBridge() {
  const secrets = fakeSecrets();
  const store = new ProfileStore(secrets as never);
  const received: CopilotProfile[] = [];
  const server = new TokenAutoRefreshServer(store, (profile) => received.push(profile));
  // Any free port, not 51827: a real VS Code may be listening there.
  Object.defineProperty(server, "port", { value: 0 });
  server.start();
  const http = (server as unknown as { server: import("node:http").Server }).server;
  await new Promise<void>((resolve) =>
    http.listening ? resolve() : http.once("listening", resolve),
  );
  const base = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
  const post = (body: string, origin = "chrome-extension://abcdefghijklmnop") =>
    fetch(`${base}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: origin },
      body,
    });
  const health = async () => (await (await fetch(`${base}/health`)).json()) as Record<string, any>;

  try {
    // The browser extension delivers a JWE profile.
    const token = jwe();
    const response = await post(browserProfile(token));
    assert.equal(response.status, 200);
    const answer = (await response.json()) as Record<string, unknown>;
    assert.equal(answer.success, true);
    assert.equal(answer.expiresAt, null, "unknown expiry is reported as unknown");
    assert.equal(received.at(-1)?.accessToken, token);
    assert.equal((await store.get())?.identity?.tid, identity.tid);
    assert.equal((await health()).rejectedToken, null);

    assert.equal(answer.tokenChanged, true);

    // The same profile delivered again and again (every frame answering a
    // re-scan, a restart…): stored once, "renewed" once.
    const writes = () => [...secrets.values.values()].length;
    let lastAnswer: Record<string, unknown> = {};
    for (let i = 0; i < 5; i++) {
      const again = await post(
        browserProfile(token, { capturedAt: new Date(Date.now() + i).toISOString() }),
      );
      lastAnswer = (await again.json()) as Record<string, unknown>;
    }
    assert.equal(lastAnswer.tokenChanged, false);
    assert.equal(lastAnswer.unchanged, true);
    assert.equal(received.length, 1, "a repeated delivery is not a renewal");
    assert.equal(writes(), 1);
    // Same token, something else changed (a model seen): stored, still not a renewal.
    const tones = (await (
      await post(browserProfile(token, { observedTones: ["Reasoning"] }))
    ).json()) as Record<string, unknown>;
    assert.deepEqual([tones.tokenChanged, tones.unchanged], [false, false]);
    assert.deepEqual((await store.get())?.observedTones, ["Reasoning"]);
    assert.equal(received.length, 1);

    // M365 rejects it: the health check says so, as a fingerprint — never the token.
    await store.markRejected(token);
    const verdict = await health();
    assert.equal(verdict.rejectedToken, tokenFingerprint(token));
    assert.ok(!JSON.stringify(verdict).includes(token.slice(0, 40)));

    // The same rejected token delivered again stays rejected and is no renewal.
    await post(browserProfile(token, { observedTones: ["Reasoning"] }));
    assert.equal((await health()).rejectedToken, tokenFingerprint(token));
    assert.equal(received.length, 1);

    // The browser renews: a new token clears the verdict, and that one is a renewal.
    assert.equal((await post(browserProfile(jwe()))).status, 200);
    assert.equal((await health()).rejectedToken, null);
    assert.equal(received.length, 2);

    // A raw JWE has no identity: refused with what is missing.
    const bare = await post(jwe());
    assert.equal(bare.status, 400);
    assert.match(String(((await bare.json()) as { error: string }).error), /\{oid\}@\{tid\}/);
    // Origin checks are unchanged: a random web page cannot write the profile.
    assert.equal((await post(browserProfile(jwe()), "https://evil.example")).status, 403);
    assert.equal((await post(jwt())).status, 200, "JWT delivery unchanged");
  } finally {
    server.dispose();
    store.dispose();
  }
  console.log(
    "  ✓ puente local: POST /token con JWE, entregas repetidas sin «renovado», /health avisa del rechazo, origen comprobado",
  );
}

/**
 * Regression: a real personal-account Chathub URL carries several KB of
 * `variants`; the old 2 KB cap dropped the endpoint in silence, the paste said
 * "ready", and every chat request then failed its endpoint check. Paste →
 * persist → reload → the chat request's own check → the URL it builds.
 */
async function testManualImportOfLongChathubUrl() {
  const token = jwe();
  const variants = Array.from({ length: 260 }, (_, i) => `feature.flight_${i}_enabled`).join(",");
  const pasted =
    `wss://substrate.office.com/m365Copilot/Chathub/${identity.oid}@${identity.tid}` +
    `?clientrequestid=c-1&X-SessionId=s-1&ConversationId=conv-1&access_token=${token}` +
    `&source=consumerweb&product=Office&variants=${variants}`;
  assert.ok(pasted.length > 8000, "as long as the real one");

  const secrets = fakeSecrets();
  const store = new ProfileStore(secrets as never);
  logged.length = 0;
  await store.setFromPaste(pasted);
  const reloaded = (await new ProfileStore(secrets as never).get())!;
  assert.ok(reloaded, "persisted");
  assert.equal(reloaded.accessToken, token);
  assert.equal(reloaded.endpointConfirmed, true);
  assert.ok(chatEndpointOf(reloaded), "passes the chat request's endpoint check");
  assert.deepEqual(chatEndpointDiagnostics(reloaded), {
    hasEndpoint: true,
    endpointHost: "substrate.office.com",
    endpointPath: "/m365Copilot/Chathub/{oid}@{tid}",
    endpointConfirmed: true,
    capturedScenario: null,
    missingRequiredFields: [],
  });
  // The diagnostic line, without the token, the ids or the URL.
  assert.ok(logged.some((line) => /chat endpoint.*"missingRequiredFields":\[\]/.test(line)));

  // The chat request: refuse the upgrade, but only after seeing what it asked for.
  const seen: string[] = [];
  const server = createServer();
  server.on("upgrade", (req, socket) => {
    seen.push(req.url ?? "");
    socket.end("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  await assert.rejects(
    streamCopilotTurn({
      profile: reloaded,
      endpointBase: `ws://127.0.0.1:${port}/m365Copilot/Chathub`,
      prompt: "PROMPT",
      tone: null,
      signal: new AbortController().signal,
      callbacks: { onText: () => {} },
      mode: "web",
    }),
    /personal Microsoft account/,
  );
  server.close();
  assert.equal(seen.length, 1, "the request reached the network: the endpoint check passed");
  const sent = new URL(`http://x${seen[0]}`);
  assert.equal(sent.pathname, `/m365Copilot/Chathub/${identity.oid}@${identity.tid}`);
  const query = sent.searchParams;
  assert.equal(query.get("access_token"), token);
  assert.equal(query.get("source"), "consumerweb");
  assert.equal(query.get("product"), "Office");
  assert.equal(query.get("variants"), variants, "web turn: the web app's flags, intact");
  for (const enterprise of ["scenario", "licenseType", "agentHost"])
    assert.equal(query.get(enterprise), null, `no ${enterprise} invented`);
  assert.notEqual(query.get("ConversationId"), "conv-1", "the web app's ids are not reused");
  assert.notEqual(query.get("clientrequestid"), "c-1");
  assert.ok(!seen[0]!.includes("officeweb") && !seen[0]!.includes("Bizchat"));
  // Nothing secret in the whole log of the turn.
  for (const secret of [token.slice(10, 60), identity.oid, "conv-1", "feature.flight_0"])
    assert.ok(!logged.join("\n").includes(secret), `logged: ${secret}`);
  store.dispose();
  console.log(
    "  ✓ regression: Chathub URL of several KB → paste → persist → reload → passes the chat check → URL without enterprise values",
  );
}

console.log("secrets.ts / tokenServer.ts");
await testPersistenceAndReload();
await testLocalBridge();
await testManualImportOfLongChathubUrl();
console.log("\nAll profile bridge tests passed.");
