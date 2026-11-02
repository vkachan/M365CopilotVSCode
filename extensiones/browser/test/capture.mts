/**
 * Tests de la lógica de captura compartida (@m365copilot/core, capture.ts):
 * es la que usan tanto el interceptor de esta extensión como el userscript de
 * Tampermonkey, así que un fallo aquí rompería los dos a la vez.
 *
 * Run: node --experimental-strip-types --import ./test/register.mjs test/capture.mts
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  EXPIRY_WATCH_MS,
  MAX_ENDPOINT_CHARS,
  MAX_JWE_CHARS,
  MAX_JWT_CHARS,
  SCAN_EXPIRING_MS,
  SCAN_FRESH_MS,
  SCAN_MISSING_MAX_MS,
  SCAN_MISSING_MS,
  acceptToken,
  areClaimsUsable,
  chathubIdentity,
  decodeJwtPayload,
  isCaptureUsable,
  isSydneyCacheEntry,
  isValidJwe,
  msalExpiresOn,
  needsResync,
  sanitizeIdentity,
  tokenCandidatesInStorageValue,
  tokenExpiry,
  tokenFingerprint,
  tokenFormat,
  connectionArtSvg,
  deliveryKey,
  describeSocketParams,
  shouldStoreTentativeEndpoint,
  connectionState,
  diagnoseToken,
  inspectOutgoingFrames,
  isCopilotSocketUrl,
  isMicrosoftHost,
  isValidJwt,
  nextScan,
  normalizeEndpoint,
  profileFromCapture,
  sameCapture,
  tokenInSocketUrl,
  tokensInStorageValue,
  toneOfTemplate,
  withObservedTone,
  withoutExpiredToken,
} from "@m365copilot/core";

const NOW = Date.UTC(2026, 9, 7, 12, 0, 0);
const b64url = (value: unknown) =>
  Buffer.from(JSON.stringify(value))
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

function jwt(claims: Record<string, unknown>): string {
  return `${b64url({ alg: "none", typ: "JWT" })}.${b64url({
    aud: "https://substrate.office.com/sydney",
    oid: "o",
    tid: "t",
    upn: "someone@contoso.com",
    ...claims,
  })}.sig`;
}

const inMinutes = (minutes: number) => Math.floor(NOW / 1000) + minutes * 60;

/** Un JWE sintético: cabecera real, el resto bytes al azar (nada que descifrar). */
const rand = (bytes: number) => randomBytes(bytes).toString("base64url");
function jwe(
  header: Record<string, unknown> = { alg: "RSA-OAEP-256", enc: "A256GCM" },
  ciphertextBytes = 900,
): string {
  const key = header.alg === "dir" || header.alg === "ECDH-ES" ? "" : rand(256);
  return `${b64url(header)}.${key}.${rand(12)}.${rand(ciphertextBytes)}.${rand(16)}`;
}

const OID = "00000000-0000-0000-1234-56789abcdef0";
const TID = "9188040d-6c67-4c5b-b112-36a304b66dad";
const chathub = (token: string, host = "substrate.office.com") =>
  `wss://${host}/m365Copilot/Chathub/${OID}@${TID}?clientrequestid=c1&X-SessionId=s1` +
  `&access_token=${token}&source=officeweb&scenario=OfficeWebConsumerCopilot`;

function testTokenValidation() {
  assert.equal(isValidJwt(jwt({ exp: inMinutes(60) })), true);
  assert.equal(isValidJwt("a.b"), false);
  assert.equal(isValidJwt("a.b.c.d"), false);
  assert.equal(isValidJwt("a.b+c.d"), false, "base64url only");
  assert.equal(isValidJwt(`a.${"x".repeat(MAX_JWT_CHARS)}.c`), false, "size cap");
  assert.equal(isValidJwt(42), false);

  assert.equal(areClaimsUsable({ exp: inMinutes(5) }, NOW), true);
  assert.equal(areClaimsUsable({ exp: inMinutes(-1) }, NOW), false, "expired");
  assert.equal(
    areClaimsUsable({ exp: inMinutes(5), iat: inMinutes(10) } as never, NOW),
    false,
    "iat after exp",
  );
  assert.equal(areClaimsUsable(null, NOW), false);

  const fresh = jwt({ exp: inMinutes(60) });
  const older = jwt({ exp: inMinutes(30) });
  const newer = jwt({ exp: inMinutes(75) });
  const accepted = acceptToken({}, fresh, NOW);
  assert.equal(accepted?.accessToken, fresh);
  assert.equal(accepted?.claims.upn, "someone@contoso.com");
  const current = { accessToken: fresh, claims: accepted!.claims };
  assert.equal(acceptToken(current, fresh, NOW), null, "same token");
  assert.equal(acceptToken(current, older, NOW), null, "older token");
  assert.equal(acceptToken(current, newer, NOW)?.accessToken, newer, "newer token");
  assert.equal(acceptToken({}, jwt({ exp: inMinutes(-5) }), NOW), null, "expired token");
  assert.equal(
    acceptToken({}, jwt({ aud: "https://graph.microsoft.com", exp: inMinutes(60) }), NOW),
    null,
    "not Sydney",
  );
  assert.equal(acceptToken({}, `  ${fresh}  `, NOW)?.accessToken, fresh, "trimmed");
  console.log(
    "  ✓ sólo se acepta un JWT de Sydney válido, sin caducar y no más viejo que el actual",
  );
}

function testDiagnosis() {
  const fresh = jwt({ exp: inMinutes(60) });
  assert.equal(diagnoseToken({}, fresh, NOW).diagnosis, "accepted");
  assert.equal(diagnoseToken({}, "not.a.jwt!", NOW).diagnosis, "not-a-jwt");
  assert.equal(
    diagnoseToken({}, jwt({ aud: "https://graph.microsoft.com", exp: inMinutes(60) }), NOW)
      .diagnosis,
    "not-sydney",
    "un bearer de Graph se reconoce como no-Sydney, no como silencio",
  );
  assert.equal(diagnoseToken({}, jwt({ exp: inMinutes(-5) }), NOW).diagnosis, "expired");
  const current = { accessToken: fresh, claims: acceptToken({}, fresh, NOW)!.claims };
  assert.equal(diagnoseToken(current, fresh, NOW).diagnosis, "duplicate");
  assert.equal(
    diagnoseToken(current, jwt({ exp: inMinutes(30) }), NOW).diagnosis,
    "older-than-current",
  );
  console.log("  ✓ diagnoseToken explica por qué se descarta cada token");
}

function testSources() {
  const token = jwt({ exp: inMinutes(60) });
  assert.deepEqual(
    tokensInStorageValue(JSON.stringify({ credentialType: "AccessToken", secret: token })),
    [token],
  );
  assert.deepEqual(tokensInStorageValue(JSON.stringify({ access_token: token })), [token]);
  assert.deepEqual(tokensInStorageValue(token), [token]);
  assert.deepEqual(tokensInStorageValue('{"secret": 1}'), []);
  assert.deepEqual(tokensInStorageValue("short"), []);
  assert.deepEqual(tokensInStorageValue(null), []);

  const socket = `wss://substrate.office.com/m365Copilot/Chathub/o@t?access_token=${token}&ConversationId=c&source=officeweb`;
  assert.equal(isCopilotSocketUrl(socket), true);
  assert.equal(isCopilotSocketUrl("wss://presence.teams.microsoft.com/"), false);
  assert.equal(tokenInSocketUrl(socket), token);
  assert.equal(tokenInSocketUrl("not a url"), null);

  // The chat hub lives on substrate.office.com: it must NOT be rejected.
  assert.equal(
    normalizeEndpoint(socket),
    "wss://substrate.office.com/m365Copilot/Chathub/o@t?source=officeweb",
  );
  assert.equal(isMicrosoftHost("substrate.office.com"), true);
  assert.equal(isMicrosoftHost("m365.cloud.microsoft"), true);
  assert.equal(isMicrosoftHost("office.com"), true);
  assert.equal(isMicrosoftHost("evil-office.com"), false);
  assert.equal(isMicrosoftHost("office.com.evil.net"), false);
  assert.equal(normalizeEndpoint("wss://evil.example/Chathub?access_token=x"), "");
  assert.equal(
    normalizeEndpoint(`wss://substrate.office.com/${"x".repeat(MAX_ENDPOINT_CHARS)}`),
    "",
  );
  console.log(
    "  ✓ fuentes: caché MSAL, JWT pelado, URL del WebSocket; endpoint de substrate.office.com aceptado",
  );
}

function testFrames() {
  const RS = "\x1e";
  const chat = JSON.stringify({
    type: 4,
    target: "chat",
    arguments: [{ tone: "magic", message: { text: "hi" } }],
  });
  const metrics = JSON.stringify({ type: 1, target: "Metrics", arguments: [{}] });
  assert.deepEqual(inspectOutgoingFrames(`${metrics}${RS}${chat}${RS}`), {
    sawChat: true,
    template: { tone: "magic", message: { text: "hi" } },
    invocationType: 4,
  });
  assert.deepEqual(inspectOutgoingFrames(`${metrics}${RS}`), { sawChat: false });
  assert.deepEqual(inspectOutgoingFrames(`{"protocol":"json"${RS}not json${RS}`), {
    sawChat: false,
  });
  const huge = JSON.stringify({
    type: 4,
    target: "chat",
    arguments: [{ blob: "x".repeat(70 * 1024) }],
  });
  assert.deepEqual(
    inspectOutgoingFrames(huge),
    { sawChat: true },
    "oversized template is not kept",
  );
  assert.deepEqual(inspectOutgoingFrames(new ArrayBuffer(4)), { sawChat: false });
  console.log("  ✓ frames SignalR: detecta la invocación chat y acota la plantilla");
}

function testStore() {
  const token = jwt({ exp: inMinutes(-1) });
  const expired = {
    accessToken: token,
    tokenSource: "x",
    claims: { exp: inMinutes(-1) },
    endpoint: "wss://e",
  };
  assert.deepEqual(withoutExpiredToken(expired, NOW), { endpoint: "wss://e" });
  assert.equal(
    withoutExpiredToken({ accessToken: token, claims: { exp: inMinutes(10) } }, NOW),
    null,
  );
  assert.equal(withoutExpiredToken({}, NOW), null);

  assert.equal(
    sameCapture({ endpoint: "a", capturedAt: "1" }, { endpoint: "a", capturedAt: "2" }),
    true,
  );
  assert.equal(sameCapture({ endpoint: "a" }, { endpoint: "b" }), false);

  assert.equal(profileFromCapture({}, "UA"), null);
  const profile = profileFromCapture(
    { accessToken: "tok", claims: { exp: 1 }, capturedAt: "when" },
    "UA",
  );
  assert.deepEqual(profile, {
    version: 1,
    capturedAt: "when",
    accessToken: "tok",
    endpoint: null,
    origin: "https://m365.cloud.microsoft",
    userAgent: "UA",
    invocationTemplate: null,
    invocationType: 4,
    claims: { exp: 1 },
  });
  console.log(
    "  ✓ store: purga del token caducado, comparación sin sello temporal y perfil para VS Code",
  );
}

function testScanLoop() {
  // No token: back off from 2 s up to the cap.
  let missing = SCAN_MISSING_MS;
  const delays: number[] = [];
  for (let i = 0; i < 8; i += 1) {
    const next = nextScan({}, missing, NOW);
    delays.push(next.delay);
    missing = next.missingDelay;
  }
  assert.equal(delays[0], 3000);
  assert.equal(Math.max(...delays), SCAN_MISSING_MAX_MS);
  // A fresh token is watched from afar; one about to expire, closely — and the
  // scan never stops while there is a token (the bug the userscript had).
  const fresh = nextScan({ accessToken: "t", claims: { exp: inMinutes(50) } }, missing, NOW);
  assert.deepEqual(fresh, { delay: SCAN_FRESH_MS, missingDelay: SCAN_MISSING_MS });
  const expiring = nextScan(
    { accessToken: "t", claims: { exp: Math.floor((NOW + EXPIRY_WATCH_MS - 1000) / 1000) } },
    missing,
    NOW,
  );
  assert.equal(expiring.delay, SCAN_EXPIRING_MS);
  console.log(
    "  ✓ bucle de escaneo: backoff sin token, vigilancia lejana con token fresco y cercana al caducar",
  );
}

function testConnectionArt() {
  assert.equal(
    connectionState({ hasToken: false, expired: false, vscodeConnected: false }),
    "waiting",
  );
  assert.equal(
    connectionState({ hasToken: true, expired: false, vscodeConnected: false }),
    "captured",
  );
  assert.equal(
    connectionState({ hasToken: true, expired: false, vscodeConnected: true }),
    "connected",
  );
  assert.equal(
    connectionState({ hasToken: true, expired: true, vscodeConnected: true }),
    "warning",
  );
  assert.equal(
    connectionState({ hasToken: false, expired: false, vscodeConnected: true, needsUser: true }),
    "warning",
  );

  const svg = connectionArtSvg({
    idPrefix: "p1",
    leftLabel: "M365",
    rightLabel: "VS <Code>",
    title: "a & b",
  });
  assert.match(svg, /^<svg class="m365-art"/);
  assert.match(svg, /id="p1-m365"/);
  assert.match(svg, /id="p1-vscode"/);
  assert.match(svg, /href="#p1-vscode"/);
  assert.match(svg, /filter="url\(#p1-grey\)"/, 'the "off" logos are desaturated');
  // La señal: tres anillos (fondo + frente) con su animación y la versión
  // quieta «apuntando a VS Code» cuando conecta.
  for (const ring of ["outer", "middle", "inner"]) {
    assert.match(svg, new RegExp(`class="ring back ${ring}"`));
    assert.match(svg, new RegExp(`class="ring front ${ring}"`));
    assert.match(svg, new RegExp(`@keyframes m365-art-${ring}`));
  }
  assert.match(svg, /\[data-state="connected"\] \.m365-art \.ring,/);
  assert.doesNotMatch(svg, /class="(track|flow|head)/, "the old arrow is gone");
  assert.doesNotMatch(svg, /m365art-/, "every id uses the prefix");
  assert.match(svg, /VS &#60;Code&#62;/, "labels are escaped");
  assert.match(svg, /aria-label="a &#38; b"/);
  for (const state of ["waiting", "captured", "connected", "warning"]) {
    assert.match(svg, new RegExp(`\\[data-state="${state}"\\]`), `styles for ${state}`);
  }
  assert.match(svg, /prefers-reduced-motion/);
  console.log(
    "  ✓ ilustración M365 → VS Code: estados, señal de tres anillos, ids con prefijo, etiquetas escapadas y movimiento reducido",
  );
}

function testObservedTones() {
  assert.equal(toneOfTemplate({ tone: "Gpt_5_7_Chat" }), "Gpt_5_7_Chat");
  assert.equal(toneOfTemplate({ tone: "not a tone!" }), null);
  assert.equal(toneOfTemplate({ tone: 42 }), null);
  assert.equal(toneOfTemplate(undefined), null);
  assert.deepEqual(withObservedTone(undefined, "A_1"), ["A_1"]);
  assert.deepEqual(
    withObservedTone(["A_1", "B_2"], "A_1"),
    ["B_2", "A_1"],
    "moved to most recent, no duplicate",
  );
  assert.deepEqual(withObservedTone(["A_1"], null), ["A_1"]);
  const many = Array.from({ length: 30 }, (_, i) => `T_${i}`);
  assert.equal(withObservedTone(many, "Last_1").length, 20);
  assert.equal(withObservedTone(many, "Last_1").at(-1), "Last_1");
  assert.deepEqual(
    profileFromCapture({ accessToken: "t", observedTones: ["A_1"] }, "UA")?.observedTones,
    ["A_1"],
  );
  assert.equal(profileFromCapture({ accessToken: "t" }, "UA")?.observedTones, undefined);
  console.log(
    "  ✓ modelos vistos en la web: tone validado, sin duplicados, acotado y enviado con el perfil",
  );
}

function testJweRecognition() {
  const token = jwe();
  assert.equal(tokenFormat(token), "jwe");
  assert.equal(isValidJwe(token), true);
  assert.equal(isValidJwt(token), false, "cinco partes no son un JWT");
  assert.equal(tokenFormat(jwt({ exp: inMinutes(60) })), "jwt");
  assert.equal(decodeJwtPayload(token), null, "la segunda parte de un JWE no es un payload");

  // `dir` / `ECDH-ES`: la clave cifrada va vacía — y sólo con ellos.
  const direct = jwe({ alg: "dir", enc: "A128CBC-HS256" });
  assert.equal(direct.split(".")[1], "");
  assert.equal(tokenFormat(direct), "jwe");
  assert.equal(tokenFormat(jwe({ alg: "ECDH-ES", enc: "A256GCM" })), "jwe");
  const [h, , iv, ct, tag] = direct.split(".");
  assert.equal(isValidJwe(`${h}.${rand(256)}.${iv}.${ct}.${tag}`), false, "dir con clave");
  const [h2, , iv2, ct2, tag2] = token.split(".");
  assert.equal(isValidJwe(`${h2}..${iv2}.${ct2}.${tag2}`), false, "RSA-OAEP sin clave");

  // Malformados.
  const parts = token.split(".");
  assert.equal(isValidJwe(parts.slice(0, 4).join(".")), false, "cuatro partes");
  assert.equal(isValidJwe(`${token}.x`), false, "seis partes");
  assert.equal(
    isValidJwe(`${parts[0]}.${parts[1]}.${parts[2]}..${parts[4]}`),
    false,
    "sin texto cifrado",
  );
  assert.equal(isValidJwe(`${parts.slice(0, 4).join(".")}.`), false, "sin tag");
  assert.equal(isValidJwe(`.${parts.slice(1).join(".")}`), false, "sin cabecera");
  assert.equal(isValidJwe(token.replace(/\.(.)/, ".+")), false, "base64url sólo");
  assert.equal(isValidJwe(`${rand(20)}.${parts.slice(1).join(".")}`), false, "cabecera no JSON");
  assert.equal(isValidJwe(jwe({ alg: "RSA-OAEP" })), false, "cabecera sin enc");
  assert.equal(isValidJwe(jwe({ enc: "A256GCM" })), false, "cabecera sin alg");
  assert.equal(
    isValidJwe(`${parts[0]}.${parts[1]}.${parts[2]}.${"A".repeat(MAX_JWE_CHARS)}.${parts[4]}`),
    false,
    "tope de tamaño",
  );
  assert.equal(tokenFormat("a.b.c.d.e"), null);
  assert.equal(tokenFormat(undefined), null);
  console.log(
    "  ✓ JWE compacto: cinco partes, cabecera con alg/enc, clave vacía sólo con dir/ECDH-ES",
  );
}

function testChathubIdentity() {
  const token = jwe();
  assert.deepEqual(chathubIdentity(chathub(token)), {
    oid: OID,
    tid: TID,
    endpointBase: "wss://substrate.office.com/m365Copilot/Chathub",
  });
  // El `@` escapado y https (copiada de DevTools) también valen.
  assert.equal(
    chathubIdentity(`https://substrate.office.com/m365Copilot/Chathub/${OID}%40${TID}?a=1`)?.tid,
    TID,
  );
  // Sólo Microsoft, sólo cifrado, sólo la ruta del hub y nada raro en los ids.
  for (const bad of [
    chathub(token, "substrate.office.com.evil.example"),
    chathub(token, "evil.example"),
    `ws://substrate.office.com/m365Copilot/Chathub/${OID}@${TID}`,
    `http://substrate.office.com/m365Copilot/Chathub/${OID}@${TID}`,
    `wss://user:pw@substrate.office.com/m365Copilot/Chathub/${OID}@${TID}`,
    `wss://substrate.office.com:8443/m365Copilot/Chathub/${OID}@${TID}`,
    `wss://substrate.office.com/m365Copilot/Presence/${OID}@${TID}`,
    `wss://substrate.office.com/m365Copilot/Chathub/${OID}`,
    `wss://substrate.office.com/m365Copilot/Chathub/@${TID}`,
    `wss://substrate.office.com/m365Copilot/Chathub/${OID}@`,
    `wss://substrate.office.com/m365Copilot/Chathub/a%2Fb@${TID}`,
    `wss://substrate.office.com/m365Copilot/Chathub/${OID}@${TID}/extra`,
    "not a url",
  ]) {
    assert.equal(chathubIdentity(bad), null, bad);
  }
  // Una identidad que llega en un JSON se revalida igual.
  const identity = chathubIdentity(chathub(token))!;
  assert.deepEqual(sanitizeIdentity(identity), identity);
  assert.equal(sanitizeIdentity({ ...identity, endpointBase: "wss://evil.example/Chathub" }), null);
  assert.equal(sanitizeIdentity({ ...identity, oid: "../x" }), null);
  assert.equal(
    sanitizeIdentity({ ...identity, endpointBase: `${identity.endpointBase}?x=1` }),
    null,
  );
  assert.equal(sanitizeIdentity("x"), null);
  console.log("  ✓ identidad {oid}@{tid} sólo de una URL de Chathub de Microsoft por wss/https");
}

function testJweDiagnosis() {
  const token = jwe();
  const socket = { kind: "socket" as const, url: chathub(token) };

  // Del socket del chat: aceptado, sin claims inventados, con identidad.
  const fromSocket = diagnoseToken({}, token, NOW, socket);
  assert.equal(fromSocket.diagnosis, "accepted");
  assert.equal(fromSocket.accepted?.claims, null);
  assert.equal(fromSocket.accepted?.identity?.oid, OID);
  assert.equal(fromSocket.accepted?.expiresAt, undefined);
  // El endpoint de ESE socket viaja con el token: nunca uno sin el otro.
  assert.equal(fromSocket.accepted?.endpoint, normalizeEndpoint(socket.url));
  assert.equal(tokenExpiry(fromSocket.accepted!), null, "caducidad desconocida, no inventada");

  // Sin origen, de una cabecera cualquiera o de un socket sin identidad: no.
  assert.equal(diagnoseToken({}, token, NOW).diagnosis, "jwe-untrusted-source");
  assert.equal(diagnoseToken({}, token, NOW, { kind: "header" }).diagnosis, "jwe-untrusted-source");
  assert.equal(
    diagnoseToken({}, token, NOW, {
      kind: "socket",
      url: `wss://evil.example/m365Copilot/Chathub/${OID}@${TID}?access_token=${token}`,
    }).diagnosis,
    "jwe-no-identity",
  );

  const current = { accessToken: token, claims: null, identity: fromSocket.accepted!.identity };
  assert.equal(diagnoseToken(current, token, NOW, socket).diagnosis, "duplicate");
  // Renovado: la web abre otro socket con otro JWE.
  const renewed = jwe();
  assert.equal(
    diagnoseToken(current, renewed, NOW, { kind: "socket", url: chathub(renewed) }).diagnosis,
    "accepted",
  );

  // Caché de MSAL: sólo la entrada de Sydney, reutilizando la identidad del socket.
  const entry = {
    credentialType: "AccessToken",
    target: "https://substrate.office.com/sydney/.default openid profile",
    expiresOn: String(inMinutes(55)),
  };
  const cached = jwe();
  assert.equal(
    diagnoseToken({}, cached, NOW, { kind: "storage", entry }).diagnosis,
    "jwe-no-identity",
  );
  const fromCache = diagnoseToken(current, cached, NOW, { kind: "storage", entry });
  assert.equal(fromCache.diagnosis, "accepted");
  assert.equal(fromCache.accepted?.expiresAt, inMinutes(55), "la caducidad real de MSAL");
  assert.deepEqual(fromCache.accepted?.identity, current.identity);
  assert.equal(
    diagnoseToken(current, cached, NOW, {
      kind: "storage",
      entry: { ...entry, target: "https://graph.microsoft.com/.default" },
    }).diagnosis,
    "jwe-untrusted-source",
  );
  assert.equal(
    diagnoseToken(current, cached, NOW, {
      kind: "storage",
      entry: { ...entry, expiresOn: String(inMinutes(-1)) },
    }).diagnosis,
    "expired",
  );
  assert.equal(
    diagnoseToken({ ...current, expiresAt: inMinutes(80) }, cached, NOW, { kind: "storage", entry })
      .diagnosis,
    "older-than-current",
  );
  assert.equal(isSydneyCacheEntry({ credentialType: "IdToken", target: "sydney" }), false);
  assert.equal(msalExpiresOn({ expiresOn: "abc" }), null);
  assert.equal(msalExpiresOn({ expiresOn: 12 }), null);

  // Con la sesión del chat en JWE, un JWT de Substrate de OTRA cuenta no la pisa.
  const otherAccount = jwt({ exp: inMinutes(60), oid: "someone-else", tid: TID });
  assert.equal(
    diagnoseToken(current, otherAccount, NOW, { kind: "storage", entry: null }).diagnosis,
    "identity-mismatch",
  );
  const sameAccount = jwt({ exp: inMinutes(60), oid: OID, tid: TID });
  assert.equal(diagnoseToken(current, sameAccount, NOW, { kind: "storage" }).diagnosis, "accepted");
  // …y del socket del chat un JWT siempre vale (es la prueba buena).
  assert.equal(
    diagnoseToken(current, otherAccount, NOW, { kind: "socket", url: chathub(otherAccount) })
      .diagnosis,
    "accepted",
  );

  // JWT de siempre: el origen no cambia nada (compatibilidad).
  const fresh = jwt({ exp: inMinutes(60) });
  for (const origin of [undefined, socket, { kind: "header" as const }]) {
    assert.equal(diagnoseToken({}, fresh, NOW, origin).diagnosis, "accepted");
  }
  assert.equal(acceptToken({}, fresh, NOW)?.expiresAt, undefined);
  console.log(
    "  ✓ un JWE se acepta del socket del chat o de la entrada de Sydney de MSAL, nunca de un fetch",
  );
}

function testJweStorageAndProfile() {
  const token = jwe();
  const entry = {
    credentialType: "AccessToken",
    secret: token,
    target: "https://substrate.office.com/sydney/.default",
    expiresOn: String(inMinutes(30)),
  };
  assert.deepEqual(tokenCandidatesInStorageValue(JSON.stringify(entry)), [{ token, entry }]);

  // El perfil que va a VS Code lleva la identidad, sin claims ni caducidad inventados.
  const accepted = acceptToken({}, token, NOW, { kind: "socket", url: chathub(token) })!;
  const store = {
    ...accepted,
    endpoint: normalizeEndpoint(chathub(token)),
    capturedAt: new Date(NOW).toISOString(),
  };
  const profile = profileFromCapture(store, "UA")!;
  assert.equal(profile.accessToken, token);
  assert.equal(profile.claims, null);
  assert.equal(profile.identity?.tid, TID);
  assert.equal("expiresAt" in profile, false);
  assert.doesNotMatch(profile.endpoint ?? "", /access_token/);
  assert.match(profile.endpoint ?? "", /scenario=OfficeWebConsumerCopilot/);
  // Un JSON redondo: lo que se envía por el puente local.
  assert.deepEqual(JSON.parse(JSON.stringify(profile)).identity, profile.identity);

  // La URL de un JWE es larga: el endpoint se conserva igual (el tope va sin el token).
  const big = chathub(jwe(undefined, 2400));
  assert.ok(big.length > 2048, "más que el tope antiguo, que la descartaba entera");
  assert.notEqual(normalizeEndpoint(big), "");
  // Varios KB de `variants` (lo normal en la web real) se conservan; el
  // resultado sigue acotado.
  const flags = Array.from({ length: 300 }, (_, i) => `feature.flight_${i}`).join(",");
  const withFlags = normalizeEndpoint(`${big}&variants=${flags}`);
  assert.ok(withFlags.length > 4000);
  assert.equal(new URL(withFlags.replace(/^wss/, "https")).searchParams.get("variants"), flags);
  assert.equal(normalizeEndpoint(`${big}&pad=${"x".repeat(MAX_ENDPOINT_CHARS)}`), "", "acotado");
  // Los ids de sesión y los tokens se quitan sin importar mayúsculas.
  const stripped = normalizeEndpoint(
    `${chathub(jwe())}&conversationId=c&CHATSESSIONID=s&id_token=secret&keep=1`,
  );
  assert.doesNotMatch(stripped, /conversationId|CHATSESSIONID|id_token|access_token|secret/i);
  assert.match(stripped, /keep=1/);

  // Usable con caducidad desconocida; con la de MSAL, hasta que pasa.
  assert.equal(isCaptureUsable(store, NOW), true);
  assert.equal(isCaptureUsable({ ...store, expiresAt: inMinutes(-1) }, NOW), false);
  assert.equal(isCaptureUsable({ ...store, accessToken: "garbage" }, NOW), false);
  assert.equal(
    isCaptureUsable(
      { accessToken: jwt({ exp: inMinutes(5) }), claims: { exp: inMinutes(5) } },
      NOW,
    ),
    true,
  );
  // Sin caducidad conocida no se poda; con la de MSAL vencida, sí.
  assert.equal(withoutExpiredToken(store, NOW), null);
  const pruned = withoutExpiredToken({ ...store, expiresAt: inMinutes(-1) }, NOW)!;
  assert.equal(pruned.accessToken, undefined);
  assert.equal(pruned.expiresAt, undefined);
  assert.deepEqual(pruned.identity, store.identity, "la identidad se queda para el siguiente");
  // El escaneo vigila de lejos un token sin caducidad, y aprieta cerca de la de MSAL.
  assert.equal(nextScan(store, SCAN_MISSING_MS, NOW).delay, SCAN_FRESH_MS);
  assert.equal(
    nextScan({ ...store, expiresAt: inMinutes(5) }, SCAN_MISSING_MS, NOW).delay,
    SCAN_EXPIRING_MS,
  );

  // Sustituir el JWE por un JWT borra la caducidad de MSAL que ya no le corresponde.
  const merged = {
    ...store,
    expiresAt: inMinutes(30),
    ...acceptToken(store, jwt({ exp: inMinutes(60), oid: OID, tid: TID }), NOW)!,
  };
  assert.equal(JSON.parse(JSON.stringify(merged)).expiresAt, undefined);

  // Huella estable, distinta por token, sin el token dentro.
  assert.equal(tokenFingerprint(token), tokenFingerprint(token));
  assert.notEqual(tokenFingerprint(token), tokenFingerprint(jwe()));
  assert.equal(
    needsResync({
      capturedAt: null,
      syncedTokenExp: null,
      currentTokenExp: null,
      syncedTokenId: tokenFingerprint(token),
      currentTokenId: tokenFingerprint(token),
      hasToken: true,
      lastSyncAttemptAt: null,
      now: NOW,
    }),
    false,
  );
  console.log(
    "  ✓ perfil JWE: identidad, endpoint sin token, caducidad desconocida y huella para sincronizar",
  );
}

function testEndpointChoiceAndDiagnostics() {
  const chat = normalizeEndpoint(chathub(jwe()));
  const presence = `wss://substrate.office.com/m365Copilot/Presence/${OID}@${TID}?source=officeweb`;
  // Substrate opens other sockets after the chat one: they no longer clobber it.
  assert.equal(shouldStoreTentativeEndpoint({}, presence), true);
  assert.equal(
    shouldStoreTentativeEndpoint({ endpoint: presence }, chat),
    true,
    "chat beats presence",
  );
  assert.equal(shouldStoreTentativeEndpoint({ endpoint: chat }, presence), false);
  assert.equal(shouldStoreTentativeEndpoint({ endpoint: chat }, chat), true);
  assert.equal(
    shouldStoreTentativeEndpoint({ endpoint: presence, endpointConfirmed: true }, chat),
    false,
  );
  assert.equal(shouldStoreTentativeEndpoint({}, ""), false);

  // The confirmation reaches VS Code (diagnostics).
  const store = { accessToken: jwe(), endpoint: chat, endpointConfirmed: true };
  assert.equal(profileFromCapture(store, "UA")?.endpointConfirmed, true);
  assert.equal(
    "endpointConfirmed" in profileFromCapture({ ...store, endpointConfirmed: false }, "UA")!,
    false,
  );

  // What a log may show about a socket URL: routing values, never the token or ids.
  const token = jwe();
  const described = describeSocketParams(
    `${chathub(token)}&variants=${"f".repeat(300)}&ConversationId=c`,
  )!;
  assert.deepEqual(
    {
      host: described.host,
      path: described.path,
      scenario: described.scenario,
      source: described.source,
      access_token: described.access_token,
      ConversationId: described.ConversationId,
      variants: described.variants,
    },
    {
      host: "substrate.office.com",
      path: "/m365Copilot/Chathub/{oid}@{tid}",
      scenario: "OfficeWebConsumerCopilot",
      source: "officeweb",
      access_token: "<redacted>",
      ConversationId: "<set>",
      variants: "<300 chars>",
    },
  );
  assert.ok(!JSON.stringify(described).includes(token.slice(0, 30)));
  assert.ok(!JSON.stringify(described).includes(OID), "ids are masked in the path");
  assert.equal(describeSocketParams(null), null);

  // Delivery key: a new timestamp is the same delivery; a new token or model is not.
  const profile = profileFromCapture({ ...store, capturedAt: "2026-01-01T00:00:00Z" }, "UA")!;
  assert.equal(
    deliveryKey(profile),
    deliveryKey({ ...profile, capturedAt: "2026-01-01T00:00:05Z" }),
  );
  assert.notEqual(deliveryKey(profile), deliveryKey({ ...profile, accessToken: jwe() }));
  assert.notEqual(deliveryKey(profile), deliveryKey({ ...profile, observedTones: ["Reasoning"] }));
  console.log(
    "  ✓ endpoint: el del chat no lo pisa otro socket; diagnóstico saneado y clave de entrega estable",
  );
}

testTokenValidation();
testDiagnosis();
testEndpointChoiceAndDiagnostics();
testJweRecognition();
testChathubIdentity();
testJweDiagnosis();
testJweStorageAndProfile();
testSources();
testFrames();
testStore();
testScanLoop();
testConnectionArt();
testObservedTones();
console.log("All tests passed.");
