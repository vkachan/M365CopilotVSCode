/**
 * Tests del interceptor de verdad (entrypoints/interceptor.content.ts) en una
 * página de mentira: la web abre el WebSocket del chat y lo que el interceptor
 * publica hacia el puente se pasa por el mismo camino que en producción — el
 * perfil del background (`profileFromCapture`), JSON por el puente local y el
 * parseo de VS Code (`parsePastedProfile`) — hasta la URL a la que conectaría.
 *
 * Es la prueba de extremo a extremo de una cuenta personal (token JWE), y la
 * de que una de empresa (JWT) sigue igual.
 *
 * Run: node --experimental-strip-types --import ./test/register.mjs test/interceptor.mts
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

// ------------------------------------------------------------ página falsa

class FakeStorage {
  private readonly map = new Map<string, string>();
  get length() {
    return this.map.size;
  }
  key(index: number) {
    return [...this.map.keys()][index] ?? null;
  }
  getItem(key: string) {
    return this.map.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.map.set(key, String(value));
  }
  removeItem(key: string) {
    this.map.delete(key);
  }
  clear() {
    this.map.clear();
  }
}

class FakeWebSocket {
  readonly sent: unknown[] = [];
  readonly url: string;
  constructor(url: string) {
    this.url = url;
  }
  send(data: unknown) {
    this.sent.push(data);
  }
}

const posted: any[] = [];
const listeners = new Map<string, ((event: any) => void)[]>();
const localStorage = new FakeStorage();
const sessionStorage = new FakeStorage();
const timers: (() => void)[] = [];
const page: any = {
  localStorage,
  sessionStorage,
  WebSocket: FakeWebSocket,
  fetch: async () => null,
  location: { origin: "https://m365.cloud.microsoft", href: "https://m365.cloud.microsoft/chat/" },
  navigator: { userAgent: "Mozilla/5.0 (test)" },
  postMessage(message: unknown) {
    posted.push(message);
  },
  addEventListener(type: string, listener: (event: any) => void) {
    listeners.set(type, [...(listeners.get(type) ?? []), listener]);
  },
};
page.top = page;
page.self = page;
Object.assign(globalThis, {
  window: page,
  localStorage,
  sessionStorage,
  location: page.location,
  document: { visibilityState: "visible", addEventListener() {} },
  defineContentScript: (definition: unknown) => definition,
});
Object.defineProperty(globalThis, "navigator", { value: page.navigator, configurable: true });
// El bucle de escaneo se reprograma solo: aquí se ejecuta a mano.
const realSetTimeout = globalThis.setTimeout;
(globalThis as any).setTimeout = (fn: () => void) => {
  timers.push(fn);
  return 0;
};

const { default: interceptor } = await import("../entrypoints/interceptor.content.ts");
const core = await import("@m365copilot/core");
const bizchat = await import("@m365copilot/core/bizchat");
(interceptor as { main: () => void }).main();
(globalThis as any).setTimeout = realSetTimeout;

// ------------------------------------------------------------------ tokens

const b64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const rand = (bytes: number) => randomBytes(bytes).toString("base64url");
const jwe = () =>
  `${b64url({ alg: "RSA-OAEP-256", enc: "A256GCM", zip: "DEF" })}.${rand(256)}.${rand(12)}.${rand(1800)}.${rand(16)}`;
const OID = "00000000-0000-0000-1234-56789abcdef0";
const TID = "9188040d-6c67-4c5b-b112-36a304b66dad";
const chathub = (token: string, host = "substrate.office.com") =>
  `wss://${host}/m365Copilot/Chathub/${OID}@${TID}?clientrequestid=c1&X-SessionId=s1` +
  `&access_token=${token}&source=officeweb&product=Office&scenario=OfficeWebConsumerCopilot`;

const profilesPosted = () =>
  posted.filter((message) => message?.kind === "PROFILE_UPDATED").map((m) => m.payload);
const lastPosted = () => profilesPosted().at(-1);

/** Lo que hace background.ts con lo publicado, y lo que hace VS Code al recibirlo. */
function throughTheBridge(store: unknown) {
  const profile = core.profileFromCapture(store as never, "UA");
  assert.ok(profile, "el background construye un perfil");
  assert.ok(core.isTokenUsable(profile), "y lo da por usable: se envía a VS Code");
  return bizchat.parsePastedProfile(JSON.stringify(profile));
}

// ------------------------------------------------------------------- casos

function testPersonalAccountSocket() {
  const token = jwe();
  const socket = new page.WebSocket(chathub(token)) as FakeWebSocket;
  const store = lastPosted();
  assert.equal(store?.accessToken, token, "el JWE del socket del chat se captura");
  assert.equal(store.claims, null);
  assert.equal(store.identity.oid, OID);
  assert.equal(store.tokenSource, "websocket-url");
  assert.doesNotMatch(store.endpoint, /access_token/);

  // La web manda su `chat`: se confirma el endpoint y se apunta el modelo.
  socket.send(
    `${JSON.stringify({ type: 4, target: "chat", arguments: [{ tone: "Gpt_5_6_Reasoning" }] })}\x1e`,
  );
  assert.equal(lastPosted().endpointConfirmed, true);
  assert.equal(
    throughTheBridge(lastPosted()).endpointConfirmed,
    true,
    "VS Code sees it was the chat",
  );
  assert.deepEqual(lastPosted().observedTones, ["Gpt_5_6_Reasoning"]);

  // VS Code recibe un perfil con identidad, sin claims ni caducidad inventados.
  const received = throughTheBridge(lastPosted());
  assert.equal(received.accessToken, token);
  assert.equal(received.claims, null);
  assert.deepEqual(received.identity, {
    oid: OID,
    tid: TID,
    endpointBase: "wss://substrate.office.com/m365Copilot/Chathub",
  });
  assert.equal(bizchat.minutesUntilExpiry(received), null);
  assert.equal(bizchat.accountOf(received)?.sessionId, `${TID}/${OID}`);
  console.log("  ✓ cuenta personal: JWE del socket → perfil con identidad → VS Code lo acepta");
}

function testRenewalAndForeignSockets() {
  const before = profilesPosted().length;
  const first = lastPosted().accessToken;
  // El mismo token otra vez (reconexión): nada nuevo que publicar.
  new page.WebSocket(chathub(first));
  assert.equal(lastPosted().accessToken, first);

  // Un socket de otro host con un JWE: no se acepta (no es el chat de Microsoft).
  new page.WebSocket(chathub(jwe(), "substrate.office.com.evil.example"));
  assert.equal(lastPosted().accessToken, first, "un host ajeno no cuela su token");

  // Un Bearer JWE de un fetch cualquiera tampoco: puede ser de otro servicio.
  const bearer = jwe();
  void page.fetch("https://substrate.office.com/x", {
    headers: { authorization: `Bearer ${bearer}` },
  });
  assert.notEqual(lastPosted().accessToken, bearer);

  // La web renueva: abre el socket con un JWE nuevo y se sustituye solo.
  const renewed = jwe();
  new page.WebSocket(chathub(renewed));
  assert.equal(lastPosted().accessToken, renewed);
  assert.ok(profilesPosted().length > before);
  assert.notEqual(core.tokenFingerprint(renewed), core.tokenFingerprint(first));
  console.log(
    "  ✓ renovación automática: un socket nuevo trae otro JWE; hosts y fetch ajenos no cuentan",
  );
}

function testMsalCacheRefresh() {
  // Si la web deja el token del chat en MSAL, el re-escaneo lo recoge con su caducidad real.
  const cached = jwe();
  const expiresOn = Math.floor(Date.now() / 1000) + 50 * 60;
  localStorage.setItem(
    "msal.accesstoken.sydney",
    JSON.stringify({
      credentialType: "AccessToken",
      secret: cached,
      target: "https://substrate.office.com/sydney/.default openid profile",
      expiresOn: String(expiresOn),
    }),
  );
  for (const listener of listeners.get("message") ?? [])
    listener({
      source: page,
      data: { [core.BRIDGE_MESSAGE_MARKER]: true, kind: "RESCAN_REQUEST" },
    });
  assert.equal(lastPosted().accessToken, cached);
  assert.equal(lastPosted().expiresAt, expiresOn);
  assert.equal(lastPosted().identity.tid, TID, "la identidad del socket se conserva");
  assert.equal(bizchat.minutesUntilExpiry(throughTheBridge(lastPosted())), 50);
  localStorage.removeItem("msal.accesstoken.sydney");
  console.log(
    "  ✓ caché de MSAL: el JWE de Sydney entra con la caducidad de MSAL, no una inventada",
  );
}

function testWorkAccountUnchanged() {
  localStorage.clear();
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const jwt = `${b64url({ alg: "RS256", typ: "JWT" })}.${b64url({
    aud: "https://substrate.office.com/sydney",
    oid: "work-oid",
    tid: "work-tid",
    upn: "someone@contoso.com",
    exp,
  })}.${rand(256)}`;
  new page.WebSocket(
    `wss://substrate.office.com/m365Copilot/Chathub/work-oid@work-tid?access_token=${jwt}&scenario=OfficeWebIncludedCopilot`,
  );
  const store = lastPosted();
  assert.equal(store.accessToken, jwt);
  assert.equal(store.claims.upn, "someone@contoso.com");
  assert.equal(store.expiresAt, undefined);
  const received = throughTheBridge(store);
  assert.equal(received.claims?.oid, "work-oid");
  assert.equal(bizchat.minutesUntilExpiry(received), 60);
  console.log("  ✓ cuenta de empresa (JWT): captura, claims y caducidad como siempre");
}

function testChatEndpointNotClobbered() {
  const token = jwe();
  new page.WebSocket(chathub(token));
  // Before the page sends anything, Substrate opens its presence socket.
  new page.WebSocket(
    `wss://substrate.office.com/m365Copilot/Presence/${OID}@${TID}?source=officeweb`,
  );
  const store = lastPosted();
  assert.match(store.endpoint, /\/Chathub\//, "the chat socket's endpoint is kept");
  assert.match(store.endpoint, /scenario=OfficeWebConsumerCopilot/);
  assert.equal(store.endpointConfirmed, undefined);
  localStorage.clear();
  console.log("  ✓ un socket de presencia abierto después no pisa el endpoint del chat");
}

console.log("interceptor.content.ts (página simulada)");
testChatEndpointNotClobbered();
testPersonalAccountSocket();
testRenewalAndForeignSockets();
testMsalCacheRefresh();
testWorkAccountUnchanged();
// Los temporizadores del bucle de escaneo se quedaron sin ejecutar a propósito.
console.log(`\nAll tests passed. (${timers.length} timers left unscheduled)`);
