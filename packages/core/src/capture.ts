/**
 * Lógica de captura del token, compartida por el interceptor de la extensión
 * de navegador (WXT, mundo MAIN) y por el userscript de Tampermonkey, que se
 * genera a partir de este mismo código (extensiones/vscode/userscript). Antes
 * cada uno tenía su copia y la del userscript se quedó atrás: dejaba de mirar
 * la caché de MSAL en cuanto tenía un token, así que nunca recogía el que la
 * web renueva sola y la sesión se rompía al caducar.
 *
 * Todo es puro — nada de `window`, `localStorage` ni `chrome` —: quien lo usa
 * pasa el estado y el reloj, y se puede probar fuera del navegador.
 */
import type { ChathubIdentity, CopilotProfile, TokenClaims } from "./profile";
import { extractClaims, isValidJwe, isValidJwt, tokenFormat } from "./jwt";
import { isSydneyToken, tokenExpiry } from "./token";

/** Frames SignalR salientes que se llegan a inspeccionar. */
export const MAX_FRAME_CHARS = 1024 * 1024;
/** Plantilla de invocación que merece la pena guardar. */
export const MAX_TEMPLATE_CHARS = 64 * 1024;
/**
 * El endpoint guardado, ya sin el token: la web lleva en `variants` cientos de
 * flags, varios KB. El tope antiguo (2 KB) lo descartaba EN SILENCIO — sin
 * endpoint no hay escenario que replicar, y una cuenta personal no puede
 * conectar —, así que éste sólo para lo que no es una URL de verdad.
 */
export const MAX_ENDPOINT_CHARS = 16 * 1024;
/** La URL del socket con el token dentro (un JWE de hasta 16 KB más el endpoint). */
const MAX_SOCKET_URL_CHARS = 32 * 1024;

/** Lo que se va acumulando de la web de M365 (token, endpoint, plantilla). */
export interface CaptureStore {
  accessToken?: string;
  tokenSource?: string;
  claims?: TokenClaims | null;
  endpoint?: string;
  endpointConfirmed?: boolean;
  origin?: string;
  userAgent?: string;
  invocationTemplate?: Record<string, unknown>;
  invocationType?: number;
  capturedAt?: string;
  /** Modelos (`tone`) que la web ha usado, del más antiguo al más reciente. */
  observedTones?: string[];
  /** Para quién se abrió el socket del chat del que salió el token (imprescindible con un JWE). */
  identity?: ChathubIdentity;
  /** Caducidad de los metadatos de MSAL, sólo cuando el token no la dice (JWE). */
  expiresAt?: number;
}

/** `exp` en el futuro y un `iat` coherente con él. */
export function areClaimsUsable(claims: TokenClaims | null | undefined, now = Date.now()): boolean {
  if (!claims || typeof claims.exp !== "number" || claims.exp <= 0) return false;
  if (claims.exp * 1000 <= now) return false;
  const iat = (claims as { iat?: unknown }).iat;
  if (iat !== undefined && (typeof iat !== "number" || iat > claims.exp)) return false;
  return true;
}

/**
 * Por qué un token candidato se aceptó o se descartó. Sirve para diagnosticar
 * «no captura y no dice nada»: el interceptor puede registrar el motivo exacto
 * en vez de un silencio (p. ej. «el socket traía un token, pero era de Graph,
 * no de Sydney»).
 */
export type TokenDiagnosis =
  | "accepted"
  /** Ni JWT ni JWE bien formado. */
  | "not-a-jwt"
  | "not-sydney"
  | "no-claims"
  | "expired"
  | "duplicate"
  | "older-than-current"
  /** Un JWE de un sitio que no prueba que sea el del chat (un fetch cualquiera). */
  | "jwe-untrusted-source"
  /** Un JWE sin una URL de Chathub de la que sacar para quién es. */
  | "jwe-no-identity"
  /** Un JWT de otra cuenta que la de la sesión del chat capturada con un JWE. */
  | "identity-mismatch";

/**
 * De dónde salió un token candidato. Con un JWT da igual — sus claims dicen
 * para quién y para qué servicio es —, pero un JWE es opaco y sólo el sitio
 * del que sale prueba que sea el del chat:
 * - `socket`: la query de la URL del WebSocket de Chathub. Es la prueba buena,
 *   y la ruta `…/Chathub/{oid}@{tid}` da además la identidad.
 * - `storage`: una entrada de la caché de MSAL; vale si su `target` (los scopes)
 *   es el de Sydney/Substrate, y su `expiresOn` da una caducidad real.
 * - `header`: un `Authorization: Bearer` de cualquier petición: un JWE de ahí
 *   puede ser de cualquier servicio, así que no se acepta.
 */
export type TokenOrigin =
  | { readonly kind: "socket"; readonly url: string }
  | { readonly kind: "storage"; readonly entry?: Record<string, unknown> | null }
  | { readonly kind: "header" };

/** Lo que se guarda al aceptar un token. `claims` es null con un JWE. */
export interface AcceptedToken {
  /**
   * Con un JWE del socket del chat, la URL de ESE socket (sin token): es lo que
   * replica la conexión, y se guarda a la vez que el token para que el perfil
   * nunca llegue a VS Code con uno y sin la otra.
   */
  endpoint?: string;
  accessToken: string;
  claims: TokenClaims | null;
  /** Sólo cuando el token salió de una URL de Chathub válida. */
  identity?: ChathubIdentity;
  /** Siempre presente (aunque `undefined`): borra la de un token anterior al fusionar. */
  expiresAt: number | undefined;
}

/**
 * Diagnostica un token candidato contra el store actual. `accepted` sólo viene
 * cuando `diagnosis === 'accepted'`. Es la lógica de decisión única: tanto el
 * sí/no (`acceptToken`) como el motivo salen de aquí. `origin` sólo cambia algo
 * con un JWE (ver {@link TokenOrigin}); sin él, un JWE no se acepta.
 */
export function diagnoseToken(
  current: CaptureStore,
  token: string,
  now = Date.now(),
  origin?: TokenOrigin,
): { diagnosis: TokenDiagnosis; accepted?: AcceptedToken } {
  const candidate = token.trim();
  const identity = origin?.kind === "socket" ? chathubIdentity(origin.url) : null;
  if (isValidJwe(candidate)) return diagnoseJwe(current, candidate, now, origin, identity);
  if (!isValidJwt(candidate)) return { diagnosis: "not-a-jwt" };
  if (!isSydneyToken(candidate)) return { diagnosis: "not-sydney" };
  const claims = extractClaims(candidate);
  if (!claims) return { diagnosis: "no-claims" };
  if (!areClaimsUsable(claims, now)) return { diagnosis: "expired" };
  if (current.accessToken === candidate) return { diagnosis: "duplicate" };
  // La sesión del chat va con un JWE (cuenta personal): un JWT de Substrate de
  // la caché o de un fetch no sustituye al del socket salvo que sea, al menos,
  // de la misma cuenta.
  if (
    !identity &&
    current.identity &&
    tokenFormat(current.accessToken) === "jwe" &&
    (claims.oid !== current.identity.oid || claims.tid !== current.identity.tid)
  )
    return { diagnosis: "identity-mismatch" };
  const currentExp = current.claims?.exp ?? 0;
  if (claims.exp && currentExp && claims.exp < currentExp)
    return { diagnosis: "older-than-current" };
  return {
    diagnosis: "accepted",
    accepted: {
      accessToken: candidate,
      claims,
      ...(identity ? { identity } : {}),
      expiresAt: undefined,
    },
  };
}

function diagnoseJwe(
  current: CaptureStore,
  candidate: string,
  now: number,
  origin: TokenOrigin | undefined,
  socketIdentity: ChathubIdentity | null,
): { diagnosis: TokenDiagnosis; accepted?: AcceptedToken } {
  let identity: ChathubIdentity | undefined;
  let expiresAt: number | undefined;
  if (origin?.kind === "socket") {
    if (!socketIdentity) return { diagnosis: "jwe-no-identity" };
    identity = socketIdentity;
  } else if (origin?.kind === "storage" && isSydneyCacheEntry(origin.entry)) {
    // La caché no dice para quién es el chat: se reutiliza la identidad del
    // socket ya capturado, que es de la misma web y la misma sesión.
    if (!current.identity) return { diagnosis: "jwe-no-identity" };
    identity = current.identity;
    expiresAt = msalExpiresOn(origin.entry) ?? undefined;
    if (expiresAt !== undefined && expiresAt * 1000 <= now) return { diagnosis: "expired" };
  } else {
    return { diagnosis: "jwe-untrusted-source" };
  }
  if (current.accessToken === candidate) return { diagnosis: "duplicate" };
  const currentExp = tokenExpiry({ claims: current.claims ?? null, expiresAt: current.expiresAt });
  if (expiresAt !== undefined && currentExp !== null && expiresAt < currentExp)
    return { diagnosis: "older-than-current" };
  const endpoint = origin?.kind === "socket" ? normalizeEndpoint(origin.url) : "";
  return {
    diagnosis: "accepted",
    accepted: {
      accessToken: candidate,
      claims: null,
      identity,
      expiresAt,
      ...(endpoint ? { endpoint } : {}),
    },
  };
}

/**
 * Lo que hay que guardar si `token` merece sustituir al actual, o null: debe
 * ser un JWT válido, de Substrate/Sydney (el de Copilot, no cualquier token de
 * Office), sin caducar, distinto del guardado y no más viejo que él — o un JWE
 * de un sitio que pruebe que es el del chat (ver {@link TokenOrigin}).
 */
export function acceptToken(
  current: CaptureStore,
  token: string,
  now = Date.now(),
  origin?: TokenOrigin,
): AcceptedToken | null {
  return diagnoseToken(current, token, now, origin).accepted ?? null;
}

/** Una entrada de la caché de MSAL con un access token para Sydney/Substrate. */
export function isSydneyCacheEntry(entry: Record<string, unknown> | null | undefined): boolean {
  if (!entry || typeof entry.target !== "string") return false;
  if (typeof entry.credentialType === "string" && !/accesstoken/i.test(entry.credentialType))
    return false;
  return /substrate\.office\.com|substrate\.svc\.cloud\.microsoft|sydney|m365chat/i.test(
    entry.target,
  );
}

/** El `expiresOn` (segundos epoch, a menudo como texto) de una entrada de MSAL, o null. */
export function msalExpiresOn(entry: Record<string, unknown> | null | undefined): number | null {
  const raw = entry?.expiresOn;
  const value = typeof raw === "string" && /^\d{9,11}$/.test(raw) ? Number(raw) : raw;
  return typeof value === "number" && Number.isInteger(value) && value > 1e9 && value < 1e11
    ? value
    : null;
}

/** Un token candidato de un valor de storage, con la entrada (JSON) en la que venía. */
export interface StorageCandidate {
  token: string;
  entry: Record<string, unknown> | null;
}

/**
 * Tokens candidatos dentro de un valor de localStorage/sessionStorage: MSAL
 * guarda cada access token como JSON (`secret`), otras librerías como
 * `access_token`/`accessToken`, y algunas entradas son el JWT pelado.
 */
export function tokenCandidatesInStorageValue(
  value: string | null | undefined,
): StorageCandidate[] {
  if (!value || value.length < 40 || !value.includes("eyJ")) return [];
  try {
    const parsed = JSON.parse(value) as Record<string, unknown> | null;
    if (!parsed || typeof parsed !== "object") return [];
    return [parsed.secret, parsed.access_token, parsed.accessToken]
      .filter((candidate): candidate is string => typeof candidate === "string")
      .map((token) => ({ token, entry: parsed }));
  } catch {
    const raw = value.trim();
    return /^ey[\w-]+\.[\w-]+\.[\w-]+$/.test(raw) ? [{ token: raw, entry: null }] : [];
  }
}

/** Sólo los tokens de {@link tokenCandidatesInStorageValue}. */
export function tokensInStorageValue(value: string | null | undefined): string[] {
  return tokenCandidatesInStorageValue(value).map((candidate) => candidate.token);
}

/** El token que viaja en la query de la URL del WebSocket, si lo hay. */
export function tokenInSocketUrl(url: string): string | null {
  try {
    return new URL(String(url).replace(/^ws/i, "http")).searchParams.get("access_token");
  } catch {
    return null;
  }
}

/** ¿Es un socket de Substrate/Chathub (y no presencia, notificaciones…)? */
export function isCopilotSocketUrl(url: string): boolean {
  const raw = String(url);
  return /chathub/i.test(raw) || /substrate/i.test(raw);
}

/**
 * Dominios de Microsoft desde los que se acepta un endpoint. El hub del chat
 * vive en `substrate.office.com`: la versión anterior sólo admitía
 * `.microsoft.com`/`.microsoft`, así que lo descartaba y el popup se quedaba
 * con «Endpoint: pendiente» para siempre.
 */
const MICROSOFT_HOST_SUFFIXES = [
  ".office.com",
  ".office.net",
  ".microsoft.com",
  ".microsoft",
  ".cloud.microsoft",
];

export function isMicrosoftHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return MICROSOFT_HOST_SUFFIXES.some(
    (suffix) => host === suffix.slice(1) || host.endsWith(suffix),
  );
}

/** Lo que cabe en un segmento de ruta sin escaparlo: `oid` y `tid` no traen otra cosa. */
const IDENTITY_PART = /^[A-Za-z0-9._-]{1,128}$/;
/** `…/Chathub/{oid}@{tid}` (el `@` puede venir escapado). */
const CHATHUB_PATH = /^(\/(?:[^/]+\/)*chathub)\/([^/]+)\/?$/i;

/**
 * La identidad de la sesión del chat en una URL de Chathub — sólo si es de
 * Microsoft y por un canal cifrado (`wss:`, o `https:` copiada de DevTools).
 * Es de donde salen `oid`/`tid` cuando el token es un JWE: no se fía de nada
 * que no venga de ahí. null si la URL no lo es.
 */
export function chathubIdentity(raw: unknown): ChathubIdentity | null {
  if (typeof raw !== "string" || raw.length > MAX_SOCKET_URL_CHARS) return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== "wss:" && url.protocol !== "https:") return null;
    if (url.username || url.password || (url.port && url.port !== "443")) return null;
    if (!isMicrosoftHost(url.hostname)) return null;
    const match = CHATHUB_PATH.exec(url.pathname);
    if (!match) return null;
    const segment = decodeURIComponent(match[2]!);
    const at = segment.lastIndexOf("@");
    if (at <= 0) return null;
    const oid = segment.slice(0, at);
    const tid = segment.slice(at + 1);
    if (!IDENTITY_PART.test(oid) || !IDENTITY_PART.test(tid)) return null;
    return { oid, tid, endpointBase: `wss://${url.hostname.toLowerCase()}${match[1]}` };
  } catch {
    return null;
  }
}

/**
 * Valida una identidad que llega de fuera (un perfil JSON): se reconstruye su
 * URL y se pasa por {@link chathubIdentity}, así que se aplican las mismas
 * reglas que a una capturada. null si no las cumple.
 */
export function sanitizeIdentity(value: unknown): ChathubIdentity | null {
  if (!value || typeof value !== "object") return null;
  const { oid, tid, endpointBase } = value as Record<string, unknown>;
  if (typeof oid !== "string" || typeof tid !== "string" || typeof endpointBase !== "string")
    return null;
  if (!IDENTITY_PART.test(oid) || !IDENTITY_PART.test(tid) || /[?#]/.test(endpointBase))
    return null;
  return chathubIdentity(`${endpointBase.replace(/\/+$/, "")}/${oid}@${tid}`);
}

/**
 * La URL del socket sin lo volátil (token, ids de sesión): no hay que guardar
 * un token caducado dentro del endpoint. '' si no es un host de Microsoft.
 */
export function normalizeEndpoint(raw: string): string {
  // El tope va sobre el resultado, sin el token: la URL cruda lo lleva dentro, y
  // la de un JWE pasa de sobra de MAX_ENDPOINT_CHARS.
  if (typeof raw !== "string" || raw.length > MAX_SOCKET_URL_CHARS) return "";
  try {
    const url = new URL(raw.replace(/^ws/i, "http"));
    if (!isMicrosoftHost(url.hostname)) return "";
    // Sin distinguir mayúsculas: `conversationId` también es un id de sesión,
    // y un token con otro nombre (`id_token`) tampoco se guarda.
    // Una copia de los nombres: borrar mientras se recorren los vivos se salta alguno.
    const names = Array.from(new Set(url.searchParams.keys()));
    for (const name of names) {
      const key = name.toLowerCase();
      if (SESSION_PARAMS.has(key) || SECRET_PARAMS.has(key)) url.searchParams.delete(name);
    }
    const endpoint = url.toString().replace(/^http/i, "ws");
    return endpoint.length > MAX_ENDPOINT_CHARS ? "" : endpoint;
  } catch {
    return "";
  }
}

/** Parámetros del socket que dicen QUÉ servicio y licencia se piden: se muestran tal cual. */
const ROUTING_PARAMS = new Set([
  "scenario",
  "licensetype",
  "source",
  "product",
  "agenthost",
  "disablememory",
]);
/** Ids de una sesión: se dice si van, nunca su valor. */
const SESSION_PARAMS = new Set([
  "conversationid",
  "chatsessionid",
  "clientrequestid",
  "x-sessionid",
]);
/** Secretos: ni se nombran con valor. */
const SECRET_PARAMS = new Set(["access_token", "id_token", "token"]);

/**
 * Los parámetros de una URL de socket, para comparar en un log la que abrió la
 * web con la que construye el cliente: los de enrutado/licencia con su valor,
 * los ids de sesión como `<set>`, el token como `<redacted>` y el resto (p. ej.
 * `variants`) como su longitud. Más `path` (con `{oid}@{tid}` tapados) y
 * `host`. null si no es una URL.
 */
export function describeSocketParams(
  raw: string | null | undefined,
): Record<string, string> | null {
  if (typeof raw !== "string" || !raw) return null;
  try {
    const url = new URL(raw.replace(/^ws/i, "http"));
    const out: Record<string, string> = {
      host: url.host,
      path: url.pathname.replace(/\/[^/]*@[^/]*$/, "/{oid}@{tid}"),
    };
    for (const [name, value] of url.searchParams) {
      const key = name.toLowerCase();
      out[name] = SECRET_PARAMS.has(key)
        ? "<redacted>"
        : SESSION_PARAMS.has(key)
          ? "<set>"
          : ROUTING_PARAMS.has(key) && value.length <= 128
            ? value
            : `<${value.length} chars>`;
    }
    return out;
  } catch {
    return null;
  }
}

/**
 * ¿Se guarda `endpoint` como endpoint tentativo? No si ya hay uno confirmado
 * (vio salir un `chat`), ni si el guardado es la URL de Chathub y éste no:
 * Substrate abre otros sockets (presencia, notificaciones) después del chat, y
 * antes pisaban el endpoint — y con él el `scenario` que replica un JWE.
 */
export function shouldStoreTentativeEndpoint(current: CaptureStore, endpoint: string): boolean {
  if (!endpoint || current.endpointConfirmed) return false;
  if (!current.endpoint) return true;
  return Boolean(chathubIdentity(endpoint)) || !chathubIdentity(current.endpoint);
}

/** SignalR separa los frames con este carácter (record separator). */
const RS = "\x1e";

/**
 * Mira un envío saliente por el socket: ¿lleva la invocación `chat` (prueba de
 * que es el hub del chat)? Si la lleva, devuelve también su plantilla.
 */
export function inspectOutgoingFrames(data: unknown): {
  sawChat: boolean;
  template?: Record<string, unknown>;
  invocationType?: number;
} {
  if (typeof data !== "string" || data.length > MAX_FRAME_CHARS) return { sawChat: false };
  let found: { sawChat: boolean; template?: Record<string, unknown>; invocationType?: number } = {
    sawChat: false,
  };
  for (const chunk of data.split(RS)) {
    if (!chunk) continue;
    let frame: { type?: unknown; target?: unknown; arguments?: unknown };
    try {
      frame = JSON.parse(chunk);
    } catch {
      continue;
    }
    // SignalR: type 4 = StreamInvocation, type 1 = Invocation.
    if ((frame.type !== 4 && frame.type !== 1) || frame.target !== "chat") continue;
    found = { sawChat: true };
    const args = Array.isArray(frame.arguments) ? frame.arguments[0] : null;
    if (args && typeof args === "object" && JSON.stringify(args).length <= MAX_TEMPLATE_CHARS) {
      found = {
        sawChat: true,
        template: args as Record<string, unknown>,
        invocationType: frame.type as number,
      };
    }
  }
  return found;
}

/** Un `tone` con forma de identificador de modelo de BizChat (p. ej. `Gpt_5_6_Reasoning`). */
export const TONE_PATTERN = /^[A-Za-z][A-Za-z0-9_.-]{1,63}$/;
/** Cuántos modelos distintos se recuerdan. */
const MAX_OBSERVED_TONES = 20;

/** El `tone` (modelo) de una plantilla de invocación `chat`, si es válido. */
export function toneOfTemplate(template: Record<string, unknown> | undefined): string | null {
  const tone = template?.tone;
  return typeof tone === "string" && TONE_PATTERN.test(tone) ? tone : null;
}

/**
 * `tones` con `tone` añadido como el más reciente (sin duplicados, acotado).
 * Así M365 puede estrenar un modelo y VS Code enterarse sin publicar versión:
 * en cuanto alguien lo usa en la web, la captura lo trae.
 */
export function withObservedTone(
  tones: readonly string[] | undefined,
  tone: string | null,
): string[] {
  const list = (tones ?? []).filter((item) => item !== tone);
  if (tone) list.push(tone);
  return list.slice(-MAX_OBSERVED_TONES);
}

/**
 * ¿Se puede usar el token guardado? Con caducidad conocida (el `exp` de un JWT
 * o la de MSAL), si no ha pasado; con un JWE sin ella, sí — hasta que M365 lo
 * rechace, que es lo único que lo dice.
 */
export function isCaptureUsable(store: CaptureStore, now = Date.now()): boolean {
  if (!store.accessToken) return false;
  const format = tokenFormat(store.accessToken);
  if (format === "jwt") return areClaimsUsable(store.claims, now);
  if (format !== "jwe") return false;
  const exp = tokenExpiry({ claims: store.claims ?? null, expiresAt: store.expiresAt });
  return exp === null || exp * 1000 > now;
}

/** El store sin el token si éste ya caducó (para invitar a recapturarlo), o null si no hay que tocarlo. */
export function withoutExpiredToken(store: CaptureStore, now = Date.now()): CaptureStore | null {
  const exp = tokenExpiry({ claims: store.claims ?? null, expiresAt: store.expiresAt });
  if (!store.accessToken || exp === null || exp * 1000 > now) return null;
  const cleaned: CaptureStore = { ...store };
  delete cleaned.accessToken;
  delete cleaned.tokenSource;
  delete cleaned.claims;
  delete cleaned.expiresAt;
  return cleaned;
}

/** Misma forma ignorando el sello temporal: sólo se escribe si algo cambió de verdad. */
export function sameCapture(a: CaptureStore, b: CaptureStore): boolean {
  const strip = (store: CaptureStore) => {
    const copy: CaptureStore = { ...store };
    delete copy.capturedAt;
    return JSON.stringify(copy);
  };
  return strip(a) === strip(b);
}

/** El perfil que se envía a VS Code, o null si todavía no hay token. */
export function profileFromCapture(
  store: CaptureStore,
  fallbackUserAgent: string,
): CopilotProfile | null {
  if (!store.accessToken) return null;
  return {
    version: 1,
    capturedAt: store.capturedAt || new Date().toISOString(),
    accessToken: store.accessToken,
    endpoint: store.endpoint || null,
    origin: store.origin || "https://m365.cloud.microsoft",
    userAgent: store.userAgent || fallbackUserAgent,
    invocationTemplate: store.invocationTemplate || null,
    invocationType: store.invocationType || 4,
    claims: store.claims || null,
    ...(store.endpointConfirmed ? { endpointConfirmed: true } : {}),
    ...(store.identity ? { identity: { ...store.identity } } : {}),
    ...(typeof store.expiresAt === "number" ? { expiresAt: store.expiresAt } : {}),
    ...(store.observedTones && store.observedTones.length > 0
      ? { observedTones: [...store.observedTones] }
      : {}),
  };
}

// ------------------------------------------------------------- bucle de escaneo

/** Sin token: insistir. Con token fresco: vigilar de lejos. Cerca de caducar: apretar. */
export const SCAN_MISSING_MS = 2_000;
export const SCAN_MISSING_MAX_MS = 15_000;
export const SCAN_FRESH_MS = 60_000;
export const SCAN_EXPIRING_MS = 5_000;
/** A partir de aquí la web ya suele haber renovado su propio token. */
export const EXPIRY_WATCH_MS = 15 * 60 * 1000;

/**
 * Cuándo volver a escanear la caché de MSAL. Se escanea SIEMPRE, haya token o
 * no: el token nuevo que la web renueva sola cada ~50 min sólo se recoge así.
 */
export function nextScan(
  store: CaptureStore,
  missingDelay: number,
  now = Date.now(),
): { delay: number; missingDelay: number } {
  if (!store.accessToken) {
    const grown = Math.min(Math.round(missingDelay * 1.5), SCAN_MISSING_MAX_MS);
    return { delay: grown, missingDelay: grown };
  }
  const exp = tokenExpiry({ claims: store.claims ?? null, expiresAt: store.expiresAt });
  const left = exp !== null ? exp * 1000 - now : null;
  return {
    delay: left !== null && left <= EXPIRY_WATCH_MS ? SCAN_EXPIRING_MS : SCAN_FRESH_MS,
    missingDelay: SCAN_MISSING_MS,
  };
}
