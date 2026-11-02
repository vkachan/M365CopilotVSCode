/**
 * El "perfil" es lo que se captura de la web de M365 Copilot (con la extensión
 * de navegador o el userscript). Puede ser:
 *   - un objeto JSON completo (token + endpoint + frame de invocación),
 *   - la URL del WebSocket del chat, con el token en su `access_token`, o
 *   - un JWT pelado (sólo el token).
 * El token puede ser un JWT o — cuentas personales de Microsoft — un JWE
 * cifrado. Un JWE no dice para quién es, así que pelado no basta: necesita la
 * identidad `{oid}@{tid}` de la URL de Chathub (o del perfil JSON).
 *
 * `endpoint` e `invocationTemplate` se conservan por compatibilidad y como
 * diagnóstico, pero client.ts ya NO los usa para construir peticiones: sólo
 * `accessToken` (y sus claims) importan. Los tipos y utilidades compartidas
 * viven en la raíz de `@m365copilot/core`; aquí sólo queda el parseo de lo
 * pegado, que es específico de los clientes de BizChat.
 */
import {
  chathubIdentity,
  decodeJwtPayload,
  describeSocketParams,
  extractClaims,
  isSydneyToken,
  isTokenUsable,
  minutesUntilExpiry,
  normalizeEndpoint,
  sanitizeIdentity,
  tokenExpiry,
  tokenFormat,
  tokenInSocketUrl,
  TONE_PATTERN,
  type ChathubIdentity,
  type CopilotProfile,
  type TokenClaims,
} from "../index";
import { t } from "./i18n";

export type { ChathubIdentity, CopilotProfile, TokenClaims, TokenFormat } from "../index";
export {
  decodeJwtPayload,
  isTokenUsable,
  minutesUntilExpiry,
  tokenExpiry,
  tokenFingerprint,
  tokenFormat,
} from "../index";

const DEFAULT_ORIGIN = "https://m365.cloud.microsoft";
const DEFAULT_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

export class ProfileParseError extends Error {}

/** `Bearer <token>`, as copied from an `Authorization` header. */
const BEARER = /^bearer\s+(\S+)$/i;
/** The chat WebSocket URL copied from DevTools (`wss://…/Chathub/…?access_token=…`). */
const SOCKET_URL = /^(wss?|https?):\/\//i;

/**
 * Something the paste command can use: a bare JWT or JWE, `Bearer <token>`,
 * the chat WebSocket URL with its `access_token`, or a JSON profile with an
 * access token — what the browser side copies or what DevTools shows.
 */
export function looksLikeProfile(text: string): boolean {
  const value = text.trim();
  if (tokenFormat(value) || tokenFormat(BEARER.exec(value)?.[1])) return true;
  if (SOCKET_URL.test(value)) return /[?&]access_token=ey/.test(value);
  return value.startsWith("{") && /"(accessToken|access_token|token)"\s*:\s*"ey/.test(value);
}

/**
 * Parsea lo que el usuario pegó en un {@link CopilotProfile} normalizado.
 * Acepta un perfil JSON completo, un JWT pelado (con o sin `Bearer `) o la
 * URL del WebSocket del chat: el token de Copilot no viaja en ninguna
 * cabecera `Authorization`, sino en el `access_token` de esa URL, así que
 * para capturarlo a mano lo más fácil es DevTools → Red, filtro `chathub` →
 * Copiar URL.
 */
export function parsePastedProfile(input: string): CopilotProfile {
  const text = input.trim();
  if (!text) throw new ProfileParseError(t("profile.error.empty"));

  // ¿Token pelado (JWT, o un JWE que dirá qué le falta)?
  if (tokenFormat(text)) {
    return normalize({ accessToken: text });
  }
  const bearer = BEARER.exec(text)?.[1];
  if (bearer && tokenFormat(bearer)) {
    return normalize({ accessToken: bearer });
  }
  if (SOCKET_URL.test(text)) {
    const token = tokenInSocketUrl(text);
    if (!token) throw new ProfileParseError(t("profile.error.urlWithoutToken"));
    // Sin el token ni los ids de esa sesión; conserva las `variants`. La
    // identidad sale de la ruta `…/Chathub/{oid}@{tid}`, si es de Microsoft.
    const identity = chathubIdentity(text);
    const endpoint = normalizeEndpoint(text) || undefined;
    return normalize({
      accessToken: token,
      endpoint,
      // Copied from the chat socket itself (DevTools, filter chathub): as sure
      // as the browser seeing a `chat` frame go out — it IS the chat hub.
      ...(endpoint && chathubIdentity(endpoint) ? { endpointConfirmed: true } : {}),
      ...(identity ? { identity } : {}),
    });
  }

  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch {
    throw new ProfileParseError(t("profile.error.notJwtOrJson"));
  }

  if (!obj || typeof obj !== "object") {
    throw new ProfileParseError(t("profile.error.notObject"));
  }

  const record = obj as Record<string, unknown>;
  const token =
    (typeof record.accessToken === "string" && record.accessToken) ||
    (typeof record.access_token === "string" && record.access_token) ||
    (typeof record.token === "string" && record.token) ||
    "";
  if (!token) {
    throw new ProfileParseError(t("profile.error.noToken"));
  }

  return normalize(record, token);
}

function normalize(record: Record<string, unknown>, token?: string): CopilotProfile {
  const accessToken = (token ?? (record.accessToken as string) ?? "").trim();
  const format = tokenFormat(accessToken);
  if (!format) {
    throw new ProfileParseError(t("profile.error.invalidJwt"));
  }

  const endpoint = typeof record.endpoint === "string" ? record.endpoint : null;
  // Lo que traiga el perfil se revalida igual que una URL capturada; si no
  // trae identidad, se busca en su `endpoint`.
  const identity: ChathubIdentity | null =
    sanitizeIdentity(record.identity) ?? chathubIdentity(endpoint ?? undefined);
  // Un JWE va cifrado: sus claims no se pueden leer, y los que diga el JSON no
  // se pueden comprobar — no se guarda ninguno, para no fingir que se saben.
  const claims: TokenClaims | null =
    format === "jwe"
      ? null
      : (extractClaims(accessToken) ?? (record.claims as TokenClaims | undefined) ?? null);
  if (format === "jwe" && !identity) {
    throw new ProfileParseError(t("profile.error.jweNeedsIdentity"));
  }
  // The same check the chat request makes: never "ready" with a profile that
  // cannot connect.
  const missing =
    format === "jwe"
      ? missingChatEndpointFields({ endpoint, identity: identity ?? undefined })
      : [];
  if (missing.length > 0) {
    throw new ProfileParseError(t("profile.error.jweNeedsChatEndpoint", missing.join(", ")));
  }
  // Una caducidad aparte sólo vale para un JWE (la de un JWT es su `exp`), y
  // sólo si es un instante plausible: la manda el navegador, de MSAL.
  const expiresAt =
    format === "jwe" &&
    typeof record.expiresAt === "number" &&
    Number.isInteger(record.expiresAt) &&
    record.expiresAt > 1e9 &&
    record.expiresAt < 1e11
      ? record.expiresAt
      : undefined;

  return {
    version: typeof record.version === "number" ? record.version : 1,
    accessToken,
    endpoint,
    origin: typeof record.origin === "string" ? record.origin : DEFAULT_ORIGIN,
    userAgent: typeof record.userAgent === "string" ? record.userAgent : DEFAULT_UA,
    invocationTemplate:
      record.invocationTemplate && typeof record.invocationTemplate === "object"
        ? (record.invocationTemplate as Record<string, unknown>)
        : null,
    invocationType: typeof record.invocationType === "number" ? record.invocationType : 4,
    claims,
    capturedAt:
      typeof record.capturedAt === "string" ? record.capturedAt : new Date().toISOString(),
    ...observedTonesOf(record),
    ...(record.endpointConfirmed === true ? { endpointConfirmed: true } : {}),
    ...(identity ? { identity } : {}),
    ...(expiresAt !== undefined ? { expiresAt } : {}),
  };
}

/**
 * The audience of a token that is NOT the M365 Copilot (Substrate/Sydney) one,
 * or null when it is. The browser extension and the userscript only ever
 * capture Copilot's token, but a token copied by hand from DevTools is often
 * the `Authorization: Bearer` of another request on the page (Graph, search…):
 * it decodes fine and has not expired — so everything looks connected — yet
 * the chat rejects it with 401. `?` when the token has no readable audience.
 */
export function foreignAudience(token: string): string | null {
  // Un JWE no deja leer su audiencia, y sólo se acepta si salió de la URL del
  // socket del chat (o de la entrada de Sydney de MSAL): no hay nada que avisar.
  if (isSydneyToken(token) || tokenFormat(token) === "jwe") return null;
  const aud = decodeJwtPayload(token)?.aud;
  return typeof aud === "string" && aud ? aud : "?";
}

/** The models the web app used (sent by the browser side), kept only if they look like tones. */
function observedTonesOf(record: Record<string, unknown>): Pick<CopilotProfile, "observedTones"> {
  if (!Array.isArray(record.observedTones)) return {};
  const tones = record.observedTones
    .filter((tone): tone is string => typeof tone === "string" && TONE_PATTERN.test(tone))
    .slice(-20);
  return tones.length > 0 ? { observedTones: tones } : {};
}

/**
 * The chat socket URL the web app opened for a personal account (JWE), when
 * the profile has it: a Chathub URL of a Microsoft host for the same `oid@tid`
 * as the identity. Its query (scenario, licence, surface) is what the web app
 * asked for and what its subscription allows — `officeweb`,
 * `OfficeWebIncludedCopilot`, `OfficeWebPaidCopilot` are the work and school web
 * app's, an entitlement a personal account does not have. A query without
 * `scenario` or `licenseType` is valid: it is sent as it came. Without the URL
 * nothing is sent: a work scenario would be a made-up entitlement.
 *
 * The ONE check both the import (here) and the chat request (client.ts) use.
 */
export function chatEndpointOf(
  profile: Pick<CopilotProfile, "endpoint" | "identity">,
): string | null {
  return missingChatEndpointFields(profile).length === 0 ? (profile.endpoint ?? null) : null;
}

/** What a personal-account profile lacks to connect, by name; empty when nothing. */
export function missingChatEndpointFields(
  profile: Pick<CopilotProfile, "endpoint" | "identity">,
): string[] {
  const missing: string[] = [];
  if (!profile.identity) missing.push("identity");
  if (!profile.endpoint) return [...missing, "endpoint"];
  const fromEndpoint = chathubIdentity(profile.endpoint);
  if (!fromEndpoint)
    return [...missing, "endpoint (not a Chathub URL of a Microsoft host over wss)"];
  if (
    profile.identity &&
    (fromEndpoint.oid !== profile.identity.oid || fromEndpoint.tid !== profile.identity.tid)
  )
    missing.push("endpoint (for another account than the identity)");
  return missing;
}

/**
 * What a log may say about a personal account's chat endpoint — never the
 * token, the account ids or the whole URL: host, path with `{oid}@{tid}`
 * masked, confirmation, the scenario it asked for and what is missing.
 */
export function chatEndpointDiagnostics(
  profile: Pick<CopilotProfile, "endpoint" | "identity" | "endpointConfirmed">,
): Record<string, unknown> {
  const params = describeSocketParams(profile.endpoint);
  const scenario = params ? Object.entries(params).find(([k]) => /^scenario$/i.test(k)) : undefined;
  return {
    hasEndpoint: Boolean(profile.endpoint),
    endpointHost: params?.host ?? null,
    endpointPath: params?.path ?? null,
    endpointConfirmed: profile.endpointConfirmed === true,
    capturedScenario: scenario?.[1] ?? null,
    missingRequiredFields: missingChatEndpointFields(profile),
  };
}

/** Who a profile signs in as, for VS Code's Accounts menu (account.ts). */
export interface ProfileAccount {
  /** Stable per user and tenant, so a renewed token is the same session. */
  readonly sessionId: string;
  readonly accountId: string;
  readonly label: string;
}

/**
 * The account behind a usable token; undefined without one or once it has
 * expired — in the Accounts menu an expired token is "signed out".
 */
export function accountOf(profile: CopilotProfile | null | undefined): ProfileAccount | undefined {
  if (!profile || !isTokenUsable(profile)) return undefined;
  const claims = profile.claims ?? extractClaims(profile.accessToken) ?? {};
  const upn = claims.upn?.trim();
  // Con un JWE la cuenta es la de la sesión del chat capturada.
  const oid = claims.oid ?? profile.identity?.oid;
  const tid = claims.tid ?? profile.identity?.tid;
  const accountId = oid ?? upn ?? "m365copilot";
  const personal = tokenFormat(profile.accessToken) === "jwe";
  return {
    sessionId: `${tid ?? "tenant"}/${accountId}`,
    accountId,
    label: upn || t(personal ? "account.personalAccount" : "account.unknownUser"),
  };
}

/**
 * What a log may say about a profile — everything useful for diagnosing a
 * connection (who, which tenant, audience, when it expires, what the browser
 * captured) and never the token itself.
 */
export function describeProfile(
  profile: CopilotProfile | null | undefined,
): Record<string, unknown> | null {
  if (!profile) return null;
  let endpointHost: string | null = null;
  try {
    endpointHost = profile.endpoint
      ? new URL(profile.endpoint.replace(/^wss?:/, "https:")).host
      : null;
  } catch {
    endpointHost = "<unparseable>";
  }
  const exp = tokenExpiry(profile);
  return {
    user: profile.claims?.upn,
    tenant: profile.claims?.tid ?? profile.identity?.tid,
    objectId: profile.claims?.oid ?? profile.identity?.oid,
    audience: profile.claims?.aud,
    tokenFormat: tokenFormat(profile.accessToken),
    expiresAt: exp ? new Date(exp * 1000).toISOString() : null,
    expirySource: profile.claims?.exp ? "claims" : exp ? "metadata" : "unknown",
    minutesLeft: minutesUntilExpiry(profile),
    usable: isTokenUsable(profile),
    rejectedAt: profile.rejectedAt ?? null,
    tokenChars: profile.accessToken.length,
    identityEndpoint: profile.identity?.endpointBase ?? null,
    capturedAt: profile.capturedAt,
    origin: profile.origin,
    userAgent: profile.userAgent,
    endpointHost,
    hasInvocationTemplate: profile.invocationTemplate !== null,
    invocationType: profile.invocationType,
    observedTones: profile.observedTones ?? [],
    // What the web app's own socket asked for (scenario, surface…), never the
    // token: what to compare with a turn's `endpoint:` line when M365 refuses it.
    endpointConfirmed: profile.endpointConfirmed === true,
    endpointIsChathub: chathubIdentity(profile.endpoint ?? undefined) !== null,
    endpointParams: describeSocketParams(profile.endpoint),
  };
}
