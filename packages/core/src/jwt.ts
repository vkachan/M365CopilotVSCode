import type { TokenClaims } from "./profile";

/** Un JWT de verdad no se acerca a esto; algo mayor no es un token. */
export const MAX_JWT_CHARS = 8 * 1024;
/**
 * Un JWE lleva la clave cifrada, el IV y el tag además del contenido: es más
 * largo que el JWT equivalente, pero tampoco se acerca a esto.
 */
export const MAX_JWE_CHARS = 16 * 1024;

/**
 * Cómo viene serializado un access token: `jwt` es el JWS compacto de siempre
 * (tres partes, claims legibles); `jwe` el JWE compacto de cinco partes que
 * reciben las cuentas personales de Microsoft — cifrado, así que sus claims
 * (`oid`, `tid`, `exp`…) no se pueden leer aquí y el token es opaco.
 */
export type TokenFormat = "jwt" | "jwe";

const SEGMENT = /^[A-Za-z0-9_-]*$/;

/**
 * Los `alg` de JWE con acuerdo directo de clave: con ellos la parte de la
 * clave cifrada va VACÍA (RFC 7516 §5.1 y RFC 7518 §4.5/§4.6); con cualquier
 * otro tiene que traer algo.
 */
const DIRECT_KEY_ALGS = new Set(["dir", "ECDH-ES"]);

/** Decodifica un segmento base64url como JSON, o null. */
function decodeSegment(part: string | undefined): Record<string, unknown> | null {
  try {
    if (!part) return null;
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64.padEnd(Math.ceil(b64.length / 4) * 4, "=");
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
    const value = JSON.parse(new TextDecoder("utf-8").decode(bytes)) as unknown;
    return value && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/**
 * Decodifica el payload de un JWT sin validar la firma. Isomorfo: `atob` y
 * `TextDecoder` existen tanto en el navegador como en Node 18+, así que sirve
 * igual en el content script del navegador y en la extensión de VS Code.
 * null para todo lo que no tenga tres partes: en un JWE la segunda es la clave
 * cifrada, no un payload.
 */
export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = String(token).split(".");
  return parts.length === 3 ? decodeSegment(parts[1]) : null;
}

/**
 * La cabecera protegida de un JWS/JWE compacto (la primera parte). En un JWE es
 * lo único legible: dice cómo va cifrado (`alg`, `enc`), no para quién.
 */
export function decodeJoseHeader(token: string): Record<string, unknown> | null {
  return decodeSegment(String(token).split(".")[0]);
}

/** Tres partes base64url y un tamaño razonable. */
export function isValidJwt(token: unknown): token is string {
  if (typeof token !== "string" || token.length > MAX_JWT_CHARS) return false;
  const parts = token.split(".");
  return parts.length === 3 && parts.every((part) => part.length > 0 && SEGMENT.test(part));
}

/**
 * Un JWE compacto bien formado (RFC 7516 §7.1): cinco partes base64url —
 * cabecera, clave cifrada, IV, texto cifrado y tag —, una cabecera JSON con
 * `alg` y `enc`, y la clave cifrada vacía sólo (y siempre) con acuerdo directo.
 * No se descifra nada: basta con que tenga la forma de uno.
 */
export function isValidJwe(token: unknown): token is string {
  if (typeof token !== "string" || token.length > MAX_JWE_CHARS) return false;
  const parts = token.split(".");
  if (parts.length !== 5 || !parts.every((part) => SEGMENT.test(part))) return false;
  const [header, encryptedKey, , ciphertext, tag] = parts;
  if (!header || !ciphertext || !tag) return false;
  const jose = decodeJoseHeader(token);
  if (!jose || typeof jose.alg !== "string" || typeof jose.enc !== "string") return false;
  if (!jose.alg || !jose.enc) return false;
  return DIRECT_KEY_ALGS.has(jose.alg) ? encryptedKey === "" : encryptedKey !== "";
}

/** `jwt`, `jwe`, o null si no es ninguno de los dos. */
export function tokenFormat(token: unknown): TokenFormat | null {
  if (typeof token !== "string") return null;
  const value = token.trim();
  if (isValidJwt(value)) return "jwt";
  if (isValidJwe(value)) return "jwe";
  return null;
}

/** Extrae los claims relevantes, normalizando el nombre de usuario (upn). */
export function extractClaims(token: string): TokenClaims | null {
  const raw = decodeJwtPayload(token);
  if (!raw) return null;
  return {
    oid: typeof raw.oid === "string" ? raw.oid : undefined,
    tid: typeof raw.tid === "string" ? raw.tid : undefined,
    aud: typeof raw.aud === "string" ? raw.aud : undefined,
    exp: typeof raw.exp === "number" ? raw.exp : undefined,
    upn:
      (typeof raw.upn === "string" && raw.upn) ||
      (typeof raw.unique_name === "string" && raw.unique_name) ||
      (typeof raw.preferred_username === "string" && raw.preferred_username) ||
      undefined,
  };
}
