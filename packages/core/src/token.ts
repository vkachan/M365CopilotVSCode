import type { CopilotProfile } from "./profile";
import { decodeJwtPayload } from "./jwt";

/** ¿Es un token de Substrate/Sydney, el que usa Copilot? (Un JWE nunca lo dice: va cifrado.) */
export function isSydneyToken(token: string): boolean {
  const claims = decodeJwtPayload(token);
  if (!claims) return false;
  const aud = String(claims.aud || "");
  const scp = String(claims.scp || claims.scope || "");
  return (
    aud.includes("substrate.office.com") ||
    aud.includes("substrate.svc.cloud.microsoft") ||
    /sydney|m365chat/i.test(scp)
  );
}

type ExpiryFields = Pick<CopilotProfile, "claims"> & Partial<Pick<CopilotProfile, "expiresAt">>;

/**
 * Caducidad conocida del token, en segundos epoch: el `exp` de un JWT o, si no
 * se puede leer (JWE), la de los metadatos que vinieron con él. null cuando se
 * desconoce — un JWE capturado del socket del chat: no se inventa ninguna.
 */
export function tokenExpiry(profile: ExpiryFields): number | null {
  const exp = profile.claims?.exp ?? profile.expiresAt;
  return typeof exp === "number" && Number.isFinite(exp) && exp > 0 ? exp : null;
}

/**
 * True cuando el token existe, M365 no lo ha rechazado y no ha caducado (con un
 * margen de skew). Con caducidad desconocida vale hasta que M365 lo rechace.
 */
export function isTokenUsable(
  profile: Pick<CopilotProfile, "accessToken" | "claims"> &
    Partial<Pick<CopilotProfile, "expiresAt" | "rejectedAt">>,
  skewSeconds = 60,
): boolean {
  if (!profile.accessToken || profile.rejectedAt) return false;
  const exp = tokenExpiry(profile);
  if (exp === null) return true;
  return exp * 1000 - Date.now() > skewSeconds * 1000;
}

/** Minutos hasta la caducidad del token, o null si se desconoce. */
export function minutesUntilExpiry(profile: ExpiryFields): number | null {
  const exp = tokenExpiry(profile);
  if (exp === null) return null;
  return Math.round((exp * 1000 - Date.now()) / 60000);
}

/**
 * Huella corta y estable de un token, para saber si dos lados tienen el MISMO
 * sin enviarlo ni guardarlo otra vez (cyrb53: no criptográfica ni reversible en
 * la práctica, y 53 bits bastan para distinguir renovaciones). Con un JWE no
 * hay `exp` con el que comparar, así que la sincronización y el aviso de
 * «M365 lo rechazó» se apoyan en esto.
 */
export function tokenFingerprint(token: string): string {
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < token.length; i++) {
    const ch = token.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return `${(4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36)}.${token.length}`;
}
