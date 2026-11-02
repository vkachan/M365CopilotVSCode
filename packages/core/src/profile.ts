/**
 * Forma normalizada del "perfil" que se captura de la web de M365 Copilot y
 * se envía a la extensión de VS Code. Sólo `accessToken` (y los claims que se
 * decodifican de él) es imprescindible; `endpoint`/`invocationTemplate` se
 * conservan por compatibilidad y diagnóstico. Con un JWE (cuentas personales)
 * los claims no se pueden leer: lo imprescindible pasa a ser `identity`.
 */
export interface TokenClaims {
  oid?: string;
  tid?: string;
  aud?: string;
  exp?: number;
  upn?: string;
}

/**
 * Para quién abrió la web el socket del chat, leído de la ruta
 * `…/Chathub/{oid}@{tid}` de una URL de Microsoft (ver `chathubIdentity`). Con
 * un JWT sale de sus claims; con un JWE es la ÚNICA forma de saberlo, porque
 * los claims van cifrados.
 */
export interface ChathubIdentity {
  oid: string;
  tid: string;
  /** `wss://host/…/Chathub`, sin la identidad ni la query. */
  endpointBase: string;
}

export interface CopilotProfile {
  version: number;
  accessToken: string;
  /** URL `wss://…/Chathub/{oid}@{tid}?…` capturada de la web. */
  endpoint: string | null;
  origin: string;
  userAgent: string;
  /** El objeto `arguments[0]` de la invocación SignalR `chat`. */
  invocationTemplate: Record<string, unknown> | null;
  /** Tipo de frame SignalR (4 = StreamInvocation, 1 = Invocation). */
  invocationType: number;
  claims: TokenClaims | null;
  capturedAt: string;
  /**
   * `tone`s (modelos) que la web de M365 Copilot ha usado de verdad, vistos en
   * sus invocaciones `chat`: la extensión de VS Code añade al selector los que
   * aún no conoce. Opcional: los perfiles antiguos no lo traen.
   */
  observedTones?: string[];
  /**
   * El navegador vio un frame `chat` salir por el socket de `endpoint`: es el
   * del hub del chat, no uno de presencia o notificaciones. Diagnóstico.
   */
  endpointConfirmed?: boolean;
  /** Identidad de la sesión del chat (ver {@link ChathubIdentity}). Opcional con un JWT. */
  identity?: ChathubIdentity;
  /**
   * Caducidad (segundos epoch) cuando el token no la dice pero sí metadatos de
   * confianza que vienen con él (el `expiresOn` de la caché de MSAL). Nunca se
   * inventa: sin ellos, un JWE tiene caducidad DESCONOCIDA.
   */
  expiresAt?: number;
  /**
   * Cuándo M365 rechazó este token (401/403). Lo marca VS Code: un token con
   * caducidad desconocida sólo se sabe muerto así, y deja de ser usable.
   */
  rejectedAt?: string;
}
