/**
 * Tests de la política de renovación del token.
 *
 * `refreshPolicy.ts` es puro a propósito (ni `chrome`, ni temporizadores, ni
 * estado en memoria), así que se puede probar la escalada entera aquí, en
 * segundos, en vez de esperando una hora a que caduque un token de verdad.
 *
 * Run: node --experimental-strip-types test/refreshPolicy.mts
 */
import assert from "node:assert/strict";
import { deliveryKey } from "@m365copilot/core";
import {
  ATTEMPTS_BEFORE_HELP,
  BASE_BACKOFF_MS,
  MAX_BACKOFF_MS,
  RENEW_MARGIN_MS,
  RESYNC_COOLDOWN_MS,
  backoffFor,
  decideRefreshAction,
  isAlreadyDelivered,
  msUntilExpiry,
  needsResync,
  type RefreshContext,
} from "../utils/refreshPolicy.ts";

const NOW = 1_700_000_000_000;
const MINUTE = 60_000;

/** Contexto por defecto: token sano, una pestaña abierta, sin intentos previos. */
function context(overrides: Partial<RefreshContext> = {}): RefreshContext {
  return {
    now: NOW,
    token: { hasToken: true, expEpochSeconds: (NOW + 40 * MINUTE) / 1000 },
    hasM365Tab: true,
    hasEverCaptured: true,
    lastAttemptAt: null,
    attempts: 0,
    autoOpenTab: true,
    ...overrides,
  };
}

function expiringIn(minutes: number) {
  return { hasToken: true, expEpochSeconds: (NOW + minutes * MINUTE) / 1000 };
}

function testHealthyToken() {
  assert.equal(decideRefreshAction(context()).action, "none");

  // Justo en el borde del margen todavía no se toca nada; un minuto por debajo, sí.
  const atMargin = expiringIn(RENEW_MARGIN_MS / MINUTE + 1);
  assert.equal(decideRefreshAction(context({ token: atMargin })).action, "none");
  const belowMargin = expiringIn(RENEW_MARGIN_MS / MINUTE - 1);
  assert.equal(decideRefreshAction(context({ token: belowMargin })).action, "rescan");

  console.log("  ✓ un token con cuerda no se toca; por debajo del margen se renueva");
}

function testEscalation() {
  // 1º lo barato: pedir a la pestaña que mire otra vez la caché de MSAL.
  assert.equal(decideRefreshAction(context({ token: expiringIn(3) })).action, "rescan");

  // 2º si el re-escaneo no trajo token nuevo, recargar — pero sólo cuando haya
  // pasado el backoff.
  const afterRescan = context({
    token: expiringIn(3),
    attempts: 1,
    lastAttemptAt: NOW - 10_000,
  });
  const waiting = decideRefreshAction(afterRescan);
  assert.equal(waiting.action, "wait");
  assert.ok((waiting.retryInMs ?? 0) > 0, "wait debe decir cuánto falta");

  assert.equal(
    decideRefreshAction({ ...afterRescan, lastAttemptAt: NOW - BASE_BACKOFF_MS - 1 }).action,
    "reload",
  );

  // 3º sin ninguna pestaña de M365, abrir una en segundo plano.
  assert.equal(
    decideRefreshAction(context({ token: expiringIn(3), hasM365Tab: false })).action,
    "open",
  );
  // …salvo que el usuario lo haya desactivado.
  assert.equal(
    decideRefreshAction(context({ token: expiringIn(3), hasM365Tab: false, autoOpenTab: false }))
      .action,
    "needsUser",
  );

  // 4º tras varios intentos seguidos, hace falta que entre el usuario.
  assert.equal(
    decideRefreshAction(
      context({
        token: expiringIn(3),
        attempts: ATTEMPTS_BEFORE_HELP,
        lastAttemptAt: NOW - MAX_BACKOFF_MS - 1,
      }),
    ).action,
    "needsUser",
  );

  console.log("  ✓ escalada re-escaneo → recarga → pestaña nueva → avisar al usuario");
}

function testExpiredAndMissing() {
  // Un token ya caducado se trata igual que uno a punto de caducar.
  assert.equal(decideRefreshAction(context({ token: expiringIn(-5) })).action, "rescan");

  // Sin token pero con capturas previas hay sesión que recuperar.
  assert.equal(
    decideRefreshAction(context({ token: { hasToken: false, expEpochSeconds: null } })).action,
    "rescan",
  );

  // Sin haber capturado nunca no se abre nada por nuestra cuenta.
  assert.equal(
    decideRefreshAction(
      context({ token: { hasToken: false, expEpochSeconds: null }, hasEverCaptured: false }),
    ).action,
    "none",
  );

  // Un token sin caducidad conocida (JWE de cuenta personal) no se renueva a
  // ciegas: antes esto pedía re-escanear y recargar la pestaña en bucle.
  const unknown = decideRefreshAction(
    context({ token: { hasToken: true, expEpochSeconds: null } }),
  );
  assert.equal(unknown.action, "none");
  assert.match(unknown.reason, /caducidad conocida/);

  console.log("  ✓ token caducado, ausente, sin exp y sin captura previa");
}

function testRejectedByVSCode() {
  // M365 rechazó el token (lo dice VS Code): con caducidad desconocida es la
  // señal para renovar, y sigue la escalada normal.
  const rejected = { hasToken: true, expEpochSeconds: null, rejected: true };
  assert.equal(decideRefreshAction(context({ token: rejected })).action, "rescan");
  assert.equal(decideRefreshAction(context({ token: rejected, attempts: 1 })).action, "reload");
  assert.equal(decideRefreshAction(context({ token: rejected, hasM365Tab: false })).action, "open");
  assert.equal(
    decideRefreshAction(context({ token: rejected, attempts: ATTEMPTS_BEFORE_HELP })).action,
    "needsUser",
  );
  // Un JWT revocado antes de su `exp` también se renueva ya.
  assert.equal(
    decideRefreshAction(
      context({
        token: { hasToken: true, expEpochSeconds: (NOW + 40 * MINUTE) / 1000, rejected: true },
      }),
    ).action,
    "rescan",
  );
  // Con caducidad de MSAL (JWE) se usa como la de un JWT.
  assert.equal(
    decideRefreshAction(
      context({ token: { hasToken: true, expEpochSeconds: (NOW + 5 * MINUTE) / 1000 } }),
    ).action,
    "rescan",
  );
  console.log(
    "  ✓ token rechazado por M365 (aviso de VS Code): se renueva aunque no se sepa su exp",
  );
}

function testBackoff() {
  assert.equal(backoffFor(0), 0);
  assert.equal(backoffFor(1), BASE_BACKOFF_MS);
  assert.equal(backoffFor(2), BASE_BACKOFF_MS * 2);
  assert.equal(backoffFor(99), MAX_BACKOFF_MS, "el backoff tiene tope");

  // Un reloj que salta hacia atrás (suspender el portátil, cambio de hora) no
  // puede dejar la renovación bloqueada para siempre.
  const future = context({ token: expiringIn(1), attempts: 1, lastAttemptAt: NOW + 60 * MINUTE });
  assert.notEqual(decideRefreshAction(future).action, "wait");

  assert.equal(msUntilExpiry({ hasToken: true, expEpochSeconds: NOW / 1000 + 60 }, NOW), 60_000);
  assert.equal(msUntilExpiry({ hasToken: false, expEpochSeconds: 1 }, NOW), null);

  console.log("  ✓ backoff creciente con tope y a prueba de saltos de reloj");
}

function testResync() {
  const base = {
    capturedAt: new Date(NOW).toISOString(),
    hasToken: true,
    currentTokenExp: NOW / 1000 + 3600,
    lastSyncAttemptAt: null,
    now: NOW,
  };

  // Nunca se envió: hay que enviarlo (VS Code pudo arrancar después).
  assert.equal(needsResync({ ...base, syncedTokenExp: null }), true);
  // Ya tiene ESTE token: no se repite.
  assert.equal(needsResync({ ...base, syncedTokenExp: base.currentTokenExp }), false);
  // Tiene uno más viejo: se reenvía.
  assert.equal(needsResync({ ...base, syncedTokenExp: base.currentTokenExp - 600 }), true);
  // Sin token no hay nada que mandar.
  assert.equal(needsResync({ ...base, hasToken: false, syncedTokenExp: null }), false);
  // Y no se martillea al servidor local cuando está apagado.
  assert.equal(
    needsResync({ ...base, syncedTokenExp: null, lastSyncAttemptAt: NOW - RESYNC_COOLDOWN_MS + 1 }),
    false,
  );
  assert.equal(
    needsResync({ ...base, syncedTokenExp: null, lastSyncAttemptAt: NOW - RESYNC_COOLDOWN_MS - 1 }),
    true,
  );

  // Sin `exp` (JWE) decide la huella: una vez por token, y otra cuando cambia.
  const jwe = { ...base, currentTokenExp: null, syncedTokenExp: null };
  assert.equal(needsResync({ ...jwe, currentTokenId: "a.1", syncedTokenId: null }), true);
  assert.equal(needsResync({ ...jwe, currentTokenId: "a.1", syncedTokenId: "a.1" }), false);
  assert.equal(needsResync({ ...jwe, currentTokenId: "b.1", syncedTokenId: "a.1" }), true);
  // Sin huellas, como antes: un `exp` desconocido se reenvía siempre (de ahí las huellas).
  assert.equal(needsResync({ ...jwe }), true);

  console.log("  ✓ reenvío a VS Code sólo cuando hace falta, con cooldown");
}

function testDeliveryDedupe() {
  const profile = {
    version: 1,
    accessToken: "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..iv.ciphertext.tag",
    endpoint: null,
    origin: "https://m365.cloud.microsoft",
    userAgent: "UA",
    invocationTemplate: null,
    invocationType: 4,
    claims: null,
    capturedAt: "2026-11-02T10:00:00Z",
  };
  const key = deliveryKey(profile);
  assert.equal(isAlreadyDelivered(profile, key), true);
  assert.equal(
    isAlreadyDelivered({ ...profile, capturedAt: "2026-11-02T10:00:01Z" }, key),
    true,
    "a new timestamp is the same delivery",
  );
  assert.equal(isAlreadyDelivered({ ...profile, accessToken: "eyJ.renewed" }, key), false);
  assert.equal(isAlreadyDelivered({ ...profile, observedTones: ["Reasoning"] }, key), false);
  assert.equal(isAlreadyDelivered(profile, null), false, "never confirmed: send");
  assert.equal(isAlreadyDelivered(null, key), false);
  console.log("  ✓ el mismo perfil (sólo cambia el sello) no se reenvía; otro token o modelo sí");
}

console.log("refreshPolicy.ts");
testDeliveryDedupe();
testHealthyToken();
testEscalation();
testExpiredAndMissing();
testRejectedByVSCode();
testBackoff();
testResync();
console.log("\nAll tests passed.");
