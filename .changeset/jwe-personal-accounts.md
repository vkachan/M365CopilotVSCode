---
"m365-copilot-vscode": patch
"m365-copilot-vscode-extension": patch
"@m365copilot/core": patch
"@m365copilot/tui": patch
---

**Cuentas personales de Microsoft (token JWE cifrado).**

- **Captura en el navegador:** las cuentas personales (Microsoft 365
  Personal/Familia) reciben un token JWE de cinco partes, no un JWT. La
  extensión de Chrome/Edge lo reconoce en el WebSocket del chat y lo envía a VS
  Code con la identidad `{oid}@{tid}` de esa URL de Chathub, que sólo se acepta
  de un host de Microsoft por `wss`. Un JWE de un `fetch` cualquiera no cuenta.
- **«Pegar perfil o token»:** acepta la URL del WebSocket del chat y el JSON de
  la extensión con un JWE. Un JWE pelado no dice de quién es: el error explica
  qué falta y qué copiar.
- **Conexión:** el chat se abre con la identidad capturada y el escenario que
  usó la web; los JWT siguen exactamente igual (claims del token).
- **Caducidad desconocida, no inventada:** la de un JWE no se puede leer. Vale
  hasta que M365 lo rechaza; entonces VS Code lo marca, avisa con la solución,
  y la extensión de navegador lo ve en el health-check y lo renueva. Antes, un
  token sin `exp` hacía que el navegador recargara la pestaña de M365 en bucle.
- **Sin valores de empresa inventados:** una cuenta personal replica la query
  del socket del chat que abrió la web (escenario, superficie, `variants`) y
  sólo cambia el token y los ids de sesión; si la web no mandó `scenario`, no
  se manda.
- **Endpoint de varios KB:** el tope de 2 KB descartaba en silencio la URL del
  chat (la web lleva miles de caracteres de `variants`), y «Pegar perfil» decía
  «listo» con un perfil que no podía conectar. Ahora se conserva, la
  importación y la petición usan la misma comprobación, y si falta algo se dice
  qué.
- **403 no es caducidad:** sólo un 401 marca el token como rechazado; un 403 ya
  no dispara la renovación en bucle. El log compara, saneado, lo que pidió el
  socket de la web con lo que se envió.
- **Sin «token renovado» repetido:** el navegador no reenvía un perfil idéntico
  y VS Code sólo anuncia una renovación cuando cambia la huella del token.
- **Registro:** los JWE se ocultan en los logs igual que los JWT.
