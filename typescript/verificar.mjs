/**
 * Contrasta la implementación TypeScript contra el banco de vectores.
 *
 *   npm test        (compila el paquete y ejecuta esto)
 *   node typescript/verificar.mjs
 *
 * IMPORTANTE: importa el PAQUETE YA COMPILADO (`dist/`), no una copia de la
 * lógica. Antes reimplementaba aquí saltDesdeEmail, derivarMK, hkdf, cifrar y
 * descifrar, con un aviso que decía «si se toca una, hay que tocar la otra».
 * Eso significaba que los vectores validaban ESTE fichero, no el que usan la web
 * y la extensión: passrodCripto.ts podía romperse y los vectores seguir en verde.
 *
 * Lo único que se mantiene aparte es el RSA de las pruebas de compartir, porque
 * el módulo no expone importación de claves en bruto y aquí hace falta abrir el
 * par de referencia del banco.
 */
import { webcrypto as cripto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  saltDesdeEmail,
  derivarMK,
  hkdf,
  construirAAD,
  cifrar,
  descifrar,
  VERSION_ESQUEMA,
  ALG_AES_GCM,
  PBKDF2_ITERACIONES,
  normalizarEmail,
  huella,
  envolverParaUsuario,
  firmarEnvoltura,
  verificarEnvoltura,
  mensajeEnvoltura,
  normalizarCodigoRecuperacion,
  nuevoCodigoRecuperacion,
  aadRecuperacion,
  envolverRecuperacion,
  abrirRecuperacion,
} from '../dist/passrodCripto.js';

const AQUI = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(AQUI, '..', 'vectores', 'vectores.json'), 'utf8'));

const utf8 = new TextEncoder();
const b64 = (u8) => Buffer.from(u8).toString('base64');
const deB64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const deHex = (s) => new Uint8Array(Buffer.from(s, 'hex'));

const P = V.parametros;
const E = V.entradas;

// Las funciones vienen del paquete; aquí solo queda comprobar que los
// parámetros del banco coinciden con los que el módulo trae compilados, porque
// si divergen los vectores dejarían de significar nada.
const desajustes = [];
if (VERSION_ESQUEMA !== V.version_esquema) desajustes.push('version_esquema');
if (ALG_AES_GCM !== P.alg_aes_gcm) desajustes.push('alg_aes_gcm');
if (PBKDF2_ITERACIONES !== P.pbkdf2_iteraciones) desajustes.push('pbkdf2_iteraciones');
if (desajustes.length) {
  console.error('El paquete y el banco de vectores no coinciden en: ' + desajustes.join(', '));
  process.exit(1);
}

const derivarMKpbkdf2 = (password, email) => derivarMK(password, email);

// ── ejecución ───────────────────────────────────────────────────────────────
const esperado = Object.fromEntries(V.casos.map((c) => [c.nombre, c.esperado]));
const resultados = [];
const comprobar = (nombre, obtenido) => {
  const ok = obtenido === esperado[nombre];
  resultados.push({ nombre, ok, obtenido, esperado: esperado[nombre] });
};

const nonce = deHex(E.nonce_hex);
const vk = deHex(E.clave_boveda_hex);

comprobar('salt_desde_email', b64(await saltDesdeEmail(E.email)));

const mk = await derivarMKpbkdf2(E.password, E.email);
comprobar('mk_pbkdf2', b64(mk));
const sk = await hkdf(mk, P.info_enc);
comprobar('sk_pbkdf2', b64(sk));
comprobar('authkey_pbkdf2', b64(await hkdf(mk, P.info_auth)));

const aadCred = construirAAD('credencial', 42, 7);
comprobar('aad_credencial', b64(aadCred));

// se cifra el JSON EXACTO del banco, no uno reconstruido: así una diferencia de
// serialización se detecta como tal y no se confunde con un fallo de cifrado
const contenido = deB64(esperado['credencial_json_utf8_b64']);
comprobar('blob_credencial', await cifrar(vk, contenido, aadCred, nonce));

const aadVk = construirAAD('clave_boveda', 7, 7);
comprobar('aad_clave_boveda', b64(aadVk));
comprobar('wrap_clave_boveda', await cifrar(sk, vk, aadVk, nonce));

const rk = await hkdf(utf8.encode(E.codigo_recuperacion), P.info_recovery);
comprobar('recovery_key', b64(rk));
comprobar('recovery_blob', await cifrar(rk, mk, construirAAD('recovery', 0, 0), nonce));

// ida y vuelta
const vuelta = await descifrar(vk, esperado['blob_credencial'], aadCred);
resultados.push({
  nombre: 'descifrar_credencial_del_banco',
  ok: Buffer.compare(Buffer.from(vuelta), Buffer.from(contenido)) === 0,
  obtenido: '(contenido recuperado)', esperado: '(igual al original)',
});

// ── RSA: compartir bóvedas ─────────────────────────────────────────────────
const aadPriv = construirAAD('clave_privada', 0, 0);
comprobar('aad_clave_privada', b64(aadPriv));
const privPkcs8 = deB64(E.rsa_privada_pkcs8_b64);
comprobar('priv_envuelta', await cifrar(sk, privPkcs8, aadPriv, nonce));

// El ciphertext RSA no se compara byte a byte: OAEP usa relleno aleatorio.
// Se comprueba DESCIFRANDO el que dejó la referencia.
const rsaOaep = { name: 'RSA-OAEP', hash: 'SHA-256' };
const privKey = await cripto.subtle.importKey('pkcs8', privPkcs8, rsaOaep, false, ['decrypt']);
const vkAbierta = new Uint8Array(await cripto.subtle.decrypt(
  { name: 'RSA-OAEP' }, privKey, deB64(E.wrap_asimetrico_b64)));
comprobar('abrir_wrap_asimetrico', b64(vkAbierta));

// ida y vuelta con la pública
const pubKey = await cripto.subtle.importKey('spki', deB64(E.rsa_publica_spki_b64),
  rsaOaep, false, ['encrypt']);
const miEnvuelta = new Uint8Array(await cripto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, vk));
const deVuelta = new Uint8Array(await cripto.subtle.decrypt(
  { name: 'RSA-OAEP' }, privKey, miEnvuelta));
resultados.push({
  nombre: 'rsa_ida_y_vuelta',
  ok: Buffer.compare(Buffer.from(deVuelta), Buffer.from(vk)) === 0,
  obtenido: '(clave recuperada)', esperado: '(igual a la original)',
});

// ── v2.2.0 ─────────────────────────────────────────────────────────────────
comprobar('mk_pbkdf2_desde_nfd', b64(await derivarMKpbkdf2(E.password_nfd, E.email)));
comprobar('email_con_i_normalizado', normalizarEmail(E.email_con_i_nfd));
comprobar('salt_email_con_i', b64(await saltDesdeEmail(E.email_con_i_nfd)));
comprobar('huella_publica', await huella(deB64(E.rsa_publica_spki_b64)));
comprobar('mensaje_envoltura', b64(mensajeEnvoltura(
  E.firma_envoltura_boveda, E.firma_envoltura_destinatario, E.wrap_asimetrico_b64)));
const pubSpki = deB64(E.rsa_publica_spki_b64);
comprobar('verificar_firma_envoltura', (await verificarEnvoltura(pubSpki,
  E.firma_envoltura_boveda, E.firma_envoltura_destinatario, E.wrap_asimetrico_b64,
  E.firma_envoltura_b64)) ? 'valida' : 'invalida');
comprobar('firma_con_otro_destinatario', (await verificarEnvoltura(pubSpki,
  E.firma_envoltura_boveda, 13, E.wrap_asimetrico_b64, E.firma_envoltura_b64)) ? 'valida' : 'invalida');
let rechaza = 'NO rechaza';
try { await envolverParaUsuario(deB64(E.rsa_publica_1024_spki_b64), vk); } catch { rechaza = 'rechaza'; }
comprobar('rechazar_rsa_1024', rechaza);
comprobar('codigo_normalizado', normalizarCodigoRecuperacion(E.codigo_tecleado));
comprobar('aad_recuperacion', b64(aadRecuperacion(E.email)));
comprobar('recovery_blob_atado', await envolverRecuperacion(E.codigo_tecleado, mk, E.email, nonce));

// Firma propia: la que hace TypeScript la verifica TypeScript, y no vale para otra bóveda
const miFirma = await firmarEnvoltura(privPkcs8, 7, 12, E.wrap_asimetrico_b64);
const firmaBuena = await verificarEnvoltura(pubSpki, 7, 12, E.wrap_asimetrico_b64, miFirma);
const firmaOtra = await verificarEnvoltura(pubSpki, 8, 12, E.wrap_asimetrico_b64, miFirma);
resultados.push({ nombre: 'firma_propia_ida_y_vuelta', ok: firmaBuena && !firmaOtra,
  obtenido: `${firmaBuena}/${firmaOtra}`, esperado: 'true/false' });

// Recuperación: abre el blob atado, abre el ANTIGUO (recovery|0|0) y no abre con otro correo
const atadoAbierto = await abrirRecuperacion(E.codigo_tecleado, esperado['recovery_blob_atado'], E.email);
// Los clientes siempre han envuelto con el código ya normalizado (con guiones),
// así que un blob antiguo real es este: código canónico y AAD recovery|0|0.
const rkCanon = await hkdf(utf8.encode(normalizarCodigoRecuperacion(E.codigo_tecleado)), P.info_recovery);
const blobAntiguo = await cifrar(rkCanon, mk, construirAAD('recovery', 0, 0));
const antiguoAbierto = await abrirRecuperacion(E.codigo_tecleado, blobAntiguo, E.email);
let otroCorreo = 'abre';
try { await abrirRecuperacion(E.codigo_tecleado, esperado['recovery_blob_atado'], 'otra@ejemplo.ec'); }
catch { otroCorreo = 'no abre'; }
resultados.push({ nombre: 'recuperacion_atada_y_antigua',
  ok: b64(atadoAbierto) === b64(mk) && b64(antiguoAbierto) === b64(mk) && otroCorreo === 'no abre',
  obtenido: otroCorreo, esperado: 'no abre' });

// El generador: formato, alfabeto y sin sesgo. Con 100 000 códigos el sesgo del
// módulo 31 (un 12 % más para 8 letras) se ve de sobra; el ruido es del 0,4 %.
const ALF = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const cuenta = Object.fromEntries([...ALF].map((c) => [c, 0]));
let formatoOk = true;
for (let i = 0; i < 100000; i++) {
  const c = nuevoCodigoRecuperacion();
  if (!/^([A-Z2-9]{5}-){4}[A-Z2-9]{5}$/.test(c)) formatoOk = false;
  for (const ch of c.replace(/-/g, '')) { if (!(ch in cuenta)) formatoOk = false; else cuenta[ch]++; }
}
const valores = Object.values(cuenta);
const media = (100000 * 25) / ALF.length;
const sinSesgo = valores.every((v) => Math.abs(v - media) < media * 0.03);
resultados.push({ nombre: 'generador_de_codigos', ok: formatoOk && sinSesgo,
  obtenido: `formato ${formatoOk}, min ${Math.min(...valores)} max ${Math.max(...valores)}`,
  esperado: `formato true, todos cerca de ${media}` });

// la AAD debe atar el blob a su ubicación
let atado = false;
try {
  await descifrar(vk, esperado['blob_credencial'], construirAAD('credencial', 43, 7));
} catch { atado = true; }
resultados.push({
  nombre: 'aad_incorrecta_debe_fallar', ok: atado,
  obtenido: atado ? 'falla como debe' : 'NO FALLÓ', esperado: 'falla como debe',
});

console.log('Verificación de la implementación TypeScript contra el banco de vectores\n');
let fallos = 0;
for (const r of resultados) {
  console.log(`  ${r.ok ? 'PASA ' : 'FALLA'}  ${r.nombre}`);
  if (!r.ok) {
    fallos++;
    console.log(`          esperado: ${String(r.esperado).slice(0, 60)}`);
    console.log(`          obtenido: ${String(r.obtenido).slice(0, 60)}`);
  }
}
console.log(`\n${resultados.length - fallos}/${resultados.length} correctos`);
if (fallos) {
  console.log('\nHAY DIVERGENCIA con la implementación de referencia.');
  process.exit(1);
}
console.log('TypeScript reproduce el esquema byte a byte.');
