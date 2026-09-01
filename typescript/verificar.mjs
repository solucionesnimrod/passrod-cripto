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
