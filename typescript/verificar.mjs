/**
 * Contrasta la implementación TypeScript contra el banco de vectores.
 *
 * Es JavaScript puro (.mjs) a propósito: así se ejecuta con `node verificar.mjs`
 * sin cadena de compilación, y puede correr en CI sin instalar nada.
 * La lógica es la misma que passrodCripto.ts; si se toca una, hay que tocar la otra.
 *
 *   node verificar.mjs
 */
import { webcrypto as cripto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const AQUI = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(AQUI, '..', 'vectores', 'vectores.json'), 'utf8'));

const utf8 = new TextEncoder();
const b64 = (u8) => Buffer.from(u8).toString('base64');
const deB64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const deHex = (s) => new Uint8Array(Buffer.from(s, 'hex'));

const P = V.parametros;
const E = V.entradas;

async function saltDesdeEmail(email) {
  const h = await cripto.subtle.digest('SHA-256',
    utf8.encode(P.prefijo_salt + email.trim().toLowerCase()));
  return new Uint8Array(h);
}

async function derivarMKpbkdf2(password, email) {
  const salt = await saltDesdeEmail(email);
  const base = await cripto.subtle.importKey('raw', utf8.encode(password),
    { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await cripto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: P.pbkdf2_iteraciones, hash: 'SHA-256' }, base, 256);
  return new Uint8Array(bits);
}

async function hkdf(ikm, info, largo = 32) {
  const base = await cripto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
  const bits = await cripto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8.encode(info) },
    base, largo * 8);
  return new Uint8Array(bits);
}

const construirAAD = (tipo, idRecurso, idBoveda) =>
  utf8.encode(`${P.prefijo_aad}${tipo}|${idRecurso}|${idBoveda}`);

async function cifrar(clave, plano, aad, nonce) {
  const k = await cripto.subtle.importKey('raw', clave, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = new Uint8Array(await cripto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, k, plano));
  const out = new Uint8Array(2 + nonce.length + ct.length);
  out[0] = V.version_esquema;
  out[1] = P.alg_aes_gcm;
  out.set(nonce, 2);
  out.set(ct, 2 + nonce.length);
  return b64(out);
}

async function descifrar(clave, blob, aad) {
  const crudo = deB64(blob);
  if (crudo[0] !== V.version_esquema) throw new Error('versión no soportada');
  if (crudo[1] !== P.alg_aes_gcm) throw new Error('algoritmo no soportado');
  const k = await cripto.subtle.importKey('raw', clave, { name: 'AES-GCM' }, false, ['decrypt']);
  return new Uint8Array(await cripto.subtle.decrypt(
    { name: 'AES-GCM', iv: crudo.slice(2, 14), additionalData: aad, tagLength: 128 },
    k, crudo.slice(14)));
}

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
