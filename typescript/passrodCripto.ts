/**
 * Núcleo criptográfico de PassRod v2 — implementación para navegador y Node.
 *
 * Debe reproducir byte a byte los valores de `vectores/vectores.json`. Si esta
 * implementación diverge de la de Java o Kotlin, una bóveda cifrada en un
 * cliente no se abrirá en otro; por eso los vectores se ejecutan en CI.
 *
 * Todo el material sensible se deriva y se usa aquí, en el cliente. El servidor
 * solo recibe `auth_hash` y blobs opacos.
 */

let _cripto: Crypto | null = null;

/**
 * La WebCrypto del entorno, resuelta la PRIMERA VEZ QUE SE USA.
 *
 * Antes se resolvía al cargar el módulo, y con un `require('crypto').webcrypto`
 * de reserva para Node antiguo. Las dos cosas estorbaban:
 *
 *  - El `require` dentro de un módulo ESM lo intentan resolver los bundlers en
 *    tiempo de compilación aunque nunca se ejecute, y este fichero pasa a
 *    empaquetarse para la web y para la extensión de navegador.
 *  - Resolverla al cargar hace que el módulo REVIENTE AL IMPORTARSE si el
 *    entorno no tiene WebCrypto. Y este módulo se importa también en el
 *    servidor: la web corre en Amplify con Next en modo SSR, así que Node la
 *    carga aunque el cifrado ocurra siempre en el navegador. Un fallo ahí
 *    tumbaría el renderizado entero por una función que nadie iba a llamar.
 *
 * Resolviéndola de forma perezosa, el módulo se puede importar en cualquier
 * sitio y el error —si de verdad falta WebCrypto— aparece al cifrar, que es
 * cuando importa y donde se entiende.
 */
function obtenerCripto(): Crypto {
  if (_cripto) return _cripto;
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error(
      'Este entorno no tiene WebCrypto (globalThis.crypto.subtle). PassRod ' +
        'necesita un navegador moderno o Node 18 o superior.'
    );
  }
  _cripto = c;
  return c;
}

// ── Parámetros del esquema (§2) ─────────────────────────────────────────────
export const VERSION_ESQUEMA = 2;
export const ALG_AES_GCM = 0x01;
export const PBKDF2_ITERACIONES = 600_000;

const PREFIJO_SALT = 'passrod.v2|';
const PREFIJO_AAD = 'passrod.v2|';
const INFO_ENC = 'passrod.v2.enc';
const INFO_AUTH = 'passrod.v2.auth';
const INFO_RECOVERY = 'passrod.v2.recovery';

const utf8 = new TextEncoder();

// ── Utilidades ──────────────────────────────────────────────────────────────

export function aBase64(datos: Uint8Array): string {
  let s = '';
  for (const b of datos) s += String.fromCharCode(b);
  return btoaSeguro(s);
}

export function deBase64(texto: string): Uint8Array {
  const s = atobSeguro(texto);
  const salida = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) salida[i] = s.charCodeAt(i);
  return salida;
}

function btoaSeguro(s: string): string {
  return typeof btoa === 'function'
    ? btoa(s)
    : Buffer.from(s, 'binary').toString('base64');
}

function atobSeguro(s: string): string {
  return typeof atob === 'function'
    ? atob(s)
    : Buffer.from(s, 'base64').toString('binary');
}

/** Borra un buffer con material sensible. No es infalible en JS, pero acorta
 *  la ventana en que la clave sigue en memoria. */
export function limpiar(...buffers: Uint8Array[]): void {
  for (const b of buffers) b.fill(0);
}

// ── Derivación ──────────────────────────────────────────────────────────────

/**
 * Salt determinista a partir del correo.
 *
 * Se deriva del correo y no de un aleatorio del servidor para que el cliente
 * pueda calcular la clave maestra ANTES de la primera petición: así la
 * contraseña nunca necesita viajar ni esperar a nadie.
 */
export async function saltDesdeEmail(email: string): Promise<Uint8Array> {
  const normalizado = email.trim().toLowerCase();
  const h = await obtenerCripto().subtle.digest('SHA-256', utf8.encode(PREFIJO_SALT + normalizado));
  return new Uint8Array(h);
}

/**
 * Clave maestra con PBKDF2-SHA256.
 *
 * Es el algoritmo por defecto porque WebCrypto lo trae nativo, igual que Java y
 * Android. Argon2id resiste mejor el ataque por hardware dedicado, pero en el
 * navegador exige WASM; el campo `kdf_tipo` del usuario existe precisamente
 * para poder cambiarlo sin romper a quien ya está registrado.
 */
export async function derivarMK(password: string, email: string): Promise<Uint8Array> {
  const salt = await saltDesdeEmail(email);
  const base = await obtenerCripto().subtle.importKey(
    'raw', utf8.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await obtenerCripto().subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERACIONES, hash: 'SHA-256' },
    base, 256);
  return new Uint8Array(bits);
}

/** HKDF-SHA256 con salt vacío (RFC 5869). */
export async function hkdf(ikm: Uint8Array, info: string, largo = 32): Promise<Uint8Array> {
  const base = await obtenerCripto().subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
  const bits = await obtenerCripto().subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8.encode(info) },
    base, largo * 8);
  return new Uint8Array(bits);
}

/** Clave de cifrado: nunca sale del cliente. */
export const derivarSK = (mk: Uint8Array) => hkdf(mk, INFO_ENC);

/** Clave de autenticación: su base64 es lo ÚNICO que se envía al servidor. */
export const derivarAuthKey = (mk: Uint8Array) => hkdf(mk, INFO_AUTH);

export async function authHash(password: string, email: string): Promise<string> {
  const mk = await derivarMK(password, email);
  const ak = await derivarAuthKey(mk);
  const salida = aBase64(ak);
  limpiar(mk, ak);
  return salida;
}

// ── Formato de blob ─────────────────────────────────────────────────────────

/**
 * Datos autenticados asociados: atan el blob a su ubicación exacta.
 *
 * Sin esto, alguien con acceso de escritura a la base podría mover el
 * ciphertext de una credencial a otra fila, o de una bóveda a otra, y el
 * descifrado seguiría funcionando.
 */
export function construirAAD(tipo: string, idRecurso: string | number,
                             idBoveda: string | number): Uint8Array {
  return utf8.encode(`${PREFIJO_AAD}${tipo}|${idRecurso}|${idBoveda}`);
}

/** base64( VER(1) ‖ ALG(1) ‖ NONCE(12) ‖ CIPHERTEXT‖TAG(16) ) */
export async function cifrar(clave: Uint8Array, plano: Uint8Array,
                             aad: Uint8Array, nonce?: Uint8Array): Promise<string> {
  const iv = nonce ?? obtenerCripto().getRandomValues(new Uint8Array(12));
  if (iv.length !== 12) throw new Error('El nonce debe ser de 12 bytes');

  const k = await obtenerCripto().subtle.importKey('raw', clave, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = new Uint8Array(
    await obtenerCripto().subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, k, plano));

  const salida = new Uint8Array(2 + iv.length + ct.length);
  salida[0] = VERSION_ESQUEMA;
  salida[1] = ALG_AES_GCM;
  salida.set(iv, 2);
  salida.set(ct, 2 + iv.length);
  return aBase64(salida);
}

export async function descifrar(clave: Uint8Array, blob: string,
                                aad: Uint8Array): Promise<Uint8Array> {
  const crudo = deBase64(blob);
  if (crudo.length < 2 + 12 + 16) throw new Error('Blob demasiado corto');

  const version = crudo[0];
  const alg = crudo[1];
  // El byte de versión permite cambiar de algoritmo en el futuro sin migrar
  // toda la base de golpe: cada blob dice cómo fue cifrado.
  if (version !== VERSION_ESQUEMA) throw new Error(`Versión de blob no soportada: ${version}`);
  if (alg !== ALG_AES_GCM) throw new Error(`Algoritmo no soportado: ${alg}`);

  const iv = crudo.slice(2, 14);
  const ct = crudo.slice(14);
  const k = await obtenerCripto().subtle.importKey('raw', clave, { name: 'AES-GCM' }, false, ['decrypt']);
  const plano = await obtenerCripto().subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, k, ct);
  return new Uint8Array(plano);
}

// ── Objetos de dominio ──────────────────────────────────────────────────────

export const cifrarCredencial = (vk: Uint8Array, credencial: unknown,
                                 idCredencial: string | number, idBoveda: string | number,
                                 nonce?: Uint8Array) =>
  cifrar(vk, utf8.encode(JSON.stringify(credencial)),
         construirAAD('credencial', idCredencial, idBoveda), nonce);

export async function descifrarCredencial<T>(vk: Uint8Array, blob: string,
                                             idCredencial: string | number,
                                             idBoveda: string | number): Promise<T> {
  const plano = await descifrar(vk, blob, construirAAD('credencial', idCredencial, idBoveda));
  return JSON.parse(new TextDecoder().decode(plano)) as T;
}

/** Clave de bóveda nueva. Aleatoria de verdad: nunca derivarla de nada. */
export const nuevaClaveBoveda = () => obtenerCripto().getRandomValues(new Uint8Array(32));

export const envolverClaveBoveda = (sk: Uint8Array, vk: Uint8Array,
                                    idBoveda: string | number, nonce?: Uint8Array) =>
  cifrar(sk, vk, construirAAD('clave_boveda', idBoveda, idBoveda), nonce);

export const abrirClaveBoveda = (sk: Uint8Array, envuelta: string,
                                 idBoveda: string | number) =>
  descifrar(sk, envuelta, construirAAD('clave_boveda', idBoveda, idBoveda));

// ── Compartir bóvedas: RSA-2048-OAEP-SHA256 (§2.2 y §2.3) ──────────────────
//
// Se eligió RSA y no X25519 porque WebCrypto, Java y Android lo traen de serie;
// X25519 en WebCrypto es reciente y de disponibilidad desigual.
//
// El relleno de OAEP es aleatorio: dos envolturas de la misma clave dan
// ciphertexts distintos. Es correcto, pero significa que no se pueden comparar
// byte a byte entre implementaciones — se comparan descifrando.

const RSA_OAEP = { name: 'RSA-OAEP', hash: 'SHA-256' } as const;

export interface ParDeClaves {
  publicaSpki: Uint8Array;   // va al servidor en claro: es pública
  privadaPkcs8: Uint8Array;  // va al servidor ENVUELTA con SK
}

/** Par de claves del usuario. Se genera una vez, en el registro. */
export async function generarParDeClaves(): Promise<ParDeClaves> {
  const par = await obtenerCripto().subtle.generateKey(
    { ...RSA_OAEP, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true, ['encrypt', 'decrypt']) as CryptoKeyPair;
  return {
    publicaSpki: new Uint8Array(await obtenerCripto().subtle.exportKey('spki', par.publicKey)),
    privadaPkcs8: new Uint8Array(await obtenerCripto().subtle.exportKey('pkcs8', par.privateKey)),
  };
}

/**
 * Envuelve la clave de bóveda para otro usuario, usando su clave pública.
 *
 * Esto es lo que permite compartir sin que el servidor participe: el dueño
 * cifra VK para el invitado y el servidor solo transporta el resultado.
 */
export async function envolverParaUsuario(publicaSpki: Uint8Array,
                                          vk: Uint8Array): Promise<string> {
  const pub = await obtenerCripto().subtle.importKey('spki', publicaSpki, RSA_OAEP, false, ['encrypt']);
  return aBase64(new Uint8Array(await obtenerCripto().subtle.encrypt({ name: 'RSA-OAEP' }, pub, vk)));
}

/** Abre una clave de bóveda que envolvieron para mí. */
export async function abrirConPrivada(privadaPkcs8: Uint8Array,
                                      envuelta: string): Promise<Uint8Array> {
  const priv = await obtenerCripto().subtle.importKey('pkcs8', privadaPkcs8, RSA_OAEP, false, ['decrypt']);
  return new Uint8Array(
    await obtenerCripto().subtle.decrypt({ name: 'RSA-OAEP' }, priv, deBase64(envuelta)));
}

/** La privada nunca llega al servidor sin envolver. */
export const envolverClavePrivada = (sk: Uint8Array, privadaPkcs8: Uint8Array,
                                     nonce?: Uint8Array) =>
  cifrar(sk, privadaPkcs8, construirAAD('clave_privada', 0, 0), nonce);

export const abrirClavePrivada = (sk: Uint8Array, envuelta: string) =>
  descifrar(sk, envuelta, construirAAD('clave_privada', 0, 0));

// ── Recuperación ────────────────────────────────────────────────────────────

export const claveDeRecuperacion = (codigo: string) =>
  hkdf(utf8.encode(codigo), INFO_RECOVERY);

export async function envolverParaRecuperacion(codigo: string, mk: Uint8Array,
                                               nonce?: Uint8Array): Promise<string> {
  const rk = await claveDeRecuperacion(codigo);
  const blob = await cifrar(rk, mk, construirAAD('recovery', 0, 0), nonce);
  limpiar(rk);
  return blob;
}

export async function recuperarMK(codigo: string, blob: string): Promise<Uint8Array> {
  const rk = await claveDeRecuperacion(codigo);
  const mk = await descifrar(rk, blob, construirAAD('recovery', 0, 0));
  limpiar(rk);
  return mk;
}
