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
let _cripto = null;
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
function obtenerCripto() {
    if (_cripto)
        return _cripto;
    const c = globalThis.crypto;
    if (!c || !c.subtle) {
        throw new Error('Este entorno no tiene WebCrypto (globalThis.crypto.subtle). PassRod ' +
            'necesita un navegador moderno o Node 18 o superior.');
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
export function aBase64(datos) {
    let s = '';
    for (const b of datos)
        s += String.fromCharCode(b);
    return btoaSeguro(s);
}
export function deBase64(texto) {
    const s = atobSeguro(texto);
    const salida = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++)
        salida[i] = s.charCodeAt(i);
    return salida;
}
function btoaSeguro(s) {
    return typeof btoa === 'function'
        ? btoa(s)
        : Buffer.from(s, 'binary').toString('base64');
}
function atobSeguro(s) {
    return typeof atob === 'function'
        ? atob(s)
        : Buffer.from(s, 'base64').toString('binary');
}
/** Borra un buffer con material sensible. No es infalible en JS, pero acorta
 *  la ventana en que la clave sigue en memoria. */
export function limpiar(...buffers) {
    for (const b of buffers)
        b.fill(0);
}
// ── Derivación ──────────────────────────────────────────────────────────────
/**
 * Salt determinista a partir del correo.
 *
 * Se deriva del correo y no de un aleatorio del servidor para que el cliente
 * pueda calcular la clave maestra ANTES de la primera petición: así la
 * contraseña nunca necesita viajar ni esperar a nadie.
 */
export async function saltDesdeEmail(email) {
    const h = await obtenerCripto().subtle.digest('SHA-256', utf8.encode(PREFIJO_SALT + normalizarEmail(email)));
    return new Uint8Array(h);
}
/**
 * El correo tal como entra en la sal: NFC, sin espacios y en minúsculas.
 *
 * La NFC importa: macOS e iOS componen los acentos en NFD y Windows en NFC, y
 * sin normalizar el mismo correo daría dos sales —la misma cuenta no abriría en
 * los dos equipos—. `toLowerCase` de JavaScript no depende del idioma, así que
 * aquí no existe la trampa de la «i» turca que sí tiene Java.
 */
export function normalizarEmail(email) {
    return email.normalize('NFC').trim().toLowerCase();
}
/** La contraseña se deriva siempre en NFC, por el mismo motivo que el correo. */
const passwordUtf8 = (password) => utf8.encode(password.normalize('NFC'));
/**
 * Clave maestra con PBKDF2-SHA256.
 *
 * Es el algoritmo por defecto porque WebCrypto lo trae nativo, igual que Java y
 * Android. Argon2id resiste mejor el ataque por hardware dedicado, pero en el
 * navegador exige WASM; el campo `kdf_tipo` del usuario existe precisamente
 * para poder cambiarlo sin romper a quien ya está registrado.
 */
export async function derivarMK(password, email) {
    const salt = await saltDesdeEmail(email);
    const base = await obtenerCripto().subtle.importKey('raw', passwordUtf8(password), { name: 'PBKDF2' }, false, ['deriveBits']);
    const bits = await obtenerCripto().subtle.deriveBits({ name: 'PBKDF2', salt, iterations: PBKDF2_ITERACIONES, hash: 'SHA-256' }, base, 256);
    return new Uint8Array(bits);
}
/** HKDF-SHA256 con salt vacío (RFC 5869). */
export async function hkdf(ikm, info, largo = 32) {
    const base = await obtenerCripto().subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
    const bits = await obtenerCripto().subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8.encode(info) }, base, largo * 8);
    return new Uint8Array(bits);
}
/** Clave de cifrado: nunca sale del cliente. */
export const derivarSK = (mk) => hkdf(mk, INFO_ENC);
/** Clave de autenticación: su base64 es lo ÚNICO que se envía al servidor. */
export const derivarAuthKey = (mk) => hkdf(mk, INFO_AUTH);
export async function authHash(password, email) {
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
export function construirAAD(tipo, idRecurso, idBoveda) {
    return utf8.encode(`${PREFIJO_AAD}${tipo}|${idRecurso}|${idBoveda}`);
}
/** base64( VER(1) ‖ ALG(1) ‖ NONCE(12) ‖ CIPHERTEXT‖TAG(16) ) */
export async function cifrar(clave, plano, aad, nonce) {
    const iv = nonce ?? obtenerCripto().getRandomValues(new Uint8Array(12));
    if (iv.length !== 12)
        throw new Error('El nonce debe ser de 12 bytes');
    const k = await obtenerCripto().subtle.importKey('raw', clave, { name: 'AES-GCM' }, false, ['encrypt']);
    const ct = new Uint8Array(await obtenerCripto().subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, k, plano));
    const salida = new Uint8Array(2 + iv.length + ct.length);
    salida[0] = VERSION_ESQUEMA;
    salida[1] = ALG_AES_GCM;
    salida.set(iv, 2);
    salida.set(ct, 2 + iv.length);
    return aBase64(salida);
}
export async function descifrar(clave, blob, aad) {
    const crudo = deBase64(blob);
    if (crudo.length < 2 + 12 + 16)
        throw new Error('Blob demasiado corto');
    const version = crudo[0];
    const alg = crudo[1];
    // El byte de versión permite cambiar de algoritmo en el futuro sin migrar
    // toda la base de golpe: cada blob dice cómo fue cifrado.
    if (version !== VERSION_ESQUEMA)
        throw new Error(`Versión de blob no soportada: ${version}`);
    if (alg !== ALG_AES_GCM)
        throw new Error(`Algoritmo no soportado: ${alg}`);
    const iv = crudo.slice(2, 14);
    const ct = crudo.slice(14);
    const k = await obtenerCripto().subtle.importKey('raw', clave, { name: 'AES-GCM' }, false, ['decrypt']);
    const plano = await obtenerCripto().subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, k, ct);
    return new Uint8Array(plano);
}
// ── Objetos de dominio ──────────────────────────────────────────────────────
export const cifrarCredencial = (vk, credencial, idCredencial, idBoveda, nonce) => cifrar(vk, utf8.encode(JSON.stringify(credencial)), construirAAD('credencial', idCredencial, idBoveda), nonce);
export async function descifrarCredencial(vk, blob, idCredencial, idBoveda) {
    const plano = await descifrar(vk, blob, construirAAD('credencial', idCredencial, idBoveda));
    return JSON.parse(new TextDecoder().decode(plano));
}
/** Clave de bóveda nueva. Aleatoria de verdad: nunca derivarla de nada. */
export const nuevaClaveBoveda = () => obtenerCripto().getRandomValues(new Uint8Array(32));
export const envolverClaveBoveda = (sk, vk, idBoveda, nonce) => cifrar(sk, vk, construirAAD('clave_boveda', idBoveda, idBoveda), nonce);
export const abrirClaveBoveda = (sk, envuelta, idBoveda) => descifrar(sk, envuelta, construirAAD('clave_boveda', idBoveda, idBoveda));
// ── Compartir bóvedas: RSA-2048-OAEP-SHA256 (§2.2 y §2.3) ──────────────────
//
// Se eligió RSA y no X25519 porque WebCrypto, Java y Android lo traen de serie;
// X25519 en WebCrypto es reciente y de disponibilidad desigual.
//
// El relleno de OAEP es aleatorio: dos envolturas de la misma clave dan
// ciphertexts distintos. Es correcto, pero significa que no se pueden comparar
// byte a byte entre implementaciones — se comparan descifrando.
const RSA_OAEP = { name: 'RSA-OAEP', hash: 'SHA-256' };
/** Par de claves del usuario. Se genera una vez, en el registro. */
export async function generarParDeClaves() {
    const par = await obtenerCripto().subtle.generateKey({ ...RSA_OAEP, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }, true, ['encrypt', 'decrypt']);
    return {
        publicaSpki: new Uint8Array(await obtenerCripto().subtle.exportKey('spki', par.publicKey)),
        privadaPkcs8: new Uint8Array(await obtenerCripto().subtle.exportKey('pkcs8', par.privateKey)),
    };
}
/** Por debajo de esto una clave RSA no protege nada: se rechaza al envolver. */
export const MIN_BITS_RSA = 2048;
/**
 * Envuelve la clave de bóveda para otro usuario, usando su clave pública.
 *
 * Esto es lo que permite compartir sin que el servidor participe: el dueño
 * cifra VK para el invitado y el servidor solo transporta el resultado.
 *
 * La clave pública la entrega el servidor, así que se comprueba su tamaño: uno
 * malicioso podría entregar una de 512 bits, que se factoriza en horas.
 */
export async function envolverParaUsuario(publicaSpki, vk) {
    const pub = await obtenerCripto().subtle.importKey('spki', publicaSpki, RSA_OAEP, false, ['encrypt']);
    const bits = pub.algorithm.modulusLength;
    if (!(bits >= MIN_BITS_RSA)) {
        throw new Error(`Clave pública RSA de ${bits} bits: el mínimo es ${MIN_BITS_RSA}`);
    }
    return aBase64(new Uint8Array(await obtenerCripto().subtle.encrypt({ name: 'RSA-OAEP' }, pub, vk)));
}
/**
 * Huella legible de una clave pública, para compararla por otro canal.
 *
 * La clave pública del otro la entrega el servidor; si entregara la suya podría
 * leer lo compartido. La única defensa es que las dos personas lean esta huella
 * y comprueben que coincide. Se calcula SIEMPRE sobre la clave recibida: la que
 * mande el servidor no comprueba nada.
 *
 * Diez bytes en cinco grupos: exige una colisión dirigida y se lee por teléfono.
 */
export async function huella(publicaSpki) {
    const h = new Uint8Array(await obtenerCripto().subtle.digest('SHA-256', publicaSpki));
    const hex = [...h.slice(0, 10)].map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join('');
    return (hex.match(/.{4}/g) ?? []).join('-');
}
// ── Firma de envolturas: RSA-PSS-SHA256 con el mismo par (v2.2.0) ──────────
//
// Sin firma, cualquiera con la clave pública de alguien —incluido el servidor—
// puede envolverle una clave de bóveda que él mismo conoce y hacerla pasar por
// compartida: lo que la víctima guardase ahí sería legible. Con la firma de
// quien comparte, el servidor no puede fabricarla, porque no tiene su privada.
//
// Se reutiliza el par RSA-OAEP del usuario: OAEP y PSS con la misma clave son
// seguros juntos (Haber y Pinkas, 2001), y así no hay que repartir, envolver ni
// re-envolver una segunda clave en el alta, el cambio de contraseña y la
// recuperación.
const RSA_PSS = { name: 'RSA-PSS', hash: 'SHA-256' };
const SAL_PSS = 32;
/** Lo que se firma: ata la envoltura a su bóveda y a su destinatario. */
export function mensajeEnvoltura(idBoveda, idDestinatario, claveEnvuelta) {
    return utf8.encode(`${PREFIJO_AAD}compartir|${idBoveda}|${idDestinatario}|${claveEnvuelta}`);
}
export async function firmarEnvoltura(privadaPkcs8, idBoveda, idDestinatario, claveEnvuelta) {
    const priv = await obtenerCripto().subtle.importKey('pkcs8', privadaPkcs8, RSA_PSS, false, ['sign']);
    const firma = await obtenerCripto().subtle.sign({ name: 'RSA-PSS', saltLength: SAL_PSS }, priv, mensajeEnvoltura(idBoveda, idDestinatario, claveEnvuelta));
    return aBase64(new Uint8Array(firma));
}
/** true solo si la firma es de la privada de `publicaSpki` y para ESA bóveda y ESE destinatario. */
export async function verificarEnvoltura(publicaSpki, idBoveda, idDestinatario, claveEnvuelta, firmaB64) {
    try {
        const pub = await obtenerCripto().subtle.importKey('spki', publicaSpki, RSA_PSS, false, ['verify']);
        if (pub.algorithm.modulusLength < MIN_BITS_RSA)
            return false;
        return await obtenerCripto().subtle.verify({ name: 'RSA-PSS', saltLength: SAL_PSS }, pub, deBase64(firmaB64), mensajeEnvoltura(idBoveda, idDestinatario, claveEnvuelta));
    }
    catch {
        return false;
    }
}
/** Abre una clave de bóveda que envolvieron para mí. */
export async function abrirConPrivada(privadaPkcs8, envuelta) {
    const priv = await obtenerCripto().subtle.importKey('pkcs8', privadaPkcs8, RSA_OAEP, false, ['decrypt']);
    return new Uint8Array(await obtenerCripto().subtle.decrypt({ name: 'RSA-OAEP' }, priv, deBase64(envuelta)));
}
/** La privada nunca llega al servidor sin envolver. */
export const envolverClavePrivada = (sk, privadaPkcs8, nonce) => cifrar(sk, privadaPkcs8, construirAAD('clave_privada', 0, 0), nonce);
export const abrirClavePrivada = (sk, envuelta) => descifrar(sk, envuelta, construirAAD('clave_privada', 0, 0));
// ── Recuperación ────────────────────────────────────────────────────────────
export const claveDeRecuperacion = (codigo) => hkdf(utf8.encode(codigo), INFO_RECOVERY);
/** Sin I, L, O, 0 ni 1: el código se apunta en papel y se confunden al leer. */
export const ALFABETO_CODIGO = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
/**
 * Código de recuperación nuevo: 25 caracteres en cinco grupos (~124 bits).
 *
 * Vive aquí para que todos los clientes lo generen igual. Se descartan los
 * bytes que no caben en un múltiplo de 31: con un simple `% 31`, ocho letras
 * salían un 12 % más a menudo que las demás.
 */
export function nuevoCodigoRecuperacion() {
    const limite = 256 - (256 % ALFABETO_CODIGO.length);
    let salida = '';
    while (salida.replace(/-/g, '').length < 25) {
        for (const b of obtenerCripto().getRandomValues(new Uint8Array(32))) {
            if (b >= limite)
                continue;
            const n = salida.replace(/-/g, '').length;
            if (n === 25)
                break;
            if (n > 0 && n % 5 === 0)
                salida += '-';
            salida += ALFABETO_CODIGO[b % ALFABETO_CODIGO.length];
        }
    }
    return salida;
}
/** Forma canónica de un código tecleado: sin espacios ni guiones, en grupos de 5. */
export function normalizarCodigoRecuperacion(codigo) {
    const limpio = codigo.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
    return (limpio.match(/.{1,5}/g) ?? []).join('-');
}
/** AAD del blob de recuperación: lo ata a SU cuenta (antes era recovery|0|0 para todas). */
export const aadRecuperacion = (email) => construirAAD('recovery', normalizarEmail(email), 0);
/** Envuelve MK con el código, atada al correo. El código se normaliza aquí. */
export async function envolverRecuperacion(codigo, mk, email, nonce) {
    const rk = await claveDeRecuperacion(normalizarCodigoRecuperacion(codigo));
    const blob = await cifrar(rk, mk, aadRecuperacion(email), nonce);
    limpiar(rk);
    return blob;
}
/**
 * Abre el blob de recuperación. Acepta también el formato anterior a la v2.2.0
 * (AAD `recovery|0|0`), para no dejar sin salida a quien lo guardó antes.
 */
export async function abrirRecuperacion(codigo, blob, email) {
    const rk = await claveDeRecuperacion(normalizarCodigoRecuperacion(codigo));
    try {
        return await descifrar(rk, blob, aadRecuperacion(email));
    }
    catch {
        return await descifrar(rk, blob, construirAAD('recovery', 0, 0));
    }
    finally {
        limpiar(rk);
    }
}
export async function envolverParaRecuperacion(codigo, mk, nonce) {
    const rk = await claveDeRecuperacion(codigo);
    const blob = await cifrar(rk, mk, construirAAD('recovery', 0, 0), nonce);
    limpiar(rk);
    return blob;
}
export async function recuperarMK(codigo, blob) {
    const rk = await claveDeRecuperacion(codigo);
    const mk = await descifrar(rk, blob, construirAAD('recovery', 0, 0));
    limpiar(rk);
    return mk;
}
// Doble factor (TOTP). Vive aparte porque no toca las claves de PassRod.
export * from './totp.js';
