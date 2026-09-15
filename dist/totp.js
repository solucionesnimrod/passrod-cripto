/**
 * Doble factor por tiempo (TOTP, RFC 6238).
 *
 * Debe dar los mismos códigos que `vectores/vectores_totp.json`, igual que la
 * versión Java del escritorio: un código distinto en un cliente es un código
 * que el sitio rechaza sin decir por qué.
 *
 * Acepta lo que el usuario tiene a mano: la URI `otpauth://totp/...` que va
 * dentro del QR, o el secreto en base32 que los sitios enseñan como alternativa
 * («¿no puedes escanear?»), con espacios, minúsculas o relleno.
 */
/** El texto no es un TOTP que se pueda usar. El mensaje va dirigido al usuario. */
export class TotpInvalido extends Error {
    constructor(mensaje) {
        super(mensaje);
        this.name = 'TotpInvalido';
    }
}
const ALFABETO_BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const ALGORITMOS = {
    SHA1: 'SHA-1',
    SHA256: 'SHA-256',
    SHA512: 'SHA-512'
};
/** Base32 tal como lo escriben las personas: sin relleno, con espacios o guiones. */
export function base32ABytes(texto) {
    const limpio = texto.replace(/\s+/g, '').replace(/-/g, '').toUpperCase().replace(/=+$/, '');
    if (!limpio)
        throw new TotpInvalido('Falta el secreto del código de verificación.');
    // Con 1, 3 o 6 caracteres sobrantes no se completa ningún byte: el secreto
    // está cortado, y calcular con lo que hay daría códigos falsos.
    if ([1, 3, 6].includes(limpio.length % 8)) {
        throw new TotpInvalido('El secreto está incompleto: revisa que se copió entero.');
    }
    const salida = new Uint8Array(Math.floor((limpio.length * 5) / 8));
    let bits = 0;
    let acumulado = 0;
    let i = 0;
    for (const c of limpio) {
        const valor = ALFABETO_BASE32.indexOf(c);
        if (valor < 0) {
            throw new TotpInvalido(`El secreto tiene un carácter que no vale («${c}»). Solo lleva letras y los números del 2 al 7.`);
        }
        acumulado = (acumulado << 5) | valor;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            salida[i++] = (acumulado >>> bits) & 0xff;
        }
    }
    return salida;
}
function decodificar(texto) {
    try {
        return decodeURIComponent(texto);
    }
    catch {
        return texto;
    }
}
function entero(texto, porDefecto, que) {
    if (texto === undefined)
        return porDefecto;
    if (!/^\s*\+?\d+\s*$/.test(texto)) {
        throw new TotpInvalido(`El QR trae ${que} que no es un número.`);
    }
    return parseInt(texto, 10);
}
/** Lee una URI `otpauth://totp/...` o un secreto base32 suelto. */
export function leerTotp(texto) {
    const entrada = (texto ?? '').trim();
    if (!/^otpauth:\/\//i.test(entrada)) {
        return {
            secreto: base32ABytes(entrada),
            algoritmo: 'SHA-1',
            digitos: 6,
            periodo: 30,
            emisor: '',
            cuenta: ''
        };
    }
    let url;
    try {
        url = new URL(entrada);
    }
    catch {
        throw new TotpInvalido('El QR no contiene una dirección otpauth válida.');
    }
    if (url.host.toLowerCase() !== 'totp') {
        throw new TotpInvalido('Este código es por contador (HOTP), no por tiempo. PassRod solo admite los de tiempo (TOTP), que son los que usan casi todos los sitios.');
    }
    const parametros = {};
    url.searchParams.forEach((valor, clave) => {
        parametros[clave.toLowerCase()] = valor;
    });
    const nombreAlgoritmo = (parametros.algorithm ?? 'SHA1').toUpperCase().replace(/-/g, '');
    const algoritmo = ALGORITMOS[nombreAlgoritmo];
    if (!algoritmo) {
        throw new TotpInvalido(`El QR usa un algoritmo que PassRod no admite (${nombreAlgoritmo}).`);
    }
    const digitos = entero(parametros.digits, 6, 'un número de dígitos');
    const periodo = entero(parametros.period, 30, 'un periodo');
    if (digitos < 6 || digitos > 8) {
        throw new TotpInvalido(`El QR pide códigos de ${digitos} dígitos; solo se admiten de 6 a 8.`);
    }
    if (periodo < 1 || periodo > 3600) {
        throw new TotpInvalido(`El QR pide un periodo de ${periodo} segundos, que no es válido.`);
    }
    // La etiqueta es «Emisor:cuenta» o solo «cuenta». El parámetro issuer, si
    // viene, manda sobre el emisor de la etiqueta.
    const etiqueta = decodificar(url.pathname.replace(/^\/+/, ''));
    const dosPuntos = etiqueta.lastIndexOf(':');
    const emisorEtiqueta = dosPuntos >= 0 ? etiqueta.slice(0, dosPuntos) : '';
    const cuenta = dosPuntos >= 0 ? etiqueta.slice(dosPuntos + 1) : etiqueta;
    return {
        secreto: base32ABytes(parametros.secret ?? ''),
        algoritmo,
        digitos,
        periodo,
        emisor: (parametros.issuer ?? '').trim() || emisorEtiqueta.trim(),
        cuenta: cuenta.trim()
    };
}
/** Segundos que le quedan de vida al código actual. */
export function segundosRestantesTotp(config, ahoraMs = Date.now()) {
    const segundos = Math.floor(ahoraMs / 1000);
    return config.periodo - (segundos % config.periodo);
}
/** El código vigente en `ahoraMs`, como texto con ceros a la izquierda. */
export async function codigoTotp(config, ahoraMs = Date.now()) {
    const sutil = globalThis.crypto?.subtle;
    if (!sutil)
        throw new Error('Este entorno no tiene WebCrypto para calcular el código.');
    const contador = Math.floor(Math.floor(ahoraMs / 1000) / config.periodo);
    const mensaje = new Uint8Array(8);
    const vista = new DataView(mensaje.buffer);
    // Contador de 64 bits en big-endian; en JavaScript los desplazamientos son de
    // 32 bits, así que la parte alta se calcula dividiendo.
    vista.setUint32(0, Math.floor(contador / 0x100000000));
    vista.setUint32(4, contador >>> 0);
    const clave = await sutil.importKey('raw', config.secreto, { name: 'HMAC', hash: config.algoritmo }, false, ['sign']);
    const mac = new Uint8Array(await sutil.sign('HMAC', clave, mensaje));
    const desplazamiento = mac[mac.length - 1] & 0x0f;
    const binario = ((mac[desplazamiento] & 0x7f) << 24) |
        (mac[desplazamiento + 1] << 16) |
        (mac[desplazamiento + 2] << 8) |
        mac[desplazamiento + 3];
    return String(binario % 10 ** config.digitos).padStart(config.digitos, '0');
}
