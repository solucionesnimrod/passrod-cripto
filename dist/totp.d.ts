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
export type AlgoritmoTotp = 'SHA-1' | 'SHA-256' | 'SHA-512';
export interface ConfigTotp {
    secreto: Uint8Array;
    algoritmo: AlgoritmoTotp;
    digitos: number;
    periodo: number;
    /** Quién emite el código («GitHub»), o cadena vacía. */
    emisor: string;
    /** La cuenta a la que pertenece («ana@correo.com»), o cadena vacía. */
    cuenta: string;
}
/** El texto no es un TOTP que se pueda usar. El mensaje va dirigido al usuario. */
export declare class TotpInvalido extends Error {
    constructor(mensaje: string);
}
/** Base32 tal como lo escriben las personas: sin relleno, con espacios o guiones. */
export declare function base32ABytes(texto: string): Uint8Array;
/** Lee una URI `otpauth://totp/...` o un secreto base32 suelto. */
export declare function leerTotp(texto: string): ConfigTotp;
/** Segundos que le quedan de vida al código actual. */
export declare function segundosRestantesTotp(config: ConfigTotp, ahoraMs?: number): number;
/** El código vigente en `ahoraMs`, como texto con ceros a la izquierda. */
export declare function codigoTotp(config: ConfigTotp, ahoraMs?: number): Promise<string>;
