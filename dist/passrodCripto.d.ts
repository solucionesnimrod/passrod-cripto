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
export declare const VERSION_ESQUEMA = 2;
export declare const ALG_AES_GCM = 1;
export declare const PBKDF2_ITERACIONES = 600000;
export declare function aBase64(datos: Uint8Array): string;
export declare function deBase64(texto: string): Uint8Array;
/** Borra un buffer con material sensible. No es infalible en JS, pero acorta
 *  la ventana en que la clave sigue en memoria. */
export declare function limpiar(...buffers: Uint8Array[]): void;
/**
 * Salt determinista a partir del correo.
 *
 * Se deriva del correo y no de un aleatorio del servidor para que el cliente
 * pueda calcular la clave maestra ANTES de la primera petición: así la
 * contraseña nunca necesita viajar ni esperar a nadie.
 */
export declare function saltDesdeEmail(email: string): Promise<Uint8Array>;
/**
 * El correo tal como entra en la sal: NFC, sin espacios y en minúsculas.
 *
 * La NFC importa: macOS e iOS componen los acentos en NFD y Windows en NFC, y
 * sin normalizar el mismo correo daría dos sales —la misma cuenta no abriría en
 * los dos equipos—. `toLowerCase` de JavaScript no depende del idioma, así que
 * aquí no existe la trampa de la «i» turca que sí tiene Java.
 */
export declare function normalizarEmail(email: string): string;
/**
 * Clave maestra con PBKDF2-SHA256.
 *
 * Es el algoritmo por defecto porque WebCrypto lo trae nativo, igual que Java y
 * Android. Argon2id resiste mejor el ataque por hardware dedicado, pero en el
 * navegador exige WASM; el campo `kdf_tipo` del usuario existe precisamente
 * para poder cambiarlo sin romper a quien ya está registrado.
 */
export declare function derivarMK(password: string, email: string): Promise<Uint8Array>;
/** HKDF-SHA256 con salt vacío (RFC 5869). */
export declare function hkdf(ikm: Uint8Array, info: string, largo?: number): Promise<Uint8Array>;
/** Clave de cifrado: nunca sale del cliente. */
export declare const derivarSK: (mk: Uint8Array) => Promise<Uint8Array<ArrayBufferLike>>;
/** Clave de autenticación: su base64 es lo ÚNICO que se envía al servidor. */
export declare const derivarAuthKey: (mk: Uint8Array) => Promise<Uint8Array<ArrayBufferLike>>;
export declare function authHash(password: string, email: string): Promise<string>;
/**
 * Datos autenticados asociados: atan el blob a su ubicación exacta.
 *
 * Sin esto, alguien con acceso de escritura a la base podría mover el
 * ciphertext de una credencial a otra fila, o de una bóveda a otra, y el
 * descifrado seguiría funcionando.
 */
export declare function construirAAD(tipo: string, idRecurso: string | number, idBoveda: string | number): Uint8Array;
/** base64( VER(1) ‖ ALG(1) ‖ NONCE(12) ‖ CIPHERTEXT‖TAG(16) ) */
export declare function cifrar(clave: Uint8Array, plano: Uint8Array, aad: Uint8Array, nonce?: Uint8Array): Promise<string>;
export declare function descifrar(clave: Uint8Array, blob: string, aad: Uint8Array): Promise<Uint8Array>;
export declare const cifrarCredencial: (vk: Uint8Array, credencial: unknown, idCredencial: string | number, idBoveda: string | number, nonce?: Uint8Array) => Promise<string>;
export declare function descifrarCredencial<T>(vk: Uint8Array, blob: string, idCredencial: string | number, idBoveda: string | number): Promise<T>;
/** Clave de bóveda nueva. Aleatoria de verdad: nunca derivarla de nada. */
export declare const nuevaClaveBoveda: () => Uint8Array<ArrayBuffer>;
export declare const envolverClaveBoveda: (sk: Uint8Array, vk: Uint8Array, idBoveda: string | number, nonce?: Uint8Array) => Promise<string>;
export declare const abrirClaveBoveda: (sk: Uint8Array, envuelta: string, idBoveda: string | number) => Promise<Uint8Array<ArrayBufferLike>>;
export interface ParDeClaves {
    publicaSpki: Uint8Array;
    privadaPkcs8: Uint8Array;
}
/** Par de claves del usuario. Se genera una vez, en el registro. */
export declare function generarParDeClaves(): Promise<ParDeClaves>;
/** Por debajo de esto una clave RSA no protege nada: se rechaza al envolver. */
export declare const MIN_BITS_RSA = 2048;
/**
 * Envuelve la clave de bóveda para otro usuario, usando su clave pública.
 *
 * Esto es lo que permite compartir sin que el servidor participe: el dueño
 * cifra VK para el invitado y el servidor solo transporta el resultado.
 *
 * La clave pública la entrega el servidor, así que se comprueba su tamaño: uno
 * malicioso podría entregar una de 512 bits, que se factoriza en horas.
 */
export declare function envolverParaUsuario(publicaSpki: Uint8Array, vk: Uint8Array): Promise<string>;
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
export declare function huella(publicaSpki: Uint8Array): Promise<string>;
/** Lo que se firma: ata la envoltura a su bóveda y a su destinatario. */
export declare function mensajeEnvoltura(idBoveda: string | number, idDestinatario: string | number, claveEnvuelta: string): Uint8Array;
export declare function firmarEnvoltura(privadaPkcs8: Uint8Array, idBoveda: string | number, idDestinatario: string | number, claveEnvuelta: string): Promise<string>;
/** true solo si la firma es de la privada de `publicaSpki` y para ESA bóveda y ESE destinatario. */
export declare function verificarEnvoltura(publicaSpki: Uint8Array, idBoveda: string | number, idDestinatario: string | number, claveEnvuelta: string, firmaB64: string): Promise<boolean>;
/** Abre una clave de bóveda que envolvieron para mí. */
export declare function abrirConPrivada(privadaPkcs8: Uint8Array, envuelta: string): Promise<Uint8Array>;
/** La privada nunca llega al servidor sin envolver. */
export declare const envolverClavePrivada: (sk: Uint8Array, privadaPkcs8: Uint8Array, nonce?: Uint8Array) => Promise<string>;
export declare const abrirClavePrivada: (sk: Uint8Array, envuelta: string) => Promise<Uint8Array<ArrayBufferLike>>;
export declare const claveDeRecuperacion: (codigo: string) => Promise<Uint8Array<ArrayBufferLike>>;
/** Sin I, L, O, 0 ni 1: el código se apunta en papel y se confunden al leer. */
export declare const ALFABETO_CODIGO = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
/**
 * Código de recuperación nuevo: 25 caracteres en cinco grupos (~124 bits).
 *
 * Vive aquí para que todos los clientes lo generen igual. Se descartan los
 * bytes que no caben en un múltiplo de 31: con un simple `% 31`, ocho letras
 * salían un 12 % más a menudo que las demás.
 */
export declare function nuevoCodigoRecuperacion(): string;
/** Forma canónica de un código tecleado: sin espacios ni guiones, en grupos de 5. */
export declare function normalizarCodigoRecuperacion(codigo: string): string;
/** AAD del blob de recuperación: lo ata a SU cuenta (antes era recovery|0|0 para todas). */
export declare const aadRecuperacion: (email: string) => Uint8Array<ArrayBufferLike>;
/** Envuelve MK con el código, atada al correo. El código se normaliza aquí. */
export declare function envolverRecuperacion(codigo: string, mk: Uint8Array, email: string, nonce?: Uint8Array): Promise<string>;
/**
 * Abre el blob de recuperación. Acepta también el formato anterior a la v2.2.0
 * (AAD `recovery|0|0`), para no dejar sin salida a quien lo guardó antes.
 */
export declare function abrirRecuperacion(codigo: string, blob: string, email: string): Promise<Uint8Array>;
export declare function envolverParaRecuperacion(codigo: string, mk: Uint8Array, nonce?: Uint8Array): Promise<string>;
export declare function recuperarMK(codigo: string, blob: string): Promise<Uint8Array>;
export * from './totp.js';
