"""
Genera el banco de vectores del esquema criptografico de PassRod v2.

Este archivo es la IMPLEMENTACION DE REFERENCIA. Las de TypeScript, Java y
Kotlin deben reproducir estos mismos bytes; si alguna diverge, una boveda
cifrada en un cliente no se abrira en otro.

Todo valor aleatorio esta FIJADO a proposito: un banco de pruebas con azar no
sirve para comparar implementaciones. En produccion el nonce y las claves de
boveda son aleatorios; aqui son constantes conocidas.

Ejecutar:  python generar_vectores.py
Salida:    vectores.json
"""
import base64
import hashlib
import hmac
import json
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION_ESQUEMA = 2

# ── Parametros del esquema (§2 de la especificacion) ────────────────────────
ARGON2 = {"m": 65536, "t": 3, "p": 4, "len": 32}     # m en KiB = 64 MiB
PBKDF2_ITER = 600_000
INFO_ENC = b"passrod.v2.enc"
INFO_AUTH = b"passrod.v2.auth"
INFO_RECOVERY = b"passrod.v2.recovery"
PREFIJO_SALT = "passrod.v2|"
PREFIJO_AAD = "passrod.v2|"

ALG_AES_GCM = 0x01


def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()


# ── Derivacion ──────────────────────────────────────────────────────────────

def salt_de(email: str) -> bytes:
    """El salt se deriva del correo, no de un aleatorio del servidor: asi el
    cliente puede derivar MK antes de la primera peticion."""
    return hashlib.sha256((PREFIJO_SALT + email.strip().lower()).encode()).digest()


def derivar_mk_argon2(password: str, email: str) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt_de(email),
        time_cost=ARGON2["t"],
        memory_cost=ARGON2["m"],
        parallelism=ARGON2["p"],
        hash_len=ARGON2["len"],
        type=Type.ID)


def derivar_mk_pbkdf2(password: str, email: str) -> bytes:
    """Alternativa nativa en las cuatro plataformas, sin dependencias."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               salt_de(email), PBKDF2_ITER, 32)


def hkdf(ikm: bytes, info: bytes, largo: int = 32) -> bytes:
    """HKDF-SHA256 con salt vacio (RFC 5869)."""
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm, bloque, contador = b"", b"", 1
    while len(okm) < largo:
        bloque = hmac.new(prk, bloque + info + bytes([contador]), hashlib.sha256).digest()
        okm += bloque
        contador += 1
    return okm[:largo]


# ── Formato de blob ─────────────────────────────────────────────────────────

def aad_de(tipo: str, id_recurso, id_boveda) -> bytes:
    """Ata cada blob a su ubicacion: mover el ciphertext a otra fila o a otra
    boveda hace que el descifrado falle."""
    return f"{PREFIJO_AAD}{tipo}|{id_recurso}|{id_boveda}".encode()


def cifrar(clave: bytes, plano: bytes, aad: bytes, nonce: bytes) -> str:
    cuerpo = AESGCM(clave).encrypt(nonce, plano, aad)
    return b64(bytes([VERSION_ESQUEMA, ALG_AES_GCM]) + nonce + cuerpo)


# ── Compartir bovedas: RSA-2048-OAEP-SHA256 (§2.2 y §2.3) ──────────────────
#
# Se elige RSA y no X25519 porque WebCrypto, Java y Android lo traen de serie:
# X25519 en WebCrypto es reciente y de disponibilidad desigual.
#
# OJO: el relleno de OAEP es ALEATORIO, asi que el ciphertext NO es
# determinista y no se puede comparar byte a byte entre implementaciones. Por
# eso los vectores de RSA van en direccion de DESCIFRADO: se fija un par de
# claves y un ciphertext conocidos, y cada implementacion debe abrirlo y
# obtener el mismo resultado.

OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None)


def envolver_asimetrico(pub, vk: bytes) -> bytes:
    """Envuelve la clave de boveda con la clave publica del invitado.

    Es lo que permite compartir sin que el servidor participe: el duenyo cifra
    VK para el invitado y el servidor solo transporta el resultado.
    """
    return pub.encrypt(vk, OAEP)


def abrir_asimetrico(priv, envuelta: bytes) -> bytes:
    return priv.decrypt(envuelta, OAEP)


def descifrar(clave: bytes, blob: str, aad: bytes) -> bytes:
    crudo = base64.b64decode(blob)
    ver, alg = crudo[0], crudo[1]
    if ver != VERSION_ESQUEMA:
        raise ValueError(f"version de blob no soportada: {ver}")
    if alg != ALG_AES_GCM:
        raise ValueError(f"algoritmo no soportado: {alg}")
    return AESGCM(clave).decrypt(crudo[2:14], crudo[14:], aad)


# ── Banco de vectores ───────────────────────────────────────────────────────

def construir():
    # Valores fijos: sin esto no se pueden comparar implementaciones.
    password = "Contraseña-Maestra-2026!"      # con tilde y ñ a proposito: UTF-8
    email = "  Ana.Perez@Ejemplo.EC  "         # con espacios y mayusculas: se normaliza
    nonce = bytes(range(12))                    # 000102...0b
    vk = bytes([0xA5] * 32)                     # clave de boveda
    codigo_recuperacion = "JBSWY3DPEHPK3PXPJBSWY3DPEH"

    salt = salt_de(email)
    mk_argon = derivar_mk_argon2(password, email)
    mk_pbkdf2 = derivar_mk_pbkdf2(password, email)

    vectores = {
        "_descripcion": "Banco de vectores del esquema criptografico de PassRod v2. "
                        "Cada implementacion (TypeScript, Java, Kotlin) debe reproducir "
                        "EXACTAMENTE estos valores. La referencia es generar_vectores.py.",
        "version_esquema": VERSION_ESQUEMA,
        "parametros": {
            "argon2id": ARGON2,
            "pbkdf2_iteraciones": PBKDF2_ITER,
            "info_enc": INFO_ENC.decode(),
            "info_auth": INFO_AUTH.decode(),
            "info_recovery": INFO_RECOVERY.decode(),
            "prefijo_salt": PREFIJO_SALT,
            "prefijo_aad": PREFIJO_AAD,
            "alg_aes_gcm": ALG_AES_GCM,
        },
        "entradas": {
            "password": password,
            "email": email,
            "email_normalizado": email.strip().lower(),
            "nonce_hex": nonce.hex(),
            "clave_boveda_hex": vk.hex(),
            "codigo_recuperacion": codigo_recuperacion,
        },
        "casos": [],
    }

    def caso(nombre, esperado, nota=""):
        vectores["casos"].append({"nombre": nombre, "esperado": esperado, "nota": nota})

    caso("salt_desde_email", b64(salt),
         "SHA-256('passrod.v2|' + email en minusculas y sin espacios)")

    for etiqueta, mk in (("argon2id", mk_argon), ("pbkdf2", mk_pbkdf2)):
        caso(f"mk_{etiqueta}", b64(mk), f"clave maestra derivada con {etiqueta}")
        caso(f"sk_{etiqueta}", b64(hkdf(mk, INFO_ENC)), "HKDF con info passrod.v2.enc")
        caso(f"authkey_{etiqueta}", b64(hkdf(mk, INFO_AUTH)), "HKDF con info passrod.v2.auth")

    # A partir de aqui se usa PBKDF2 como base, por ser el nativo en todas las
    # plataformas; el formato de blob no depende del KDF.
    sk = hkdf(mk_pbkdf2, INFO_ENC)

    aad_cred = aad_de("credencial", 42, 7)
    caso("aad_credencial", b64(aad_cred), "passrod.v2|credencial|42|7")

    contenido = json.dumps({
        "nombre": "Banco Pichincha",
        "usuario": "ana.perez",
        "clave": "S3cr3t@2026",
        "url": "https://banco.example.ec",
        "notas": "cuenta de ahorros — ñandú",
    }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    caso("credencial_json_utf8_b64", b64(contenido),
         "el JSON exacto que se cifra, para descartar diferencias de serializacion")

    blob_cred = cifrar(vk, contenido, aad_cred, nonce)
    caso("blob_credencial", blob_cred,
         "AES-256-GCM con la clave de boveda; formato VER|ALG|NONCE|CT+TAG")

    # la envoltura de la clave de boveda con SK
    aad_vk = aad_de("clave_boveda", 7, 7)
    caso("aad_clave_boveda", b64(aad_vk), "passrod.v2|clave_boveda|7|7")
    caso("wrap_clave_boveda", cifrar(sk, vk, aad_vk, nonce),
         "la clave de boveda envuelta con SK; esto es lo que guarda el servidor")

    # recuperacion
    rk = hkdf(codigo_recuperacion.encode(), INFO_RECOVERY)
    caso("recovery_key", b64(rk), "HKDF del codigo de recuperacion")
    aad_rec = aad_de("recovery", 0, 0)
    caso("recovery_blob", cifrar(rk, mk_pbkdf2, aad_rec, nonce),
         "MK envuelta con la clave de recuperacion")

    # ── Compartir bovedas ───────────────────────────────────────────────────
    # Par de claves FIJO, generado una vez y guardado aqui. Es material de
    # PRUEBA y no debe usarse jamas en produccion, donde cada usuario genera el
    # suyo en el registro y nunca sale de su equipo sin envolver.
    priv = cargar_o_crear_par()
    pub = priv.public_key()

    pub_spki = pub.public_bytes(serialization.Encoding.DER,
                                serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_pkcs8 = priv.private_bytes(serialization.Encoding.DER,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())

    vectores["entradas"]["rsa_publica_spki_b64"] = b64(pub_spki)
    vectores["entradas"]["rsa_privada_pkcs8_b64"] = b64(priv_pkcs8)
    vectores["entradas"]["_aviso_rsa"] = (
        "Par de claves de PRUEBA. Sirve para verificar implementaciones; nunca "
        "debe usarse en produccion.")

    # La clave privada viaja al servidor ENVUELTA con SK: el servidor la guarda
    # pero no puede abrirla.
    aad_priv = aad_de("clave_privada", 0, 0)
    caso("aad_clave_privada", b64(aad_priv), "passrod.v2|clave_privada|0|0")
    caso("priv_envuelta", cifrar(sk, priv_pkcs8, aad_priv, nonce),
         "la clave privada RSA envuelta con SK; esto es lo que guarda el servidor")

    # Ciphertext RSA fijo para que las otras implementaciones lo DESCIFREN.
    # No se compara el cifrado porque OAEP usa relleno aleatorio.
    envuelta = envolver_asimetrico(pub, vk)
    vectores["entradas"]["wrap_asimetrico_b64"] = b64(envuelta)
    caso("abrir_wrap_asimetrico", b64(vk),
         "descifrar entradas.wrap_asimetrico_b64 con la privada debe dar la clave de boveda")

    # comprobacion negativa: una AAD distinta debe hacer fallar el descifrado
    try:
        descifrar(vk, blob_cred, aad_de("credencial", 43, 7))
        estado = "NO FALLO — el formato no esta atando el blob a su ubicacion"
    except Exception:
        estado = "falla como debe"
    caso("aad_incorrecta_debe_fallar", estado,
         "descifrar el mismo blob con id_recurso 43 en vez de 42 debe fallar")

    return vectores


def cargar_o_crear_par():
    """Par RSA estable entre ejecuciones.

    Si se generara uno nuevo cada vez, los vectores cambiarian en cada
    ejecucion y dejarian de servir para comparar implementaciones.
    """
    ruta = os.path.join(os.path.dirname(os.path.abspath(__file__)), "par_rsa_pruebas.pem")
    if os.path.exists(ruta):
        with open(ruta, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(ruta, "wb") as f:
        f.write(priv.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    print(f"par RSA de pruebas creado en {ruta}")
    return priv


if __name__ == "__main__":
    v = construir()
    destino = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectores.json")
    with open(destino, "w", encoding="utf-8") as f:
        json.dump(v, f, ensure_ascii=False, indent=2)

    print(f"{len(v['casos'])} vectores escritos en {destino}\n")
    for c in v["casos"]:
        valor = c["esperado"]
        print(f"  {c['nombre']:<28} {valor[:52]}{'...' if len(valor) > 52 else ''}")
