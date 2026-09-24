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
import unicodedata

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

def nfc(texto: str) -> str:
    return unicodedata.normalize("NFC", texto)


def normalizar_email(email: str) -> str:
    """NFC, sin espacios y en minusculas (independiente del idioma del equipo).

    Sin la NFC, un correo con tilde escrito en macOS (que compone en NFD) y en
    Windows (NFC) daria dos sales distintas: la misma cuenta no abriria."""
    return nfc(email).strip().lower()


def password_utf8(password: str) -> bytes:
    """La contrasena se normaliza a NFC antes de derivar, por el mismo motivo."""
    return nfc(password).encode("utf-8")


def salt_de(email: str) -> bytes:
    """El salt se deriva del correo, no de un aleatorio del servidor: asi el
    cliente puede derivar MK antes de la primera peticion."""
    return hashlib.sha256((PREFIJO_SALT + normalizar_email(email)).encode()).digest()


def derivar_mk_argon2(password: str, email: str) -> bytes:
    return hash_secret_raw(
        secret=password_utf8(password),
        salt=salt_de(email),
        time_cost=ARGON2["t"],
        memory_cost=ARGON2["m"],
        parallelism=ARGON2["p"],
        hash_len=ARGON2["len"],
        type=Type.ID)


def derivar_mk_pbkdf2(password: str, email: str) -> bytes:
    """Alternativa nativa en las cuatro plataformas, sin dependencias."""
    return hashlib.pbkdf2_hmac("sha256", password_utf8(password),
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


# -- Firma de envolturas: RSA-PSS-SHA256 con el MISMO par del usuario --------
#
# Sin firma, cualquiera con la clave publica de alguien -incluido el servidor-
# puede envolverle una clave de boveda que el mismo conoce y hacerla pasar por
# compartida. Firmar con la privada de quien comparte lo impide: el servidor no
# la tiene. Se reutiliza el par RSA-OAEP: OAEP y PSS con la misma clave son
# seguros juntos (Haber y Pinkas, 2001) y asi no hay que repartir otra clave.

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
MIN_BITS_RSA = 2048


def mensaje_envoltura(id_boveda, id_destinatario, clave_envuelta: str) -> bytes:
    return f"{PREFIJO_AAD}compartir|{id_boveda}|{id_destinatario}|{clave_envuelta}".encode()


def firmar_envoltura(priv, id_boveda, id_destinatario, clave_envuelta: str) -> bytes:
    return priv.sign(mensaje_envoltura(id_boveda, id_destinatario, clave_envuelta),
                     PSS, hashes.SHA256())


def verificar_envoltura(pub, id_boveda, id_destinatario, clave_envuelta: str,
                        firma: bytes) -> bool:
    try:
        pub.verify(firma, mensaje_envoltura(id_boveda, id_destinatario, clave_envuelta),
                   PSS, hashes.SHA256())
        return True
    except Exception:
        return False


def huella(pub_spki: bytes) -> str:
    """10 bytes de SHA-256 en cinco grupos: se lee por telefono."""
    h = hashlib.sha256(pub_spki).digest()[:10].hex().upper()
    return "-".join(h[i:i + 4] for i in range(0, 20, 4))


# -- Codigo de recuperacion --------------------------------------------------
ALFABETO_CODIGO = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"   # sin I, L, O, 0, 1


def normalizar_codigo(codigo: str) -> str:
    limpio = "".join(c for c in codigo if c.isascii() and c.isalnum()).upper()
    return "-".join(limpio[i:i + 5] for i in range(0, len(limpio), 5))


def aad_recuperacion(email: str) -> bytes:
    """Ata el blob a su cuenta. Antes era recovery|0|0 para todas."""
    return aad_de("recovery", normalizar_email(email), 0)


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
            "email_normalizado": normalizar_email(email),
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

    # -- v2.2.0 --------------------------------------------------------------
    # Normalizacion: la misma contrasena en NFD (como la compone macOS) debe
    # dar la MISMA clave maestra, y un correo con I mayuscula y tildes en NFD la
    # misma sal que su forma NFC (en Java, con cualquier idioma del equipo).
    password_nfd = unicodedata.normalize("NFD", password)
    assert password_nfd != password
    vectores["entradas"]["password_nfd"] = password_nfd
    caso("mk_pbkdf2_desde_nfd", b64(derivar_mk_pbkdf2(password_nfd, email)),
         "la contrasena en NFD debe dar la misma MK que en NFC (igual a mk_pbkdf2)")
    email_i = unicodedata.normalize("NFD", "  IVÁN.DÍAZ@Ejemplo.EC ")
    vectores["entradas"]["email_con_i_nfd"] = email_i
    caso("email_con_i_normalizado", normalizar_email(email_i),
         "NFC + trim + minusculas SIN idioma: la I da i, nunca la i sin punto turca")
    caso("salt_email_con_i", b64(salt_de(email_i)), "sal del correo anterior")

    # Huella de la clave publica de pruebas
    caso("huella_publica", huella(pub_spki), "10 bytes de SHA-256(SPKI) en grupos de 4 hex")

    # Firma de la envoltura (PSS es aleatorio: se verifica, no se compara)
    firma = firmar_envoltura(priv, 7, 12, b64(envuelta))
    vectores["entradas"]["firma_envoltura_b64"] = b64(firma)
    vectores["entradas"]["firma_envoltura_boveda"] = 7
    vectores["entradas"]["firma_envoltura_destinatario"] = 12
    caso("mensaje_envoltura", b64(mensaje_envoltura(7, 12, b64(envuelta))),
         "passrod.v2|compartir|7|12|<clave_envuelta en base64>")
    caso("verificar_firma_envoltura",
         "valida" if verificar_envoltura(pub, 7, 12, b64(envuelta), firma) else "invalida",
         "la firma de entradas.firma_envoltura_b64 debe verificar con la publica")
    caso("firma_con_otro_destinatario",
         "valida" if verificar_envoltura(pub, 7, 13, b64(envuelta), firma) else "invalida",
         "la misma firma para el destinatario 13 debe ser invalida")

    # RSA de 1024 bits: debe rechazarse al envolver
    corta = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
    vectores["entradas"]["rsa_publica_1024_spki_b64"] = b64(corta.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    caso("rechazar_rsa_1024", "rechaza", "envolver para una publica de 1024 bits debe fallar")

    # Codigo de recuperacion: forma canonica y blob atado al correo
    tecleado = "abcde fghjk-mnpqr  stuvw xyz23"
    vectores["entradas"]["codigo_tecleado"] = tecleado
    codigo_canon = normalizar_codigo(tecleado)
    caso("codigo_normalizado", codigo_canon,
         "sin espacios ni guiones, en mayusculas y en grupos de 5")
    rk2 = hkdf(codigo_canon.encode(), INFO_RECOVERY)
    caso("aad_recuperacion", b64(aad_recuperacion(email)),
         "passrod.v2|recovery|<correo normalizado>|0")
    caso("recovery_blob_atado", cifrar(rk2, mk_pbkdf2, aad_recuperacion(email), nonce),
         "MK envuelta con la clave del codigo canonico y AAD atada al correo")

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
