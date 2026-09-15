"""
Banco de vectores del doble factor (TOTP, RFC 6238) — IMPLEMENTACION DE REFERENCIA.

Igual que generar_vectores.py para el cifrado: esto es el contrato que firman
TypeScript (web y extension) y Java (escritorio). Si un cliente calcula otro
codigo que los demas, el usuario ve un codigo que el sitio rechaza y no sabe
por que.

Solo usa la biblioteca estandar de Python (hmac, hashlib, base64), a proposito:
asi la referencia no depende de nada que pueda tener el mismo fallo que los
clientes.

    python vectores/generar_vectores_totp.py
"""
import base64
import hashlib
import hmac
import json
import os
import struct
from urllib.parse import parse_qs, quote, unquote, urlparse

AQUI = os.path.dirname(os.path.abspath(__file__))

ALGORITMOS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


class TotpInvalido(Exception):
    pass


def base32_a_bytes(texto: str) -> bytes:
    """Como lo escriben las personas: minusculas, espacios, guiones y sin relleno."""
    limpio = "".join(texto.split()).replace("-", "").upper().rstrip("=")
    if not limpio:
        raise TotpInvalido("secreto vacio")
    if any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in limpio):
        raise TotpInvalido("caracter no valido en base32")
    relleno = "=" * (-len(limpio) % 8)
    return base64.b32decode(limpio + relleno)


def leer_totp(texto: str) -> dict:
    texto = (texto or "").strip()
    if not texto.lower().startswith("otpauth://"):
        return {"secreto": base32_a_bytes(texto), "algoritmo": "SHA1", "digitos": 6,
                "periodo": 30, "emisor": "", "cuenta": ""}

    u = urlparse(texto)
    if u.netloc.lower() != "totp":
        raise TotpInvalido("solo TOTP")
    q = {k.lower(): v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
    etiqueta = unquote(u.path.lstrip("/"))
    emisor_etiqueta, _, cuenta = etiqueta.rpartition(":")
    if not _:
        emisor_etiqueta, cuenta = "", etiqueta

    algoritmo = q.get("algorithm", "SHA1").upper().replace("-", "")
    if algoritmo not in ALGORITMOS:
        raise TotpInvalido("algoritmo no admitido")
    try:
        digitos = int(q.get("digits", "6"))
        periodo = int(q.get("period", "30"))
    except ValueError:
        raise TotpInvalido("digitos o periodo no numericos")
    if not 6 <= digitos <= 8:
        raise TotpInvalido("digitos fuera de rango")
    if not 1 <= periodo <= 3600:
        raise TotpInvalido("periodo fuera de rango")

    return {"secreto": base32_a_bytes(q.get("secret", "")), "algoritmo": algoritmo,
            "digitos": digitos, "periodo": periodo,
            "emisor": q.get("issuer", "").strip() or emisor_etiqueta.strip(),
            "cuenta": cuenta.strip()}


def codigo_totp(cfg: dict, segundos_unix: int) -> str:
    contador = segundos_unix // cfg["periodo"]
    mac = hmac.new(cfg["secreto"], struct.pack(">Q", contador), ALGORITMOS[cfg["algoritmo"]]).digest()
    desplazamiento = mac[-1] & 0x0F
    binario = struct.unpack(">I", mac[desplazamiento:desplazamiento + 4])[0] & 0x7FFFFFFF
    return str(binario % (10 ** cfg["digitos"])).zfill(cfg["digitos"])


def b32(b: bytes) -> str:
    return base64.b32encode(b).decode().rstrip("=")


def construir():
    casos = []

    # RFC 6238, apendice B: las semillas son ASCII y cada algoritmo usa la suya.
    semillas = {
        "SHA1": b"12345678901234567890",
        "SHA256": b"12345678901234567890123456789012",
        "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",
    }
    rfc = {  # tiempo -> (SHA1, SHA256, SHA512), copiados de la RFC
        59: ("94287082", "46119246", "90693936"),
        1111111109: ("07081804", "68084774", "25091201"),
        1111111111: ("14050471", "67062674", "99943326"),
        1234567890: ("89005924", "91819424", "93441116"),
        2000000000: ("69279037", "90698825", "38618901"),
        20000000000: ("65353130", "77737706", "47863826"),
    }
    for tiempo, codigos in rfc.items():
        for algoritmo, esperado_rfc in zip(("SHA1", "SHA256", "SHA512"), codigos):
            entrada = (f"otpauth://totp/RFC6238?secret={b32(semillas[algoritmo])}"
                       f"&algorithm={algoritmo}&digits=8&period=30")
            obtenido = codigo_totp(leer_totp(entrada), tiempo)
            # Si la referencia no reproduce la RFC, el banco entero no vale.
            assert obtenido == esperado_rfc, (algoritmo, tiempo, obtenido, esperado_rfc)
            casos.append({"nombre": f"rfc6238_{algoritmo.lower()}_{tiempo}",
                          "entrada": entrada, "tiempo": tiempo, "esperado": obtenido})

    secreto = "JBSWY3DPEHPK3PXP"
    variantes = [
        ("secreto_solo", secreto, 1789467000),
        ("secreto_minusculas_espacios", "jbsw y3dp ehpk 3pxp", 1789467000),
        ("secreto_con_relleno", secreto + "======", 1789467000),
        ("uri_minima", f"otpauth://totp/Ejemplo?secret={secreto}", 1789467000),
        ("uri_periodo_60_6_digitos", f"otpauth://totp/X?secret={secreto}&period=60", 1789467059),
        ("uri_algoritmo_minusculas", f"otpauth://totp/X?secret={secreto}&algorithm=sha256", 1789467000),
        ("uri_parametros_mayusculas", f"otpauth://TOTP/X?SECRET={secreto}&DIGITS=7", 1789467000),
        ("uri_limite_de_periodo", f"otpauth://totp/X?secret={secreto}", 1789467029),
        ("uri_siguiente_periodo", f"otpauth://totp/X?secret={secreto}", 1789467030),
        # Contador por encima de 2^32: obliga a usar los 64 bits del contador.
        ("contador_de_64_bits", secreto, (2 ** 32) * 30 + 59),
    ]
    for nombre, entrada, tiempo in variantes:
        casos.append({"nombre": nombre, "entrada": entrada, "tiempo": tiempo,
                      "esperado": codigo_totp(leer_totp(entrada), tiempo)})

    etiquetas = []
    for nombre, entrada in [
        ("etiqueta_emisor_y_cuenta",
         f"otpauth://totp/GitHub:ana%40correo.com?secret={secreto}&issuer=GitHub"),
        ("etiqueta_issuer_manda",
         f"otpauth://totp/Viejo:ana?secret={secreto}&issuer={quote('Nuevo Nombre')}"),
        ("etiqueta_sin_emisor", f"otpauth://totp/ana%40correo.com?secret={secreto}"),
        ("etiqueta_espacio_tras_dos_puntos",
         f"otpauth://totp/{quote('Banco: ana')}?secret={secreto}"),
    ]:
        cfg = leer_totp(entrada)
        etiquetas.append({"nombre": nombre, "entrada": entrada,
                          "emisor": cfg["emisor"], "cuenta": cfg["cuenta"]})

    invalidos = [
        ("vacio", ""),
        ("hotp", f"otpauth://hotp/X?secret={secreto}&counter=0"),
        ("sin_secreto", "otpauth://totp/X?issuer=Y"),
        ("base32_con_caracter_1", "JBSWY3DPEHPK3PX1"),
        ("algoritmo_desconocido", f"otpauth://totp/X?secret={secreto}&algorithm=MD5"),
        ("cinco_digitos", f"otpauth://totp/X?secret={secreto}&digits=5"),
        ("nueve_digitos", f"otpauth://totp/X?secret={secreto}&digits=9"),
        ("periodo_cero", f"otpauth://totp/X?secret={secreto}&period=0"),
        ("digitos_no_numericos", f"otpauth://totp/X?secret={secreto}&digits=seis"),
        ("otra_url", "https://github.com/login"),
    ]
    rechazos = []
    for nombre, entrada in invalidos:
        try:
            leer_totp(entrada)
        except TotpInvalido:
            rechazos.append({"nombre": nombre, "entrada": entrada})
            continue
        raise AssertionError(f"la referencia acepta una entrada invalida: {nombre}")

    return {
        "descripcion": "TOTP (RFC 6238) de PassRod. Generado por generar_vectores_totp.py; no editar a mano.",
        "codigos": casos,
        "etiquetas": etiquetas,
        "invalidos": rechazos,
    }


if __name__ == "__main__":
    v = construir()
    with open(os.path.join(AQUI, "vectores_totp.json"), "w", encoding="utf-8") as f:
        json.dump(v, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"{len(v['codigos'])} codigos, {len(v['etiquetas'])} etiquetas, "
          f"{len(v['invalidos'])} invalidos -> vectores_totp.json")
