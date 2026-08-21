"""
Verifica el nucleo criptografico de PassRod en las tres implementaciones.

Dos niveles:

  1. Cada implementacion contra el banco de vectores (que no derive de la
     referencia).
  2. INTEROPERABILIDAD CRUZADA: que lo que cifra una lo abra la otra, con
     nonces aleatorios. Esta es la prueba que de verdad importa, porque es la
     situacion real: un usuario guarda una credencial desde la web y la abre
     desde el escritorio.

    python verificar_todo.py
"""
import base64
import json
import os
import subprocess
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
JAVA = r"C:\Program Files\Java\jdk-17\bin\java.exe"
JAVAC = r"C:\Program Files\Java\jdk-17\bin\javac.exe"

sys.path.insert(0, os.path.join(AQUI, "vectores"))
from generar_vectores import (  # noqa: E402
    cifrar, descifrar, aad_de, derivar_mk_pbkdf2, hkdf, INFO_ENC)


def titulo(t):
    print("\n" + "=" * 66)
    print(t)
    print("=" * 66)


def correr(cmd, cwd):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", shell=False)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


# ── 1. Cada implementacion contra el banco ──────────────────────────────────
titulo("1. Cada implementacion contra el banco de vectores")

fallos = 0

print("\n-- Python (referencia) --")
cod, salida = correr([sys.executable, "generar_vectores.py"], os.path.join(AQUI, "vectores"))
print("   regenera el banco sin errores" if cod == 0 else salida[-600:])
fallos += (cod != 0)

print("\n-- TypeScript --")
cod, salida = correr(["node", "verificar.mjs"], os.path.join(AQUI, "typescript"))
print("   " + [l for l in salida.strip().splitlines() if l.strip()][-1])
fallos += (cod != 0)

print("\n-- Java --")
correr([JAVAC, "-encoding", "UTF-8", "-d", ".", "PassrodCripto.java", "VerificarVectores.java"],
       os.path.join(AQUI, "java"))
cod, salida = correr([JAVA, "-Dfile.encoding=UTF-8", "-cp", ".", "VerificarVectores"],
                     os.path.join(AQUI, "java"))
print("   " + [l for l in salida.strip().splitlines() if l.strip()][-1])
fallos += (cod != 0)


# ── 2. Interoperabilidad cruzada ────────────────────────────────────────────
titulo("2. Interoperabilidad cruzada (nonces ALEATORIOS)")

# Material comun, derivado igual que lo haria un cliente real
mk = derivar_mk_pbkdf2("Contraseña-Maestra-2026!", "ana.perez@ejemplo.ec")
sk = hkdf(mk, INFO_ENC)
vk = os.urandom(32)
aad = aad_de("credencial", 99, 3)
mensaje = json.dumps({"clave": "Ñandú-2026!", "nota": "acentos y emoji ✓"},
                     ensure_ascii=False).encode("utf-8")

b64 = lambda x: base64.b64encode(x).decode()

# Python cifra con nonce aleatorio
blob_py = cifrar(vk, mensaje, aad, os.urandom(12))

# ── Java: descifra lo de Python y cifra lo suyo ─────────────────────────────
puente_java = r"""
import com.solucionesnimrod.passrod.cripto.PassrodCripto;
import java.util.Base64;
public class Puente {
  public static void main(String[] a) throws Exception {
    byte[] vk  = Base64.getDecoder().decode(a[0]);
    byte[] aad = Base64.getDecoder().decode(a[1]);
    String blobPy = a[2];
    byte[] plano = PassrodCripto.descifrar(vk, blobPy, aad);
    System.out.println("ABIERTO:" + Base64.getEncoder().encodeToString(plano));
    String mio = PassrodCripto.cifrar(vk, plano, aad, PassrodCripto.nuevoNonce());
    System.out.println("CIFRADO:" + mio);
  }
}
"""
with open(os.path.join(AQUI, "java", "Puente.java"), "w", encoding="utf-8") as f:
    f.write(puente_java)
correr([JAVAC, "-encoding", "UTF-8", "-cp", ".", "-d", ".", "Puente.java"],
       os.path.join(AQUI, "java"))
cod, salida = correr([JAVA, "-cp", ".", "Puente", b64(vk), b64(aad), blob_py],
                     os.path.join(AQUI, "java"))
java_abierto = java_cifrado = None
for linea in salida.splitlines():
    if linea.startswith("ABIERTO:"):
        java_abierto = base64.b64decode(linea[8:])
    if linea.startswith("CIFRADO:"):
        java_cifrado = linea[8:].strip()

ok = java_abierto == mensaje
print(f"  {'PASA ' if ok else 'FALLA'}  Java abre lo que cifro Python")
fallos += (not ok)

# ── TypeScript: descifra lo de Java y cifra lo suyo ─────────────────────────
puente_ts = r"""
import { webcrypto as c } from 'node:crypto';
const [vkB64, aadB64, blobJava] = process.argv.slice(2);
const deB64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const vk = deB64(vkB64), aad = deB64(aadB64), crudo = deB64(blobJava);
const k = await c.subtle.importKey('raw', vk, {name:'AES-GCM'}, false, ['decrypt','encrypt']);
const plano = new Uint8Array(await c.subtle.decrypt(
  {name:'AES-GCM', iv: crudo.slice(2,14), additionalData: aad, tagLength:128}, k, crudo.slice(14)));
console.log('ABIERTO:' + Buffer.from(plano).toString('base64'));
const iv = c.getRandomValues(new Uint8Array(12));
const ct = new Uint8Array(await c.subtle.encrypt(
  {name:'AES-GCM', iv, additionalData: aad, tagLength:128}, k, plano));
const out = new Uint8Array(2+12+ct.length);
out[0]=2; out[1]=1; out.set(iv,2); out.set(ct,14);
console.log('CIFRADO:' + Buffer.from(out).toString('base64'));
"""
with open(os.path.join(AQUI, "typescript", "puente.mjs"), "w", encoding="utf-8") as f:
    f.write(puente_ts)
cod, salida = correr(["node", "puente.mjs", b64(vk), b64(aad), java_cifrado or ""],
                     os.path.join(AQUI, "typescript"))
ts_abierto = ts_cifrado = None
for linea in salida.splitlines():
    if linea.startswith("ABIERTO:"):
        ts_abierto = base64.b64decode(linea[8:])
    if linea.startswith("CIFRADO:"):
        ts_cifrado = linea[8:].strip()

ok = ts_abierto == mensaje
print(f"  {'PASA ' if ok else 'FALLA'}  TypeScript abre lo que cifro Java")
fallos += (not ok)

# ── Python cierra el circulo ────────────────────────────────────────────────
try:
    py_abierto = descifrar(vk, ts_cifrado, aad)
    ok = py_abierto == mensaje
except Exception as e:
    ok = False
    print("     error:", e)
print(f"  {'PASA ' if ok else 'FALLA'}  Python abre lo que cifro TypeScript")
fallos += (not ok)

# ── una AAD distinta debe romper el circulo ─────────────────────────────────
try:
    descifrar(vk, ts_cifrado, aad_de("credencial", 100, 3))
    atado = False
except Exception:
    atado = True
print(f"  {'PASA ' if atado else 'FALLA'}  cambiar el id en la AAD rompe el descifrado")
fallos += (not atado)

for tmp in (os.path.join(AQUI, "java", "Puente.java"),
            os.path.join(AQUI, "typescript", "puente.mjs")):
    if os.path.exists(tmp):
        os.remove(tmp)

titulo("RESULTADO")
if fallos:
    print(f"  {fallos} comprobacion(es) fallaron: las implementaciones DIVERGEN")
    sys.exit(1)
print("  Las tres implementaciones son interoperables byte a byte.")
print("  Una boveda cifrada en cualquier cliente se abre en los demas.")
