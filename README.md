# passrod-cripto — núcleo criptográfico de PassRod v2

Implementación del esquema de conocimiento cero descrito en la especificación
`docs/passrod-cifrado-v2.html`, §2.

El servidor **no puede leer las bóvedas**. Todo el material sensible se deriva y
se usa en el cliente; al servidor solo llegan `auth_hash` y blobs opacos.

## Por qué existe esta carpeta

El esquema tiene que implementarse una vez por plataforma —web, escritorio,
móvil— y las tres deben producir **exactamente los mismos bytes**. Si una diverge,
una bóveda cifrada desde la web no se abrirá desde el escritorio, y el usuario
pierde sus contraseñas sin que nadie se entere hasta que es tarde.

Por eso el banco de vectores es la pieza central, no un extra: es el contrato
que las tres firman.

```
passrod-cripto/
├── vectores/
│   ├── generar_vectores.py   ← IMPLEMENTACIÓN DE REFERENCIA
│   └── vectores.json         ← el contrato: 15 valores esperados
├── typescript/
│   ├── passrodCripto.ts      ← para visual-gestion-claves y la extensión
│   └── verificar.mjs
├── java/
│   ├── PassrodCripto.java    ← para desktop-passrod; base directa para Android
│   └── VerificarVectores.java
└── verificar_todo.py         ← ejecuta todo, incluida la prueba cruzada
```

## Verificar

```bash
python verificar_todo.py
```

Comprueba dos cosas distintas:

1. **Cada implementación contra el banco**, para detectar que una se desvía.
2. **Interoperabilidad cruzada con nonces aleatorios**: Python cifra → Java abre
   → Java cifra → TypeScript abre → TypeScript cifra → Python abre. Esta es la
   que reproduce la situación real, y la que hay que ejecutar antes de tocar
   cualquier cosa del esquema.

## El esquema, en corto

```
salt      = SHA-256("passrod.v2|" + email en minúsculas y sin espacios)
MK        = PBKDF2-SHA256(password, salt, 600 000 iteraciones, 32 B)
SK        = HKDF-SHA256(MK, info="passrod.v2.enc")     ← nunca sale del cliente
AuthKey   = HKDF-SHA256(MK, info="passrod.v2.auth")    ← su base64 es lo único
                                                          que ve el servidor

blob      = base64( VER(1) ‖ ALG(1) ‖ NONCE(12) ‖ CIPHERTEXT‖TAG(16) )
            VER = 0x02   ALG = 0x01 (AES-256-GCM)
AAD       = "passrod.v2|" + tipo + "|" + id_recurso + "|" + id_bóveda
```

Tres decisiones que conviene no revertir sin leer el porqué:

- **El salt sale del correo**, no de un aleatorio del servidor. Así el cliente
  deriva la clave maestra antes de la primera petición y la contraseña nunca
  necesita viajar ni esperar a nadie.
- **El byte de versión va dentro del blob.** El blob viaja entre tablas,
  respaldos y exportaciones; que sea autodescriptivo es lo que permitirá
  descifrarlo dentro de cinco años, y cambiar de algoritmo sin migrar toda la
  base en una sola ventana.
- **La AAD ata el blob a su ubicación.** Alguien con acceso de escritura a la
  base no puede mover el ciphertext de una credencial a otra fila ni de una
  bóveda a otra: el descifrado falla. Hay una prueba dedicada a esto.

## Sobre el KDF: PBKDF2 hoy, Argon2id después

El esquema define **Argon2id** (m=64 MiB, t=3, p=4) como algoritmo preferido, y
el banco de vectores incluye sus valores. Pero las implementaciones usan
**PBKDF2-SHA256 con 600 000 iteraciones**, que es nativo en las cuatro
plataformas: WebCrypto, `javax.crypto`, Android y Python.

Argon2id resiste mejor el ataque con hardware dedicado, pero exige una
dependencia externa en cada plataforma: WASM en el navegador (~300 KB), JNI con
binarios nativos en Java, `argon2kt` en Android. Es una decisión que se puede
tomar más adelante **sin romper a nadie**, porque el usuario guarda su
`kdf_tipo` y `kdf_params`: el cliente lee esos campos antes de derivar.

Es también lo que hace Bitwarden: PBKDF2 por defecto, Argon2id opcional.

Cuando se adopte, los vectores `mk_argon2id`, `sk_argon2id` y `authkey_argon2id`
ya están generados y esperando.

## Al tocar el esquema

1. Cambiar `generar_vectores.py`, que es la referencia.
2. Regenerar `vectores.json`.
3. Actualizar TypeScript y Java hasta que `verificar_todo.py` pase entero.
4. Si cambia el formato del blob, **subir el byte de versión** y dejar que el
   código siga leyendo el anterior. Nunca reinterpretar un blob viejo con reglas
   nuevas.

## Pendiente

- **Kotlin/Android**: la app móvil aún no existe. `PassrodCripto.java` funciona
  tal cual en Android (misma API de JVM), así que servirá de punto de partida.
- **RSA-2048-OAEP** para compartir bóvedas entre usuarios: está especificado en
  §2.2 pero no implementado aquí todavía. Hace falta para `invitar_usuario` y
  `aceptar_invitacion`.
- Integrar en `visual-gestion-claves` y `desktop-passrod`, que hoy siguen
  usando el esquema v1 con cifrado en el servidor.
