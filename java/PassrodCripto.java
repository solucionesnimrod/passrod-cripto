package com.solucionesnimrod.passrod.cripto;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Núcleo criptográfico de PassRod v2 — implementación Java.
 *
 * Debe reproducir byte a byte los valores de {@code vectores/vectores.json}. Si
 * diverge de la implementación de TypeScript o Kotlin, una bóveda cifrada en un
 * cliente no se abrirá en otro; por eso los vectores se ejecutan como prueba.
 *
 * Sin dependencias externas: todo sale de la biblioteca estándar de Java.
 */
public final class PassrodCripto {

    public static final int VERSION_ESQUEMA = 2;
    public static final int ALG_AES_GCM = 0x01;
    public static final int PBKDF2_ITERACIONES = 600_000;

    private static final String PREFIJO_SALT = "passrod.v2|";
    private static final String PREFIJO_AAD = "passrod.v2|";
    private static final String INFO_ENC = "passrod.v2.enc";
    private static final String INFO_AUTH = "passrod.v2.auth";
    private static final String INFO_RECOVERY = "passrod.v2.recovery";

    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private static final SecureRandom AZAR = new SecureRandom();

    private PassrodCripto() {}

    // ── Derivación ──────────────────────────────────────────────────────────

    /**
     * Salt determinista a partir del correo.
     *
     * Se deriva del correo y no de un aleatorio del servidor para que el cliente
     * pueda calcular la clave maestra ANTES de la primera petición.
     */
    public static byte[] saltDesdeEmail(String email) throws Exception {
        String normalizado = email.trim().toLowerCase();
        return MessageDigest.getInstance("SHA-256")
                .digest((PREFIJO_SALT + normalizado).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Clave maestra con PBKDF2-SHA256.
     *
     * Se recibe {@code char[]} y no {@code String} a propósito: un String es
     * inmutable y queda en el heap hasta que pase el recolector, con lo que la
     * contraseña maestra puede acabar en un volcado de memoria o en el archivo
     * de intercambio. El array se puede sobrescribir al terminar.
     */
    public static byte[] derivarMK(char[] password, String email) throws Exception {
        byte[] salt = saltDesdeEmail(email);
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERACIONES, 256);
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return f.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    /** HKDF-SHA256 con salt vacío (RFC 5869). */
    public static byte[] hkdf(byte[] ikm, String info, int largo) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");

        // extract
        mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);

        // expand
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        ByteArrayOutputStream salida = new ByteArrayOutputStream();
        byte[] bloque = new byte[0];
        byte[] infoBytes = info.getBytes(StandardCharsets.UTF_8);
        for (int contador = 1; salida.size() < largo; contador++) {
            mac.reset();
            mac.update(bloque);
            mac.update(infoBytes);
            mac.update((byte) contador);
            bloque = mac.doFinal();
            salida.write(bloque, 0, bloque.length);
        }
        return Arrays.copyOf(salida.toByteArray(), largo);
    }

    public static byte[] derivarSK(byte[] mk) throws Exception {
        return hkdf(mk, INFO_ENC, 32);
    }

    public static byte[] derivarAuthKey(byte[] mk) throws Exception {
        return hkdf(mk, INFO_AUTH, 32);
    }

    /** Lo ÚNICO que se envía al servidor para autenticarse. */
    public static String authHash(char[] password, String email) throws Exception {
        byte[] mk = derivarMK(password, email);
        byte[] ak = derivarAuthKey(mk);
        String salida = Base64.getEncoder().encodeToString(ak);
        limpiar(mk, ak);
        return salida;
    }

    // ── Formato de blob ─────────────────────────────────────────────────────

    /**
     * Datos autenticados asociados: atan el blob a su ubicación exacta.
     *
     * Sin esto, alguien con acceso de escritura a la base podría mover el
     * ciphertext de una credencial a otra fila y el descifrado seguiría
     * funcionando.
     */
    public static byte[] construirAAD(String tipo, Object idRecurso, Object idBoveda) {
        return (PREFIJO_AAD + tipo + "|" + idRecurso + "|" + idBoveda)
                .getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] nuevoNonce() {
        byte[] n = new byte[NONCE_BYTES];
        AZAR.nextBytes(n);
        return n;
    }

    /** base64( VER(1) ‖ ALG(1) ‖ NONCE(12) ‖ CIPHERTEXT‖TAG(16) ) */
    public static String cifrar(byte[] clave, byte[] plano, byte[] aad, byte[] nonce)
            throws Exception {
        if (nonce.length != NONCE_BYTES) {
            throw new IllegalArgumentException("El nonce debe ser de 12 bytes");
        }
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey k = new SecretKeySpec(clave, "AES");
        c.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(TAG_BITS, nonce));
        c.updateAAD(aad);
        byte[] ct = c.doFinal(plano);

        byte[] salida = new byte[2 + nonce.length + ct.length];
        salida[0] = (byte) VERSION_ESQUEMA;
        salida[1] = (byte) ALG_AES_GCM;
        System.arraycopy(nonce, 0, salida, 2, nonce.length);
        System.arraycopy(ct, 0, salida, 2 + nonce.length, ct.length);
        return Base64.getEncoder().encodeToString(salida);
    }

    public static byte[] descifrar(byte[] clave, String blob, byte[] aad) throws Exception {
        byte[] crudo = Base64.getDecoder().decode(blob);
        if (crudo.length < 2 + NONCE_BYTES + 16) {
            throw new IllegalArgumentException("Blob demasiado corto");
        }
        int version = crudo[0] & 0xFF;
        int alg = crudo[1] & 0xFF;
        // El byte de versión permite cambiar de algoritmo sin migrar toda la
        // base de golpe: cada blob dice cómo fue cifrado.
        if (version != VERSION_ESQUEMA) {
            throw new IllegalArgumentException("Versión de blob no soportada: " + version);
        }
        if (alg != ALG_AES_GCM) {
            throw new IllegalArgumentException("Algoritmo no soportado: " + alg);
        }

        byte[] nonce = Arrays.copyOfRange(crudo, 2, 2 + NONCE_BYTES);
        byte[] ct = Arrays.copyOfRange(crudo, 2 + NONCE_BYTES, crudo.length);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(clave, "AES"),
               new GCMParameterSpec(TAG_BITS, nonce));
        c.updateAAD(aad);
        return c.doFinal(ct);
    }

    // ── Objetos de dominio ──────────────────────────────────────────────────

    public static String cifrarCredencial(byte[] vk, String json, Object idCredencial,
                                          Object idBoveda, byte[] nonce) throws Exception {
        return cifrar(vk, json.getBytes(StandardCharsets.UTF_8),
                      construirAAD("credencial", idCredencial, idBoveda), nonce);
    }

    public static String descifrarCredencial(byte[] vk, String blob, Object idCredencial,
                                             Object idBoveda) throws Exception {
        return new String(descifrar(vk, blob, construirAAD("credencial", idCredencial, idBoveda)),
                          StandardCharsets.UTF_8);
    }

    /** Clave de bóveda nueva. Aleatoria de verdad: nunca derivarla de nada. */
    public static byte[] nuevaClaveBoveda() {
        byte[] vk = new byte[32];
        AZAR.nextBytes(vk);
        return vk;
    }

    public static String envolverClaveBoveda(byte[] sk, byte[] vk, Object idBoveda, byte[] nonce)
            throws Exception {
        return cifrar(sk, vk, construirAAD("clave_boveda", idBoveda, idBoveda), nonce);
    }

    public static byte[] abrirClaveBoveda(byte[] sk, String envuelta, Object idBoveda)
            throws Exception {
        return descifrar(sk, envuelta, construirAAD("clave_boveda", idBoveda, idBoveda));
    }

    // ── Compartir bóvedas: RSA-2048-OAEP-SHA256 (§2.2 y §2.3) ───────────────
    //
    // Se eligió RSA y no X25519 porque WebCrypto, Java y Android lo traen de
    // serie; X25519 en WebCrypto es reciente y de disponibilidad desigual.
    //
    // El relleno de OAEP es aleatorio: dos envolturas de la misma clave dan
    // ciphertexts distintos. Por eso no se comparan byte a byte entre
    // implementaciones, sino descifrando.

    /** Nombre completo: sin él, Java usa SHA-1 en MGF1 y no interopera con WebCrypto. */
    private static final String RSA_OAEP = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public static java.security.KeyPair generarParDeClaves() throws Exception {
        java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("RSA");
        g.initialize(2048, AZAR);
        return g.generateKeyPair();
    }

    /**
     * Envuelve la clave de bóveda para otro usuario, con su clave pública.
     *
     * Es lo que permite compartir sin que el servidor participe: el dueño cifra
     * VK para el invitado y el servidor solo transporta el resultado.
     */
    public static String envolverParaUsuario(byte[] publicaSpki, byte[] vk) throws Exception {
        java.security.PublicKey pub = java.security.KeyFactory.getInstance("RSA")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(publicaSpki));
        Cipher c = Cipher.getInstance(RSA_OAEP);
        c.init(Cipher.ENCRYPT_MODE, pub, parametrosOaep());
        return Base64.getEncoder().encodeToString(c.doFinal(vk));
    }

    /** Abre una clave de bóveda que envolvieron para mí. */
    public static byte[] abrirConPrivada(byte[] privadaPkcs8, String envuelta) throws Exception {
        java.security.PrivateKey priv = java.security.KeyFactory.getInstance("RSA")
                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(privadaPkcs8));
        Cipher c = Cipher.getInstance(RSA_OAEP);
        c.init(Cipher.DECRYPT_MODE, priv, parametrosOaep());
        return c.doFinal(Base64.getDecoder().decode(envuelta));
    }

    /**
     * SHA-256 también en la función generadora de máscara.
     *
     * Java, con el nombre de algoritmo a secas, usa SHA-256 para el hash pero
     * deja SHA-1 en MGF1. WebCrypto usa SHA-256 en ambos, así que sin esto un
     * mensaje cifrado en el navegador no se abre en el escritorio.
     */
    private static javax.crypto.spec.OAEPParameterSpec parametrosOaep() {
        return new javax.crypto.spec.OAEPParameterSpec(
                "SHA-256", "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA256,
                javax.crypto.spec.PSource.PSpecified.DEFAULT);
    }

    /** La privada nunca llega al servidor sin envolver. */
    public static String envolverClavePrivada(byte[] sk, byte[] privadaPkcs8, byte[] nonce)
            throws Exception {
        return cifrar(sk, privadaPkcs8, construirAAD("clave_privada", 0, 0), nonce);
    }

    public static byte[] abrirClavePrivada(byte[] sk, String envuelta) throws Exception {
        return descifrar(sk, envuelta, construirAAD("clave_privada", 0, 0));
    }

    // ── Recuperación ────────────────────────────────────────────────────────

    public static byte[] claveDeRecuperacion(String codigo) throws Exception {
        return hkdf(codigo.getBytes(StandardCharsets.UTF_8), INFO_RECOVERY, 32);
    }

    public static String envolverParaRecuperacion(String codigo, byte[] mk, byte[] nonce)
            throws Exception {
        byte[] rk = claveDeRecuperacion(codigo);
        String blob = cifrar(rk, mk, construirAAD("recovery", 0, 0), nonce);
        limpiar(rk);
        return blob;
    }

    public static byte[] recuperarMK(String codigo, String blob) throws Exception {
        byte[] rk = claveDeRecuperacion(codigo);
        byte[] mk = descifrar(rk, blob, construirAAD("recovery", 0, 0));
        limpiar(rk);
        return mk;
    }

    // ── Higiene ─────────────────────────────────────────────────────────────

    /** Sobrescribe material sensible en cuanto deja de hacer falta. */
    public static void limpiar(byte[]... buffers) {
        for (byte[] b : buffers) {
            if (b != null) Arrays.fill(b, (byte) 0);
        }
    }

    public static void limpiar(char[] password) {
        if (password != null) Arrays.fill(password, '\0');
    }
}
