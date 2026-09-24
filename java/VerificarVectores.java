import com.solucionesnimrod.passrod.cripto.PassrodCripto;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Contrasta la implementación Java contra el banco de vectores.
 *
 * Lee vectores.json con un analizador mínimo propio para no arrastrar una
 * dependencia de JSON solo para esto: el archivo lo genera un script conocido y
 * su forma es estable.
 *
 *   javac -d . PassrodCripto.java VerificarVectores.java
 *   java -cp . VerificarVectores
 */
public class VerificarVectores {

    static final Base64.Encoder B64 = Base64.getEncoder();
    static final Base64.Decoder DEB64 = Base64.getDecoder();

    static Map<String, String> esperado = new LinkedHashMap<>();
    static Map<String, String> entradas = new LinkedHashMap<>();
    static List<String[]> resultados = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        Path ruta = Path.of("..", "vectores", "vectores.json");
        if (!Files.exists(ruta)) ruta = Path.of("vectores", "vectores.json");
        String json = Files.readString(ruta, StandardCharsets.UTF_8);

        leerCasos(json);
        leerEntradas(json);

        byte[] nonce = deHex(entradas.get("nonce_hex"));
        byte[] vk = deHex(entradas.get("clave_boveda_hex"));
        String password = entradas.get("password");
        String email = entradas.get("email");

        comprobar("salt_desde_email",
                  B64.encodeToString(PassrodCripto.saltDesdeEmail(email)));

        byte[] mk = PassrodCripto.derivarMK(password.toCharArray(), email);
        comprobar("mk_pbkdf2", B64.encodeToString(mk));

        byte[] sk = PassrodCripto.derivarSK(mk);
        comprobar("sk_pbkdf2", B64.encodeToString(sk));
        comprobar("authkey_pbkdf2", B64.encodeToString(PassrodCripto.derivarAuthKey(mk)));

        byte[] aadCred = PassrodCripto.construirAAD("credencial", 42, 7);
        comprobar("aad_credencial", B64.encodeToString(aadCred));

        // se cifra el JSON EXACTO del banco, no uno reconstruido: así una
        // diferencia de serialización se detecta como tal
        byte[] contenido = DEB64.decode(esperado.get("credencial_json_utf8_b64"));
        comprobar("blob_credencial",
                  PassrodCripto.cifrar(vk, contenido, aadCred, nonce));

        byte[] aadVk = PassrodCripto.construirAAD("clave_boveda", 7, 7);
        comprobar("aad_clave_boveda", B64.encodeToString(aadVk));
        comprobar("wrap_clave_boveda", PassrodCripto.cifrar(sk, vk, aadVk, nonce));

        byte[] rk = PassrodCripto.claveDeRecuperacion(entradas.get("codigo_recuperacion"));
        comprobar("recovery_key", B64.encodeToString(rk));
        comprobar("recovery_blob",
                  PassrodCripto.cifrar(rk, mk, PassrodCripto.construirAAD("recovery", 0, 0), nonce));

        // ida y vuelta
        byte[] vuelta = PassrodCripto.descifrar(vk, esperado.get("blob_credencial"), aadCred);
        anotar("descifrar_credencial_del_banco",
               java.util.Arrays.equals(vuelta, contenido), "(recuperado)", "(igual)");

        // ── RSA: compartir bóvedas ──────────────────────────────────────
        byte[] aadPriv = PassrodCripto.construirAAD("clave_privada", 0, 0);
        comprobar("aad_clave_privada", B64.encodeToString(aadPriv));
        byte[] privPkcs8 = DEB64.decode(entradas.get("rsa_privada_pkcs8_b64"));
        comprobar("priv_envuelta", PassrodCripto.cifrar(sk, privPkcs8, aadPriv, nonce));

        // El ciphertext RSA no se compara byte a byte: OAEP usa relleno
        // aleatorio. Se comprueba DESCIFRANDO el que dejó la referencia.
        byte[] vkAbierta = PassrodCripto.abrirConPrivada(
                privPkcs8, entradas.get("wrap_asimetrico_b64"));
        comprobar("abrir_wrap_asimetrico", B64.encodeToString(vkAbierta));

        // ida y vuelta con la pública
        String miEnvuelta = PassrodCripto.envolverParaUsuario(
                DEB64.decode(entradas.get("rsa_publica_spki_b64")), vk);
        byte[] deVuelta = PassrodCripto.abrirConPrivada(privPkcs8, miEnvuelta);
        anotar("rsa_ida_y_vuelta", java.util.Arrays.equals(deVuelta, vk),
               "(clave recuperada)", "(igual a la original)");

        // ── v2.2.0 ──────────────────────────────────────────────────────────
        comprobar("mk_pbkdf2_desde_nfd", B64.encodeToString(
                PassrodCripto.derivarMK(entradas.get("password_nfd").toCharArray(), email)));
        comprobar("email_con_i_normalizado",
                PassrodCripto.normalizarEmail(entradas.get("email_con_i_nfd")));
        comprobar("salt_email_con_i", B64.encodeToString(
                PassrodCripto.saltDesdeEmail(entradas.get("email_con_i_nfd"))));
        byte[] pubSpki = DEB64.decode(entradas.get("rsa_publica_spki_b64"));
        comprobar("huella_publica", PassrodCripto.huella(pubSpki));
        String envueltaRef = entradas.get("wrap_asimetrico_b64");
        comprobar("mensaje_envoltura",
                B64.encodeToString(PassrodCripto.mensajeEnvoltura(7, 12, envueltaRef)));
        comprobar("verificar_firma_envoltura", PassrodCripto.verificarEnvoltura(pubSpki, 7, 12,
                envueltaRef, entradas.get("firma_envoltura_b64")) ? "valida" : "invalida");
        comprobar("firma_con_otro_destinatario", PassrodCripto.verificarEnvoltura(pubSpki, 7, 13,
                envueltaRef, entradas.get("firma_envoltura_b64")) ? "valida" : "invalida");
        String rechaza = "NO rechaza";
        try {
            PassrodCripto.envolverParaUsuario(DEB64.decode(entradas.get("rsa_publica_1024_spki_b64")), vk);
        } catch (Exception e) {
            rechaza = "rechaza";
        }
        comprobar("rechazar_rsa_1024", rechaza);
        comprobar("codigo_normalizado",
                PassrodCripto.normalizarCodigoRecuperacion(entradas.get("codigo_tecleado")));
        comprobar("aad_recuperacion", B64.encodeToString(PassrodCripto.aadRecuperacion(email)));
        comprobar("recovery_blob_atado", PassrodCripto.envolverRecuperacion(
                entradas.get("codigo_tecleado"), mk, email, nonce));

        String miFirma = PassrodCripto.firmarEnvoltura(privPkcs8, 7, 12, envueltaRef);
        boolean buena = PassrodCripto.verificarEnvoltura(pubSpki, 7, 12, envueltaRef, miFirma);
        boolean otra = PassrodCripto.verificarEnvoltura(pubSpki, 8, 12, envueltaRef, miFirma);
        anotar("firma_propia_ida_y_vuelta", buena && !otra, buena + "/" + otra, "true/false");

        byte[] atadoAbierto = PassrodCripto.abrirRecuperacion(entradas.get("codigo_tecleado"),
                esperado.get("recovery_blob_atado"), email);
        byte[] rkCanon = PassrodCripto.claveDeRecuperacion(
                PassrodCripto.normalizarCodigoRecuperacion(entradas.get("codigo_tecleado")));
        String blobAntiguo = PassrodCripto.cifrar(rkCanon, mk,
                PassrodCripto.construirAAD("recovery", 0, 0), PassrodCripto.nuevoNonce());
        byte[] antiguoAbierto = PassrodCripto.abrirRecuperacion(
                entradas.get("codigo_tecleado"), blobAntiguo, email);
        String otroCorreo = "abre";
        try {
            PassrodCripto.abrirRecuperacion(entradas.get("codigo_tecleado"),
                    esperado.get("recovery_blob_atado"), "otra@ejemplo.ec");
        } catch (Exception e) {
            otroCorreo = "no abre";
        }
        anotar("recuperacion_atada_y_antigua", java.util.Arrays.equals(atadoAbierto, mk)
                && java.util.Arrays.equals(antiguoAbierto, mk) && otroCorreo.equals("no abre"),
                otroCorreo, "no abre");

        boolean formato = true;
        for (int i = 0; i < 2000; i++) {
            if (!PassrodCripto.nuevoCodigoRecuperacion().matches("([A-Z2-9]{5}-){4}[A-Z2-9]{5}")
                    || PassrodCripto.nuevoCodigoRecuperacion().matches(".*[ILO01].*")) formato = false;
        }
        anotar("generador_de_codigos", formato, String.valueOf(formato), "true");

        // ── v2.3.0: Argon2id y límites del KDF ──────────────────────────────
        PassrodCripto.Kdf a2 = new PassrodCripto.Kdf("argon2id", 3, 65536, 4);
        byte[] mkA = PassrodCripto.derivarMK(password.toCharArray(), email, a2);
        comprobar("mk_argon2id", B64.encodeToString(mkA));
        comprobar("sk_argon2id", B64.encodeToString(PassrodCripto.derivarSK(mkA)));
        comprobar("authkey_argon2id", B64.encodeToString(PassrodCripto.derivarAuthKey(mkA)));
        anotar("argon2id_desde_nfd", java.util.Arrays.equals(mkA, PassrodCripto.derivarMK(
                entradas.get("password_nfd").toCharArray(), email, a2)), "-", "igual que desde NFC");
        anotar("kdf_nuevas_es_argon2id_del_banco", a2.equals(PassrodCripto.KDF_NUEVAS),
                String.valueOf(PassrodCripto.KDF_NUEVAS), String.valueOf(a2));
        Object[][] limites = {
            {"pbkdf2 con 1 iteración", new PassrodCripto.Kdf("pbkdf2", 1, 0, 0), true},
            {"pbkdf2 con 599 999", new PassrodCripto.Kdf("pbkdf2", 599_999, 0, 0), true},
            {"pbkdf2 con 2 000 000 000 (colgaría el cliente)", new PassrodCripto.Kdf("pbkdf2", 2_000_000_000, 0, 0), true},
            {"argon2id con 1 MiB", new PassrodCripto.Kdf("argon2id", 3, 1024, 4), true},
            {"argon2id con 1 pasada", new PassrodCripto.Kdf("argon2id", 1, 65536, 4), true},
            {"argon2id con 64 GiB", new PassrodCripto.Kdf("argon2id", 3, 67_108_864, 4), true},
            {"un tipo desconocido", new PassrodCripto.Kdf("md5", 1, 0, 0), true},
            {"admite pbkdf2 600 000", new PassrodCripto.Kdf("pbkdf2", 600_000, 0, 0), false},
            {"admite el de las cuentas nuevas", PassrodCripto.KDF_NUEVAS, false},
        };
        for (Object[] l : limites) {
            boolean rechazaKdf;
            try {
                PassrodCripto.validarKdf((PassrodCripto.Kdf) l[1]);
                rechazaKdf = false;
            } catch (IllegalArgumentException e) {
                rechazaKdf = true;
            }
            anotar("kdf: " + l[0], rechazaKdf == (Boolean) l[2], String.valueOf(rechazaKdf), String.valueOf(l[2]));
        }
        String[] ida = PassrodCripto.kdfParaServidor(PassrodCripto.KDF_NUEVAS);
        boolean vueltaKdf = PassrodCripto.kdfDesdeServidor(ida[0], ida[1]).equals(PassrodCripto.KDF_NUEVAS)
                && PassrodCripto.kdfDesdeServidor(null, null).equals(PassrodCripto.KDF_PBKDF2);
        boolean rechaza1;
        try {
            PassrodCripto.kdfDesdeServidor("pbkdf2", "{\"iteraciones\":1}");
            rechaza1 = false;
        } catch (IllegalArgumentException e) {
            rechaza1 = true;
        }
        anotar("kdf ida y vuelta con el servidor", vueltaKdf && rechaza1, ida[0] + " " + ida[1], "ida y vuelta");
        anotar("kdf_params igual que TypeScript", "{\"m\":65536,\"t\":3,\"p\":4}".equals(ida[1]), ida[1], "{\"m\":65536,\"t\":3,\"p\":4}");
        anotar("authHash con argon2id = base64(authkey_argon2id)",
                PassrodCripto.authHash(password.toCharArray(), email, a2).equals(esperado.get("authkey_argon2id")), "-", "-");

        // la AAD debe atar el blob a su ubicación
        boolean atado = false;
        try {
            PassrodCripto.descifrar(vk, esperado.get("blob_credencial"),
                                    PassrodCripto.construirAAD("credencial", 43, 7));
        } catch (Exception e) {
            atado = true;
        }
        anotar("aad_incorrecta_debe_fallar", atado,
               atado ? "falla como debe" : "NO FALLÓ", "falla como debe");

        System.out.println("Verificación de la implementación Java contra el banco de vectores\n");
        int fallos = 0;
        for (String[] r : resultados) {
            boolean ok = "1".equals(r[1]);
            System.out.printf("  %s  %s%n", ok ? "PASA " : "FALLA", r[0]);
            if (!ok) {
                fallos++;
                System.out.printf("          esperado: %s%n", recorta(r[3]));
                System.out.printf("          obtenido: %s%n", recorta(r[2]));
            }
        }
        System.out.printf("%n%d/%d correctos%n", resultados.size() - fallos, resultados.size());
        if (fallos > 0) {
            System.out.println("\nHAY DIVERGENCIA con la implementación de referencia.");
            System.exit(1);
        }
        System.out.println("Java reproduce el esquema byte a byte.");
    }

    static void comprobar(String nombre, String obtenido) {
        anotar(nombre, obtenido.equals(esperado.get(nombre)), obtenido, esperado.get(nombre));
    }

    static void anotar(String nombre, boolean ok, String obtenido, String esp) {
        resultados.add(new String[]{nombre, ok ? "1" : "0", obtenido, esp});
    }

    static String recorta(String s) {
        if (s == null) return "(ausente)";
        return s.length() > 60 ? s.substring(0, 60) : s;
    }

    static byte[] deHex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /** Extrae los pares nombre/esperado del array "casos". */
    static void leerCasos(String json) {
        int i = 0;
        while ((i = json.indexOf("\"nombre\"", i)) >= 0) {
            String nombre = valorTras(json, i);
            int j = json.indexOf("\"esperado\"", i);
            if (j < 0) break;
            esperado.put(nombre, valorTras(json, j));
            i = j + 1;
        }
    }

    static void leerEntradas(String json) {
        int ini = json.indexOf("\"entradas\"");
        int fin = json.indexOf("\"casos\"");
        String bloque = json.substring(ini, fin);
        for (String clave : new String[]{"password", "email", "email_normalizado",
                                         "nonce_hex", "clave_boveda_hex", "codigo_recuperacion",
                                         "rsa_publica_spki_b64", "rsa_privada_pkcs8_b64",
                                         "wrap_asimetrico_b64", "password_nfd", "email_con_i_nfd",
                                         "firma_envoltura_b64", "rsa_publica_1024_spki_b64",
                                         "codigo_tecleado"}) {
            int p = bloque.indexOf("\"" + clave + "\"");
            if (p >= 0) entradas.put(clave, valorTras(bloque, p));
        }
    }

    /** Lee el valor de cadena que sigue al primer ':' tras la posición dada. */
    static String valorTras(String s, int desde) {
        int c = s.indexOf(':', desde);
        int a = s.indexOf('"', c + 1);
        StringBuilder sb = new StringBuilder();
        for (int k = a + 1; k < s.length(); k++) {
            char ch = s.charAt(k);
            if (ch == '\\') {
                char sig = s.charAt(++k);
                switch (sig) {
                    case 'n': sb.append('\n'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        sb.append((char) Integer.parseInt(s.substring(k + 1, k + 5), 16));
                        k += 4;
                        break;
                    default: sb.append(sig);
                }
            } else if (ch == '"') {
                break;
            } else {
                sb.append(ch);
            }
        }
        return sb.toString();
    }
}
