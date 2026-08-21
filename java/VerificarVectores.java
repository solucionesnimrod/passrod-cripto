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
                                         "wrap_asimetrico_b64"}) {
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
