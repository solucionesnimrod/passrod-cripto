import com.solucionesnimrod.passrod.cripto.PassrodTotp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Contrasta el TOTP de Java contra vectores/vectores_totp.json.
 *
 * Mismo criterio que VerificarVectores: sin dependencia de JSON. El archivo lo
 * genera un script conocido y sus objetos son planos (texto y números).
 *
 *   javac -encoding UTF-8 -d . PassrodTotp.java VerificarTotp.java
 *   java -cp . VerificarTotp
 */
public class VerificarTotp {

    static int bien = 0;
    static int fallos = 0;

    static void comprobar(String nombre, boolean ok, String detalle) {
        System.out.println((ok ? "  OK   " : " FALLA ") + nombre + (ok ? "" : " — " + detalle));
        if (ok) bien++; else fallos++;
    }

    /** Los objetos planos de una lista del JSON: {"nombre": "...", "tiempo": 59, ...}. */
    static List<Map<String, String>> lista(String json, String nombreLista) {
        int inicio = json.indexOf("\"" + nombreLista + "\"");
        int abre = json.indexOf('[', inicio);
        int cierra = json.indexOf(']', abre);
        Matcher objeto = Pattern.compile("\\{([^{}]*)\\}").matcher(json.substring(abre, cierra));
        Pattern campo = Pattern.compile("\"(\\w+)\"\\s*:\\s*(\"((?:[^\"\\\\]|\\\\.)*)\"|-?\\d+)");
        List<Map<String, String>> salida = new ArrayList<>();
        while (objeto.find()) {
            Map<String, String> m = new HashMap<>();
            Matcher c = campo.matcher(objeto.group(1));
            while (c.find()) {
                m.put(c.group(1), c.group(3) != null ? desescapar(c.group(3)) : c.group(2));
            }
            salida.add(m);
        }
        return salida;
    }

    static String desescapar(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch != '\\' || i + 1 >= s.length()) { sb.append(ch); continue; }
            char sig = s.charAt(++i);
            switch (sig) {
                case 'u' -> { sb.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16)); i += 4; }
                case 'n' -> sb.append('\n');
                default -> sb.append(sig);
            }
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        Path ruta = Path.of("..", "vectores", "vectores_totp.json");
        if (!Files.exists(ruta)) ruta = Path.of("vectores", "vectores_totp.json");
        String json = Files.readString(ruta, StandardCharsets.UTF_8);

        System.out.println("TOTP (Java) contra el banco de vectores\n");

        for (Map<String, String> c : lista(json, "codigos")) {
            String obtenido = PassrodTotp.codigo(PassrodTotp.leer(c.get("entrada")),
                    Long.parseLong(c.get("tiempo")) * 1000L);
            comprobar(c.get("nombre"), obtenido.equals(c.get("esperado")),
                    "esperaba " + c.get("esperado") + ", dio " + obtenido);
        }

        for (Map<String, String> e : lista(json, "etiquetas")) {
            PassrodTotp.Config cfg = PassrodTotp.leer(e.get("entrada"));
            comprobar(e.get("nombre"),
                    cfg.emisor().equals(e.get("emisor")) && cfg.cuenta().equals(e.get("cuenta")),
                    "dio «" + cfg.emisor() + "»/«" + cfg.cuenta() + "»");
        }

        for (Map<String, String> i : lista(json, "invalidos")) {
            String error = null;
            try {
                PassrodTotp.leer(i.get("entrada"));
            } catch (PassrodTotp.TotpInvalido ex) {
                error = ex.getMessage();
            } catch (Exception ex) {
                error = "OTRA: " + ex;
            }
            comprobar("rechaza_" + i.get("nombre"),
                    error != null && !error.startsWith("OTRA"), String.valueOf(error));
        }

        PassrodTotp.Config cfg = PassrodTotp.leer("JBSWY3DPEHPK3PXP");
        comprobar("restantes_al_empezar_periodo",
                PassrodTotp.segundosRestantes(cfg, 1789467030_000L) == 30, "");
        comprobar("restantes_al_final_periodo",
                PassrodTotp.segundosRestantes(cfg, 1789467059_999L) == 1, "");
        boolean cortado = false;
        try { PassrodTotp.leer("JBSWY3DPEHPK3PXPA"); } catch (PassrodTotp.TotpInvalido ex) { cortado = true; }
        comprobar("rechaza_secreto_cortado", cortado, "");

        System.out.println("\nRESULTADO: " + bien + " bien, " + fallos + " mal");
        System.exit(fallos == 0 ? 0 : 1);
    }
}
