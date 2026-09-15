package com.solucionesnimrod.passrod.cripto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Doble factor por tiempo (TOTP, RFC 6238), versión Java.
 *
 * Debe dar los mismos códigos que {@code vectores/vectores_totp.json} y que
 * {@code typescript/totp.ts}: un código distinto en un cliente es un código que
 * el sitio rechaza sin decir por qué.
 *
 * Acepta la URI {@code otpauth://totp/...} del QR o el secreto base32 suelto,
 * con espacios, minúsculas o relleno.
 */
public final class PassrodTotp {

    private static final String ALFABETO_BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private PassrodTotp() {}

    /** El texto no es un TOTP utilizable. El mensaje va dirigido al usuario. */
    public static final class TotpInvalido extends Exception {
        public TotpInvalido(String mensaje) { super(mensaje); }
    }

    /**
     * @param algoritmo nombre JCA del HMAC: HmacSHA1, HmacSHA256 o HmacSHA512
     * @param emisor    quién emite el código, o cadena vacía
     * @param cuenta    la cuenta a la que pertenece, o cadena vacía
     */
    public record Config(byte[] secreto, String algoritmo, int digitos, int periodo,
                         String emisor, String cuenta) {}

    /** Base32 tal como lo escriben las personas: sin relleno, con espacios o guiones. */
    public static byte[] base32ABytes(String texto) throws TotpInvalido {
        String limpio = texto.replaceAll("\\s+", "").replace("-", "")
                .toUpperCase(Locale.ROOT).replaceAll("=+$", "");
        if (limpio.isEmpty()) throw new TotpInvalido("Falta el secreto del código de verificación.");

        // Con 1, 3 o 6 caracteres sobrantes no se completa ningún byte: el
        // secreto está cortado, y calcular con lo que hay daría códigos falsos.
        int resto = limpio.length() % 8;
        if (resto == 1 || resto == 3 || resto == 6) {
            throw new TotpInvalido("El secreto está incompleto: revisa que se copió entero.");
        }

        byte[] salida = new byte[limpio.length() * 5 / 8];
        int bits = 0;
        int acumulado = 0;
        int i = 0;
        for (char c : limpio.toCharArray()) {
            int valor = ALFABETO_BASE32.indexOf(c);
            if (valor < 0) {
                throw new TotpInvalido("El secreto tiene un carácter que no vale («" + c
                        + "»). Solo lleva letras y los números del 2 al 7.");
            }
            acumulado = (acumulado << 5) | valor;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                salida[i++] = (byte) ((acumulado >>> bits) & 0xff);
            }
        }
        return salida;
    }

    /** Lee una URI {@code otpauth://totp/...} o un secreto base32 suelto. */
    public static Config leer(String texto) throws TotpInvalido {
        String entrada = texto == null ? "" : texto.strip();

        if (!entrada.toLowerCase(Locale.ROOT).startsWith("otpauth://")) {
            return new Config(base32ABytes(entrada), "HmacSHA1", 6, 30, "", "");
        }

        URI uri;
        try {
            uri = new URI(entrada);
        } catch (URISyntaxException e) {
            throw new TotpInvalido("El QR no contiene una dirección otpauth válida.");
        }
        if (uri.getHost() == null || !uri.getHost().equalsIgnoreCase("totp")) {
            throw new TotpInvalido("Este código es por contador (HOTP), no por tiempo. PassRod solo "
                    + "admite los de tiempo (TOTP), que son los que usan casi todos los sitios.");
        }

        Map<String, String> parametros = new HashMap<>();
        String consulta = uri.getRawQuery();
        if (consulta != null) {
            for (String par : consulta.split("&")) {
                if (par.isEmpty()) continue;
                int igual = par.indexOf('=');
                String clave = igual < 0 ? par : par.substring(0, igual);
                String valor = igual < 0 ? "" : par.substring(igual + 1);
                parametros.putIfAbsent(
                        URLDecoder.decode(clave, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT),
                        URLDecoder.decode(valor, StandardCharsets.UTF_8));
            }
        }

        String nombreAlgoritmo = parametros.getOrDefault("algorithm", "SHA1")
                .toUpperCase(Locale.ROOT).replace("-", "");
        String algoritmo = switch (nombreAlgoritmo) {
            case "SHA1" -> "HmacSHA1";
            case "SHA256" -> "HmacSHA256";
            case "SHA512" -> "HmacSHA512";
            default -> throw new TotpInvalido(
                    "El QR usa un algoritmo que PassRod no admite (" + nombreAlgoritmo + ").");
        };

        int digitos = entero(parametros.get("digits"), 6, "un número de dígitos");
        int periodo = entero(parametros.get("period"), 30, "un periodo");
        if (digitos < 6 || digitos > 8) {
            throw new TotpInvalido("El QR pide códigos de " + digitos
                    + " dígitos; solo se admiten de 6 a 8.");
        }
        if (periodo < 1 || periodo > 3600) {
            throw new TotpInvalido("El QR pide un periodo de " + periodo
                    + " segundos, que no es válido.");
        }

        // La etiqueta es «Emisor:cuenta» o solo «cuenta». El parámetro issuer,
        // si viene, manda sobre el emisor de la etiqueta. getPath() decodifica
        // los %XX pero deja los «+», igual que las demás implementaciones.
        String etiqueta = uri.getPath() == null ? "" : uri.getPath().replaceFirst("^/+", "");
        int dosPuntos = etiqueta.lastIndexOf(':');
        String emisorEtiqueta = dosPuntos >= 0 ? etiqueta.substring(0, dosPuntos) : "";
        String cuenta = dosPuntos >= 0 ? etiqueta.substring(dosPuntos + 1) : etiqueta;
        String emisor = parametros.getOrDefault("issuer", "").strip();

        return new Config(base32ABytes(parametros.getOrDefault("secret", "")), algoritmo,
                digitos, periodo, emisor.isEmpty() ? emisorEtiqueta.strip() : emisor, cuenta.strip());
    }

    private static int entero(String texto, int porDefecto, String que) throws TotpInvalido {
        if (texto == null) return porDefecto;
        if (!texto.matches("\\s*\\+?\\d+\\s*")) {
            throw new TotpInvalido("El QR trae " + que + " que no es un número.");
        }
        try {
            return Integer.parseInt(texto.strip().replace("+", ""));
        } catch (NumberFormatException e) {
            throw new TotpInvalido("El QR trae " + que + " demasiado grande.");
        }
    }

    /** Segundos que le quedan de vida al código actual. */
    public static int segundosRestantes(Config config, long ahoraMs) {
        long segundos = Math.floorDiv(ahoraMs, 1000L);
        return (int) (config.periodo() - Math.floorMod(segundos, config.periodo()));
    }

    /** El código vigente en {@code ahoraMs}, con ceros a la izquierda. */
    public static String codigo(Config config, long ahoraMs) {
        long contador = Math.floorDiv(Math.floorDiv(ahoraMs, 1000L), config.periodo());
        byte[] mac;
        try {
            Mac hmac = Mac.getInstance(config.algoritmo());
            hmac.init(new SecretKeySpec(config.secreto(), config.algoritmo()));
            mac = hmac.doFinal(ByteBuffer.allocate(8).putLong(contador).array());
        } catch (GeneralSecurityException e) {
            // Los tres HMAC son obligatorios en toda JVM: si falta uno, el entorno está roto.
            throw new IllegalStateException("No se pudo calcular el código TOTP", e);
        }

        int desplazamiento = mac[mac.length - 1] & 0x0f;
        int binario = ((mac[desplazamiento] & 0x7f) << 24)
                | ((mac[desplazamiento + 1] & 0xff) << 16)
                | ((mac[desplazamiento + 2] & 0xff) << 8)
                | (mac[desplazamiento + 3] & 0xff);
        int modulo = (int) Math.pow(10, config.digitos());
        String codigo = Integer.toString(binario % modulo);
        return "0".repeat(config.digitos() - codigo.length()) + codigo;
    }
}
