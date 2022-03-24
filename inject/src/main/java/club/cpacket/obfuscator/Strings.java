package club.cpacket.obfuscator;

import java.util.Base64;

public class Strings {

    private static long KEY;

    public static String valueOf(long[] pieces, String key, long hashedKey) {
        StringBuilder b = new StringBuilder();
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        long checksum = stackTrace[2].getClassName().hashCode();

        for (long piece : pieces) {
            checksum = ~checksum + piece;
            checksum ^= checksum >> 24;
        }
        checksum = checksum ^ (checksum >>> 32);
        long pieceKey = hashedKey ^ checksum;

        for (long piece : pieces) {
            long value = (piece + KEY) ^ pieceKey;
            b.append(decode(toString(value), key));
        }

        return b.toString();
    }

    private static String toString(long piece) {
        char a = (char) (piece & 0xFFFF);
        char b = (char) ((piece >> 16) & 0xFFFF);
        char c = (char) ((piece >> 32) & 0xFFFF);
        char d = (char) ((piece >> 48) & 0xFFFF);

        return new String(new char[]{a, b, c, d});
    }

    private static String decode(String original, String keyString) {
        char[] key = keyString.toCharArray();
        byte[] bytes = Base64.getDecoder().decode(original);

        StringBuilder builder = new StringBuilder();

        for (int i = 0; i < bytes.length; i++) {
            byte a = bytes[i];
            byte b = (byte) key[i % key.length];
            byte c = (byte) key[(i + bytes.length / 2) % key.length];
            byte d = (byte) (bytes.length % 256);
            byte e = (byte) key[(31 + i * i) % key.length];

            int mod = d ^ (((-a + b) - c + e) % 256);
            int digit = (byte) (mod < 0 ? mod + 256 : mod);
            builder.append((char) digit);
        }

        return builder.toString();
    }
}
