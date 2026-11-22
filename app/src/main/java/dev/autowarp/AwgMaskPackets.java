package dev.autowarp;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Diagnostic CPS packets only. No sockets, registration or profile writes.
 * QUIC v1 Initial protection: RFC 9001 section 5; framing: RFC 9000.
 * These are protocol-shaped probes, not a functioning QUIC/DNS/STUN tunnel.
 */
public final class AwgMaskPackets {
    private static final SecureRandom RANDOM = new SecureRandom();
    private AwgMaskPackets() {}

    public static String signature(String mode) throws GeneralSecurityException {
        byte[] packet;
        switch (mode) {
            case "quic": packet = quic(); break;
            case "dns": packet = dns(); break;
            case "stun": packet = stun(); break;
            default: throw new IllegalArgumentException("awg_mask_unknown_variant");
        }
        return "<b 0x" + hex(packet) + ">";
    }

    static byte[] quic() throws GeneralSecurityException {
        byte[] dcid = random(8), scid = random(8);
        byte[] hello = hello(scid);
        byte[] crypto = concat(new byte[]{6, 0}, varint(hello.length), hello);
        byte[] prefix = concat(new byte[]{(byte)0xc3, 0, 0, 0, 1, 8}, dcid,
                new byte[]{8}, scid, new byte[]{0});
        // Two-byte Length and four-byte packet number, followed by ciphertext/tag.
        int payloadSize = 1200 - prefix.length - 2 - 4 - 16;
        if (crypto.length > payloadSize) throw new IllegalStateException("awg_mask_quic_size");
        byte[] payload = Arrays.copyOf(crypto, payloadSize);
        byte[] header = concat(prefix, varint(4 + payload.length + 16), new byte[4]);
        byte[][] keys = initialKeys(dcid);
        Cipher aead = Cipher.getInstance("AES/GCM/NoPadding");
        aead.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keys[0], "AES"), new GCMParameterSpec(128, keys[1]));
        aead.updateAAD(header);
        byte[] ciphertext = aead.doFinal(payload); // packet number zero: nonce equals IV
        Cipher hp = Cipher.getInstance("AES/ECB/NoPadding");
        hp.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keys[2], "AES"));
        byte[] mask = hp.doFinal(Arrays.copyOf(ciphertext, 16));
        header[0] ^= mask[0] & 15;
        for (int i = 0; i < 4; i++) header[header.length - 4 + i] ^= mask[1 + i];
        return concat(header, ciphertext);
    }

    static byte[][] initialKeys(byte[] dcid) throws GeneralSecurityException {
        byte[] salt = unhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
        byte[] client = expand(hmac(salt, dcid), "client in", 32);
        return new byte[][]{expand(client, "quic key", 16), expand(client, "quic iv", 12), expand(client, "quic hp", 16)};
    }
    private static byte[] expand(byte[] secret, String label, int size) throws GeneralSecurityException {
        byte[] name = ascii("tls13 " + label);
        return Arrays.copyOf(hmac(secret, concat(u16(size), new byte[]{(byte)name.length}, name, new byte[]{0, 1})), size);
    }
    private static byte[] hmac(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac m = Mac.getInstance("HmacSHA256"); m.init(new SecretKeySpec(key, "HmacSHA256")); return m.doFinal(data);
    }
    private static byte[] hello(byte[] scid) {
        byte[] name = ascii("www.apple.com");
        byte[] sni = concat(u16(name.length + 3), new byte[]{0}, u16(name.length), name);
        byte[] share = concat(u16(36), u16(29), u16(32), random(32));
        byte[] ext = concat(extension(0, sni), extension(43, new byte[]{2, 3, 4}),
                extension(10, new byte[]{0, 2, 0, 29}),
                extension(13, new byte[]{0, 6, 4, 3, 8, 4, 8, 7}),
                extension(51, share), extension(16, new byte[]{0, 3, 2, 'h', '3'}),
                extension(57, concat(new byte[]{15, (byte)scid.length}, scid)));
        byte[] body = concat(new byte[]{3, 3}, random(32), new byte[]{0, 0, 2, 0x13, 1, 1, 0}, u16(ext.length), ext);
        return concat(new byte[]{1, (byte)(body.length >> 16), (byte)(body.length >> 8), (byte)body.length}, body);
    }
    private static byte[] extension(int type, byte[] value) { return concat(u16(type), u16(value.length), value); }

    static byte[] dns() {
        ByteArrayOutputStream question = new ByteArrayOutputStream();
        for (String label : new String[]{"www", "apple", "com"}) { question.write(label.length()); put(question, ascii(label)); }
        put(question, new byte[]{0, 0, 1, 0, 1});
        int pad = 60 + RANDOM.nextInt(121);
        // DNS A query, one EDNS0 OPT record with a padding option (RFC 7830).
        return concat(random(2), new byte[]{1, 0, 0, 1, 0, 0, 0, 0, 0, 1}, question.toByteArray(),
                new byte[]{0, 0, 41, 4, (byte)0xd0, 0, 0, 0, 0}, u16(4 + pad), u16(12), u16(pad), new byte[pad]);
    }
    static byte[] stun() {
        byte[] software = ascii("ZBS test " + hex(random(4)));
        byte[] attr = concat(u16(0x8022), u16(software.length), Arrays.copyOf(software, (software.length + 3) & ~3));
        return concat(u16(1), u16(attr.length), unhex("2112a442"), random(12), attr);
    }
    static byte[] random(int size) { byte[] b = new byte[size]; RANDOM.nextBytes(b); return b; }
    static byte[] u16(int n) { return new byte[]{(byte)(n >> 8), (byte)n}; }
    static byte[] varint(int n) {
        if (n < 0 || n >= 16384) throw new IllegalArgumentException("awg_mask_length");
        return n < 64 ? new byte[]{(byte)n} : new byte[]{(byte)(0x40 | n >> 8), (byte)n};
    }
    static byte[] concat(byte[]... parts) { ByteArrayOutputStream b = new ByteArrayOutputStream(); for (byte[] p : parts) put(b, p); return b.toByteArray(); }
    private static void put(ByteArrayOutputStream b, byte[] p) { b.write(p, 0, p.length); }
    static byte[] ascii(String s) { return s.getBytes(StandardCharsets.US_ASCII); }
    static String hex(byte[] b) { char[] alphabet = "0123456789abcdef".toCharArray(), out = new char[b.length * 2]; for (int i=0;i<b.length;i++) {out[2*i]=alphabet[(b[i]&255)>>>4];out[2*i+1]=alphabet[b[i]&15];} return new String(out); }
    static byte[] unhex(String s) { byte[] b=new byte[s.length()/2];for(int i=0;i<b.length;i++)b[i]=(byte)Integer.parseInt(s.substring(i*2,i*2+2),16);return b; }
}
