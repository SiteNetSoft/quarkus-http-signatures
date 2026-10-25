package org.sitenetsoft.httpsignatures;

import java.io.ByteArrayOutputStream;

/**
 * Just enough DER to wrap PKCS#1 and raw Ed25519 keys into the PKCS#8 / SubjectPublicKeyInfo forms the JDK accepts.
 */
final class Der {

    static final byte[] OID_RSA = hex("06092A864886F70D010101");
    static final byte[] OID_ED25519 = hex("06032B6570");
    static final byte[] NULL = { 0x05, 0x00 };

    private Der() {
    }

    static byte[] tlv(int tag, byte[]... contents) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] c : contents) {
            body.writeBytes(c);
        }
        byte[] content = body.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int len = content.length;
        if (len < 0x80) {
            out.write(len);
        } else {
            int n = (32 - Integer.numberOfLeadingZeros(len) + 7) / 8;
            out.write(0x80 | n);
            for (int k = n - 1; k >= 0; k--) {
                out.write((len >> (8 * k)) & 0xff);
            }
        }
        out.writeBytes(content);
        return out.toByteArray();
    }

    static byte[] seq(byte[]... contents) {
        return tlv(0x30, contents);
    }

    static byte[] octetString(byte[] content) {
        return tlv(0x04, content);
    }

    static byte[] bitString(byte[] content) {
        byte[] padded = new byte[content.length + 1];
        System.arraycopy(content, 0, padded, 1, content.length);
        return tlv(0x03, padded);
    }

    static byte[] integer(int value) {
        return tlv(0x02, new byte[] { (byte) value });
    }

    /** PKCS#1 RSAPrivateKey -> PKCS#8 PrivateKeyInfo. */
    static byte[] pkcs1ToPkcs8(byte[] pkcs1) {
        return seq(integer(0), seq(OID_RSA, NULL), octetString(pkcs1));
    }

    /** PKCS#1 RSAPublicKey -> SubjectPublicKeyInfo. */
    static byte[] pkcs1ToSpki(byte[] pkcs1) {
        return seq(seq(OID_RSA, NULL), bitString(pkcs1));
    }

    /** Raw 32-byte Ed25519 public key -> SubjectPublicKeyInfo. */
    static byte[] ed25519Spki(byte[] raw) {
        return seq(seq(OID_ED25519), bitString(raw));
    }

    /** Raw 32-byte Ed25519 seed -> PKCS#8 PrivateKeyInfo. */
    static byte[] ed25519Pkcs8(byte[] seed) {
        return seq(integer(0), seq(OID_ED25519), octetString(octetString(seed)));
    }

    static byte[] hex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }
}
