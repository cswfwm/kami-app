package com.kami.app;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ECIES：真正的非对称加密，客户端只持有服务端公钥。
 *
 * 每次请求：
 *   1. 生成临时 EC 密钥对
 *   2. shared = ECDH(临时私钥, 服务端公钥)
 *   3. key    = HKDF-SHA256(shared, salt, info="kami-v1")
 *   4. AES-256-GCM 加密明文
 *   5. 发送 {epk, salt, iv, ct, tag}
 *
 * 抓包者只能看到临时公钥 epk。没有服务端私钥就无法算出 shared，
 * 因此即使完全逆向 APK 也解不开抓到的其他请求。
 */
final class Ecies {

    // 服务端 EC 公钥由 native 提供（SDK 中无明文）
    private static byte[] serverPub() {
        byte[] k = Integrity.serverPubkey();
        if (k == null) {
            throw new IllegalStateException("公钥不可用");
        }
        return k;
    }

    private static final byte[] SPKI_PREFIX = hex(
        "3059301306072a8648ce3d020106082a8648ce3d030107034200");

    private static final byte[] HKDF_INFO = "kami-v1".getBytes();

    private Ecies() {
    }

    /** 封装结果：请求字段 + 会话密钥（用于解密响应） */
    static final class Sealed {
        final String epk, salt, iv, ct, tag;
        final byte[] sessionKey;

        Sealed(String epk, String salt, String iv, String ct, String tag, byte[] sessionKey) {
            this.epk = epk;
            this.salt = salt;
            this.iv = iv;
            this.ct = ct;
            this.tag = tag;
            this.sessionKey = sessionKey;
        }
    }

    static Sealed seal(byte[] plain) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        KeyPair ephemeral = gen.generateKeyPair();

        // 临时公钥转成 SEC1 未压缩点（取 SPKI 的最后 65 字节）
        byte[] spki = ephemeral.getPublic().getEncoded();
        byte[] epk = new byte[65];
        System.arraycopy(spki, spki.length - 65, epk, 0, 65);

        PublicKey serverPub = KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(concat(SPKI_PREFIX, serverPub())));

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(ephemeral.getPrivate());
        ka.doPhase(serverPub, true);
        byte[] shared = ka.generateSecret();

        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        byte[] key = hkdf(shared, salt, 32);

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        byte[] out = c.doFinal(plain);
        byte[] ct = new byte[out.length - 16];
        byte[] tag = new byte[16];
        System.arraycopy(out, 0, ct, 0, ct.length);
        System.arraycopy(out, ct.length, tag, 0, 16);

        return new Sealed(Base64Url.encode(epk), Base64Url.encode(salt), Base64Url.encode(iv),
                Base64Url.encode(ct), Base64Url.encode(tag), key);
    }

    /** 用请求协商出的会话密钥解密响应 */
    static byte[] open(String ivB64, String ctB64, String tagB64, byte[] sessionKey) throws Exception {
        byte[] iv = Base64Url.decode(ivB64);
        byte[] ct = Base64Url.decode(ctB64);
        byte[] tag = Base64Url.decode(tagB64);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sessionKey, "AES"), new GCMParameterSpec(128, iv));
        return c.doFinal(concat(ct, tag));
    }

    /** HKDF-SHA256（RFC 5869），输出 32 字节 */
    private static byte[] hkdf(byte[] ikm, byte[] salt, int len) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);

        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] t = new byte[0];
        byte[] okm = new byte[len];
        int off = 0;
        for (byte i = 1; off < len; i++) {
            mac.update(t);
            mac.update(HKDF_INFO);
            mac.update(i);
            t = mac.doFinal();
            int n = Math.min(t.length, len - off);
            System.arraycopy(t, 0, okm, off, n);
            off += n;
        }
        return okm;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
