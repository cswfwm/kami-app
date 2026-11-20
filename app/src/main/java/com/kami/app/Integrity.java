package com.kami.app;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.util.Locale;

/**
 * 防重打包与配置保护。
 *
 * 服务端地址与公钥都存在 native 库中（异或混淆），DEX 里没有明文，
 * 因此「解包后把 URL 改成自己的服务器」不再是一行字符串替换。
 *
 * 更关键的是签名自校验：改任何东西重新打包，签名证书必然变化，
 * 期望指纹硬编码在 native 里，Java 侧只做调用。攻击者必须同时逆向
 * native 并绕过多个校验点。
 *
 * 注意：这些都能被绕过（改 so 或 hook）。它能挡住 apktool 改一行
 * 这种低成本攻击，防不住有经验的逆向者。
 */
final class Integrity {

    /**
     * 期望的签名证书指纹（SHA-256，小写 hex）。
     *
     * 只对「证书本身」算哈希，不对整个签名块算。
     * 原因是 Signature.toByteArray() 的返回内容随系统变化：
     *   - Android 7.0+ 读到 v2 签名时返回证书 DER
     *   - Android 5.x/6.x 只认 v1，返回整个 PKCS#7 块
     * 直接对返回值哈希会得到两个不同的值，旧系统上正常安装也会被判非法。
     * 所以先统一用 CertificateFactory 解析出证书，再哈希。
     */
    private static final String EXPECTED_FP =
            "5006539cd0771eacf846c20ca33e3b2ee163b920aa7232258c561f3cae9e6f94";

    /** native 侧持有的服务端地址，避免 DEX 直接暴露 */
    private static volatile String cachedBase;

    private Integrity() {
    }

    /** 计算当前 APK 的签名证书 SHA-256，转小写 hex */
    static String currentFingerprint(Context ctx) {
        try {
            PackageManager pm = ctx.getPackageManager();
            PackageInfo pi = pm.getPackageInfo(ctx.getPackageName(), PackageManager.GET_SIGNATURES);
            if (pi == null || pi.signatures == null || pi.signatures.length == 0) {
                return null;
            }
            Signature sig = pi.signatures[0];
            byte[] certDer = extractCertDer(sig.toByteArray());
            if (certDer == null) {
                return null;
            }
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return hex(md.digest(certDer));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 双重校验：Java 比对一次，native 再比对一次。
     * 只改 Java 里的字符串常量不足以绕过——native 中另有一份期望值。
     */
    static boolean isGenuine(Context ctx) {
        String fp = currentFingerprint(ctx);
        if (fp == null || !EXPECTED_FP.equals(fp)) {
            return false;
        }
        return NativeGuard.verifyFingerprint(fp.getBytes(), fp.length()) == 1;
    }

    /**
     * 从 Signature.toByteArray() 的返回值中取出证书 DER。
     *
     * 输入可能本身就是证书 DER（v2 签名），也可能是 PKCS#7 块（v1 签名）。
     * CertificateFactory 两种都能解析，因此不必依赖系统版本判断。
     */
    private static byte[] extractCertDer(byte[] raw) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            java.util.Collection<? extends java.security.cert.Certificate> certs =
                    cf.generateCertificates(new java.io.ByteArrayInputStream(raw));
            if (certs.isEmpty()) {
                return null;
            }
            return certs.iterator().next().getEncoded();
        } catch (Exception e) {
            return null;
        }
    }

    /** 从 native 取服务端地址 */
    static String baseUrl() {
        String b = cachedBase;
        if (b != null) {
            return b;
        }
        byte[] buf = new byte[64];
        int n = NativeGuard.getBase(buf, buf.length);
        if (n <= 0) {
            return null;
        }
        b = new String(buf, 0, n);
        cachedBase = b;
        return b;
    }

    /** 从 native 取服务器 EC 公钥（65 字节 SEC1） */
    static byte[] serverPubkey() {
        byte[] buf = new byte[65];
        int n = NativeGuard.getPubkey(buf, buf.length);
        return n == 65 ? buf : null;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format(Locale.ROOT, "%02x", x));
        }
        return sb.toString();
    }
}
