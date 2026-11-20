package com.kami.app;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * 证书固定（Certificate Pinning）。
 *
 * 解决的问题：DNS 污染把域名解析到攻击者服务器时，系统的 CA 校验本应拦住
 * （自签证书会失败）。但如果攻击者能让客户端信任他的 CA——例如诱导安装用户证书、
 * 或在 root 设备上把证书塞进系统信任区——系统校验就会失效。
 *
 * 固定后只认「内置的那张证书的公钥」，任何其他证书一律拒绝，
 * 与系统信任了哪些 CA 无关。
 *
 * 只固定公钥（SPKI）不固定整张证书：证书会定期续期，固定公钥让续期不破坏客户端。
 */
final class Pinning {

    /** 服务端证书公钥（SPKI）的 SHA-256，base64 编码 */
    private static final String PIN_SPKI_SHA256 = "J3Pn6GB/D5DePcex22inD4pwWBBfs73mLiGg0go76pA=";

    /** 必须匹配的域名 */
    private static final String EXPECT_HOST = "uuk.pp.ua";

    private Pinning() {
    }

    /** 为 HttpsURLConnection 装上固定校验的 SSLSocketFactory */
    static SSLSocketFactory pinnedFactory() throws Exception {
        TrustManager tm = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                // 客户端不验证对端
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType)
                    throws java.security.cert.CertificateException {
                if (chain == null || chain.length == 0) {
                    throw new java.security.cert.CertificateException("empty chain");
                }
                if (!matchesPin(chain[0])) {
                    throw new java.security.cert.CertificateException("pin mismatch");
                }
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{tm}, new java.security.SecureRandom());
        return ctx.getSocketFactory();
    }

    /**
     * 校验主机名。
     *
     * 只做后缀匹配不够——攻击者可以注册 xxx.uuk.pp.ua.evil.com。
     * 这里要求主机名以 uuk.pp.ua 结尾，且前一个字符是点（或就是根域名）。
     */
    static boolean hostAllowed(String host) {
        if (host == null) {
            return false;
        }
        String h = host.toLowerCase();
        int idx = h.lastIndexOf(EXPECT_HOST);
        if (idx < 0) {
            return false;
        }
        // 必须恰好以该域名结尾
        if (idx + EXPECT_HOST.length() != h.length()) {
            return false;
        }
        return idx == 0 || h.charAt(idx - 1) == '.';
    }

    /** 计算证书公钥的 SPKI 摘要并与内置值比对 */
    private static boolean matchesPin(X509Certificate cert) {
        try {
            byte[] spki = cert.getPublicKey().getEncoded();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(spki);
            String actual = android.util.Base64.encodeToString(digest, android.util.Base64.NO_WRAP);
            return constantTimeEquals(PIN_SPKI_SHA256, actual);
        } catch (Exception e) {
            return false;
        }
    }

    /** 定长比较，避免时序侧信道 */
    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int r = 0;
        for (int i = 0; i < a.length(); i++) {
            r |= a.charAt(i) ^ b.charAt(i);
        }
        return r == 0;
    }

    /** 给连接装上固定校验与主机名校验 */
    static void apply(HttpsURLConnection conn, String urlHost) throws Exception {
        if (!hostAllowed(urlHost)) {
            throw new java.net.MalformedURLException("host not allowed: " + urlHost);
        }
        conn.setSSLSocketFactory(pinnedFactory());
        conn.setHostnameVerifier((h, session) -> hostAllowed(h));
    }
}
