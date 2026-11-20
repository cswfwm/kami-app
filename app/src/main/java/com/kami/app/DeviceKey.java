package com.kami.app;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;

/**
 * 每台设备一把专属 ECDSA P-256 密钥。
 *
 * 私钥只存本机 SharedPreferences，公钥在首次激活时交给服务端。
 * 这样 APK 里不含任何共享密钥，逆向拿不到「万能钥匙」，
 * 泄漏也只影响单台设备。
 */
final class DeviceKey {

    private static final String PREFS = "kami_key";
    private static final String K_PRIV = "priv";       // PKCS#8 DER，base64
    private static final String K_PUB = "pub";         // X.509 DER，base64url

    private final PrivateKey priv;
    private final String pubB64Url;

    private DeviceKey(PrivateKey priv, String pubB64Url) {
        this.priv = priv;
        this.pubB64Url = pubB64Url;
    }

    String publicKey() {
        return pubB64Url;
    }

    /** 对 动作+设备+时间戳+nonce 签名，返回 base64url 的 DER 签名。 */
    String sign(String action, String deviceId, long ts, String nonce) throws Exception {
        Signature sg = Signature.getInstance("SHA256withECDSA");
        sg.initSign(priv);
        sg.update(base(action, deviceId, ts, nonce).getBytes("UTF-8"));
        return Base64Url.encode(sg.sign());
    }

    static String base(String action, String deviceId, long ts, String nonce) {
        return action + "\n" + deviceId + "\n" + ts + "\n" + nonce;
    }

    /** 读取本机密钥；不存在则生成一对并存盘。 */
    static DeviceKey loadOrCreate(android.content.Context ctx) {
        android.content.SharedPreferences sp = ctx.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE);
        String privB64 = sp.getString(K_PRIV, null);
        String pubB64 = sp.getString(K_PUB, null);

        if (privB64 != null && pubB64 != null) {
            try {
                KeyFactory kf = KeyFactory.getInstance("EC");
                PrivateKey pk = kf.generatePrivate(new PKCS8EncodedKeySpec(android.util.Base64.decode(privB64, android.util.Base64.NO_WRAP)));
                return new DeviceKey(pk, pubB64);
            } catch (Exception e) {
                // 密钥损坏则重新生成，旧公钥留在服务端会被判签名无效，属可接受的失败
            }
        }

        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            KeyPair kp = g.generateKeyPair();
            PrivateKey pk = kp.getPrivate();
            PublicKey pub = kp.getPublic();
            String pubUrl = Base64Url.encode(pub.getEncoded());

            sp.edit()
                    .putString(K_PRIV, android.util.Base64.encodeToString(pk.getEncoded(), android.util.Base64.NO_WRAP))
                    .putString(K_PUB, pubUrl)
                    .apply();

            return new DeviceKey(pk, pubUrl);
        } catch (Exception e) {
            throw new IllegalStateException("无法创建设备密钥", e);
        }
    }

    static String nonce() {
        byte[] b = new byte[16];
        new SecureRandom().nextBytes(b);
        StringBuilder sb = new StringBuilder(32);
        for (byte x : b) {
            sb.append(String.format(Locale.ROOT, "%02x", x & 0xff));
        }
        return sb.toString();
    }
}
