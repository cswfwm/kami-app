package com.kami.app;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

/**
 * 授权状态的唯一可信来源。
 *
 * 只持久化服务端签发的 license 与其签名，其余信息（套餐、功能、到期）
 * 都从 license 中解析，并且每次读取都重新验签。
 *
 * 这样直接往 SharedPreferences 里写 plan/features/expire 是无效的：
 * 没有服务端私钥就造不出能通过验签的 license。
 */
final class LicenseStore {

    private static final String PREFS = "kami_state";
    private static final String K_LICENSE = "license";
    private static final String K_SIG = "sig";
    private static final String K_CODE = "code";

    /** 服务端签名公钥（ECDSA P-256），与响应签名同一把 */
    private static final String PUBLIC_KEY_PEM =
            "-----BEGIN PUBLIC KEY-----\n"
          + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgxbmKjxvbzeI3AsJm0LNid4MOrKj\n"
          + "imR93TDcB2T6hWSBrQjhJpBkYHsMRdDK/XZLCeCSCCC9UxEXyuwvuqn+fw==\n"
          + "-----END PUBLIC KEY-----";

    /** 验签通过后的授权快照 */
    static final class Grant {
        final String license;
        final String sig;
        final String plan;
        final String[] features;
        final long expireAt;

        Grant(String license, String sig, String plan, String[] features, long expireAt) {
            this.license = license;
            this.sig = sig;
            this.plan = plan;
            this.features = features;
            this.expireAt = expireAt;
        }
    }

    private LicenseStore() {
    }

    static void save(Context ctx, String code, String license, String sig) {
        prefs(ctx).edit()
                .putString(K_CODE, code)
                .putString(K_LICENSE, license)
                .putString(K_SIG, sig)
                .apply();
    }

    static String savedCode(Context ctx) {
        return prefs(ctx).getString(K_CODE, "");
    }

    static void clear(Context ctx) {
        prefs(ctx).edit().clear().apply();
    }

    /**
     * 读出并验签。签名无效、缺少字段、设备不符都返回 null，
     * 上层据此判定为未授权——不依赖任何明文存储的 plan/features。
     */
    static Grant load(Context ctx, String deviceId) {
        SharedPreferences sp = prefs(ctx);
        String license = sp.getString(K_LICENSE, "");
        String sig = sp.getString(K_SIG, "");
        if (license.isEmpty() || sig.isEmpty()) {
            return null;
        }
        return verify(license, sig, deviceId);
    }

    /** 验签 + 解析，不读存储。响应处理与本地缓存共用这一条路径。 */
    static Grant verify(String license, String sig, String deviceId) {
        try {
            PublicKey key = loadPublicKey();
            Signature sg = Signature.getInstance("SHA256withECDSA");
            sg.initVerify(key);
            sg.update(license.getBytes("UTF-8"));
            if (!sg.verify(Base64Url.decode(sig))) {
                return null;
            }

            String payloadJson = new String(Base64Url.decode(license), "UTF-8");
            JSONObject p = new JSONObject(payloadJson);

            // 许可证必须绑定本机，防止把别人的 license 拷过来
            if (!deviceId.equals(p.optString("device"))) {
                return null;
            }

            JSONArray arr = p.optJSONArray("features");
            String[] feats = new String[arr == null ? 0 : arr.length()];
            for (int i = 0; i < feats.length; i++) {
                feats[i] = arr.getString(i);
            }
            Object exp = p.opt("expire_at");
            long expireAt = (exp == null || exp == JSONObject.NULL) ? -1 : p.getLong("expire_at") * 1000L;

            return new Grant(license, sig, p.optString("plan"), feats, expireAt);
        } catch (Exception e) {
            return null;
        }
    }

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static PublicKey loadPublicKey() throws Exception {
        String body = PUBLIC_KEY_PEM
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = android.util.Base64.decode(body, android.util.Base64.DEFAULT);
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
    }
}
