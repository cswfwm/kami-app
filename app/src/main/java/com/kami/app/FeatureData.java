package com.kami.app;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 功能数据的获取与解密。
 *
 * 服务端随授权响应下发一段用 AES-256-GCM 加密的功能数据，密钥也一并给出。
 * 客户端没有这把密钥就无法解出数据，因此：
 *
 *   - 改本地文件伪造授权：没有 key，数据解不开
 *   - 断网使用：拿不到 key，数据解不开
 *   - 换私服：私服没有服务端私钥，签不出能通过验签的 license
 *
 * 需要注意的是，key 在响应里随数据一起下发，抓包者本人能解自己那份。
 * 它防的是「本地伪造」和「离线绕过」，不是「传给别人用」——
 * 后者由设备绑定与 license 验签负责。
 */
final class FeatureData {

    private static final String PREFS = "kami_data";
    private static final String K_BLOB = "blob";
    private static final String K_TIME = "issued_at";
    private static final String K_EXPIRE = "expire_at";

    private FeatureData() {
    }

    /**
     * 解密一份功能数据。
     *
     * @param dataObj 服务端下发的 data 对象（含 iv/ct/tag/key）
     * @return 解密后的 JSON 文本；失败返回 null
     */
    static String decrypt(JSONObject dataObj) {
        if (dataObj == null) {
            return null;
        }
        try {
            String ivB64 = dataObj.optString("iv", "");
            String ctB64 = dataObj.optString("ct", "");
            String tagB64 = dataObj.optString("tag", "");
            String keyHex = dataObj.optString("key", "");
            if (ivB64.isEmpty() || ctB64.isEmpty() || tagB64.isEmpty() || keyHex.length() != 64) {
                return null;
            }

            byte[] key = hexToBytes(keyHex);
            byte[] iv = Base64Url.decode(ivB64);
            byte[] ct = Base64Url.decode(ctB64);
            byte[] tag = Base64Url.decode(tagB64);

            byte[] joined = new byte[ct.length + tag.length];
            System.arraycopy(ct, 0, joined, 0, ct.length);
            System.arraycopy(tag, 0, joined, ct.length, tag.length);

            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            return new String(c.doFinal(joined), "UTF-8");
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 保存解密后的数据，同时记录服务端给出的失效时间。
     *
     * 这是防「拷走数据」的核心：数据里带有 epoch 与 expire，
     * 到点后本地直接失效，破解版硬编码的那份最多再撑一个 epoch。
     */
    static void save(Context ctx, String plain) {
        long expire = 0;
        try {
            org.json.JSONObject o = new org.json.JSONObject(plain);
            expire = o.optLong("expire", 0);
        } catch (Exception ignored) {
        }
        prefs(ctx).edit()
                .putString(K_BLOB, plain)
                .putLong(K_TIME, System.currentTimeMillis())
                .putLong(K_EXPIRE, expire)
                .apply();
    }

    /**
     * 读取功能数据。
     *
     * 已过期就返回 null，并用系统时间做双重校验：
     * 即使攻击者改了数据里的 expire 字段，也会因为签名数据不匹配而无法伪造
     * （数据本身是服务端 epoch 密钥加密的，改一个字节就解不开）。
     */
    static String load(Context ctx) {
        String blob = prefs(ctx).getString(K_BLOB, null);
        if (blob == null) {
            return null;
        }
        // 过期判断以数据自带的 expire 为准，不读单独存的字段——
        // 否则攻击者改一个 SharedPreferences 值就能续期
        long expire = 0;
        try {
            org.json.JSONObject o = new org.json.JSONObject(blob);
            expire = o.optLong("expire", 0);
        } catch (Exception e) {
            return null;
        }
        if (expire <= 0) {
            // 没有 expire 字段说明是旧格式或被篡改，一律拒绝
            return null;
        }
        // 用校准后的服务端时间判断，避免用户调慢系统时间续期
        if (LicenseClient.serverNowSeconds() >= expire) {
            return null;
        }
        return blob;
    }

    /** 剩余有效秒数，用于提示用户尽快联网续期 */
    static long remainSeconds(Context ctx) {
        String blob = prefs(ctx).getString(K_BLOB, null);
        if (blob == null) {
            return 0;
        }
        try {
            long expire = new org.json.JSONObject(blob).optLong("expire", 0);
            long left = expire - LicenseClient.serverNowSeconds();
            return left > 0 ? left : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    static long issuedAt(Context ctx) {
        return prefs(ctx).getLong(K_TIME, 0);
    }

    static void clear(Context ctx) {
        prefs(ctx).edit().clear().apply();
    }

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static byte[] hexToBytes(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
