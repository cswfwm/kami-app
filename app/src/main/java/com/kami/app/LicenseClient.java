package com.kami.app;

import android.content.Context;
import android.provider.Settings;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 卡密客户端。只内置公钥，验签在本地完成，服务端私钥无法伪造。
 *
 * 用法：
 *   LicenseClient c = new LicenseClient(context);
 *   LicenseClient.Result r = c.activate("ABCD-EFGH-IJKL-MNOP");
 *   if (r.ok) { if (c.hasFeature("export")) { ... } }
 *
 * 注意：本类处理了该免费主机前置的 AES 挑战（非浏览器 UA 会收到 aes.js 挑战页），
 * 因此不要替换 User-Agent，也不要走系统 Uri 下载。
 */
public final class LicenseClient {

    /** 服务端公钥（ECDSA P-256），固定写入 APK，用于验证响应签名。 */
    private static final String PUBLIC_KEY_PEM =
            "-----BEGIN PUBLIC KEY-----\n"
          + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgxbmKjxvbzeI3AsJm0LNid4MOrKj\n"
          + "imR93TDcB2T6hWSBrQjhJpBkYHsMRdDK/XZLCeCSCCC9UxEXyuwvuqn+fw==\n"
          + "-----END PUBLIC KEY-----";

    // 服务端地址由 native 提供，DEX 中不出现明文，避免解包后一行替换
    private static String defaultBase() {
        String b = Integrity.baseUrl();
        if (b == null || b.isEmpty()) {
            throw new IllegalStateException("配置不可用");
        }
        return b;
    }
    private static final String UA =
            "Mozilla/5.0 (Linux; Android 5.1; MI 8) AppleWebKit/537.36 (KHTML, like Gecko) "
          + "Chrome/50.0.2661.89 Mobile Safari/537.36";
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private final Context context;
    private final String baseUrl;
    private final String deviceId;
    private final DeviceKey key;
    private final String deviceName;
    private final String appVersion;

    /** __test cookie 缓存（服务端挑战解出的结果，有效期约 6 小时）。 */
    private final Map<String, String> cookies = new ConcurrentHashMap<String, String>();

    private String cachedLicense;
    private String[] cachedFeatures = new String[0];
    private long cachedExpireAt = -1;
    private String cachedPlan = "";
    private String cachedSig = "";
    /** 本次请求协商出的会话密钥，用于解密对应响应 */
    private byte[] lastSessionKey;

    /**
     * 服务端时间与本机时间的偏移（毫秒）。
     *
     * 数据里的 expire 是服务端时间戳，如果直接用本机时间判断，
     * 用户把系统时间调回去就能续命。这里在每次成功请求后记录偏移，
     * 之后用「本机时间 + 偏移」近似服务端时间。
     */
    private static volatile long serverTimeOffsetMs = 0;

    public LicenseClient(Context ctx) {
        this(ctx, defaultBase());
    }

    public LicenseClient(Context ctx, String base) {
        this.context = ctx.getApplicationContext();
        // 重打包后签名必变，这里直接拒绝，连请求都不发
        if (!Integrity.isGenuine(this.context)) {
            throw new IllegalStateException("签名校验失败");
        }
        String b = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        if (b.startsWith("http://")) {
            // 卡密会随请求体明文传输，明文 HTTP 等于把卡密广播给同一网络的任何人
            throw new IllegalArgumentException("base url must use https");
        }
        this.baseUrl = b;
        this.deviceId = buildDeviceId();
        this.key = DeviceKey.loadOrCreate(this.context);
        this.deviceName = android.os.Build.MANUFACTURER + " " + android.os.Build.MODEL;
        this.appVersion = readVersionName();
    }

    // ---------------------------------------------------------------- 对外接口

    /** 首次激活：绑定设备并领取许可证。 */
    public Result activate(String code) {
        try {
            String nonce = DeviceKey.nonce();
            long ts = System.currentTimeMillis() / 1000L;
            JSONObject body = new JSONObject();
            body.put("action", "activate");
            body.put("code", code);
            body.put("device", deviceId);
            body.put("device_id", deviceId);
            body.put("device_name", deviceName);
            body.put("app_version", appVersion);
            body.put("nonce", nonce);
            body.put("ts", ts);
            body.put("pubkey", key.publicKey());
            body.put("fp", new JSONObject(DeepAudit.buildFpJson()));
            body.put("sig", key.sign("activate", deviceId, ts, nonce));
            return handleResponse(post("/api.php?action=activate", body));
        } catch (Exception e) {
            return Result.fail("network", e.toString());
        }
    }

    /** 联网复验：建议每次启动调用一次，失败时回退到本地缓存。 */
    public Result verify(String code) {
        try {
            String nonce = DeviceKey.nonce();
            long ts = System.currentTimeMillis() / 1000L;
            JSONObject body = new JSONObject();
            body.put("action", "verify");
            body.put("code", code);
            body.put("device", deviceId);
            body.put("device_id", deviceId);
            body.put("nonce", nonce);
            body.put("ts", ts);
            body.put("sig", key.sign("verify", deviceId, ts, nonce));
            body.put("fp", new JSONObject(DeepAudit.buildFpJson()));
            return handleResponse(post("/api.php?action=verify", body));
        } catch (Exception e) {
            return Result.fail("network", e.toString());
        }
    }
    /** 拉取套餐清单（只读，但也必须套壳并验签）。 */
    public Result plans() {
        try {
            String nonce = DeviceKey.nonce();
            long ts = System.currentTimeMillis() / 1000L;
            JSONObject body = new JSONObject();
            body.put("action", "plans");
            body.put("device", deviceId);
            body.put("nonce", nonce);
            body.put("ts", ts);
            body.put("fp", new JSONObject(DeepAudit.buildFpJson()));

            String raw = post("/api.php?action=plans", body);
            JSONObject json = new JSONObject(openResponse(raw));
            if (!json.optBoolean("ok")) {
                return Result.fail(json.optString("error", "unknown"), json.optString("msg", ""));
            }
            return Result.ok("", new String[0], -1, "", "", "");
        } catch (Exception e) {
            return Result.fail("network", e.toString());
        }
    }

    /** 当前是否解锁某功能（未激活或已过期返回 false）。 */
    public boolean hasFeature(String feature) {
        if (isExpiredLocally() || !isAuthorized()) {
            return false;
        }
        for (String f : cachedFeatures) {
            if (f.equals(feature)) {
                return true;
            }
        }
        return false;
    }

    public String[] features() {
        return cachedFeatures.clone();
    }

    public String plan() {
        return cachedPlan;
    }

    /** 估算的服务端当前时间（秒），用于判断数据是否过期 */
    public static long serverNowSeconds() {
        return (System.currentTimeMillis() + serverTimeOffsetMs) / 1000L;
    }

    /**
     * 是否持有有效授权。每次调用都从存储重新验签，
     * 直接改 SharedPreferences 里的明文键不会影响结果。
     */
    public boolean isAuthorized() {
        LicenseStore.Grant g = LicenseStore.load(context, deviceId);
        if (g == null || FeatureData.load(context) == null) {
            return false;
        }
        return nativeAuthorize(g);
    }

    /**
     * 完整性 + 授权一并交给 native 判定，Java 只取一个数字。
     * 这样 Frida 只 hook 某一项检查（比如指纹）是无效的，
     * 必须整体改写 authorize 的返回值或逻辑。
     */
    private boolean nativeAuthorize(LicenseStore.Grant g) {
        String fp = Integrity.currentFingerprint(context);
        if (fp == null) {
            return false;
        }
        byte[] fpBytes = fp.getBytes(UTF8);
        long expireSec = g.expireAt < 0 ? -1 : g.expireAt / 1000L;
        int r = NativeGuard.authorize(fpBytes, fpBytes.length,
                (int) expireSec, (int) (System.currentTimeMillis() / 1000L),
                g.license.getBytes(UTF8), g.sig.getBytes(UTF8));

        // 负值是明确的拒绝原因；命中调试检测则直接退出，不再给用户「继续使用」的机会
        if (r == -100) {
            NativeGuard.exitNow();
        }
        return r > 0;
    }

    /** 到期时间（毫秒时间戳），-1 表示永久。 */
    public long expireAt() {
        return cachedExpireAt;
    }

    public String deviceId() {
        return deviceId;
    }

    /**
     * 离线可用性判断：到期前或宽限期内返回 true。
     * 超过宽限期必须联网复验，避免长期断网绕过停用。
     */
    public boolean isExpiredLocally() {
        if (cachedExpireAt < 0) {
            return false;
        }
        return System.currentTimeMillis() > cachedExpireAt + GRACE_MS;
    }

    private static final long GRACE_MS = 3L * 24 * 60 * 60 * 1000;

    // ---------------------------------------------------------------- 响应处理

    private Result handleResponse(String raw) throws Exception {
        JSONObject json = new JSONObject(openResponse(raw));
        if (!json.optBoolean("ok")) {
            return Result.fail(json.optString("error", "unknown"), json.optString("msg", ""));
        }
        // 校准服务端时间：server_time 由服务端在响应中给出
        long serverTime = json.optLong("server_time", 0);
        if (serverTime > 0) {
            serverTimeOffsetMs = serverTime * 1000L - System.currentTimeMillis();
        }

        String license = json.getString("license");
        String sig = json.getString("sig");

        // 响应里的授权信息一律从 license 验签解析，不信任任何明文伴随字段
        LicenseStore.Grant g = LicenseStore.verify(license, sig, deviceId);
        if (g == null) {
            return Result.fail("bad_signature", "响应签名校验失败或设备不符");
        }

        cachedLicense = g.license;
        cachedSig = g.sig;
        cachedPlan = g.plan;
        cachedFeatures = g.features;
        cachedExpireAt = g.expireAt;

        // 与本地路径同一套 native 判定，避免两条链路防护不一致
        if (!nativeAuthorize(g)) {
            return Result.fail("native_reject", "授权校验未通过");
        }

        // 功能数据必须能解密，否则视为未授权：这是「无服务器不可用」的关键
        String plain = FeatureData.decrypt(json.optJSONObject("data"));
        if (plain == null) {
            return Result.fail("no_data", "功能数据缺失，请联网后重试");
        }
        FeatureData.save(context, plain);

        return Result.ok(g.plan, g.features, g.expireAt, g.license, g.sig, plain);
    }

    private static boolean verifySignature(String licenseB64, String sigB64) {
        try {
            PublicKey key = loadPublicKey();
            Signature sg = Signature.getInstance("SHA256withECDSA");
            sg.initVerify(key);
            sg.update(licenseB64.getBytes(UTF8));
            return sg.verify(Base64Url.decode(sigB64));
        } catch (Exception e) {
            return false;
        }
    }

    private static PublicKey loadPublicKey() throws Exception {
        String body = PUBLIC_KEY_PEM
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = android.util.Base64.decode(body, android.util.Base64.DEFAULT);
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
    }

    // ---------------------------------------------------------------- 网络

    private String post(String path, JSONObject body) throws Exception {
        // 每次请求用临时 ECDH 密钥协商，客户端只持服务端公钥
        Ecies.Sealed sealed = Ecies.seal(body.toString().getBytes(UTF8));
        lastSessionKey = sealed.sessionKey;
        byte[] payload = ("{\"epk\":\"" + sealed.epk + "\",\"salt\":\"" + sealed.salt
                + "\",\"iv\":\"" + sealed.iv + "\",\"ct\":\"" + sealed.ct
                + "\",\"tag\":\"" + sealed.tag + "\"}").getBytes(UTF8);
        String last = "";
        for (int attempt = 0; attempt < 4; attempt++) {
            HttpURLConnection conn = open(path, "POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            OutputStream os = conn.getOutputStream();
            os.write(payload);
            os.close();

            int code = conn.getResponseCode();
            String text = read(conn, code);
            conn.disconnect();

            if (text != null && text.contains("slowAES.decrypt")) {
                solveChallenge(text);
                continue;
            }
            if (text != null && text.length() > 0) {
                return text;
            }
            last = text == null ? "" : text;
            // 空响应：主机在缺少 __test cookie 时会丢弃 POST，先取一次 GET 再重试
            primeCookie(path);
        }
        throw new IllegalStateException("empty response from server: " + last);
    }

    /**
     * 解开响应信封：先验服务端 ECDSA 签名，再逐层解密。
     * 先验签是关键：伪造服务器即使拿到对称密钥也过不了这一步。
     */
    private String openResponse(String raw) throws Exception {
        JSONObject outer = new JSONObject(raw);
        String iv = outer.optString("iv", "");
        String ct = outer.optString("ct", "");
        String tag = outer.optString("tag", "");
        if (iv.isEmpty() || ct.isEmpty() || tag.isEmpty()) {
            // 只有完全无信封时才是服务端的明文错误，此时不含任何授权信息
            String err = outer.optString("error", "");
            if (!err.isEmpty() && outer.length() <= 3) {
                throw new IllegalStateException(err);
            }
            throw new SecurityException("响应格式异常");
        }
        if (lastSessionKey == null) {
            throw new IllegalStateException("缺少会话密钥");
        }

        // 先验签再解密。签名覆盖 iv||ct||tag 的原始字节，
        // 任何改动（含替换整段密文）都会导致验签失败。
        String sigB64 = outer.optString("s", "");
        if (sigB64.isEmpty()) {
            throw new SecurityException("响应缺少签名");
        }
        byte[] ivRaw = Base64Url.decode(iv);
        byte[] ctRaw = Base64Url.decode(ct);
        byte[] tagRaw = Base64Url.decode(tag);
        byte[] signed = new byte[ivRaw.length + ctRaw.length + tagRaw.length];
        System.arraycopy(ivRaw, 0, signed, 0, ivRaw.length);
        System.arraycopy(ctRaw, 0, signed, ivRaw.length, ctRaw.length);
        System.arraycopy(tagRaw, 0, signed, ivRaw.length + ctRaw.length, tagRaw.length);

        Signature sg = Signature.getInstance("SHA256withECDSA");
        sg.initVerify(loadPublicKey());
        sg.update(signed);
        if (!sg.verify(Base64Url.decode(sigB64))) {
            throw new SecurityException("响应签名无效，可能不是真实服务器");
        }

        return new String(Ecies.open(iv, ct, tag, lastSessionKey), UTF8);
    }

    private void primeCookie(String path) throws Exception {
        HttpURLConnection conn = open(path, "GET");
        int code = conn.getResponseCode();
        String text = read(conn, code);
        conn.disconnect();
        if (text != null && text.contains("slowAES.decrypt")) {
            solveChallenge(text);
        }
    }

    private HttpURLConnection open(String path, String method) throws Exception {
        URL u = new URL(baseUrl + path);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();

        // 证书固定：只认内置的那张证书的公钥，与系统信任了哪些 CA 无关。
        // 这样即使 DNS 被污染、或攻击者让系统信任了他的 CA，连接也会失败。
        if (conn instanceof javax.net.ssl.HttpsURLConnection) {
            Pinning.apply((javax.net.ssl.HttpsURLConnection) conn, u.getHost());
        } else {
            // 非 HTTPS 直接拒绝，避免被降级到明文
            throw new SecurityException("仅允许 HTTPS 连接");
        }

        conn.setRequestMethod(method);
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(20000);
        conn.setRequestProperty("User-Agent", UA);
        conn.setRequestProperty("Accept", "*/*");
        String cookie = cookies.get("__test");
        if (cookie != null) {
            conn.setRequestProperty("Cookie", "__test=" + cookie);
        }
        return conn;
    }

    private static String read(HttpURLConnection conn, int code) throws Exception {
        InputStream is = (code >= 200 && code < 400) ? conn.getInputStream() : conn.getErrorStream();
        if (is == null) {
            return "";
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) > 0) {
            bos.write(buf, 0, n);
        }
        is.close();
        return new String(bos.toByteArray(), UTF8);
    }

    // ---------------------------------------------------------------- 前置挑战

    /**
     * 主机对非 Googlebot UA 下发 AES 挑战：页面给出 a,b,c 三段 hex，
     * cookie = AES-128-CBC-decrypt(key=a, iv=b, c)。解出后 6 小时内免挑战。
     */
    private void solveChallenge(String html) throws Exception {
        java.util.List<String> parts = new java.util.ArrayList<String>();
        int idx = 0;
        while (true) {
            int p = html.indexOf("toNumbers(\"", idx);
            if (p < 0) {
                break;
            }
            int start = p + "toNumbers(\"".length();
            int end = html.indexOf("\"", start);
            if (end < 0) {
                break;
            }
            parts.add(html.substring(start, end));
            idx = end;
        }
        if (parts.size() < 3) {
            throw new IllegalStateException("challenge parse failed");
        }
        byte[] key = hexToBytes(parts.get(0));
        byte[] iv = hexToBytes(parts.get(1));
        byte[] ct = hexToBytes(parts.get(2));
        byte[] plain = AesCbc.decrypt(key, iv, ct);
        cookies.put("__test", toHex(plain));
    }

    private static byte[] hexToBytes(String s) {
        int len = s.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    // ---------------------------------------------------------------- 设备标识

    /**
     * 用 ANDROID_ID 做设备指纹。同一设备重装应用保持不变，
     * 恢复出厂/换机才变化，正好对应「同一台机器」的语义。
     */
    private String buildDeviceId() {
        String androidId = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
        if (androidId == null || androidId.length() < 6) {
            androidId = "fallback-" + android.os.Build.FINGERPRINT;
        }
        return "a" + Integer.toHexString(androidId.hashCode()) + "-" + androidId.substring(0, Math.min(8, androidId.length()));
    }

    private String readVersionName() {
        try {
            return context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionName;
        } catch (Exception e) {
            return "0";
        }
    }

    // ---------------------------------------------------------------- 结果

    public static final class Result {
        public final boolean ok;
        public final String error;
        public final String message;
        public final String plan;
        public final String[] features;
        public final long expireAt;
        /** 服务端签发的 license 与签名，持久化后供下次验签 */
        public final String license;
        public final String sig;
        /** 解密后的功能数据。拿不到它就无法使用付费功能。 */
        public final String data;

        private Result(boolean ok, String error, String message, String plan, String[] features,
                       long expireAt, String license, String sig, String data) {
            this.ok = ok;
            this.error = error;
            this.message = message;
            this.plan = plan;
            this.features = features;
            this.expireAt = expireAt;
            this.license = license;
            this.sig = sig;
            this.data = data;
        }

        static Result ok(String plan, String[] features, long expireAt,
                         String license, String sig, String data) {
            return new Result(true, "", "", plan, features, expireAt, license, sig, data);
        }

        static Result fail(String error, String message) {
            return new Result(false, error, message, "", new String[0], -1, "", "", "");
        }
    }
}
