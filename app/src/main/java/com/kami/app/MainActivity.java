package com.kami.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 单页卡密界面：未激活时输入卡密，激活后展示授权状态与已解锁功能。
 * 卡密、最近一次功能列表与到期时间缓存在 SharedPreferences，启动时先本地展示再后台复验。
 */
public class MainActivity extends Activity {



    private LicenseClient client;
    private ExecutorService executor;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final Handler handler = new Handler(Looper.getMainLooper());

    private EditText codeInput;
    private Button activateBtn;
    private TextView msgText;
    private View activateBox;
    private View statusBox;
    private TextView statusTag;
    private TextView planText;
    private TextView expireText;
    private TextView featureText;
    private TextView deviceText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        executor = Executors.newSingleThreadExecutor();

        codeInput = findViewById(R.id.codeInput);
        activateBtn = findViewById(R.id.activateBtn);
        msgText = findViewById(R.id.msgText);
        activateBox = findViewById(R.id.activateBox);
        statusBox = findViewById(R.id.statusBox);
        statusTag = findViewById(R.id.statusTag);
        planText = findViewById(R.id.planText);
        expireText = findViewById(R.id.expireText);
        featureText = findViewById(R.id.featureText);
        deviceText = findViewById(R.id.deviceText);
        Button verifyBtn = findViewById(R.id.verifyBtn);

        try {
            client = new LicenseClient(this);
        } catch (RuntimeException e) {
            showFatal("应用完整性校验失败，请从官方渠道下载");
            return;
        }

        deviceText.setText("设备标识 " + client.deviceId());

        activateBtn.setOnClickListener(v -> doActivate());
        verifyBtn.setOnClickListener(v -> doVerify());

        RuntimeGuard.start(this, new RuntimeGuard.onStateChange() {
            @Override
            public void onNetwork(final boolean online) {
                runOnUiThread(() -> updateNetBadge(online));
            }

            @Override
            public void onTamper(final String reason) {
                runOnUiThread(() -> showTamper(reason));
            }
        });

        // 环境检测含文件 IO 与 su 调用，必须离开主线程，否则会 ANR
        setBusy(true);
        executor.execute(() -> {
            EnvCheck.Result env = EnvCheck.scan(MainActivity.this);
            DeepAudit.Report deep = DeepAudit.run();

            // 反隐藏：找「隐藏行为」而非「root 文件」
            HideDetect.Report hide = HideDetect.run();

            // 有隐藏迹象但还没拿到 root：强行索取授权，不授权就退出
            if (HideDetect.shouldRequestRoot(hide, env) && !env.rootGranted) {
                boolean ok = EnvCheck.trySu();
                if (!ok) {
                    final String why = String.join(",", hide.signals);
                    ui.post(() -> {
                        setBusy(false);
                        showFatal("检测到环境隐藏迹象（" + why + "），请授予 root 权限后重试");
                        delayExit(2500);
                    });
                    return;
                }
            }

            // 检测到 root 且已授权：必须通过特权守护进程的独立审计
            // 这一步无法被 Java 层 hook 绕过，因为它跑在另一个进程里
            PrivGuard.Verdict priv = null;
            if (env.rootDetected && env.rootGranted) {
                priv = PrivGuard.run(MainActivity.this);
            }

            final PrivGuard.Verdict pv = priv;
            ui.post(() -> {
                setBusy(false);
                if (deep.injectDetected || deep.frameworkDetected) {
                    showFatal("检测到注入框架或不安全环境，本软件无法运行");
                    delayExit(1800);
                    return;
                }
                if (pv != null) {
                    if (!pv.ran) {
                        showFatal("环境审计模块未能运行，请确认已授予 root 权限后重试");
                        delayExit(1800);
                        return;
                    }
                    if (!pv.clean) {
                        showFatal("检测到内核模块或系统防护已被关闭，请恢复后重试");
                        delayExit(1800);
                        return;
                    }
                }
                // 100% 确定的虚拟环境：卸载本应用（只删自己，不碰其他数据）
                if (SelfDestruct.isDefinitelyVirtual(env)) {
                    showFatal("检测到虚拟运行环境，本应用不支持在其中使用");
                    executor.execute(() -> SelfDestruct.uninstall(MainActivity.this));
                    delayExit(3000);
                    return;
                }
                if (!env.emulator && !(env.rootDetected && !env.rootGranted)) {
                    askShizukuIfPresent();
                    afterEnvGate(env);
                } else {
                    rejectEnv(env);
                }
            });
        });
    }

    /** 环境通过后继续原有流程 */
    private void afterEnvGate(EnvCheck.Result env) {
        if (!env.isNormalUser()) {
            deviceText.setText(deviceText.getText() + " · 已授权环境");
        }

        String saved = LicenseStore.savedCode(this);
        if (!TextUtils.isEmpty(saved)) {
            codeInput.setText(saved);
            showFromCache();
            doVerify();
        }
    }

    /** 环境不通过：说明原因后强制退出 */
    private void rejectEnv(EnvCheck.Result env) {
        if (env.emulator) {
            showFatal("检测到模拟器环境，本软件不支持在模拟器中运行");
        } else {
            showFatal("检测到 root 环境但未获得授权，请授予后重试");
        }
        delayExit(1800);
    }

    @Override
    protected void onDestroy() {
        RuntimeGuard.stop();
        ShizukuCheck.removeResult(permissionRequestResult);
        executor.shutdownNow();
        super.onDestroy();
    }

    /** 顶部显示联网状态，每分钟刷新 */
    private void updateNetBadge(boolean online) {
        if (deviceText == null) {
            return;
        }
        String base = "设备 " + client.deviceId();
        deviceText.setText(online ? base + " · 已联网" : base + " · 离线");
        deviceText.setTextColor(online ? 0xFF6B7280 : 0xFFB42318);
    }

    /**
     * 检测到调试/注入：让进程退出。
     *
     * 只弹提示等于没有防护——用 Frida 挂着照样能用。
     * native 侧已按进程名判断，PRoot/沙盒这类正常环境不会误判。
     */
    private void showTamper(String reason) {
        if (isFinishing()) {
            return;
        }
        showMessage("检测到调试环境（" + reason + "），即将退出");
        codeInput.setEnabled(false);
        activateBtn.setEnabled(false);
        handler.postDelayed(NativeGuard::exitNow, 1200);
    }

    /** 致命错误：显示原因并禁用所有交互，不直接崩溃以便取证 */
    /** 有 Shizuku 就请求授权，没有则什么都不做 */
    private void askShizukuIfPresent() {
        if (!ShizukuCheck.isInstalled(this)) {
            return;
        }
        if (!ShizukuCheck.isServiceAlive()) {
            // 装了管理器但服务没起（未通过 ADB/root 启动），无法请求
            return;
        }
        if (ShizukuCheck.isGranted()) {
            return;
        }
        ShizukuCheck.onResult(permissionRequestResult);
        ShizukuCheck.request(this);
    }

    private final rikka.shizuku.Shizuku.OnRequestPermissionResultListener permissionRequestResult =
            (requestCode, grantResult) -> {
                ShizukuCheck.removeResult(this.permissionRequestResult);
                if (grantResult != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                    runOnUiThread(() -> {
                        showFatal("已安装 Shizuku 但拒绝授权，请授予后重试");
                        delayExit(1500);
                    });
                }
            };

    private void delayExit(long ms) {
        handler.postDelayed(NativeGuard::exitNow, ms);
    }

    private void showFatal(String msg) {
        codeInput.setEnabled(false);
        activateBtn.setEnabled(false);
        showMessage(msg);
    }

    private void doActivate() {
        String code = normalize(codeInput.getText().toString());
        if (code.length() != 16) {
            showMessage("卡密格式应为 16 位，如 ABCD-EFGH-IJKL-MNOP");
            return;
        }
        setBusy(true);
        hideMessage();
        executor.execute(() -> {
            LicenseClient.Result r = client.activate(code);
            ui.post(() -> onResult(r, code, true));
        });
    }

    private void doVerify() {
        String code = normalize(codeInput.getText().toString());
        if (code.length() != 16) {
            return;
        }
        hideMessage();
        executor.execute(() -> {
            LicenseClient.Result r = client.verify(code);
            ui.post(() -> onResult(r, code, false));
        });
    }

    private void onResult(LicenseClient.Result r, String code, boolean fromActivate) {
        setBusy(false);
        if (r.ok) {
            LicenseStore.save(this, code, r.license, r.sig);
            hideMessage();
            render(r.plan, r.features, r.expireAt);
            if (fromActivate) {
                showUnlockDialog(r.plan, r.features, r.expireAt);
            }
            return;
        }
        // 已激活用户在复验失败时保留界面并说明原因；首次激活失败则留在输入页
        String text = describe(r.error, r.message);
        if (!fromActivate && !LicenseStore.savedCode(this).isEmpty()) {
            showMessage("校验未通过：" + text);
        } else {
            showMessage(text);
        }
    }

    private void showFromCache() {
        // 只认服务端签名过的 license；直接改 prefs 里的 plan/features 无效
        if (!client.isAuthorized()) {
            return;
        }
        LicenseStore.Grant g = LicenseStore.load(this, client.deviceId());
        if (g == null) {
            return;
        }
        render(g.plan, g.features, g.expireAt);
    }

    /** 解锁成功弹窗：显示卡密、套餐、到期时间与剩余时长。 */
    private void showUnlockDialog(String plan, String[] features, long expireAt) {
        View v = getLayoutInflater().inflate(R.layout.dialog_unlocked, null);
        TextView remain = v.findViewById(R.id.dlgRemain);
        TextView detail = v.findViewById(R.id.dlgDetail);

        String state = remainText(expireAt);
        remain.setText(state);

        StringBuilder sb = new StringBuilder();
        sb.append("套餐：").append(planLabel(plan));
        if (expireAt > 0) {
            sb.append('\n').append("到期：")
              .append(new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.CHINA).format(new Date(expireAt)));
        }
        sb.append('\n').append("功能：");
        for (int i = 0; i < features.length; i++) {
            if (i > 0) {
                sb.append('、');
            }
            sb.append(featureLabel(features[i]).replace("• ", ""));
        }
        detail.setText(sb.toString());

        AlertDialog dlg = new AlertDialog.Builder(this)
                .setView(v)
                .setCancelable(false)
                .create();
        v.findViewById(R.id.dlgOk).setOnClickListener(x -> dlg.dismiss());
        dlg.show();
    }

    /** 永久与带期限分开表达，剩余不足一天精确到小时。 */
    private static String remainText(long expireAt) {
        if (expireAt <= 0) {
            return "永久有效";
        }
        long left = expireAt - System.currentTimeMillis();
        if (left <= 0) {
            return "已过期";
        }
        long days = left / 86400000L;
        long hours = (left % 86400000L) / 3600000L;
        if (days > 0) {
            return "剩余 " + days + " 天" + (hours > 0 ? " " + hours + " 小时" : "");
        }
        long mins = (left % 3600000L) / 60000L;
        return "剩余 " + hours + " 小时 " + mins + " 分钟";
    }

    private void render(String plan, String[] features, long expireAt) {
        activateBox.setVisibility(View.GONE);
        statusBox.setVisibility(View.VISIBLE);

        boolean expired = client.isExpiredLocally();
        statusTag.setText(expired ? "已过期" : "已激活");
        statusTag.setTextColor(expired ? 0xFFB42318 : 0xFF18794E);
        statusTag.setBackgroundColor(expired ? 0xFFFDECED : 0xFFE7F7EE);

        planText.setText("套餐：" + planLabel(plan));
        expireText.setText("有效期：" + (expireAt < 0 ? "永久"
                : new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.CHINA).format(new Date(expireAt))));

        StringBuilder sb = new StringBuilder();
        for (String f : features) {
            sb.append(featureLabel(f)).append('\n');
        }
        featureText.setText(sb.length() == 0 ? "无" : sb.toString().trim());
    }

    private void setBusy(boolean busy) {
        activateBtn.setEnabled(!busy);
        activateBtn.setText(busy ? "处理中…" : "激 活");
    }

    private void showMessage(String text) {
        msgText.setText(text);
        msgText.setVisibility(View.VISIBLE);
    }

    private void hideMessage() {
        msgText.setVisibility(View.GONE);
    }

    /** 去掉分隔符并转大写，服务端同样会做归一化 */
    private static String normalize(String raw) {
        return raw.replaceAll("[^A-Za-z0-9]", "").toUpperCase(Locale.ROOT);
    }

    private static String planLabel(String plan) {
        switch (plan) {
            case "basic": return "基础版";
            case "pro": return "专业版";
            case "trial7": return "7 天试用";
            case "team": return "团队版";
            default: return plan;
        }
    }

    private static String featureLabel(String key) {
        switch (key) {
            case "core": return "• 基础功能";
            case "export": return "• 数据导出";
            case "batch": return "• 批量处理";
            case "api": return "• 开放接口";
            default: return "• " + key;
        }
    }

    private String describe(String error, String message) {
        switch (error) {
            case "invalid_code": return "卡密不存在，请检查是否输入有误";
            case "disabled": return "该卡密已被停用";
            case "expired": return "该卡密已过期";
            case "device_limit": return "该卡密已绑定其他设备，请先联系客服解绑";
            case "device_revoked": return "本机授权已被解绑";
            case "device_mismatch": return "本机未激活此卡密";
            case "replay": return "请求重复，请重试";
            case "bad_timestamp": return "设备时间不准，请校准系统时间";
            case "too_many": return "操作过于频繁，请稍后再试";
            case "network": return "网络连接失败，请检查网络后重试";
            case "bad_signature": return "服务端响应校验失败";
            default: return TextUtils.isEmpty(message) ? error : message;
        }
    }
}
