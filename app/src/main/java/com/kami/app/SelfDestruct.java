package com.kami.app;

import android.content.Context;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * 自毁：在确认的虚拟环境中卸载本应用。
 *
 * 与「格机」的区别：只作用于本应用自身，用户重装即可恢复，
 * 不影响设备上的任何其他数据。
 *
 * 触发条件必须严格——误判会删掉正常用户的应用，所以：
 *   1. 必须是「确定」的虚拟环境（多个强特征同时命中）
 *   2. 必须已获得 root 或 Shizuku 权限（否则做不到，也不强求）
 *   3. 只执行 pm uninstall 本包名，不做任何其他操作
 */
final class SelfDestruct {

    private SelfDestruct() {
    }

    /**
     * 卸载本应用。优先用 Shizuku（shell 权限即可），退而用 su。
     *
     * @return true 表示卸载命令已发出
     */
    static boolean uninstall(Context ctx) {
        String pkg = ctx.getPackageName();

        if (ShizukuCheck.isGranted()) {
            if (uninstallViaShizuku(pkg)) {
                return true;
            }
        }

        if (EnvCheck.findSu() != null) {
            if (uninstallViaSu(pkg)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 通过 Shizuku 执行 pm uninstall。
     *
     * Shizuku 没有对外暴露 newProcess 的静态封装，需要自己包一层 binder 调用。
     * 这里用反射拿到 IShizukuService，避免直接依赖 aidl 生成类。
     */
    private static boolean uninstallViaShizuku(String pkg) {
        try {
            Class<?> svcCls = Class.forName("moe.shizuku.server.IShizukuService$Stub");
            android.os.IBinder binder = rikka.shizuku.Shizuku.getBinder();
            if (binder == null) {
                return false;
            }
            Object svc = svcCls.getMethod("asInterface", android.os.IBinder.class)
                    .invoke(null, binder);

            // newProcess(String[] cmd, String[] env, String dir)
            Object remote = svc.getClass()
                    .getMethod("newProcess", String[].class, String[].class, String.class)
                    .invoke(svc,
                            new String[]{"sh", "-c", "pm uninstall " + pkg},
                            null, null);
            if (remote == null) {
                return false;
            }
            Object code = remote.getClass().getMethod("waitFor").invoke(remote);
            return code instanceof Integer && (Integer) code == 0;
        } catch (Throwable e) {
            return false;
        }
    }

    /** 通过 su 执行 pm uninstall */
    private static boolean uninstallViaSu(String pkg) {
        Process p = null;
        try {
            // pm uninstall 由 shell 执行即可，不需要 root，
            // 但无 root 时应用无法自删，只能借 su
            p = Runtime.getRuntime().exec(new String[]{"su", "-c", "pm uninstall " + pkg});

            final Process proc = p;
            final boolean[] done = {false};
            Thread killer = new Thread(() -> {
                try {
                    Thread.sleep(6000);
                    if (!done[0]) {
                        proc.destroy();
                    }
                } catch (InterruptedException ignored) {
                }
            });
            killer.setDaemon(true);
            killer.start();

            StringBuilder out = new StringBuilder();
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = r.readLine()) != null) {
                out.append(line);
            }
            r.close();
            p.waitFor();
            done[0] = true;
            return out.toString().contains("Success");
        } catch (Exception e) {
            return false;
        } finally {
            if (p != null) {
                try {
                    p.destroy();
                } catch (Exception ignored) {
                }
            }
        }
    }

    /**
     * 是否为「确定」的虚拟环境。
     *
     * 比 EnvCheck.isEmulator() 更严格：要求多个独立强特征同时成立。
     * 这一步判定错误会删掉用户的正版应用，所以宁可漏判不可误判。
     */
    static boolean isDefinitelyVirtual(EnvCheck.Result env) {
        if (!env.emulator) {
            return false;
        }
        int strong = 0;

        // 1. 模拟器特有的设备节点或程序
        if (exists("/dev/qemu_pipe") || exists("/dev/socket/qemud")
                || exists("/sys/qemu_trace") || exists("/system/bin/qemu-props")) {
            strong++;
        }

        // 2. 硬件为通用占位值（真机不会这样）
        String hw = android.os.Build.HARDWARE;
        if (hw != null && (hw.equals("goldfish") || hw.equals("ranchu")
                || hw.equals("vbox86") || hw.contains("qemu"))) {
            strong++;
        }

        // 3. 产品名/型号含模拟器标识
        String product = android.os.Build.PRODUCT;
        String model = android.os.Build.MODEL;
        if ((product != null && (product.contains("sdk") || product.contains("emulator")
                || product.contains("vbox")))
                || (model != null && model.contains("Android SDK built for"))) {
            strong++;
        }

        // 4. x86 架构 + ARM ABI 翻译层，是模拟器的典型特征
        String[] abis = android.os.Build.SUPPORTED_ABIS;
        if (abis != null) {
            boolean hasX86 = false;
            boolean hasArm = false;
            for (String a : abis) {
                if (a.contains("x86")) {
                    hasX86 = true;
                }
                if (a.contains("arm")) {
                    hasArm = true;
                }
            }
            if (hasX86 && hasArm) {
                strong++;
            }
        }

        return strong >= 3;
    }

    private static boolean exists(String p) {
        try {
            return new java.io.File(p).exists();
        } catch (Exception e) {
            return false;
        }
    }
}
