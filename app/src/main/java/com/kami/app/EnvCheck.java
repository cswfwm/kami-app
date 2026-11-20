package com.kami.app;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 运行环境检测：root 管理器、模拟器、调试环境。
 *
 * 关于「向 root 管理器索取权限」：
 * root 管理器（Magisk / SuperSU / KernelSU / APatch 等）没有统一的授权 API，
 * 它们的工作方式是拦截 su 调用并弹窗询问用户。所以「索取」只能是执行 su，
 * 由管理器决定是否弹窗、是否记住选择。
 *
 * 各家 su 路径不同，必须逐个尝试才能覆盖。只执行 id，不做任何破坏性动作。
 */
final class EnvCheck {

    /** 常见 root 管理器的 su 可执行文件路径 */
    private static final String[] SU_PATHS = {
            // Magisk
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/su/bin/su", "/debug_ramdisk/su",
            // KernelSU / APatch
            "/data/adb/ksu/bin/su", "/data/adb/ap/bin/su",
            "/data/adb/magisk/su",
            // SuperSU / 传统
            "/system/sbin/su", "/vendor/bin/su",
            "/data/local/su", "/data/local/bin/su",
            "/data/local/xbin/su", "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
    };

    /** root 管理器的包名，用于判断「有管理器」而非「有 root」 */
    private static final String[] ROOT_MANAGER_PKGS = {
            "com.topjohnwu.magisk",          // Magisk
            "io.github.vvb2060.magisk",      // Magisk Alpha
            "me.weishu.kernelsu",            // KernelSU
            "me.bmax.apatch",                // APatch
            "eu.chainfire.supersu",          // SuperSU
            "com.koushikdutta.superuser",    // Superuser
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.kingroot.kinguser",         // KingRoot
            "com.kingo.root",                // KingoRoot
            "com.ramdroid.appquarantine",
            "com.devadvance.rootcloak",      // RootCloak（本身就是隐藏工具）
            "com.formyhm.hideroot",
    };

    /** 模拟器特征 */
    private static final String[] EMU_FINGERPRINTS = {
            "generic", "unknown", "google_sdk", "vbox86p",
            "sdk_gphone", "emulator", "Android SDK built for",
            "Genymotion", "NOX", "BlueStacks", "Microvirt", "ldplayer",
    };

    /** 检测结果 */
    static final class Result {
        /** 是否检测到 root 管理器 App、su 文件或 root 专属路径 */
        final boolean rootDetected;
        /** su 是否可执行且获得 uid=0 */
        final boolean rootGranted;
        /** 是否模拟器 */
        final boolean emulator;
        /** 详细原因，用于展示与审计 */
        final List<String> reasons;

        Result(boolean rootDetected, boolean rootGranted, boolean emulator, List<String> reasons) {
            this.rootDetected = rootDetected;
            this.rootGranted = rootGranted;
            this.emulator = emulator;
            this.reasons = reasons;
        }

        /** 普通用户：既没有 root 痕迹，也不是模拟器 */
        boolean isNormalUser() {
            return !rootDetected && !rootGranted && !emulator;
        }
    }

    private EnvCheck() {
    }

    static Result scan(Context ctx) {
        List<String> reasons = new ArrayList<>();

        boolean hasManager = hasRootManagerApp(ctx);
        if (hasManager) {
            reasons.add("root 管理器");
        }

        String su = findSu();
        if (su != null) {
            reasons.add("su:" + su);
        }

        boolean rootOnly = hasRootOnlyPaths();
        if (rootOnly) {
            reasons.add("root 专属路径");
        }

        boolean suInPath = commandExists("su");
        if (suInPath && su == null) {
            reasons.add("su 在 PATH 中");
        }

        boolean rootDetected = hasManager || su != null || rootOnly || suInPath;

        boolean emulator = isEmulator();
        if (emulator) {
            reasons.add("模拟器特征");
        }

        // 只有存在 root 痕迹时才索取授权，避免普通用户被无谓的 su 弹窗骚扰
        boolean granted = false;
        if (rootDetected) {
            granted = trySu();
            reasons.add(granted ? "已授权" : "未授权");
        }

        return new Result(rootDetected, granted, emulator, reasons);
    }

    /** 是否安装了 root 管理器 */
    static boolean hasRootManagerApp(Context ctx) {
        PackageManager pm = ctx.getPackageManager();
        for (String pkg : ROOT_MANAGER_PKGS) {
            try {
                pm.getPackageInfo(pkg, 0);
                return true;
            } catch (PackageManager.NameNotFoundException ignored) {
                // 未安装
            }
        }
        return false;
    }

    /**
     * 找到 su 的路径。
     *
     * 除了硬编码的常见位置，还要遍历 PATH —— 部分环境把 su 放在非标准目录，
     * 只查固定路径会漏掉（实测容器里 su 在 PATH 中但不在任何默认路径下）。
     */
    static String findSu() {
        for (String p : SU_PATHS) {
            try {
                if (new File(p).exists()) {
                    return p;
                }
            } catch (Exception ignored) {
                // 无权限访问，跳过
            }
        }
        // 遍历 PATH
        String path = System.getenv("PATH");
        if (path != null) {
            for (String dir : path.split(":")) {
                if (dir.isEmpty()) {
                    continue;
                }
                try {
                    File f = new File(dir, "su");
                    if (f.exists() && f.canExecute()) {
                        return f.getAbsolutePath();
                    }
                } catch (Exception ignored) {
                }
            }
        }
        return null;
    }

    /** 命令是否可执行（不依赖 PATH 解析，直接试跑） */
    static boolean commandExists(String cmd) {
        Process p = null;
        try {
            p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "command -v " + cmd});
            final Process proc = p;
            final boolean[] done = {false};
            Thread k = new Thread(() -> {
                try {
                    Thread.sleep(1500);
                    if (!done[0]) {
                        proc.destroy();
                    }
                } catch (InterruptedException ignored) {
                }
            });
            k.setDaemon(true);
            k.start();

            StringBuilder out = new StringBuilder();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = r.readLine()) != null) {
                    out.append(line);
                }
            }
            p.waitFor();
            done[0] = true;
            return out.toString().trim().length() > 0;
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

    /** 只有 root 才能读到的路径，存在即高度可疑 */
    private static boolean hasRootOnlyPaths() {
        String[] paths = {
                "/system/app/Superuser.apk",
                "/data/adb/magisk",
                "/data/adb/ksu",
                "/data/adb/ap",
                "/sbin/.magisk",
                "/.magisk",
                "/cache/.disable_magisk",
                "/dev/.magisk.unblock",
        };
        for (String p : paths) {
            try {
                if (new File(p).exists()) {
                    return true;
                }
            } catch (Exception ignored) {
            }
        }
        return false;
    }

    /**
     * 执行 su 索取授权，这是触发管理器弹窗的唯一方式。
     *
     * 只跑 id，读输出是否含 uid=0。超时 5 秒避免用户不理会弹窗导致挂起。
     */
    static boolean trySu() {
        String su = findSu();
        if (su == null) {
            su = "su";
        }
        Process p = null;
        try {
            p = Runtime.getRuntime().exec(new String[]{su, "-c", "id"});
            final Process proc = p;
            final boolean[] done = {false};
            Thread killer = new Thread(() -> {
                try {
                    Thread.sleep(5000);
                    if (!done[0]) {
                        proc.destroy();
                    }
                } catch (InterruptedException ignored) {
                }
            });
            killer.setDaemon(true);
            killer.start();

            StringBuilder out = new StringBuilder();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = r.readLine()) != null) {
                    out.append(line);
                }
            }
            p.waitFor();
            done[0] = true;

            return out.toString().contains("uid=0");
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

    /** 模拟器判定：多个特征叠加才判定，避免误伤定制 ROM */
    static boolean isEmulator() {
        int score = 0;

        String fp = Build.FINGERPRINT == null ? "" : Build.FINGERPRINT;
        String model = Build.MODEL == null ? "" : Build.MODEL;
        String product = Build.PRODUCT == null ? "" : Build.PRODUCT;
        String hardware = Build.HARDWARE == null ? "" : Build.HARDWARE;
        String brand = Build.BRAND == null ? "" : Build.BRAND;

        for (String k : EMU_FINGERPRINTS) {
            if (fp.contains(k)) score += 2;
            if (product.contains(k)) score += 2;
            if (model.contains(k)) score += 2;
            if (hardware.contains(k)) score += 1;
            if (brand.contains(k)) score += 1;
        }

        if (Build.MANUFACTURER != null
                && Build.MANUFACTURER.equalsIgnoreCase(Build.BRAND)
                && product.contains("sdk")) {
            score += 2;
        }

        String[] emuFiles = {
                "/dev/socket/qemud", "/dev/qemu_pipe",
                "/system/lib/libc_malloc_debug_qemu.so",
                "/sys/qemu_trace", "/system/bin/qemu-props",
        };
        for (String f : emuFiles) {
            try {
                if (new File(f).exists()) score += 3;
            } catch (Exception ignored) {
            }
        }

        // 阈值 4：单个特征命中不判，避免定制 ROM 误杀
        return score >= 4;
    }
}
