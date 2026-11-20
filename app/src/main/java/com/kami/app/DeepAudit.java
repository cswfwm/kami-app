package com.kami.app;

import android.os.Build;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 深度环境审计。
 *
 * 与 EnvCheck 的分工：EnvCheck 判断「有没有 root」，这里判断
 * 「这台机器是否被改造成不可信状态」——注入框架、调试附加、
 * 系统分区被写、SELinux 关闭等。
 *
 * 诚实的边界：如果对方有内核模块，它可以伪造 /proc 的所有内容。
 * 这些检查是给「用户态 root」准备的，对内核级隐藏无效。
 */
final class DeepAudit {

    /** 注入框架在进程内存里的特征 */
    private static final String[] INJECT_MARKS = {
            "frida", "gum-js-loop", "gmain", "xposed", "edxp",
            "lspd", "riru", "zygisk", "substrate", "magisk",
            "libfrida", "frida-gadget", "dobby", "whale",
    };

    /** 框架安装路径 */
    private static final String[] FRAMEWORK_PATHS = {
            "/data/adb/lspd",                    // LSPosed
            "/data/adb/modules/zygisksu",        // Zygisk
            "/data/adb/modules/riru-core",
            "/data/adb/modules/riru_edxposed",
            "/data/misc/riru",                   // Riru
            "/system/framework/XposedBridge.jar",
            "/system/lib/libxposed_art.so",
            "/system/lib64/libxposed_art.so",
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
    };

    static final class Report {
        final List<String> findings = new ArrayList<>();
        boolean injectDetected;
        boolean frameworkDetected;
        boolean selinuxPermissive;
        boolean systemModified;

        boolean clean() {
            return !injectDetected && !frameworkDetected && !selinuxPermissive && !systemModified;
        }
    }

    private DeepAudit() {
    }

    static Report run() {
        Report r = new Report();
        scanMaps(r);
        scanFrameworkPaths(r);
        checkSelinux(r);
        checkSystemProps(r);
        return r;
    }

    /** 扫描 /proc/self/maps：注入的 .so 会以文件名形式出现 */
    private static void scanMaps(Report r) {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = br.readLine()) != null) {
                String lower = line.toLowerCase();
                for (String mark : INJECT_MARKS) {
                    if (lower.contains(mark)) {
                        r.injectDetected = true;
                        r.findings.add("maps:" + mark);
                        return;
                    }
                }
            }
        } catch (Exception ignored) {
            // 读不到就跳过，不误判
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    /** 框架的典型安装路径 */
    private static void scanFrameworkPaths(Report r) {
        for (String p : FRAMEWORK_PATHS) {
            try {
                if (new File(p).exists()) {
                    r.frameworkDetected = true;
                    r.findings.add("path:" + p);
                }
            } catch (Exception ignored) {
            }
        }
    }

    /** SELinux 被改成 permissive 说明系统防护已关闭 */
    private static void checkSelinux(Report r) {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/sys/fs/selinux/enforce"));
            String v = br.readLine();
            if (v != null && v.trim().equals("0")) {
                r.selinuxPermissive = true;
                r.findings.add("selinux:permissive");
            }
        } catch (Exception ignored) {
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    /** ro.debuggable=1、ro.secure=0 或 test-keys 说明是 userdebug/eng 版本 */
    private static void checkSystemProps(Report r) {
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            java.lang.reflect.Method get = sp.getMethod("get", String.class);
            String debuggable = (String) get.invoke(null, "ro.debuggable");
            String secure = (String) get.invoke(null, "ro.secure");
            String tags = (String) get.invoke(null, "ro.build.tags");

            if ("1".equals(debuggable)) {
                r.systemModified = true;
                r.findings.add("prop:ro.debuggable=1");
            }
            if ("0".equals(secure)) {
                r.systemModified = true;
                r.findings.add("prop:ro.secure=0");
            }
            if (tags != null && tags.contains("test-keys")) {
                r.systemModified = true;
                r.findings.add("prop:test-keys");
            }
        } catch (Exception ignored) {
            // 反射失败（部分 ROM 隐藏该类）不判定
        }
    }

    /**
     * 收集设备特征，上报给服务端固化。
     * boot_id 每次开机变，只用于「同一开机周期」的比对。
     */
    static String buildFpJson() {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"model\":\"").append(esc(Build.MODEL)).append("\",");
        sb.append("\"brand\":\"").append(esc(Build.BRAND)).append("\",");
        sb.append("\"device\":\"").append(esc(Build.DEVICE)).append("\",");
        sb.append("\"product\":\"").append(esc(Build.PRODUCT)).append("\",");
        sb.append("\"board\":\"").append(esc(Build.BOARD)).append("\",");
        sb.append("\"hardware\":\"").append(esc(Build.HARDWARE)).append("\",");
        sb.append("\"boot_id\":\"").append(esc(readBootId())).append("\"");
        sb.append("}");
        return sb.toString();
    }

    private static String readBootId() {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/sys/kernel/random/boot_id"));
            String v = br.readLine();
            return v == null ? "" : v.trim();
        } catch (Exception e) {
            return "";
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
