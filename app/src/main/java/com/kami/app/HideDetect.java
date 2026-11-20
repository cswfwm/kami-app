package com.kami.app;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 反隐藏检测：不找「root 文件」，找「隐藏行为」本身。
 *
 * 为什么换思路：
 * Magisk 的 DenyList / Shamiko 在 mount namespace 层做隔离，
 * 被保护的应用看到的是一个「干净」的文件系统视图——
 * su 不存在、/data/adb 不可见、ro.debuggable 返回原值。
 * 所以「找 su 文件」这类检测对现代隐藏手段完全失效。
 *
 * 但隐藏本身会留下破绽：
 *   1. mount namespace 被改写 → mountinfo 出现异常挂载
 *   2. SELinux context 漂移 → 进程 context 与其身份不符
 *   3. 进程树异常 → 父进程不是 zygote
 *   4. 挂载点数量异常少 → 大量挂载被卸载以隐藏
 */
final class HideDetect {

    static final class Report {
        final List<String> signals = new ArrayList<>();
        boolean mountAnomaly;
        boolean selinuxDrift;
        boolean parentAnomaly;
        boolean namespaceSplit;

        boolean suspicious() {
            return mountAnomaly || selinuxDrift || parentAnomaly || namespaceSplit;
        }
    }

    private HideDetect() {
    }

    static Report run() {
        Report r = new Report();
        checkMountInfo(r);
        checkSelinuxContext(r);
        checkParentProcess(r);
        checkMountCount(r);
        return r;
    }

    /**
     * 检查 mountinfo 里的异常挂载。
     *
     * DenyList 通过在目标进程的 namespace 里 unmount magisk overlay 实现隐藏，
     * 这个动作会在 mountinfo 留下痕迹。
     */
    private static void checkMountInfo(Report r) {
        BufferedReader br = null;
        int tmpfsCount = 0;
        try {
            br = new BufferedReader(new FileReader("/proc/self/mountinfo"));
            String line;
            while ((line = br.readLine()) != null) {
                String lower = line.toLowerCase();

                if (lower.contains("/data/adb") || lower.contains("magisk")) {
                    r.mountAnomaly = true;
                    r.signals.add("mount:magisk_path");
                }

                // overlay 挂载在非系统路径，是模块注入的典型特征
                if (lower.contains(" overlay ")
                        && !lower.contains("/system")
                        && !lower.contains("/vendor")
                        && !lower.contains("/product")) {
                    r.mountAnomaly = true;
                    r.signals.add("mount:overlay");
                }

                if (line.contains(" tmpfs ")) {
                    tmpfsCount++;
                }
            }
            if (tmpfsCount > 60) {
                r.mountAnomaly = true;
                r.signals.add("mount:tmpfs_" + tmpfsCount);
            }
        } catch (Exception ignored) {
        } finally {
            close(br);
        }
    }

    /**
     * 检查 SELinux context 是否漂移。
     * 正常应用应为 untrusted_app；被注入后可能变成 magisk、su 等。
     */
    private static void checkSelinuxContext(Report r) {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/self/attr/current"));
            String ctx = br.readLine();
            if (ctx != null) {
                String c = ctx.trim().toLowerCase();
                if (c.isEmpty()) {
                    return;
                }
                if (c.contains("magisk") || c.contains("su:") || c.contains("su_")) {
                    r.selinuxDrift = true;
                    r.signals.add("selinux:" + c);
                    return;
                }
                if (!c.contains("untrusted_app")
                        && !c.contains("platform_app")
                        && !c.contains("system_app")) {
                    r.selinuxDrift = true;
                    r.signals.add("selinux_unexpected:" + c);
                }
            }
        } catch (Exception ignored) {
        } finally {
            close(br);
        }
    }

    /**
     * 检查父进程。
     * 正常应用由 zygote fork，父进程名是 zygote / zygote64。
     */
    private static void checkParentProcess(Report r) {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            int ppid = -1;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("PPid:")) {
                    try {
                        ppid = Integer.parseInt(line.substring(5).trim());
                    } catch (Exception ignored) {
                    }
                    break;
                }
            }
            close(br);
            br = null;

            if (ppid > 0) {
                String comm = readComm(ppid);
                if (comm != null) {
                    String c = comm.toLowerCase();
                    if (c.contains("magisk") || c.equals("su") || c.contains("daemonsu")
                            || c.contains("zygisk")) {
                        r.parentAnomaly = true;
                        r.signals.add("parent:" + c);
                    }
                }
            }
        } catch (Exception ignored) {
        } finally {
            close(br);
        }
    }

    /**
     * 挂载点数量异常少，说明大量挂载被卸载以隐藏内容。
     * 正常 Android 应用挂载点通常在 100+
     */
    private static void checkMountCount(Report r) {
        BufferedReader br = null;
        try {
            if (!new File("/proc/self/ns/mnt").exists()) {
                return;
            }
            int mounts = 0;
            br = new BufferedReader(new FileReader("/proc/self/mounts"));
            while (br.readLine() != null) {
                mounts++;
            }
            close(br);
            br = null;

            if (mounts > 0 && mounts < 40) {
                r.namespaceSplit = true;
                r.signals.add("ns:mounts_" + mounts);
            }
        } catch (Exception ignored) {
        } finally {
            close(br);
        }
    }

    private static String readComm(int pid) {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/" + pid + "/comm"));
            String v = br.readLine();
            return v == null ? null : v.trim();
        } catch (Exception e) {
            return null;
        } finally {
            close(br);
        }
    }

    private static void close(BufferedReader br) {
        if (br != null) {
            try {
                br.close();
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * 判断是否需要强行索取 root 授权。
     *
     * 用户要求「有一点怀疑就弹」，但无差别弹窗会骚扰正常用户。
     * 用信号打分做门槛：单个弱信号不弹，累计到阈值才索取。
     * 真实用户几乎不会同时命中多项。
     */
    static boolean shouldRequestRoot(Report hide, EnvCheck.Result env) {
        int score = 0;
        if (hide.mountAnomaly) {
            score += 2;
        }
        if (hide.selinuxDrift) {
            score += 2;
        }
        if (hide.parentAnomaly) {
            score += 3;
        }
        if (hide.namespaceSplit) {
            score += 2;
        }
        if (env != null && env.rootDetected) {
            score += 2;
        }
        return score >= 2;
    }
}
