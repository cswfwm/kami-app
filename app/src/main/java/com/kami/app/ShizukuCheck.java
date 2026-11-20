package com.kami.app;

import android.content.pm.PackageManager;
import rikka.shizuku.Shizuku;

/**
 * Shizuku 检测与授权。
 *
 * Shizuku 是用户态特权框架：它通过 ADB 或 root 启动一个后台服务，
 * 其他 App 绑定该服务后可以代执行部分系统级操作。
 *
 * 与 root 的区别：
 *   - root 靠 su 弹窗，各管理器互不相通
 *   - Shizuku 有统一 API，授权状态可查询、可主动请求
 *
 * 注意：应用无法「获得 ADB 权限」。ADB 是独立调试通道，权限高于普通应用。
 * 这里只是检测 Shizuku 是否存在并请求它的授权。
 */
final class ShizukuCheck {

    /** Shizuku 管理器的包名 */
    private static final String PKG_SHIZUKU = "moe.shizuku.privileged.api";
    /** Sui（Magisk 版 Shizuku） */
    private static final String PKG_SUI = "com.zhanghai.android.sui";

    static final class State {
        /** 是否装了 Shizuku / Sui 管理器 */
        final boolean installed;
        /** Shizuku 服务是否在运行（绑定成功） */
        final boolean serviceAlive;
        /** 是否已获得授权 */
        final boolean granted;

        State(boolean installed, boolean serviceAlive, boolean granted) {
            this.installed = installed;
            this.serviceAlive = serviceAlive;
            this.granted = granted;
        }
    }

    private ShizukuCheck() {
    }

    /** 检测管理器是否安装 */
    static boolean isInstalled(android.content.Context ctx) {
        PackageManager pm = ctx.getPackageManager();
        for (String pkg : new String[]{PKG_SHIZUKU, PKG_SUI}) {
            try {
                pm.getPackageInfo(pkg, 0);
                return true;
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }
        return false;
    }

    /** 服务是否在运行。pingBinder 在 Shizuku 未启动时返回 false，不会抛异常 */
    static boolean isServiceAlive() {
        try {
            return Shizuku.pingBinder();
        } catch (Throwable e) {
            // 类加载失败或 API 不兼容，视为不可用
            return false;
        }
    }

    /** 当前是否已获授权 */
    static boolean isGranted() {
        try {
            if (!Shizuku.pingBinder()) {
                return false;
            }
            return Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
        } catch (Throwable e) {
            return false;
        }
    }

    /**
     * 请求授权。
     *
     * 必须从 Activity 上下文发起，Shizuku 会弹出系统授权框。
     * 结果通过 addRequestPermissionResultListener 异步返回，这里只负责发出请求。
     *
     * @return true 表示请求已发出；false 表示服务不可用、无法请求
     */
    static boolean request(android.app.Activity activity) {
        try {
            if (!Shizuku.pingBinder()) {
                return false;
            }
            // 已经授权过就不用再弹
            if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                return true;
            }
            // shouldShowRequestPermissionRationale 为 true 说明用户曾拒绝，
            // 仍可再次请求（Shizuku 允许重复请求）
            Shizuku.requestPermission(0);
            return true;
        } catch (Throwable e) {
            return false;
        }
    }

    /** 注册授权结果回调 */
    static void onResult(Shizuku.OnRequestPermissionResultListener l) {
        try {
            Shizuku.addRequestPermissionResultListener(l);
        } catch (Throwable ignored) {
        }
    }

    static void removeResult(Shizuku.OnRequestPermissionResultListener l) {
        try {
            Shizuku.removeRequestPermissionResultListener(l);
        } catch (Throwable ignored) {
        }
    }

    /** Shizuku 服务 uid，可用于确认它确实以高权限运行 */
    static int serviceUid() {
        try {
            return Shizuku.pingBinder() ? Shizuku.getUid() : -1;
        } catch (Throwable e) {
            return -1;
        }
    }

    static State scan(android.content.Context ctx) {
        boolean installed = isInstalled(ctx);
        boolean alive = isServiceAlive();
        boolean granted = alive && isGranted();
        return new State(installed, alive, granted);
    }
}
