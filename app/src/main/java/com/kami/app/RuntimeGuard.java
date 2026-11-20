package com.kami.app;

import android.content.Context;
import android.os.Debug;
import android.os.Handler;
import android.os.Looper;

import java.io.BufferedReader;
import java.io.FileReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 运行期自检：
 *   1. 每 60 秒探测一次外网连通性（默认 baidu.com:443）
 *   2. 反调试检测：被调试器附加、TracerPid 非 0、常见注入框架
 *
 * 网络检测的意义：软件离线仍可用（见宽限期），但会记录联网状态，
 * 供上层决定是否提示或降级。
 */
final class RuntimeGuard {

    private static final long PROBE_INTERVAL_MS = 60_000L;

    private static final String[] PROBE_HOSTS = {"www.baidu.com", "baidu.com"};

    interface onStateChange {
        void onNetwork(boolean online);

        void onTamper(String reason);
    }

    private static final AtomicBoolean running = new AtomicBoolean(false);
    private static final Handler handler = new Handler(Looper.getMainLooper());

    private RuntimeGuard() {
    }

    static void start(Context ctx, onStateChange cb) {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        Runnable tick = new Runnable() {
            @Override
            public void run() {
                String tamper = detectTamper();
                if (tamper != null) {
                    cb.onTamper(tamper);
                }
                // 网络探测放到工作线程，避免阻塞主线程
                new Thread(() -> {
                    boolean online = isOnline();
                    handler.post(() -> cb.onNetwork(online));
                }, "kami-net").start();
                handler.postDelayed(this, PROBE_INTERVAL_MS);
            }
        };
        handler.post(tick);
    }

    static void stop() {
        running.set(false);
        handler.removeCallbacksAndMessages(null);
    }

    /** 连通性探测：直连 443 端口，比 ping 更可靠且不受 ICMP 屏蔽影响 */
    static boolean isOnline() {
        for (String host : PROBE_HOSTS) {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(host, 443), 3000);
                return true;
            } catch (Exception ignored) {
                // 换下一个目标
            }
        }
        return false;
    }

    /**
     * 反调试。命中返回原因，未命中返回 null。
     *
     * 这些检查都能被绕过（改 smali 或 hook），作用是提高破解门槛并留下线索，
     * 不是不可突破的防护。
     */
    static String detectTamper() {
        // 1. Java 层调试器附加
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            return "debugger";
        }

        // 2. 内核 TracerPid（ptrace 附加时会变为非 0）
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/self/status"))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    String v = line.substring("TracerPid:".length()).trim();
                    if (!v.isEmpty() && !"0".equals(v)) {
                        return "tracer:" + v;
                    }
                    break;
                }
            }
        } catch (Exception ignored) {
            // 读不到就跳过这一项，不影响正常使用
        }

        // 3. 常见注入框架的特征进程/端口迹象（Xposed、frida）
        if (hasFridaPort()) {
            return "frida";
        }
        return null;
    }

    /** frida-server 默认监听 27042 */
    private static boolean hasFridaPort() {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("127.0.0.1", 27042), 200);
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

}
