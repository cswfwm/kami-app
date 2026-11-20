package com.kami.app;

import android.content.Context;
import android.os.Build;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

/**
 * 特权守护进程：把 native 可执行文件释放到私有目录，用 su 以 root 身份运行。
 *
 * 与 Java 层检测的区别：
 *   Java 层的检查会被 Frida hook 掉，因为它的执行流在对方的掌控之内。
 *   这个守护进程由 su 拉起、独立于 ART 运行时，hook Java 方法影响不到它。
 *   它读 /proc/modules、SELinux 状态、root 框架目录，把结论写回 stdout。
 *
 * 它仍然不是内核模块——内核模块在 Android 上装不上（vermagic 不匹配、
 * CONFIG_MODULES 默认关闭、模块签名校验）。它是普通 ELF 可执行文件。
 *
 * 边界：有 root 的人可以替换这个二进制文件，所以每次运行前校验摘要。
 */
final class PrivGuard {

    private static final String ASSET_64 = "bin/kguard_arm64";
    private static final String ASSET_32 = "bin/kguard_armv7";

    /** 期望的二进制 SHA-256，防止被替换。构建后由 tools/gen_sha.py 回填 */
    private static final String SHA_64 = "64addcbb465dcb4c6abcbd620bb06693f2842e54db8b74af1e4a0d181e2a78af";
    private static final String SHA_32 = "6b7485ec83e4265d6239147baeac1bcf8e5eaef746d9a5c44b4dd8982070ac7a";

    static final class Verdict {
        final boolean ran;
        final boolean clean;
        final String output;

        Verdict(boolean ran, boolean clean, String output) {
            this.ran = ran;
            this.clean = clean;
            this.output = output;
        }
    }

    private PrivGuard() {
    }

    /** 释放并执行守护进程。调用前必须已获得 su 授权。 */
    static Verdict run(Context ctx) {
        try {
            File bin = extract(ctx);
            if (bin == null) {
                return new Verdict(false, false, "extract_failed");
            }

            String actual = sha256(bin);
            String expect = is64() ? SHA_64 : SHA_32;
            if (!expect.equals(actual)) {
                return new Verdict(false, false, "binary_tampered:" + actual);
            }

            return exec(bin);
        } catch (Exception e) {
            return new Verdict(false, false, e.getClass().getSimpleName());
        }
    }

    /** 从 assets 释放到 filesDir，并加可执行权限 */
    private static File extract(Context ctx) {
        String asset = is64() ? ASSET_64 : ASSET_32;
        File out = new File(ctx.getFilesDir(), "kguard");
        if (out.exists() && out.length() > 0) {
            return out;
        }
        InputStream is = null;
        OutputStream os = null;
        try {
            is = ctx.getAssets().open(asset);
            os = new FileOutputStream(out);
            byte[] b = new byte[8192];
            int n;
            while ((n = is.read(b)) > 0) {
                os.write(b, 0, n);
            }
            os.flush();
        } catch (Exception e) {
            return null;
        } finally {
            try {
                if (is != null) {
                    is.close();
                }
            } catch (Exception ignored) {
            }
            try {
                if (os != null) {
                    os.close();
                }
            } catch (Exception ignored) {
            }
        }
        // assets 里的文件默认没有执行位，必须显式设置
        out.setExecutable(true, false);
        out.setReadable(true, false);
        return out;
    }

    /** 用 su 执行，读取 stdout 判断结果 */
    private static Verdict exec(File bin) {
        Process p = null;
        try {
            p = Runtime.getRuntime().exec(new String[]{"su", "-c", bin.getAbsolutePath()});

            final Process proc = p;
            final boolean[] done = {false};
            Thread killer = new Thread(() -> {
                try {
                    Thread.sleep(8000);
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
                out.append(line).append('\n');
            }
            r.close();
            p.waitFor();
            done[0] = true;

            String s = out.toString();
            boolean clean = s.contains("RESULT_CLEAN");
            return new Verdict(true, clean, s.trim());
        } catch (Exception e) {
            return new Verdict(false, false, e.getClass().getSimpleName());
        } finally {
            if (p != null) {
                try {
                    p.destroy();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private static boolean is64() {
        for (String abi : Build.SUPPORTED_64_BIT_ABIS) {
            if (abi.contains("arm64")) {
                return true;
            }
        }
        return false;
    }

    private static String sha256(File f) {
        InputStream is = null;
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            is = new java.io.FileInputStream(f);
            byte[] b = new byte[8192];
            int n;
            while ((n = is.read(b)) > 0) {
                md.update(b, 0, n);
            }
            StringBuilder sb = new StringBuilder();
            for (byte x : md.digest()) {
                sb.append(String.format("%02x", x));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        } finally {
            try {
                if (is != null) {
                    is.close();
                }
            } catch (Exception ignored) {
            }
        }
    }
}
