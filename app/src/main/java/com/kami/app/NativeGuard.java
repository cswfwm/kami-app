package com.kami.app;

/**
 * 解锁判定放在 native 层，Java 只消费结果。
 * 把判定逻辑从 Java 移到 so 后，单纯改 DEX 里的布尔值不会生效，
 * 破解者必须同时逆向并绕开 native 校验，成本明显抬高。
 */
final class NativeGuard {

    static {
        System.loadLibrary("guard");
    }

    private NativeGuard() {
    }

    /**
     * 授权判定。
     *
     * 返回剩余天数，**必须 > 0 才算有效**；-1 表示判定失败。
     * 返回值依赖 license 与 sig 的摘要，硬编码 mov w0,#0; ret 得到 0，
     * 会被上层判为无效。
     *
     * @param expireAt 到期时间戳（秒），-1 表示永久
     * @param now      当前时间戳（秒）
     * @param license  服务端签发的 license
     * @param sig      对应签名
     */
    static native int check(int expireAt, int now, byte[] license, byte[] sig);

    /** 校验 APK 签名指纹，期望值硬编码在 native 中 */
    static native int verifyFingerprint(byte[] fp, int len);

    /** 输出服务端地址，返回写入字节数 */
    static native int getBase(byte[] out, int cap);

    /** 输出服务器 EC 公钥（65 字节 SEC1），返回写入字节数 */
    static native int getPubkey(byte[] out, int cap);

    /**
     * 统一授权判定：指纹校验 + 调试检测 + license 摘要 + 到期判断，
     * 全部在 native 内完成，只返回一个结果。
     *
     * 返回值 > 0 表示有效（值为剩余天数）；负值表示拒绝，不同负值对应不同原因。
     * Java 层只判断 > 0，因此无法只绕过其中某一项检查。
     */
    static native int authorize(byte[] fingerprint, int fpLen,
                                int expireAt, int now,
                                byte[] license, byte[] sig);

    /** 立即终止进程，用于检测到调试环境时 */
    static native void exitNow();
}
