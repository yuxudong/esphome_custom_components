/*
 * mi_lock_crypto.h — 米家「高安全级 BLE 门锁」会话层密码学封装
 *
 * 依据：MiHome 11.0.622 反编译
 *   - securitychipauth/OooOO0.java   (BleSecurityChipLoginConnector)
 *   - securitychipauth/OooOO0O.java  (Step 4 生成 P-256 密钥对)
 *   - _m_j/a28.java                  (ECDH / AES-CCM / CRC32 表)
 *   - _m_j/w50.java                  (开锁帧加解密 / 计数器)
 *   - _m_j/js3.java:1206             (CRC32)
 *
 * 适用范围：仅本人所有、已完成米家账号绑定的门锁。
 *
 * 【重要】本文件只实现密码层与开锁帧层；GATT 认证通道由 verify_crypto.py 的
 *   ReliableChannel 实现（0x0010 命令字 + 0x0016 CTR/ACK/DATA 分片）。
 *   帧格式已按 APK 反编译还原（pl0 / fz0 / OooOO0O / yf7 / kn9 / wb0），
 *   并于 2026-11-16 在 lumi.lock.mcn01 / 固件 2.2.1_0142 上真机校准：
 *   ★ ACK 第 4 字节是 status 枚举（0=全部收齐 / 1=CTR 已接受可发 DATA /
 *     5=按 1-based 序号请求重传），不是 CTR 里的 packageType。
 *     证据 OooOO0O.java:51 toString()、fz0.java:170-204 / 446 / 870 / 903。
 *   移植 C++ 时务必按此实现：收到设备 CTR 回 00 00 01 01、收齐 DATA 回
 *   00 00 01 00；若误回 00 00 01 03，设备会无限重发 CTR。
 *
 *   ★ 第二轮真机校准（2026-11-16，TX 顺序）：所有 0x0016 写入必须串行 FIFO。
 *     收齐设备公钥的 ACK(00 00 01 00) 必须先于下一步登录确认的 CTR(00 00 00 05 01 00)
 *     写出；否则设备仍在等 ACK 时会把 CTR 当乱序包丢弃，登录确认永远等不到 ACK。
 *     ESP32 上建议用单一队列 + 状态机，发新包前等上一包写完并留 100~200ms settle，
 *     CTR 等不到 ACK 时重发 2~3 次。
 *   ★ fz0.java:299-300 把 mode 写死为 0，:732 `i==0 || frameCount>1` 恒真
 *     ⇒ 8B 登录确认也走 CTR/DATA/ACK 完整流程，不要用 single_ctr 捷径。
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace esphome {
namespace xiaomi_lock {

// 认证服务与开锁服务 UUID（来自 _m_j/wb0.java、BleSecurityChipOperate.java）
static const char *const UUID_MI_SERVICE = "0000fe95-0000-1000-8000-00805f9b34fb";
static const char *const UUID_MI_VERSION = "00000004-0000-1000-8000-00805f9b34fb";
static const char *const UUID_MI_AUTH_WRITE = "00000010-0000-1000-8000-00805f9b34fb";  // 0x0010
static const char *const UUID_MI_AUTH_NOTIFY = "00000016-0000-1000-8000-00805f9b34fb"; // 0x0016
static const char *const UUID_LOCK_SERVICE = "00001000-0065-6c62-2e74-6f696d2e696d";
static const char *const UUID_LOCK_WRITE = "00001001-0065-6c62-2e74-6f696d2e696d";    // 0x1001
static const char *const UUID_LOCK_STATE = "00001002-0065-6c62-2e74-6f696d2e696d";    // 0x1002
static const char *const UUID_LOCK_LOG = "00001003-0065-6c62-2e74-6f696d2e696d";      // 0x1003

enum LockCmd : uint8_t {
  LOCK_CMD_UNLOCK = 0,       // 开锁
  LOCK_CMD_LOCK = 1,         // 上锁
  LOCK_CMD_ANTI_LOCK = 2,    // 反锁
};

/** HKDF-SHA256 (RFC 5869)，用 mbedtls_md HMAC 手写，避免依赖 MBEDTLS_HKDF_C。
 *  ESP-IDF 默认 sdkconfig 常常没开 HKDF，这个实现在任何 mbedtls 配置下都能编。
 *  okm_len 最大 255*32 = 8160。 */
bool hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *salt, size_t salt_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, size_t okm_len);

/** P-256 (secp256r1) ECDH 密钥对生成。
 *  priv32: 输出 32B 大端私钥；pub64: 输出 64B = 公钥 X||Y（去掉 0x04 前缀）。
 *  私钥每次连接都必须重新生成（前向安全），由状态机在 START_CMD 阶段调用。 */
bool ecdh_p256_generate(uint8_t priv32[32], uint8_t pub64[64]);

/** P-256 ECDH 共享密钥：priv32(本端) × dev_pub64(设备 X||Y) → shared32(32B 大端)。 */
bool ecdh_p256_shared(const uint8_t priv32[32], const uint8_t dev_pub64[64], uint8_t shared32[32]);

/** 从登录握手结果派生 64 字节 sessionKey（OooOO0.java:148-160）。
 *
 *  ikm  = ECDH(客户端私钥, 设备公钥 0x04||64B) 得到的 32B 共享密钥 || LTMK(32B)
 *  salt = "smartcfg-login-salt"
 *  info = "smartcfg-login-info"
 *  L    = 64
 *
 *  ⚠ 注意：这与网上常见的 miot-mesh-login-salt/info、以及米家 App 里
 *    standardauth（普通 2.x.x 设备）的 mible-login-info 是不同产品线参数。
 *    安全芯片门锁必须用 smartcfg-* 这一组，否则设备会拒绝登录确认帧。
 *
 *  sessionKey 布局：
 *    [0:16]  devKey   设备→App 解密
 *    [16:32] appKey   App→设备 加密
 *    [32:36] devIV    设备→App nonce 前缀
 *    [36:40] appIV    App→设备 nonce 前缀
 */
bool derive_session_key(const uint8_t shared_secret[32], const uint8_t ltmk[32], uint8_t session_key[64]);

/** 米家 CRC32（reflected poly 0xEDB88320，init 0xFFFFFFFF，final ~crc），
 *  返回小端 4 字节（_m_j/js3.java:1206 + _m_j/zd.java:907）。
 *  等价于 Python: struct.pack("<I", zlib.crc32(data)) */
std::vector<uint8_t> crc32_mi(const uint8_t *data, size_t len);

/** 登录确认帧（Step 6，OooOO0.java:161）。
 *  明文 = CRC32(设备发来的 64B 公钥)
 *  AES-CCM-128, key = sessionKey[16:32] (appKey)
 *  nonce = 0x10 0x11 ... 0x1B (固定 12B)
 *  MIC = 4B；输出 = 4B 密文 || 4B MIC = 8B
 *  随后由上层以 msgType=5 写到 FE95/0x0010（帧头/分包见 TODO）。 */
bool make_login_confirm(const uint8_t session_key[64], const uint8_t dev_pub64[64],
                        std::vector<uint8_t> &out);

/** 开锁 / 上锁 / 反锁帧（_m_j/w50.java，已确认）。
 *  帧 = [ctr_lo 2B 小端] || AESCCM(appKey) 密文 || 4B MIC
 *  明文 = 1 字节 cmd，因此 cmd=0 时整帧 7 字节。
 *  nonce(12B) = appIV(4B) || 00000000(4B) || ctr_lo(2B LE) || ctr_hi(2B LE) */
bool make_lock_frame(const uint8_t session_key[64], uint8_t cmd,
                     uint16_t ctr_lo, uint16_t ctr_hi, std::vector<uint8_t> &out);

/** 解析 0x1002 / 0x1003 的上行帧。
 *  nonce 用帧内携带的 ctr_lo 重建，devKey = sessionKey[0:16]，devIV = [32:36]。
 *
 *  ★ 2026-11-16 第五轮真机交叉验证：写完 0x1001 开锁帧后，设备确实在
 *    0x1002/0x1003 上发了 notify，且该帧用 devKey + 上述 nonce 通过了
 *    AES-CCM 4B MIC 校验（即「设备→App 用 devKey、与下行同构」已实机成立）。
 *    v4 脚本因把明文转成 hex 字符串后又调 .hex()，在 asyncio 回调里抛异常，
 *    把原始帧吞了；v5 已修，实机 hex 待补采后即可定死状态字段语义。
 *    ESPHome 侧：订阅这两个特征后按本函数解，解不开只记日志、不要判开锁失败。 */
bool parse_lock_frame(const uint8_t session_key[64], const uint8_t *frame, size_t len,
                      uint16_t ctr_hi, std::vector<uint8_t> &plaintext);

/** 计数器：低 16 位溢出时高位 +1（w50.java:100-112）。收发方向各自独立维护。
 *
 *  ★★ 2026-11-16 移植注意（策略已定案）★★
 *    真机两次确认开门：ctr=3 与 ctr=6（两轮都回 0x1002 plain=00）。
 *    关键样本：ctr=5 那轮因连接失败**帧根本没发出**，设备从未见过 5，
 *    下一会话却接受了 ctr=6 并真正开门 ⇒ 设备【不要求 ctr 严格 +1 连续】，
 *    跳号无害。担心「连接失败/重启造成本地计数与设备不同步会被拒」是多余的。
 *
 *    A（设备侧跨会话累积）/ B（计数每会话重置，w50.java:120-127 清 App 侧
 *    Map）至今无法区分：ctr=6 在两种解释下都会被接受，不是判别性样本。
 *    但这已不影响实现选择 —— 单调递增 + 持久化在 A 下必需、在 B 下无害。
 *
 *    ⇒ ESP32 侧按以下方式实现 lo/hi 存 NVS / Preferences：
 *      · 写 0x1001 **之前**就 prefs.put 预占（连接/登录失败不要预占，v7 已修）；
 *      · 开机 setup() 里 prefs.get 恢复，绝不从 0 重新猜；
 *      · 收发两份计数器都要存（上行 ctr_hi 由 lo 翻转推算，w50.java:63-68）；
 *      · 首次烧录与设备当前值对齐（用 PC 脚本 --ctr N 试出可用值后写入）。
 *    「--ctr 0 新会话显式回退」对照实验仍可做，但已不再是开工前置条件。
 *    详见报告 3.5.3·补⑫ / 补⑬。
 */
struct FrameCounter {
  uint16_t lo{0};
  uint16_t hi{0};
  uint16_t next_lo();
};

}  // namespace xiaomi_lock
}  // namespace esphome
