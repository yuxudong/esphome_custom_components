/*
 * mi_lock_crypto.cpp — 见 mi_lock_crypto.h
 * 复用你组件里已经在用的 mbedtls/ccm.h；额外只需要 mbedtls/md.h（HMAC-SHA256）。
 */
#include "mi_lock_crypto.h"

#include <cstring>
#include <vector>

#include "mbedtls/ccm.h"
#include "mbedtls/md.h"
// 用稳定的 mbedtls_ecp_* 底层 API 做 ECDH，规避 mbedtls_ecdh_context 在
// 2.x/3.x 之间的结构体布局差异（ESP-IDF 4.x=2.28 / 5.x=3.x 都要编得过）。
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"

// ESP-IDF 的 esp_random() 是硬件真随机源；mbedtls RNG 回调签名为 0=成功。
// 注意：esp_fill_random() 在部分 IDF 版本/组件配置下未导出，直接逐字节用
// esp_random() 填充，跨 IDF 4.x/5.x 都可用。
#include "esp_random.h"
static int esp_mbedtls_rng(void *ctx, uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i++)
    buf[i] = (uint8_t) esp_random();
  return 0;
}

namespace esphome {
namespace xiaomi_lock {

static const char *const TAG = "mi_lock_crypto";

bool ecdh_p256_generate(uint8_t priv32[32], uint8_t pub64[64]) {
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point Q;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&Q);
  bool ok = false;
  do {
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
      break;
    // 一次生成 (d, Q=d*G)；gen_keypair 在 mbedtls 2.x/3.x 签名一致
    if (mbedtls_ecp_gen_keypair(&grp, &d, &Q, esp_mbedtls_rng, nullptr) != 0)
      break;
    if (mbedtls_mpi_write_binary(&d, priv32, 32) != 0)
      break;
    // 公钥：非压缩点 0x04||X||Y = 65B，取后 64B（X||Y）
    uint8_t buf[65];
    size_t olen = 0;
    if (mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &olen, buf, sizeof(buf)) != 0 || olen != 65)
      break;
    memcpy(pub64, buf + 1, 64);
    ok = true;
  } while (0);
  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return ok;
}

bool ecdh_p256_shared(const uint8_t priv32[32], const uint8_t dev_pub64[64], uint8_t shared32[32]) {
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point Q, P;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&Q);
  mbedtls_ecp_point_init(&P);
  bool ok = false;
  do {
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
      break;
    if (mbedtls_mpi_read_binary(&d, priv32, 32) != 0)
      break;
    // 设备公钥是 64B X||Y，补回 0x04 前缀后读成非压缩点
    uint8_t point[65];
    point[0] = 0x04;
    memcpy(point + 1, dev_pub64, 64);
    if (mbedtls_ecp_point_read_binary(&grp, &Q, point, sizeof(point)) != 0)
      break;
    // 共享点 P = d*Q，其 X 坐标即 ECDH 共享密钥（32B 大端）。
    // 不直接访问 P.X：mbedTLS 3.x 把结构体成员改成 MBEDTLS_PRIVATE(X)，
    // 直接用 P.X 在 ESP-IDF 5.x（mbedTLS 3.x）上编译失败。改用公开的
    // point_write_binary 序列化成 0x04||X||Y，再取 X，2.x/3.x 都兼容。
    if (mbedtls_ecp_mul(&grp, &P, &d, &Q, esp_mbedtls_rng, nullptr) != 0)
      break;
    uint8_t point_out[65];
    size_t olen = 0;
    if (mbedtls_ecp_point_write_binary(&grp, &P, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &olen, point_out, sizeof(point_out)) != 0 ||
        olen != 65)
      break;
    memcpy(shared32, point_out + 1, 32);
    ok = true;
  } while (0);
  mbedtls_ecp_point_free(&P);
  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return ok;
}

static bool hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len, uint8_t out[32]) {
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (info == nullptr) return false;
  return mbedtls_md_hmac(info, key, key_len, data, data_len, out) == 0;
}

bool hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *salt, size_t salt_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, size_t okm_len) {
  if (okm_len == 0 || okm_len > 255 * 32) return false;

  // Extract: PRK = HMAC(salt, IKM)；salt 为空时按 RFC5869 用 32 个 0
  uint8_t zero_salt[32] = {0};
  const uint8_t *s = salt;
  size_t s_len = salt_len;
  if (s == nullptr || s_len == 0) {
    s = zero_salt;
    s_len = sizeof(zero_salt);
  }
  uint8_t prk[32];
  if (!hmac_sha256(s, s_len, ikm, ikm_len, prk)) return false;

  // Expand: T(i) = HMAC(PRK, T(i-1) || info || i)
  uint8_t t[32];
  size_t t_len = 0, done = 0;
  uint8_t counter = 1;
  while (done < okm_len) {
    std::vector<uint8_t> in;
    in.reserve(t_len + info_len + 1);
    in.insert(in.end(), t, t + t_len);
    if (info != nullptr && info_len) in.insert(in.end(), info, info + info_len);
    in.push_back(counter);
    if (!hmac_sha256(prk, sizeof(prk), in.data(), in.size(), t)) return false;
    t_len = sizeof(t);
    size_t n = okm_len - done < 32 ? okm_len - done : 32;
    memcpy(okm + done, t, n);
    done += n;
    counter++;
  }
  memset(prk, 0, sizeof(prk));
  memset(t, 0, sizeof(t));
  return true;
}

bool derive_session_key(const uint8_t shared_secret[32], const uint8_t ltmk[32],
                        uint8_t session_key[64]) {
  static const uint8_t SALT[] = "smartcfg-login-salt";   // 19B，不含结尾 \0
  static const uint8_t INFO[] = "smartcfg-login-info";   // 19B
  uint8_t ikm[64];
  memcpy(ikm, shared_secret, 32);   // OooOO0.java:150
  memcpy(ikm + 32, ltmk, 32);       // OooOO0.java:151
  bool ok = hkdf_sha256(ikm, sizeof(ikm),
                        SALT, sizeof(SALT) - 1,
                        INFO, sizeof(INFO) - 1,
                        session_key, 64);
  memset(ikm, 0, sizeof(ikm));
  return ok;
}

std::vector<uint8_t> crc32_mi(const uint8_t *data, size_t len) {
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int k = 0; k < 8; k++) {
      crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
  }
  crc = ~crc;
  std::vector<uint8_t> out(4);
  for (int i = 0; i < 4; i++) out[i] = (uint8_t)(crc >> (i * 8));  // 小端
  return out;
}

static bool ccm_encrypt(const uint8_t key[16], const uint8_t nonce[12],
                        const uint8_t *plain, size_t plain_len,
                        uint8_t *cipher, uint8_t tag[4]) {
  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);
  bool ok = false;
  if (mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128) == 0) {
    ok = mbedtls_ccm_encrypt_and_tag(&ctx, plain_len, nonce, 12,
                                     nullptr, 0, plain, cipher, tag, 4) == 0;
  }
  mbedtls_ccm_free(&ctx);
  return ok;
}

static bool ccm_decrypt(const uint8_t key[16], const uint8_t nonce[12],
                        const uint8_t *cipher, size_t cipher_len, const uint8_t tag[4],
                        uint8_t *plain) {
  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);
  bool ok = false;
  if (mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128) == 0) {
    ok = mbedtls_ccm_auth_decrypt(&ctx, cipher_len, nonce, 12,
                                  nullptr, 0, cipher, plain, tag, 4) == 0;
  }
  mbedtls_ccm_free(&ctx);
  return ok;
}

bool make_login_confirm(const uint8_t session_key[64], const uint8_t dev_pub64[64],
                        std::vector<uint8_t> &out) {
  std::vector<uint8_t> crc = crc32_mi(dev_pub64, 64);
  uint8_t nonce[12];
  for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(0x10 + i);  // 10 11 .. 1B
  uint8_t cipher[4], tag[4];
  if (!ccm_encrypt(session_key + 16, nonce, crc.data(), 4, cipher, tag)) return false;
  out.assign(cipher, cipher + 4);
  out.insert(out.end(), tag, tag + 4);   // 8 字节，交由上层按 msgType=5 封装
  return true;
}

bool make_lock_frame(const uint8_t session_key[64], uint8_t cmd,
                     uint16_t ctr_lo, uint16_t ctr_hi, std::vector<uint8_t> &out) {
  uint8_t nonce[12];
  memcpy(nonce, session_key + 36, 4);       // appIV
  memset(nonce + 4, 0, 4);
  nonce[8] = (uint8_t)(ctr_lo & 0xFF);
  nonce[9] = (uint8_t)(ctr_lo >> 8);
  nonce[10] = (uint8_t)(ctr_hi & 0xFF);
  nonce[11] = (uint8_t)(ctr_hi >> 8);

  uint8_t cipher[1], tag[4];
  if (!ccm_encrypt(session_key + 16, nonce, &cmd, 1, cipher, tag)) return false;
  out.clear();
  out.push_back((uint8_t)(ctr_lo & 0xFF));
  out.push_back((uint8_t)(ctr_lo >> 8));
  out.push_back(cipher[0]);
  out.insert(out.end(), tag, tag + 4);      // 共 7 字节
  return true;
}

bool parse_lock_frame(const uint8_t session_key[64], const uint8_t *frame, size_t len,
                      uint16_t ctr_hi, std::vector<uint8_t> &plaintext) {
  if (len < 2 + 4 + 1) return false;        // 至少 ctr(2) + 密文(1) + MIC(4)
  const uint16_t ctr_lo = (uint16_t)(frame[0] | (frame[1] << 8));
  const size_t cipher_len = len - 2 - 4;

  uint8_t nonce[12];
  memcpy(nonce, session_key + 32, 4);       // devIV
  memset(nonce + 4, 0, 4);
  nonce[8] = (uint8_t)(ctr_lo & 0xFF);
  nonce[9] = (uint8_t)(ctr_lo >> 8);
  nonce[10] = (uint8_t)(ctr_hi & 0xFF);
  nonce[11] = (uint8_t)(ctr_hi >> 8);

  plaintext.resize(cipher_len);
  return ccm_decrypt(session_key, nonce, frame + 2, cipher_len,
                     frame + 2 + cipher_len, plaintext.data());
}

// 注意：这里只做内存里的 +1 / hi 进位，持久化由组件层（ESPHome Preferences）
// 负责 —— 必须在「写 0x1001 之前」把返回值连同 hi 一起存盘，见 .h 的 ★★ 注释。
// 策略已定案：真机 ctr=3 与 ctr=6 两轮确认开门，其中 ctr=5 因连接失败从未
// 发出、设备仍接受跳到 6 ⇒ 不要求严格 +1，跳号无害。A/B 之争不再影响实现，
// 单调递增 + NVS 持久化在两种解释下都可用。
uint16_t FrameCounter::next_lo() {
  uint16_t cur = this->lo;
  this->lo++;
  if (this->lo == 0) this->hi++;
  return cur;
}

}  // namespace xiaomi_lock
}  // namespace esphome
