/*
 * xiaomi_lock_ble.h — 米家高安全级 BLE 门锁「连接开锁」ESPHome 组件
 *
 * 与现有 xiaomi_lock 组件（被动解 MiBeacon 广播）是两件独立的事：
 *   - xiaomi_lock       : ESPBTDeviceListener，只读广播，用 bindkey（16B）
 *   - xiaomi_lock_ble   : ble_client 主动连接，用 LTMK（32B）+ 每次会话的 sessionKey
 * 两者可同时配置在同一台 ESP32 上，但同一时刻门锁只能被一方持有：
 * 连接期间门锁停发广播 → 广播传感器会短暂断更；本组件发完帧立刻断开并恢复扫描。
 *
 * 协议链路由 MiHome 11.0.622 逆向 + 2026-11-16 真机（lumi.lock.mcn01 /
 * 固件 2.2.1_0142）逐帧校准，已两次确认开门（ctr=3 与 ctr=6）。详见工作区报告
 * 《ESPHome小米门锁开锁可行性分析.html》3.5.3 补⑦~补⑬。
 *
 * 设计要点：
 *   1. 继承 ble_client::BLEClientNode，在 gattc_event_handler() 里接管 GATT 事件：
 *      SEARCH_CMPL → 解析 6 个特征 handle + 注册 notify；NOTIFY_EVT → TX/RX 分发；
 *      WRITE_CHAR_EVT → 串行 TX 队列推进；CLOSE/DISCONNECT → 复位状态机。
 *   2. 0x0016 可靠通道：CTR → 等 ACK(status=1) → DATA(seq 1..N) → 等 ACK(status=0/5)。
 *      ★ ACK 第 4 字节是 status（0 收齐 / 1 可发 DATA / 5 请求重传 1-based 缺片），
 *        不是 CTR 里的 packageType；回错成 3 会导致设备无限重发 CTR。
 *   3. 所有 0x0016 写入走单一 FIFO（tx_queue_），保证「收齐公钥的 ACK(0)」排在
 *      「登录确认 CTR」之前；发新包前留 settle 毫秒给设备处理上一包。
 *   4. 计数器（nonce 组成 + 防重放）存 NVS：写 0x1001 之前先 save 预占，
 *      连接/登录失败不消耗；真机证实设备不要求严格 +1，跳号无害。
 *   5. 状态机由 loop() 驱动 + deadline 超时，绝不在 GATT 回调里阻塞或做耗时计算。
 *
 * ⚠ 合规：仅用于本人所有、已完成米家账号绑定的门锁。
 */
#pragma once

#ifdef USE_ESP32

#include "esphome/core/component.h"
#include "esphome/core/helpers.h"
#include "esphome/core/preferences.h"
#include "esphome/components/ble_client/ble_client.h"
#include "esphome/components/lock/lock.h"
#include "esphome/components/esp32_ble_tracker/esp32_ble_tracker.h"

#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <vector>

#include "mi_lock_crypto.h"

namespace esphome {
namespace xiaomi_lock_ble {

// 新版 ESPHome 里 esp32_ble_tracker 是 namespace（不是类），必须用 namespace 别名；
// 旧写法 `using espbt = esphome::esp32_ble_tracker;` 会把 namespace 当类型用而编译失败。
namespace espbt = esphome::esp32_ble_tracker;

// 一轮完整开锁的最长时限；各子阶段另有独立 deadline。
static constexpr uint32_t DEFAULT_STEP_TIMEOUT_MS = 12000;
static constexpr uint32_t DEFAULT_AUTH_TIMEOUT_MS = 20000;
static constexpr uint32_t DEFAULT_SETTLE_MS = 150;  // 发新包前留给设备的处理时间
static constexpr size_t CHANNEL_CHUNK = 18;          // 0x0016 单片 payload 上限

// 0x0016 ACK status（OooOO0O.java / fz0.java，真机校准）
enum ChannelStatus : uint8_t {
  CH_STATUS_COMPLETE = 0,  // 全部分片收齐
  CH_STATUS_READY = 1,     // CTR 已接受，可发 DATA
  // status=2 在 OooOO0O 里叫 single_ack，本通道 mode=0 用不到
  CH_STATUS_RETRANS = 5,   // 缺片，后续跟 1-based 缺失序号（u16 LE）
};

// 顶层状态机阶段
enum class AuthPhase : uint8_t {
  IDLE = 0,
  WAIT_CONNECT,        // 等 ble_client 连接 + 服务发现完成
  START_CMD,           // 写 0x0010 = 20 00 00 00，注册两个 FE95 notify
  CLIENT_PUB_TX,       // 发客户端 64B 公钥（packageType=3）
  WAIT_DEV_PUB,        // 等设备 64B 公钥（packageType=3）
  CONFIRM_TX,          // 发 8B 登录确认（packageType=5）
  WAIT_RESULT,         // 等 0x0010 返回 0x21
  UNLOCK_WRITE,        // 订阅 0x1002/0x1003，提交计数器，写 0x1001
  COLLECT_STATE,       // 收集状态帧（仅日志，不作为成功判据）
  DONE,
  FAILED,
};

// 0x0016 TX 事务子状态（TRX = Transmit RELIABLE eXchange）
enum class TxPhase : uint8_t {
  IDLE = 0,
  WAIT_CTR_ACK,   // CTR 已发，等 status=1
  WAIT_DATA_ACK,  // DATA 已发，等 status=0 / 5
};

struct PendingWrite {
  uint16_t handle;
  std::vector<uint8_t> data;
  bool with_response;
};

class XiaomiLockBle final : public Component,
                            public ble_client::BLEClientNode,
                            public lock::Lock {
 public:
  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::HARDWARE; }

  // ---- 配置注入（由 Python codegen 调用） ----
  void set_ltmk(const std::string &hex);
  void set_cmd(uint8_t cmd) { this->cmd_ = cmd; }
  void set_step_timeout_ms(uint32_t ms) { this->step_timeout_ms_ = ms; }
  void set_auth_timeout_ms(uint32_t ms) { this->auth_timeout_ms_ = ms; }
  void set_settle_ms(uint32_t ms) { this->settle_ms_ = ms; }
  void set_ctr_lo(uint16_t lo) { this->ctr_override_lo_ = lo; this->has_ctr_override_ = true; }
  void set_ctr_hi(uint16_t hi) { this->ctr_override_hi_ = hi; }

  // lock 平台：control() 是唯一的动作入口（lock/unlock/open 都会进这里）
  void control(const lock::LockCall &call) override;

  // BLEClientNode：GATT 事件总入口
  void gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                           esp_ble_gattc_cb_param_t *param) override;

 protected:
  // ---- 连接 / 断开 ----
  void request_connect_();
  void on_search_complete_();
  void on_disconnected_();
  void fail_(const char *reason);
  void finish_ok_();

  // ---- 可靠通道 0x0016 ----
  void queue_write_(uint16_t handle, const std::vector<uint8_t> &data, bool with_response);
  void pump_tx_();
  void start_channel_tx_(uint8_t msg_type, const std::vector<uint8_t> &payload);
  void send_channel_ctr_();
  void send_channel_data_();
  void on_channel_notify_(const uint8_t *data, size_t len);
  void on_channel_ack_(uint8_t status, const std::vector<uint16_t> &missing);
  void send_ack_(uint8_t status, const std::vector<uint16_t> &missing = {});

  // ---- 0x0010 命令字 / 结果码 ----
  void on_cmd_notify_(const uint8_t *data, size_t len);

  // ---- 0x1002 / 0x1003 状态 / 日志 ----
  void on_state_notify_(const uint8_t *data, size_t len, const char *which);

  // ---- 计数器 NVS ----
  void load_counter_();
  void save_counter_();

  // ---- 工具 ----
  uint16_t find_char_handle_(espbt::ESPBTUUID service, espbt::ESPBTUUID chr);
  bool phase_expired_() const;
  void set_phase_(AuthPhase phase, uint32_t timeout_ms);

  // 配置（BLEClient 通过 BLEClientNode::parent() 取得，由 register_ble_node 注入）
  uint8_t ltmk_[32]{0};
  bool ltmk_valid_{false};
  uint8_t cmd_{0};  // 0 开锁 / 1 上锁 / 2 反锁
  uint32_t step_timeout_ms_{DEFAULT_STEP_TIMEOUT_MS};
  uint32_t auth_timeout_ms_{DEFAULT_AUTH_TIMEOUT_MS};
  uint32_t settle_ms_{DEFAULT_SETTLE_MS};

  // 特征值 handle
  uint16_t h_version_{0};
  uint16_t h_cmd_{0};       // 0x0010
  uint16_t h_channel_{0};   // 0x0016
  uint16_t h_lock_write_{0};  // 0x1001
  uint16_t h_state_{0};     // 0x1002
  uint16_t h_log_{0};       // 0x1003

  // 连接 / 状态机
  AuthPhase phase_{AuthPhase::IDLE};
  uint32_t phase_deadline_{0};
  bool services_ready_{false};
  bool pending_unlock_{false};  // control() 已请求，等连接完成后继续
  lock::LockState target_state_{lock::LOCK_STATE_NONE};

  // ECDH / 会话（session key 只在连接期存在，绝不落盘）
  uint8_t priv_[32]{0};
  uint8_t client_pub_[64]{0};
  uint8_t dev_pub_[64]{0};
  uint8_t session_key_[64]{0};
  bool session_ready_{false};

  // 0x0016 TX 事务
  std::deque<PendingWrite> tx_queue_;
  bool write_in_flight_{false};
  uint32_t last_write_ms_{0};
  TxPhase tx_phase_{TxPhase::IDLE};
  uint8_t tx_msg_type_{0};
  std::vector<std::vector<uint8_t>> tx_chunks_;
  uint8_t tx_ctr_retry_{0};
  uint32_t tx_ctr_sent_ms_{0};  // 最近一次 CTR 发出时刻，用于 ACK 超时重发
  uint8_t tx_data_retry_{0};
  bool tx_done_{false};
  bool tx_failed_{false};
  std::vector<uint8_t> ack_scratch_;  // 收到 ACK 的 missing 列表暂存

  // 0x0016 RX 重组（设备→我们）
  bool rx_active_{false};
  uint8_t rx_msg_type_{0};
  uint16_t rx_expected_{0};
  std::map<uint16_t, std::vector<uint8_t>> rx_chunks_;
  std::vector<uint8_t> rx_payload_;
  bool rx_ready_{false};
  uint32_t rx_started_ms_{0};

  // 结果 / 状态
  bool result_received_{false};
  uint8_t result_code_{0};
  uint8_t last_state_plain_{0};
  bool state_frame_seen_{false};

  // 计数器（NVS）
  ESPPreferenceObject ctr_pref_;
  uint16_t ctr_lo_{0};
  uint16_t ctr_hi_{0};
  bool has_ctr_override_{false};
  uint16_t ctr_override_lo_{0};
  uint16_t ctr_override_hi_{0};
};

}  // namespace xiaomi_lock_ble
}  // namespace esphome

#endif  // USE_ESP32
