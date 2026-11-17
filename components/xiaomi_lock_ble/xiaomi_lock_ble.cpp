/*
 * xiaomi_lock_ble.cpp — 见 xiaomi_lock_ble.h
 * 逐帧翻译自已真机跑通的 verify_crypto.py（BUILD_ID v7）。
 */
#include "xiaomi_lock_ble.h"

#ifdef USE_ESP32

#include "esphome/core/log.h"
#include "esphome/core/application.h"
#include "esphome/core/alloc_helpers.h"  // format_hex_pretty(vector) 的明确来源

#include <cstring>

namespace esphome {
namespace xiaomi_lock_ble {

static const char *const TAG = "xiaomi_lock_ble";

// 与 mi_lock_crypto.h 里的 xiaomi_lock 命名空间函数对接
using xiaomi_lock::derive_session_key;
using xiaomi_lock::ecdh_p256_generate;
using xiaomi_lock::ecdh_p256_shared;
using xiaomi_lock::make_lock_frame;
using xiaomi_lock::make_login_confirm;
using xiaomi_lock::parse_lock_frame;

// 128-bit 服务 UUID：由字符串直接构造（from_raw 内部处理小端）
static const espbt::ESPBTUUID UUID_MI_SERVICE =
    espbt::ESPBTUUID::from_raw("0000fe95-0000-1000-8000-00805f9b34fb");
static const espbt::ESPBTUUID UUID_LOCK_SERVICE =
    espbt::ESPBTUUID::from_raw("00001000-0065-6c62-2e74-6f696d2e696d");

static const char *phase_name(AuthPhase p) {
  switch (p) {
    case AuthPhase::IDLE: return "IDLE";
    case AuthPhase::WAIT_CONNECT: return "WAIT_CONNECT";
    case AuthPhase::START_CMD: return "START_CMD";
    case AuthPhase::CLIENT_PUB_TX: return "CLIENT_PUB_TX";
    case AuthPhase::WAIT_DEV_PUB: return "WAIT_DEV_PUB";
    case AuthPhase::CONFIRM_TX: return "CONFIRM_TX";
    case AuthPhase::WAIT_RESULT: return "WAIT_RESULT";
    case AuthPhase::UNLOCK_WRITE: return "UNLOCK_WRITE";
    case AuthPhase::COLLECT_STATE: return "COLLECT_STATE";
    case AuthPhase::DONE: return "DONE";
    case AuthPhase::FAILED: return "FAILED";
  }
  return "?";
}

// ======================= 生命周期 =======================

void XiaomiLockBle::setup() {
  this->traits.set_assumed_state(true);      // 门锁不会主动上报可靠状态，用假定状态
  this->traits.set_supports_open(true);      // open() = 开锁（cmd=0）
  this->load_counter_();
  ESP_LOGCONFIG(TAG, "XiaomiLockBle 已初始化（计数器 %u/%u，settle=%ums，step=%ums）",
                this->ctr_lo_, this->ctr_hi_, this->settle_ms_, this->step_timeout_ms_);
}

void XiaomiLockBle::dump_config() {
  ESP_LOGCONFIG(TAG, "XiaomiLockBle:");
  LOG_LOCK("", "XiaomiLockBle", this);
  ESP_LOGCONFIG(TAG, "  LTMK: %s", this->ltmk_valid_ ? "已配置(32B, 未打印)" : "未配置/无效");
  ESP_LOGCONFIG(TAG, "  计数器(NVS): %u/%u  按钮命令: %u", this->ctr_lo_, this->ctr_hi_, this->cmd_);
}

void XiaomiLockBle::set_ltmk(const std::string &hex) {
  this->ltmk_valid_ = parse_hex(hex, this->ltmk_, sizeof(this->ltmk_));
  if (!this->ltmk_valid_) {
    ESP_LOGE(TAG, "LTMK 必须是 64 位合法 hex（32 字节），实际 %u 位", (unsigned) hex.size());
    memset(this->ltmk_, 0, sizeof(this->ltmk_));
  }
}

// ======================= lock 平台动作入口 =======================

void XiaomiLockBle::control(const lock::LockCall &call) {
  const auto &st = call.get_state();
  if (!st.has_value()) return;

  uint8_t cmd;
  lock::LockState target;
  switch (*st) {
    case lock::LOCK_STATE_UNLOCKED:
    case lock::LOCK_STATE_OPEN:
    case lock::LOCK_STATE_OPENING:
      cmd = 0;  // 开锁
      target = lock::LOCK_STATE_UNLOCKED;
      break;
    case lock::LOCK_STATE_LOCKED:
    case lock::LOCK_STATE_LOCKING:
      cmd = 1;  // 上锁
      target = lock::LOCK_STATE_LOCKED;
      break;
    default:
      ESP_LOGW(TAG, "不支持的锁状态指令 %u", (unsigned) *st);
      return;
  }

  if (this->phase_ != AuthPhase::IDLE && this->phase_ != AuthPhase::DONE &&
      this->phase_ != AuthPhase::FAILED) {
    ESP_LOGW(TAG, "上一轮流程仍在进行（%s），忽略本次请求", phase_name(this->phase_));
    return;
  }
  if (!this->ltmk_valid_) {
    ESP_LOGE(TAG, "LTMK 未配置，无法开锁");
    this->publish_state(lock::LOCK_STATE_JAMMED);
    return;
  }

  this->cmd_ = cmd;
  this->target_state_ = target;
  this->pending_unlock_ = true;
  this->publish_state(target);  // 假定状态：先更新 UI，真机动作为最终判据
  this->request_connect_();
}

// ======================= 连接管理 =======================

void XiaomiLockBle::request_connect_() {
  if (this->parent() == nullptr) {
    ESP_LOGE(TAG, "未绑定 ble_client");
    this->fail_("no ble_client");
    return;
  }
  this->session_ready_ = false;
  this->services_ready_ = false;
  this->set_phase_(AuthPhase::WAIT_CONNECT, this->auth_timeout_ms_);
  this->parent()->connect();
  ESP_LOGI(TAG, "请求连接门锁…");
}

void XiaomiLockBle::on_search_complete_() {
  // 解析 FE95 服务的 3 个特征 + 自定义锁服务的 3 个特征
  this->h_version_ = this->find_char_handle_(UUID_MI_SERVICE, espbt::ESPBTUUID::from_uint16(0x0004));
  this->h_cmd_ = this->find_char_handle_(UUID_MI_SERVICE, espbt::ESPBTUUID::from_uint16(0x0010));
  this->h_channel_ = this->find_char_handle_(UUID_MI_SERVICE, espbt::ESPBTUUID::from_uint16(0x0016));
  this->h_lock_write_ = this->find_char_handle_(UUID_LOCK_SERVICE, espbt::ESPBTUUID::from_uint16(0x1001));
  this->h_state_ = this->find_char_handle_(UUID_LOCK_SERVICE, espbt::ESPBTUUID::from_uint16(0x1002));
  this->h_log_ = this->find_char_handle_(UUID_LOCK_SERVICE, espbt::ESPBTUUID::from_uint16(0x1003));

  ESP_LOGI(TAG, "GATT 特征: 0x0004=%u 0x0010=%u 0x0016=%u 0x1001=%u 0x1002=%u 0x1003=%u",
           this->h_version_, this->h_cmd_, this->h_channel_,
           this->h_lock_write_, this->h_state_, this->h_log_);

  if (this->h_cmd_ == 0 || this->h_channel_ == 0 || this->h_lock_write_ == 0) {
    this->fail_("关键特征未找到");
    return;
  }

  // 注册 FE95 通知（0x0010 命令字 / 0x0016 可靠通道）
  if (this->parent()->register_for_notify(this->h_cmd_) != ESP_OK) {
    ESP_LOGW(TAG, "注册 0x0010 notify 失败");
  }
  if (this->parent()->register_for_notify(this->h_channel_) != ESP_OK) {
    ESP_LOGW(TAG, "注册 0x0016 notify 失败");
  }

  this->services_ready_ = true;
  // 实际的 ECDH 生成 + Step3 写入放到 loop() 的 WAIT_CONNECT 分支完成，
  // 避免在 GATT 回调里做耗时运算或与 loop 的 phase 切换产生竞态。
}

void XiaomiLockBle::on_disconnected_() {
  ESP_LOGI(TAG, "连接已断开，状态机复位");
  // 复位所有连接期状态
  this->services_ready_ = false;
  this->session_ready_ = false;
  this->result_received_ = false;
  this->tx_queue_.clear();
  this->write_in_flight_ = false;
  this->tx_phase_ = TxPhase::IDLE;
  this->tx_chunks_.clear();
  this->rx_active_ = false;
  this->rx_chunks_.clear();
  this->rx_ready_ = false;
  this->ack_scratch_.clear();
  memset(this->session_key_, 0, sizeof(this->session_key_));
  memset(this->priv_, 0, sizeof(this->priv_));

  if (this->phase_ == AuthPhase::WAIT_CONNECT || this->phase_ == AuthPhase::START_CMD ||
      this->phase_ == AuthPhase::CLIENT_PUB_TX || this->phase_ == AuthPhase::WAIT_DEV_PUB ||
      this->phase_ == AuthPhase::CONFIRM_TX || this->phase_ == AuthPhase::WAIT_RESULT) {
    this->phase_ = AuthPhase::FAILED;
    this->pending_unlock_ = false;
    this->publish_state(lock::LOCK_STATE_JAMMED);
  } else {
    this->phase_ = AuthPhase::IDLE;
  }

  // 断开后 ble_client（auto_connect:false）不再重连，esp32_ble_tracker 的被动
  // 扫描由 tracker 自己维持，无需在这里干预；广播传感器会自动恢复。
}

void XiaomiLockBle::fail_(const char *reason) {
  ESP_LOGE(TAG, "开锁流程失败: %s（阶段 %s）", reason, phase_name(this->phase_));
  this->phase_ = AuthPhase::FAILED;
  this->pending_unlock_ = false;
  this->publish_state(lock::LOCK_STATE_JAMMED);
  if (this->parent() != nullptr && this->services_ready_)
    this->parent()->disconnect();
}

void XiaomiLockBle::finish_ok_() {
  ESP_LOGI(TAG, "✔ 开锁帧已送达，状态更新为 %s", target_state_ == lock::LOCK_STATE_UNLOCKED ? "UNLOCKED" : "LOCKED");
  this->publish_state(this->target_state_);
  this->phase_ = AuthPhase::DONE;
  this->pending_unlock_ = false;
  if (this->parent() != nullptr && this->services_ready_)
    this->parent()->disconnect();
}

// ======================= GATT 事件 =======================

void XiaomiLockBle::gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                                        esp_ble_gattc_cb_param_t *param) {
  switch (event) {
    case ESP_GATTC_SEARCH_CMPL_EVT:
      // 告诉父组件不再需要读取 GATT 缓存，可释放内存
      this->node_state = espbt::ClientState::ESTABLISHED;
      this->on_search_complete_();
      break;

    case ESP_GATTC_WRITE_CHAR_EVT:
      if (param->write.status == ESP_GATT_OK) {
        this->write_in_flight_ = false;
        this->last_write_ms_ = millis();
      } else {
        ESP_LOGW(TAG, "写特征失败 status=0x%x", param->write.status);
        this->write_in_flight_ = false;
        if (this->phase_ == AuthPhase::START_CMD || this->phase_ == AuthPhase::CLIENT_PUB_TX ||
            this->phase_ == AuthPhase::CONFIRM_TX || this->phase_ == AuthPhase::UNLOCK_WRITE) {
          this->fail_("写特征失败");
        }
      }
      break;

    case ESP_GATTC_NOTIFY_EVT: {
      const uint16_t handle = param->notify.handle;
      const uint8_t *data = param->notify.value;
      const size_t len = param->notify.value_len;
      if (handle == this->h_cmd_) {
        this->on_cmd_notify_(data, len);
      } else if (handle == this->h_channel_) {
        this->on_channel_notify_(data, len);
      } else if (handle == this->h_state_) {
        this->on_state_notify_(data, len, "0x1002");
      } else if (handle == this->h_log_) {
        this->on_state_notify_(data, len, "0x1003");
      }
      break;
    }

    case ESP_GATTC_CLOSE_EVT:
    case ESP_GATTC_DISCONNECT_EVT:
      this->node_state = espbt::ClientState::IDLE;
      this->on_disconnected_();
      break;

    default:
      break;
  }
}

// ======================= 可靠通道 0x0016 =======================

void XiaomiLockBle::queue_write_(uint16_t handle, const std::vector<uint8_t> &data, bool with_response) {
  if (handle == 0) return;
  PendingWrite w;
  w.handle = handle;
  w.data = data;
  w.with_response = with_response;
  this->tx_queue_.push_back(std::move(w));
}

void XiaomiLockBle::pump_tx_() {
  // 看门狗：NO_RSP 写在某些 IDF 版本不给 WRITE_CHAR_EVT，2s 无回调强制解锁，
  // 避免整个 TX 队列卡死（真机 Python 侧也是无响应写，但 bleak 会兜底完成）。
  if (this->write_in_flight_ && millis() - this->last_write_ms_ > 2000) {
    ESP_LOGW(TAG, "写特征 2s 无 WRITE 事件，强制推进 TX 队列");
    this->write_in_flight_ = false;
  }
  if (this->write_in_flight_ || this->tx_queue_.empty()) return;
  // settle：发新包前给设备时间处理上一包（防 TX 抢序，见报告补⑧）
  if (millis() - this->last_write_ms_ < this->settle_ms_) return;

  auto &w = this->tx_queue_.front();
  esp_err_t err = esp_ble_gattc_write_char(
      this->parent()->get_gattc_if(), this->parent()->get_conn_id(), w.handle,
      w.data.size(), const_cast<uint8_t *>(w.data.data()),
      w.with_response ? ESP_GATT_WRITE_TYPE_RSP : ESP_GATT_WRITE_TYPE_NO_RSP,
      ESP_GATT_AUTH_REQ_NONE);
  if (err == ESP_OK) {
    ESP_LOGV(TAG, "0x%04X TX %s", w.handle, format_hex_pretty(w.data).c_str());
    this->write_in_flight_ = true;
    this->last_write_ms_ = millis();
    this->tx_queue_.pop_front();
  } else {
    ESP_LOGE(TAG, "esp_ble_gattc_write_char 失败: %s", esp_err_to_name(err));
    this->tx_queue_.pop_front();
    this->fail_("GATT 写失败");
  }
}

void XiaomiLockBle::send_ack_(uint8_t status, const std::vector<uint16_t> &missing) {
  // ACK = 00 00 01 <status> [缺失序号 u16 LE…]
  std::vector<uint8_t> b = {0x00, 0x00, 0x01, status};
  for (uint16_t s : missing) {
    b.push_back((uint8_t) (s & 0xFF));
    b.push_back((uint8_t) (s >> 8));
  }
  this->queue_write_(this->h_channel_, b, false);
}

void XiaomiLockBle::on_channel_notify_(const uint8_t *data, size_t len) {
  if (len < 2) return;
  const uint16_t seq = (uint16_t) (data[0] | (data[1] << 8));
  ESP_LOGV(TAG, "0x0016 RX %s", format_hex_pretty(data, len).c_str());

  if (seq != 0) {
    // DATA 帧：seq(1-based) + payload
    if (!this->rx_active_ || seq == 0 || seq > this->rx_expected_ ||
        this->rx_chunks_.count(seq)) {
      return;  // 未期待 / 越界 / 重复片，丢弃
    }
    this->rx_chunks_[seq] = std::vector<uint8_t>(data + 2, data + len);
    if ((uint16_t) this->rx_chunks_.size() == this->rx_expected_) {
      this->rx_payload_.clear();
      for (uint16_t i = 1; i <= this->rx_expected_; i++) {
        const auto &c = this->rx_chunks_[i];
        this->rx_payload_.insert(this->rx_payload_.end(), c.begin(), c.end());
      }
      this->rx_active_ = false;
      this->rx_chunks_.clear();
      this->rx_ready_ = true;
      this->send_ack_(CH_STATUS_COMPLETE);  // 收齐回 ACK(0)
      ESP_LOGI(TAG, "0x0016 重组完成 msgType=%u payload=%uB", this->rx_msg_type_, (unsigned) this->rx_payload_.size());
    }
    return;
  }

  if (len < 4) return;
  const uint8_t opcode = data[2];
  const uint8_t val = data[3];

  if (opcode == 0) {
    // CTR：00 00 00 <packageType> <frameCount:u16LE>
    const uint16_t frame_count = (len >= 6) ? (uint16_t) (data[4] | (data[5] << 8)) : 0;
    if (frame_count == 0) return;
    this->rx_active_ = true;
    this->rx_msg_type_ = val;
    this->rx_expected_ = frame_count;
    this->rx_chunks_.clear();
    this->rx_payload_.clear();
    this->rx_ready_ = false;
    this->rx_started_ms_ = millis();
    this->send_ack_(CH_STATUS_READY);  // ★ 回 01，不是 packageType
    ESP_LOGI(TAG, "0x0016 收到 CTR msgType=%u frames=%u → ACK(1)", val, frame_count);
  } else if (opcode == 1) {
    // ACK：00 00 01 <status> [missing…]
    std::vector<uint16_t> missing;
    for (size_t i = 4; i + 1 < len; i += 2)
      missing.push_back((uint16_t) (data[i] | (data[i + 1] << 8)));
    this->on_channel_ack_(val, missing);
  }
}

void XiaomiLockBle::on_channel_ack_(uint8_t status, const std::vector<uint16_t> &missing) {
  ESP_LOGI(TAG, "0x0016 收到 ACK status=%u（%s）", status,
           status == CH_STATUS_READY ? "READY" : status == CH_STATUS_COMPLETE ? "COMPLETE" :
           status == CH_STATUS_RETRANS ? "RETRANS" : "未知");

  if (this->tx_phase_ == TxPhase::WAIT_CTR_ACK) {
    if (status == CH_STATUS_READY) {
      this->send_channel_data_();
    } else if (status == CH_STATUS_RETRANS) {
      // 设备请求重发 CTR（少见的握手重试）
      if (++this->tx_ctr_retry_ <= 3) {
        this->send_channel_ctr_();
      } else {
        this->tx_failed_ = true;
      }
    } else {
      this->tx_failed_ = true;  // 期望 status=1，收到别的（含 3）都当异常
    }
  } else if (this->tx_phase_ == TxPhase::WAIT_DATA_ACK) {
    if (status == CH_STATUS_COMPLETE) {
      this->tx_done_ = true;
      this->tx_phase_ = TxPhase::IDLE;
    } else if (status == CH_STATUS_RETRANS && !missing.empty()) {
      // 按 1-based 缺片序号重传
      std::vector<std::vector<uint8_t>> retry;
      for (uint16_t s : missing) {
        if (s >= 1 && s <= this->tx_chunks_.size())
          retry.push_back(this->tx_chunks_[s - 1]);
      }
      if (retry.empty()) {
        this->tx_done_ = true;
        this->tx_phase_ = TxPhase::IDLE;
      } else if (++this->tx_data_retry_ <= 5) {
        this->tx_chunks_ = retry;
        this->send_channel_data_();
      } else {
        this->tx_failed_ = true;
      }
    } else {
      this->tx_failed_ = true;
    }
  }
}

void XiaomiLockBle::start_channel_tx_(uint8_t msg_type, const std::vector<uint8_t> &payload) {
  this->tx_msg_type_ = msg_type;
  this->tx_chunks_.clear();
  if (payload.empty()) {
    this->tx_chunks_.push_back({});
  } else {
    for (size_t i = 0; i < payload.size(); i += CHANNEL_CHUNK) {
      size_t n = std::min(CHANNEL_CHUNK, payload.size() - i);
      this->tx_chunks_.emplace_back(payload.begin() + i, payload.begin() + i + n);
    }
  }
  this->tx_ctr_retry_ = 0;
  this->tx_data_retry_ = 0;
  this->tx_done_ = false;
  this->tx_failed_ = false;
  this->tx_phase_ = TxPhase::IDLE;
  ESP_LOGI(TAG, "0x0016 发送 msgType=%u payload=%uB 分 %u 片", msg_type,
           (unsigned) payload.size(), (unsigned) this->tx_chunks_.size());
  this->send_channel_ctr_();
}

void XiaomiLockBle::send_channel_ctr_() {
  // CTR = 00 00 <msgType> <frameCount:u16LE>（4B 头，seq=0 表示控制帧）
  std::vector<uint8_t> b = {0x00, 0x00, this->tx_msg_type_,
                            (uint8_t) (this->tx_chunks_.size() & 0xFF),
                            (uint8_t) (this->tx_chunks_.size() >> 8)};
  this->tx_phase_ = TxPhase::WAIT_CTR_ACK;
  this->queue_write_(this->h_channel_, b, false);
}

void XiaomiLockBle::send_channel_data_() {
  // DATA = seq(u16LE 从1开始) + payload(≤18B)
  for (size_t i = 0; i < this->tx_chunks_.size(); i++) {
    const auto &chunk = this->tx_chunks_[i];
    std::vector<uint8_t> b;
    b.push_back((uint8_t) ((i + 1) & 0xFF));
    b.push_back((uint8_t) ((i + 1) >> 8));
    b.insert(b.end(), chunk.begin(), chunk.end());
    this->queue_write_(this->h_channel_, b, false);
  }
  this->tx_phase_ = TxPhase::WAIT_DATA_ACK;
}

// ======================= 0x0010 命令字 =======================

void XiaomiLockBle::on_cmd_notify_(const uint8_t *data, size_t len) {
  ESP_LOGI(TAG, "0x0010 RX %s", format_hex_pretty(data, len).c_str());
  if (len < 1) return;
  this->result_code_ = data[0];
  this->result_received_ = true;
  if (data[0] == 0x21 && this->phase_ == AuthPhase::WAIT_RESULT) {
    ESP_LOGI(TAG, "Step7 登录成功 (0x21)");
  } else if (data[0] != 0x21) {
    ESP_LOGW(TAG, "0x0010 结果码 0x%02X（0x21 才是登录成功）", data[0]);
  }
}

// ======================= 0x1002 / 0x1003 状态 =======================

void XiaomiLockBle::on_state_notify_(const uint8_t *data, size_t len, const char *which) {
  // 上行帧用 devKey 解密；解不开只记日志，绝不作为开锁成功判据
  ESP_LOGI(TAG, "%s RX %s", which, format_hex_pretty(data, len).c_str());
  if (!this->session_ready_ || len < 7) return;
  std::vector<uint8_t> plain;
  if (xiaomi_lock::parse_lock_frame(this->session_key_, data, len, 0, plain)) {
    this->state_frame_seen_ = true;
    if (!plain.empty()) this->last_state_plain_ = plain[0];
    ESP_LOGI(TAG, "%s 解密成功 plain=%s（0x00=命令已接受，非动作完成确认）",
             which, format_hex_pretty(plain).c_str());
  } else {
    ESP_LOGW(TAG, "%s 解密未通过（格式/方向待确认，忽略）", which);
  }
}

// ======================= 计数器 NVS =======================

void XiaomiLockBle::load_counter_() {
  // 用一个 32-bit preference 存 (hi<<16)|lo；key 用固定 hash
  this->ctr_pref_ = global_preferences->make_preference<uint32_t>(0x584C4F43U);  // "XLOC"
  uint32_t stored = 0;
  if (this->ctr_pref_.load(&stored)) {
    this->ctr_lo_ = (uint16_t) (stored & 0xFFFF);
    this->ctr_hi_ = (uint16_t) (stored >> 16);
  }
  if (this->has_ctr_override_) {
    this->ctr_lo_ = this->ctr_override_lo_;
    this->ctr_hi_ = this->ctr_override_hi_;
    ESP_LOGI(TAG, "计数器被显式覆盖为 %u/%u", this->ctr_lo_, this->ctr_hi_);
  }
}

void XiaomiLockBle::save_counter_() {
  this->ctr_lo_++;
  if (this->ctr_lo_ == 0) this->ctr_hi_++;
  uint32_t packed = ((uint32_t) this->ctr_hi_ << 16) | this->ctr_lo_;
  this->ctr_pref_.save(&packed);
  ESP_LOGI(TAG, "计数器已提交 %u/%u（写帧前预占）", this->ctr_lo_, this->ctr_hi_);
}

// ======================= 工具 =======================

uint16_t XiaomiLockBle::find_char_handle_(espbt::ESPBTUUID service, espbt::ESPBTUUID chr) {
  auto *c = this->parent()->get_characteristic(service, chr);
  if (c == nullptr) {
    char sb[espbt::UUID_STR_LEN], cb[espbt::UUID_STR_LEN];
    ESP_LOGW(TAG, "特征 %s 在服务 %s 中未找到", chr.to_str(cb), service.to_str(sb));
    return 0;
  }
  return c->handle;
}

bool XiaomiLockBle::phase_expired_() const {
  return this->phase_deadline_ != 0 && millis() >= this->phase_deadline_;
}

void XiaomiLockBle::set_phase_(AuthPhase phase, uint32_t timeout_ms) {
  this->phase_ = phase;
  this->phase_deadline_ = timeout_ms ? (millis() + timeout_ms) : 0;
  ESP_LOGD(TAG, "→ 阶段 %s", phase_name(phase));
}

// ======================= 主循环：驱动状态机 =======================

void XiaomiLockBle::loop() {
  this->pump_tx_();

  // 0x0016 设备公钥重组超时：主动请求重传缺失片
  if (this->rx_active_ && millis() - this->rx_started_ms_ > this->step_timeout_ms_) {
    std::vector<uint16_t> missing;
    for (uint16_t i = 1; i <= this->rx_expected_; i++)
      if (!this->rx_chunks_.count(i)) missing.push_back(i);
    if (!missing.empty()) {
      ESP_LOGW(TAG, "0x0016 收片超时，请求重传 %u 片", (unsigned) missing.size());
      this->send_ack_(CH_STATUS_RETRANS, missing);
      this->rx_started_ms_ = millis();
    }
  }

  switch (this->phase_) {
    case AuthPhase::WAIT_CONNECT:
      if (this->services_ready_) {
        // 生成一次性 P-256 密钥对（前向安全）
        if (!ecdh_p256_generate(this->priv_, this->client_pub_)) {
          this->fail_("ECDH 密钥对生成失败");
          break;
        }
        // Step 3：0x0010 直写 4B 启动命令
        const uint8_t start_cmd[4] = {0x20, 0x00, 0x00, 0x00};
        this->queue_write_(this->h_cmd_, std::vector<uint8_t>(start_cmd, start_cmd + 4), false);
        ESP_LOGI(TAG, "Step3 已写 0x0010 = 20 00 00 00");
        // 客户端公钥 TX 与 Step3 写同一轮 pipeline：公钥事务启动后等 ACK
        this->start_channel_tx_(3, std::vector<uint8_t>(this->client_pub_, this->client_pub_ + 64));
        this->set_phase_(AuthPhase::CLIENT_PUB_TX, this->step_timeout_ms_);
      }
      break;

    case AuthPhase::CLIENT_PUB_TX:
      // 等公钥 TX 事务完成（CTR+DATA+ACK 全走完）
      if (this->tx_failed_) {
        this->fail_("公钥发送失败");
      } else if (this->tx_done_) {
        this->tx_done_ = false;
        this->set_phase_(AuthPhase::WAIT_DEV_PUB, this->step_timeout_ms_);
        ESP_LOGI(TAG, "Step4 完成：64B 客户端公钥已送达");
      }
      break;

    case AuthPhase::WAIT_DEV_PUB:
      if (this->rx_ready_) {
        this->rx_ready_ = false;
        if (this->rx_msg_type_ != 3 || this->rx_payload_.size() != 64) {
          this->fail_("设备公钥格式不符");
          break;
        }
        memcpy(this->dev_pub_, this->rx_payload_.data(), 64);
        // Step 6：ECDH → HKDF → 登录确认
        uint8_t shared[32];
        if (!ecdh_p256_shared(this->priv_, this->dev_pub_, shared)) {
          this->fail_("ECDH 共享密钥失败");
          break;
        }
        if (!derive_session_key(shared, this->ltmk_, this->session_key_)) {
          this->fail_("HKDF 派生失败");
          break;
        }
        memset(shared, 0, sizeof(shared));
        std::vector<uint8_t> confirm;
        if (!make_login_confirm(this->session_key_, this->dev_pub_, confirm)) {
          this->fail_("登录确认生成失败");
          break;
        }
        this->session_ready_ = true;
        this->start_channel_tx_(5, confirm);  // msgType=5
        this->set_phase_(AuthPhase::CONFIRM_TX, this->step_timeout_ms_);
        ESP_LOGI(TAG, "Step5/6 收到设备公钥并已发出登录确认");
      }
      break;

    case AuthPhase::CONFIRM_TX:
      if (this->tx_failed_) {
        this->fail_("登录确认发送失败");
      } else if (this->tx_done_) {
        this->tx_done_ = false;
        this->set_phase_(AuthPhase::WAIT_RESULT, this->auth_timeout_ms_);
        ESP_LOGI(TAG, "Step6 登录确认已送达，等待 0x0010 结果码");
      }
      break;

    case AuthPhase::WAIT_RESULT:
      if (this->result_received_) {
        if (this->result_code_ != 0x21) {
          this->fail_("登录被设备拒绝");
          break;
        }
        // Step 8：先订阅状态/日志，再提交计数器并写 0x1001
        if (this->h_state_) this->parent()->register_for_notify(this->h_state_);
        if (this->h_log_) this->parent()->register_for_notify(this->h_log_);
        this->save_counter_();
        std::vector<uint8_t> frame;
        if (!make_lock_frame(this->session_key_, this->cmd_, this->ctr_lo_, this->ctr_hi_, frame)) {
          this->fail_("开锁帧生成失败");
          break;
        }
        ESP_LOGI(TAG, "Step8 写 0x1001 开锁帧 %s (cmd=%u ctr=%u/%u)",
                 format_hex_pretty(frame).c_str(), this->cmd_, this->ctr_lo_, this->ctr_hi_);
        this->queue_write_(this->h_lock_write_, frame, true);
        this->set_phase_(AuthPhase::COLLECT_STATE, 3000);
      }
      break;

    case AuthPhase::COLLECT_STATE:
      // 状态帧只记日志；3 秒收集窗口结束即视为已完成（现场动作是最终判据）
      if (this->phase_expired_()) this->finish_ok_();
      break;

    case AuthPhase::START_CMD:
    case AuthPhase::DONE:
    case AuthPhase::FAILED:
    case AuthPhase::IDLE:
      break;
  }

  // 各阶段统一超时保护
  if (this->phase_expired_() && this->phase_ != AuthPhase::IDLE &&
      this->phase_ != AuthPhase::DONE && this->phase_ != AuthPhase::FAILED &&
      this->phase_ != AuthPhase::COLLECT_STATE) {
    this->fail_("阶段超时");
  }
}

}  // namespace xiaomi_lock_ble
}  // namespace esphome

#endif  // USE_ESP32
