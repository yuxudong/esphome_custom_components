#include "xiaomi_lock.h"
#include "esphome/core/log.h"

#ifdef USE_ESP32
#include "mbedtls/ccm.h"

namespace esphome {
namespace xiaomi_lock {
  std::map<uint8_t, std::string> BioEvtMap = {
    { 0x00, "Bio Success" },
    { 0x01, "Bio failed"},
    { 0x02, "Timeout"},
    { 0x03, "Low quality"},
    { 0x04, "Insufficient area"},
    { 0x05, "Too dry"},
    { 0x06, "Too wet"}
  };

  std::map<uint8_t, std::string> DoorEvtMap = {
    { 0x00, "Opened" },
    { 0x01, "Closed" },
    { 0x02, "Unclosed" },
    { 0x03, "Knock" },
    { 0x04, "Pry" },
    { 0x05, "Stuck"}
  };

  std::map<uint8_t, std::string> LockEvtHBMap = {
    { 0b0000, "Unlock Outside"  },
    { 0b0001, "Locked" },
    { 0b0010, "Turn on anti-lock" },
    { 0b0011, "Turn off anti-lock" },
    { 0b0100, "Inside Unlock" },
    { 0b0101, "Inside Locked" },
    { 0b0110, "Turn on child lock" },
    { 0b0111, "Turn off child lock" },
    { 0b1000, "Outside Locked" },
    { 0b1111, "Abnormal" }
  }; 

  std::map<uint8_t, std::string> LockEvtLBMap = {  
    { 0b0000, "Bluetooth"  },
    { 0b0001, "Password" },
    { 0b0010, "BIO" },
    { 0b0011, "key" },
    { 0b0100, "Turntable" },
    { 0b0101, "NFC" },
    { 0b0110, "OPT" },
    { 0b0111, "2FA" },
    { 0b1001, "Homekit" },
    { 0b1000, "Duress" },
    { 0b1010, "Manual" },
    { 0b1011, "Automatic" },
    { 0b1111, "Abnormal" }
  }; 

  // 0x00000000 - 0x7FFFFFFF：蓝牙（最多 2147483647 个）
  // 0x80010000 - 0x8001FFFF：生物特征-指纹（最多 65536 个）
  // 0x80020000 - 0x8002FFFF：密码（最多 65536 个）
  // 0x80030000 - 0x8003FFFF：钥匙（最多 65536 个）
  // 0x80040000 - 0x8004FFFF：NFC（最多 65536 个）
  // 0x80050000 - 0x8005FFFF：双重验证（最多 65536 个）
  // 0x80060000 - 0x8006FFFF：生物特征-人脸（最多 65536 个）
  // 0x80070000 - 0x8007FFFF：生物特征-指静脉（最多 65536 个）
  // 0x80080000 - 0x8008FFFF：生物特征-掌纹（最多 65536 个

  std::map<uint32_t, std::string> KeyIDMap = { 
    { 0x00000000, "Admin" },
    { 0xFFFFFFFF, "Unknown Operator" },
    { 0xDEADBEEF, "Invalid Operator" },
    { 0xC0DE0000, "错误密码频繁开锁" },
    { 0xC0DE0001, "错误指纹频繁开锁" },
    { 0xC0DE0002, "操作超时（密码输入超时）" },
    { 0xC0DE0003, "撬锁" },
    { 0xC0DE0004, "重置按键按下" },
    { 0xC0DE0005, "错误钥匙频繁开锁" },
    { 0xC0DE0006, "钥匙孔异物" },
    { 0xC0DE0007, "钥匙未取出" },
    { 0xC0DE0008, "错误NFC频繁开锁" },
    { 0xC0DE0009, "超时未按要求上锁" },
    { 0xC0DE000A, "多种方式频繁开锁失败" },
    { 0xC0DE000B, "人脸频繁开锁失败" },
    { 0xC0DE000C, "静脉频繁开锁失败" },
    { 0xC0DE000D, "劫持报警" },
    { 0xC0DE000E, "布防后门内开锁" },
    { 0xC0DE000F, "掌纹频繁开锁失败" },
    { 0xC0DE0010, "保险箱被移动" },
    { 0xC0DE1000, "电量低于10%" },
    { 0xC0DE1001, "电量低于5%" },
    { 0xC0DE1002, "指纹传感器异常" },
    { 0xC0DE1003, "配件电池电量低" },
    { 0xC0DE1004, "机械故障" },
    { 0xC0DE1005, "锁体传感器故障" }
  };

std::string findOperator(uint32_t keyid) {
  if(keyid >= 0x00000000 && keyid <= 0x7FFFFFFF) {
    return std::string("Bluetooth ") + std::to_string(keyid - 0x00000000);
  }
  if(keyid >= 0x80010000 && keyid <= 0x8001FFFF) {
    return std::string("BIO-fingerprint ") + std::to_string(keyid - 0x80010000);
  }
  if(keyid >= 0x80020000 && keyid <= 0x8002FFFF) {
    return std::string("Password ") + std::to_string(keyid - 0x80020000);
  }
  if(keyid >= 0x80030000 && keyid <= 0x8003FFFF) {
    return std::string("Key ") + std::to_string(keyid - 0x80030000);
  }
  if(keyid >= 0x80040000 && keyid <= 0x8004FFFF) {
    return std::string("NFC ") + std::to_string(keyid - 0x80040000);
  }
  if(keyid >= 0x80050000 && keyid <= 0x8005FFFF) {
    return std::string("2FA ") + std::to_string(keyid - 0x80050000);
  }
  if(keyid >= 0x80060000 && keyid <= 0x8006FFFF) {
    return std::string("BIO-face ") + std::to_string(keyid - 0x80060000);
  }
  if(keyid >= 0x8007000 && keyid <= 0x8007FFFF) {
    return std::string("BIO-fingervein") + std::to_string(keyid - 0x80070000);
  }
  if(keyid >= 0x8008000 && keyid <= 0x8008FFFF) {
    return std::string("BIO-palmprint") + std::to_string(keyid - 0x80080000);
  }
  return std::string("Error");
}

std::string findLockEvt(uint8_t data) {
  uint8_t HB = data & 0x0F;
  uint8_t LB = (data >> 4) & 0x0F;
  auto it1 = LockEvtLBMap.find(LB);
  std::string s1 = (it1 == LockEvtLBMap.end()) ? "Error" : it1->second;
  auto it2 = LockEvtHBMap.find(HB);
  std::string s2 = (it2 == LockEvtLBMap.end()) ? "Error" : it2->second;
  return s1 + std::string(" ") + s2;
}

static const char *const TAG = "xiaomi_lock";

void XiaomiLock::dump_config() {
  ESP_LOGCONFIG(TAG, "Xiaomi Lock");
  ESP_LOGCONFIG(TAG, "  Bindkey: %s", format_hex_pretty(this->bindkey_, 16).c_str());
  LOG_SENSOR("  ", "BattLvl", this->battlvl_);
  LOG_TEXT_SENSOR("  ", "BattLvlTS", this->battlvlts_);
  LOG_TEXT_SENSOR("  ", "KeyID", this->keyid_);
  LOG_TEXT_SENSOR("  ", "BIOEvt", this->bioevt_);
  LOG_TEXT_SENSOR("  ", "LockEvt", this->lockevt_);
  LOG_TEXT_SENSOR("  ", "LockEvtTS", this->lockevtts_);
  LOG_TEXT_SENSOR("  ", "DoorEvt", this->doorevt_);
  LOG_TEXT_SENSOR("  ", "DoorEvtTS", this->doorevtts_);
}

bool XiaomiLock::parse_device(const esp32_ble_tracker::ESPBTDevice &device) {
  if (device.address_uint64() != this->address_) {
    ESP_LOGVV(TAG, "parse_device(): unknown MAC address.");
    return false;
  }
  ESP_LOGVV(TAG, "parse_device(): MAC address %s found.", device.address_str().c_str());

  bool success = false;
  for (auto &service_data : device.get_manufacturer_datas())  {

  }
  for (auto &service_data : device.get_service_datas()) {
    auto res = mi.parse_xiaomi_header(service_data);
    if (!res.has_value()) {
      continue;
    }
    if (res->is_duplicate) {
      continue;
    }
    if (res->has_encryption && (!(decrypt_xiaomi_message(const_cast<std::vector<uint8_t> &>(service_data.data), this->bindkey_, this->address_)))) {
      continue;
    }
    if (!(mi.parse_xiaomi_message(service_data.data, *res))) {
      continue;
    }
    if (res->battlvl.has_value() && this->battlvl_ != nullptr)
      this->battlvl_->publish_state(*res->battlvl);
    if (!res->battlvlts.empty() && this->battlvlts_ != nullptr)
      this->battlvlts_->publish_state(res->battlvlts);
    if (!res->keyid.empty() && this->keyid_ != nullptr)
      this->keyid_->publish_state(res->keyid);
    if (!res->lockevt.empty() && this->lockevt_ != nullptr)
      this->lockevt_->publish_state(res->lockevt);
    if (!res->lockevtts.empty() && this->lockevtts_ != nullptr)
      this->lockevtts_->publish_state(res->lockevtts);
    if (!res->bioevt.empty() && this->bioevt_ != nullptr)
      this->bioevt_->publish_state(res->bioevt);
    if (!res->doorevt.empty() && this->doorevt_ != nullptr)
      this->doorevt_->publish_state(res->doorevt);
    if (!res->doorevtts.empty() && this->doorevtts_ != nullptr)
      this->doorevtts_->publish_state(res->doorevtts);
    success = true;
  }

  if (!success) {
    return false;
  }

  return true;
}

void XiaomiLock::set_bindkey(const std::string &bindkey) {
  memset(bindkey_, 0, 16);
  if (bindkey.size() != 32) {
    return;
  }
  char temp[3] = {0};
  for (int i = 0; i < 16; i++) {
    strncpy(temp, &(bindkey.c_str()[i * 2]), 2);
    bindkey_[i] = std::strtoul(temp, NULL, 16);
  }
}

static bool decrypt_xiaomi_message(std::vector<uint8_t> &raw, const uint8_t *bindkey, const uint64_t &address) {
    /* if (!((raw.size() == 19) || ((raw.size() >= 22) && (raw.size() <= 24)))) {
    ESP_LOGD(TAG, "decrypt_xiaomi_payload(): data packet has wrong size (%d)!", raw.size());
    ESP_LOGD(TAG, "  Packet : %s", format_hex_pretty(raw.data(), raw.size()).c_str());
    return false;
  } */

  uint8_t mac_reverse[6] = {0};
  mac_reverse[5] = (uint8_t)(address >> 40);
  mac_reverse[4] = (uint8_t)(address >> 32);
  mac_reverse[3] = (uint8_t)(address >> 24);
  mac_reverse[2] = (uint8_t)(address >> 16);
  mac_reverse[1] = (uint8_t)(address >> 8);
  mac_reverse[0] = (uint8_t)(address >> 0);

  XiaomiAESVector vector{.key = {0},
                         .plaintext = {0},
                         .ciphertext = {0},
                         .authdata = {0x11},
                         .iv = {0},
                         .tag = {0},
                         .keysize = 16,
                         .authsize = 1,
                         .datasize = 0,
                         .tagsize = 4,
                         .ivsize = 12};

  vector.datasize = raw.size() - 12 ;
  int cipher_pos = 5;

  const uint8_t *v = raw.data();

  memcpy(vector.key, bindkey, vector.keysize);
  memcpy(vector.ciphertext, v + cipher_pos, vector.datasize);
  memcpy(vector.tag, v + raw.size() - vector.tagsize, vector.tagsize);
  memcpy(vector.iv, mac_reverse, 6);             // MAC address reverse
  memcpy(vector.iv + 6, v + 2, 3);               // sensor type (2) + packet id (1)
  memcpy(vector.iv + 9, v + raw.size() - 7, 3);  // payload counter

  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);

  int ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, vector.key, vector.keysize * 8);
  if (ret) {
    ESP_LOGV(TAG, "decrypt_xiaomi_payload(): mbedtls_ccm_setkey() failed.");
    mbedtls_ccm_free(&ctx);
    return false;
  }

  ret = mbedtls_ccm_auth_decrypt(&ctx, vector.datasize, vector.iv, vector.ivsize, vector.authdata, vector.authsize,
                                 vector.ciphertext, vector.plaintext, vector.tag, vector.tagsize);
  if (ret) {
    uint8_t mac_address[6] = {0};
    memcpy(mac_address, mac_reverse + 5, 1);
    memcpy(mac_address + 1, mac_reverse + 4, 1);
    memcpy(mac_address + 2, mac_reverse + 3, 1);
    memcpy(mac_address + 3, mac_reverse + 2, 1);
    memcpy(mac_address + 4, mac_reverse + 1, 1);
    memcpy(mac_address + 5, mac_reverse, 1);
    ESP_LOGD(TAG, "decrypt_xiaomi_payload(): authenticated decryption failed.");
    ESP_LOGD(TAG, "  MAC address : %s", format_hex_pretty(mac_address, 6).c_str());
    ESP_LOGD(TAG, "       Packet : %s", format_hex_pretty(raw.data(), raw.size()).c_str());
    ESP_LOGD(TAG, "          Key : %s", format_hex_pretty(vector.key, vector.keysize).c_str());
    ESP_LOGD(TAG, "           Iv : %s", format_hex_pretty(vector.iv, vector.ivsize).c_str());
    ESP_LOGD(TAG, "       Cipher : %s", format_hex_pretty(vector.ciphertext, vector.datasize).c_str());
    ESP_LOGD(TAG, "          Tag : %s", format_hex_pretty(vector.tag, vector.tagsize).c_str());
    mbedtls_ccm_free(&ctx);
    return false;
  }

  // replace encrypted payload with plaintext
  uint8_t *p = vector.plaintext;
  for (std::vector<uint8_t>::iterator it = raw.begin() + cipher_pos; it != raw.begin() + cipher_pos + vector.datasize;
       ++it) {
    *it = *(p++);
  }

  // clear encrypted flag
  raw[0] &= ~0x08;

  ESP_LOGD(TAG, "decrypt_xiaomi_payload(): authenticated decryption passed.");
  ESP_LOGD(TAG, "  Plaintext : %s, Packet : %d", format_hex_pretty(raw.data() + cipher_pos, vector.datasize).c_str(),
            static_cast<int>(raw[4]));

  mbedtls_ccm_free(&ctx);
  return true;
}

optional<XiaomiParseResult> MiBeacon::parse_xiaomi_header(const esp32_ble_tracker::ServiceData &service_data) {
  XiaomiParseResult result;
  if (!service_data.uuid.contains(0x8F, 0x03) and !service_data.uuid.contains(0x95, 0xFE)) {
    ESP_LOGD(TAG, "parse_xiaomi_header(): no service data UUID magic bytes.");
    return {};
  }
  auto raw = service_data.data;
  result.has_data = (raw[0] & 0x40) ? true : false;
  result.has_capability = (raw[0] & 0x20) ? true : false;
  result.has_encryption = (raw[0] & 0x08) ? true : false;
  result.has_mac = (raw[0] & 0x10) ? true : false;
  result.has_mesh = (raw[0] & 0x80) ? true : false;
  result.has_io_capability = false;

  if(result.has_capability) {
    if(result.has_mac) {
      result.has_io_capability = (raw[5 + 6] & 0x20) ? true : false;
    }else{
      result.has_io_capability = (raw[5] & 0x20) ? true : false;
    }
  }

  ESP_LOGV(TAG, "Packet : %s", format_hex_pretty(raw.data(), raw.size()).c_str());

  if (!result.has_data) {
    ESP_LOGV(TAG, "parse_xiaomi_header(): service data has no DATA flag.");
    return {};
  }

  static uint8_t last_frame_count = 0;
  if (last_frame_count == raw[4]) {
    ESP_LOGV(TAG, "parse_xiaomi_header(): duplicate data packet received (%d).", static_cast<int>(last_frame_count));
    result.is_duplicate = true;
    return {};
  }
  last_frame_count = raw[4];
  result.is_duplicate = false;

  ESP_LOGD(TAG, "Packet : %s", format_hex_pretty(raw.data(), raw.size()).c_str());
  ESP_LOGD(TAG, "         Capability: %s", result.has_capability ? "True" : "False");
  ESP_LOGD(TAG, "      IO Capability: %s", result.has_io_capability ? "True" : "False");
  ESP_LOGD(TAG, "         Encryption: %s", result.has_encryption ? "True" : "False");
  ESP_LOGD(TAG, "                MAC: %s", result.has_mac ? "True" : "False");
  ESP_LOGD(TAG, "               Mesh: %s", result.has_mesh ? "True" : "False");

  return result;
}

bool MiBeacon::parse_xiaomi_value(uint8_t value_type, const uint8_t *data, uint8_t value_length, XiaomiParseResult &result) {
  ESPTime et;
  // 操作方式, 10字节，第二字节含action和method，锁事件5，后面是keyid和时间戳
  if ((value_type == 0x05) && (value_length == 10)) {
    uint32_t keyid = encode_uint32(data[5], data[4], data[3], data[2]);
    auto it = KeyIDMap.find(keyid);
    result.keyid = (it == KeyIDMap.end()) ? findOperator(keyid) : it->second;
    ESP_LOGD(TAG, "  KeyID: %s", result.keyid.c_str());
    et=ESPTime::from_epoch_local(encode_uint32(data[9], data[8], data[7], data[6]));
    ESP_LOGD(TAG, "  LockEvtTime: %s",et.strftime("%Y-%m-%d %H:%M:%S").c_str());
    ESP_LOGD(TAG, "  LockEvt: %s", str_upper_case(format_hex(std::vector<uint8_t>{data[1]})).c_str());
    //result.lockevt = str_upper_case(format_hex(std::vector<uint8_t>{data[1]}));
    result.lockevt = findLockEvt(data[1]);
    result.lockevtts = et.strftime("%Y-%m-%d %H:%M:%S");
  }
  //米家门锁，标准协议 锁事件B
  else if ((value_type == 0x0b) && (value_length == 9)) {
    uint32_t keyid = encode_uint32(data[4], data[3], data[2], data[1]);
    auto it = KeyIDMap.find(keyid);
    result.keyid = (it == KeyIDMap.end()) ? findOperator(keyid) : it->second;
    ESP_LOGD(TAG, "  KeyID: %s", result.keyid.c_str());
    et=ESPTime::from_epoch_local(encode_uint32(data[8], data[7], data[6], data[5]));
    ESP_LOGD(TAG, "  LockEvtTime: %s",et.strftime("%Y-%m-%d %H:%M:%S").c_str());
    ESP_LOGD(TAG, "  LockEvt: %s", str_upper_case(format_hex(std::vector<uint8_t>{data[0]})).c_str());
    //result.lockevt = str_upper_case(format_hex(std::vector<uint8_t>{data[0]}));
    result.lockevt = findLockEvt(data[0]);
    result.lockevtts = et.strftime("%Y-%m-%d %H:%M:%S");
  }
  // battery, 5 byte, 8-bit unsigned integer, 1 %，后面为时间戳
  else if ((value_type == 0x0A) && (value_length == 5)) {
    et=ESPTime::from_epoch_local(encode_uint32(data[4], data[3], data[2], data[1]));
    ESP_LOGD(TAG, "  BattLevelTime: %s",et.strftime("%Y-%m-%d %H:%M:%S").c_str());
    result.battlvl = data[0];
    result.battlvlts = et.strftime("%Y-%m-%d %H:%M:%S");
  }
  // 门事件7，5字节，首字节仅取值02，代表超时未关，后面为时间戳
  else if ((value_type == 0x07) && (value_length == 5)) {
    auto it = DoorEvtMap.find(data[0]);
    result.doorevt = (it == DoorEvtMap.end())? "" : it->second;
    ESP_LOGD(TAG, "  DoorEvt: %s", result.doorevt.c_str());
    et=ESPTime::from_epoch_local(encode_uint32(data[4], data[3], data[2], data[1]));
    ESP_LOGD(TAG, "  DoorEvtTime: %s",et.strftime("%Y-%m-%d %H:%M:%S").c_str());
    result.doorevtts = et.strftime("%Y-%m-%d %H:%M:%S");
  }
  // 指纹事件，5字节，4字节keyid，第五字节指纹
  else if ((value_type == 0x06) && (value_length == 5)) {
    uint32_t keyid = encode_uint32(data[3], data[2], data[1], data[0]);
    auto it1 = KeyIDMap.find(keyid);
    result.keyid = (it1 == KeyIDMap.end()) ? findOperator(keyid) : it1->second;
    ESP_LOGD(TAG, "  KeyID: %s", result.keyid.c_str());
    auto it2 = BioEvtMap.find(data[4]);
    result.bioevt = (it2 == BioEvtMap.end()) ? "" : it2->second;
    ESP_LOGD(TAG, "  BioEvt: %s", result.bioevt.c_str());
  }
  else {
    return false;
  }

  return true;
}

bool MiBeacon::parse_xiaomi_message(const std::vector<uint8_t> &message, XiaomiParseResult &result) {
  bool encryption_flag = (message[0] & 0x08) ? true : false;
  if (encryption_flag) {
    ESP_LOGD(TAG, "parse_xiaomi_message(): payload is encrypted, stop reading message.");
    return false;
  }

  // Data point specs
  // Byte 0: type
  // Byte 1: fixed 0x10
  // Byte 2: length
  // Byte 3..3+len-1: data point value
  uint8_t *payload=nullptr;
  uint8_t payload_offset = 0;
  uint8_t payload_length=0;

  payload_offset += 5;
  payload_offset += result.has_mac ? 6 : 0;
  payload_offset += result.has_capability ? 1 : 0;
  payload_offset += result.has_io_capability ? 2 : 0;

  payload = (uint8_t*) message.data() + payload_offset;

  payload_length = message.size() - 5;
  payload_length -= result.has_mac ? 6 : 0;
  payload_length -= result.has_capability ? 1 : 0;
  payload_length -= result.has_io_capability ? 2 : 0;
  payload_length -= result.has_encryption ? 7 : 0;

  bool success = false;

  if (payload_length < 4) {
    ESP_LOGD(TAG, "parse_xiaomi_message(): payload has wrong size (%d)!", payload_length);
    return false;
  }

  const uint8_t value_length = payload[2];
  ESP_LOGD(TAG, "value_length:%i;payload_length:%i",value_length,payload_length);
  if ((value_length < 1) || (payload_length < (3 + value_length))) {
    ESP_LOGD(TAG, "parse_xiaomi_message(): value has wrong size (%d)!", value_length);
    ESP_LOGD(TAG, "payload[0~3]%02X%02X%02X%02X",payload[0],payload[1],payload[2],payload[3]);
  }

  const uint8_t value_type = payload[0];
  const uint8_t *data = &payload[3];

  if (parse_xiaomi_value(value_type, data, value_length, result))
    success = true;

  return success;
}

}  // namespace xiaomi_lock
}  // namespace esphome

#endif
