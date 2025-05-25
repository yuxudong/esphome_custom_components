
/*
   米家BLE协议:
   https://iot.mi.com/new/doc/accesses/direct-access/embedded-development/ble/object-definition
*/

#pragma once

#include "esphome/core/component.h"
#include "esphome/core/time.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/text_sensor/text_sensor.h"
#include "esphome/components/esp32_ble_tracker/esp32_ble_tracker.h"

#ifdef USE_ESP32
#define BLE_UUID_MI_SERVICE                         0xFE95
#define BLE_UUID_COMPANY_ID_XIAOMI                  0x038F
#define MIBLE_MAX_ADV_LENGTH                        31

namespace esphome {
namespace xiaomi_lock {
  struct XiaomiParseResult {
    std::string name;
    optional<uint8_t> battlvl;
    std::string battlvlts;
    std::string keyid;
    std::string lockevt;
    std::string lockevtts;
    std::string doorevt;
    std::string doorevtts;
    std::string bioevt;
    bool has_data;        // 0x40
    bool has_capability;  // 0x20
    bool has_encryption;  // 0x08
    bool has_mac;         // 0x10
    bool has_mesh;        // 0x80
    bool has_io_capability;
    bool is_duplicate;
  };

  struct XiaomiAESVector {
    uint8_t key[16];
    uint8_t plaintext[16];
    uint8_t ciphertext[16];
    uint8_t authdata[16];
    uint8_t iv[16];
    uint8_t tag[16];
    size_t keysize;
    size_t authsize;
    size_t datasize;
    size_t tagsize;
    size_t ivsize;
  };

  class MiBeacon {
    public:
      bool parse_xiaomi_value(uint8_t value_type, const uint8_t *data, uint8_t value_length, XiaomiParseResult &result);
      bool parse_xiaomi_message(const std::vector<uint8_t> &message, XiaomiParseResult &result);
      optional<XiaomiParseResult> parse_xiaomi_header(const esp32_ble_tracker::ServiceData &service_data); 
  };

  class XiaomiLock : public Component, public esp32_ble_tracker::ESPBTDeviceListener {
    public:
      void set_address(uint64_t address) { address_ = address; };
      void set_bindkey(const std::string &bindkey);

      bool parse_device(const esp32_ble_tracker::ESPBTDevice &device) override;
      void dump_config() override;
      float get_setup_priority() const override { return setup_priority::DATA; };
      void set_battlvl(sensor::Sensor *battlvl) { battlvl_ = battlvl; };
      void set_battlvlts(text_sensor::TextSensor *battlvlts) { battlvlts_ = battlvlts; };
      void set_doorevt(text_sensor::TextSensor *doorevt) { doorevt_ = doorevt; };
      void set_doorevtts(text_sensor::TextSensor *doorevtts) { doorevtts_ = doorevtts; };
      void set_lockevt(text_sensor::TextSensor *lockevt) { lockevt_ = lockevt; };
      void set_lockevtts(text_sensor::TextSensor *lockevtts) { lockevtts_ = lockevtts; };
      void set_bioevt(text_sensor::TextSensor *bioevt) { bioevt_ = bioevt; };
      void set_keyid(text_sensor::TextSensor *keyid) { keyid_ = keyid; };
      
    protected:
      uint64_t address_;
      uint8_t bindkey_[16];
      sensor::Sensor *battlvl_{nullptr};
      text_sensor::TextSensor *battlvlts_{nullptr};
      text_sensor::TextSensor *doorevt_{nullptr};
      text_sensor::TextSensor *doorevtts_{nullptr};
      text_sensor::TextSensor *lockevt_{nullptr};
      text_sensor::TextSensor *lockevtts_{nullptr};
      text_sensor::TextSensor *bioevt_{nullptr};
      text_sensor::TextSensor *keyid_{nullptr};

    private:
      MiBeacon mi;
  };

  static bool decrypt_xiaomi_message(std::vector<uint8_t> &raw, const uint8_t *bindkey, const uint64_t &address);

}  // namespace xiaomi_lock
}  // namespace esphome

#endif
