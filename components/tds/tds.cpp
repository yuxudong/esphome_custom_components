#include "tds.h"
#include "esphome/core/log.h"

namespace esphome {
namespace tds {
static const char *const TAG = "TDS";
static const uint8_t TDS_REQUEST_LENGTH = 6;
static const uint8_t TDS_RESPONSE_LENGTH = 6;
static const std::vector<uint8_t> TDS_COMMAND_GET = {0xA0, 0x00, 0x00, 0x00, 0x00, 0xA0};


void TDSComponent::dump_config() {
  ESP_LOGCONFIG(TAG, "TDS:");
  ESP_LOGCONFIG(TAG, "  Send Interval: %d", this->send_interval_);
  LOG_SENSOR("  ", "inputTemperature", this->inputTemperature_);
  LOG_SENSOR("  ", "outputTemperature", this->outputTemperature_);
  LOG_SENSOR("  ", "inputTDS", this->inputTDS_);
  LOG_SENSOR("  ", "outputTDS", this->inputTDS_);
}

void TDSComponent::send() {
  this->write_array(TDS_COMMAND_GET);
  this->flush();;
}

void TDSComponent::update() {
    if (micros() < this->next_time_ && this->next_time_ - micros() < this->send_interval_) {
        return;
    }
    this->send();
    this->next_time_ = micros() + this->send_interval_;
}

void TDSComponent::loop() {
  while (this->available()) {
    uint8_t byte;
    this->read_byte(&byte);
    this->rx_buffer_.push_back(byte);
    if (this->parse_()) this->rx_buffer_.clear();
  }
}

bool TDSComponent::checksum_(std::vector<uint8_t> &data, int start, int length) {
  uint8_t crc = 0;
  for (int i = start; i < start + length - 1; i++)  crc += data[i];
  if(crc == data[start + length - 1]) return true;
  ESP_LOGW(TAG, "CheckSum want 0x%X but current is 0x%X", data[start + length - 1], crc);
  return false;
}

bool TDSComponent::parse_() {
    if (!rx_buffer_.empty()) {
    ESP_LOGD(TAG, "Rx buffer : %s", format_hex_pretty(rx_buffer_).c_str());
    for (int i = 0; i < this->rx_buffer_.size(); i++) {
      if (this->rx_buffer_[i] == 0xAA || this->rx_buffer_[i] == 0xAB || this->rx_buffer_[i] == 0xAC ) {
        if (i + TDS_RESPONSE_LENGTH > this->rx_buffer_.size()) {
          continue;
        }
        if (!this->checksum_(this->rx_buffer_, i, TDS_RESPONSE_LENGTH)) {
          continue;
        }
        this->handle_response(this->rx_buffer_, i);
        i += TDS_RESPONSE_LENGTH - 1;
        this->next_time_ = micros() + this->send_interval_;
        return true;
      }
    }
  }
  return false;
}

void TDSComponent::handle_response(std::vector<uint8_t> &data, int pos) {
  if(data[pos] == 0xaa) {
      if (this->inputTDS_ != nullptr) this->inputTDS_->publish_state(float((data[pos + 1] << 8) | data[pos + 2]));
      if (this->outputTDS_ != nullptr) this->outputTDS_->publish_state(float((data[pos + 3] << 8) | data[pos + 4]));
  }
  if(data[pos] == 0xab) {
      if (this->inputTemperature_ != nullptr) this->inputTemperature_->publish_state(float((data[pos + 1] << 8) | data[pos + 2])/100.0f);
      if (this->outputTemperature_ != nullptr) this->outputTemperature_->publish_state(float((data[pos + 3] << 8) | data[pos + 4])/100.0f);
  }
}

} //namespace tds
} //namespace esphome