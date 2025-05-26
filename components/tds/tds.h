#include "esphome/core/component.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/uart/uart.h"

namespace esphome {
namespace tds {
class TDSComponent : public PollingComponent, public uart::UARTDevice {
    public:
        void dump_config() override;
        void update() override;
        void loop() override;
        float get_setup_priority() const override { return setup_priority::DATA; };

        void set_inputTemperature(sensor::Sensor *inputTemperature) { inputTemperature_ = inputTemperature; };
        void set_outputTemperature(sensor::Sensor *outputTemperature) { outputTemperature_ = outputTemperature; };
        void set_inputTDS(sensor::Sensor *inputTDS) { inputTDS_ = inputTDS; };
        void set_outputTDS(sensor::Sensor *outputTDS) { outputTDS_ = outputTDS; };
        void set_send_interval(uint32_t interval) { this->send_interval_ = interval; }

    protected:
        sensor::Sensor *inputTemperature_{nullptr};
        sensor::Sensor *outputTemperature_{nullptr};
        sensor::Sensor *inputTDS_{nullptr};
        sensor::Sensor *outputTDS_{nullptr};

        void send();
        bool parse_();
        bool checksum_(std::vector<uint8_t> &data, int start, int length);
        void handle_response(std::vector<uint8_t> &data, int pos);

        std::vector<uint8_t> rx_buffer_;
        uint32_t next_time_{0};
        uint32_t send_interval_{2000000};

};

} //namespace tds
} //namespace esphome