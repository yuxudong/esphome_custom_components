import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import sensor, uart
from esphome.const import (
    ICON_EMPTY,
    ICON_WATER,
    CONF_ID,
    UNIT_CELSIUS,
    DEVICE_CLASS_TEMPERATURE,
    DEVICE_CLASS_WATER,
    STATE_CLASS_MEASUREMENT,
)

CODEOWNERS = ["@Yuxudong"]
DEPENDENCIES = ["uart"]

tds_ns = cg.esphome_ns.namespace("tds")
TDSComponent = tds_ns.class_(
    "TDSComponent", cg.Component, uart.UARTDevice
)

UNIT_MILLIGRAMS_PER_LITRE = "mg/L"
CONF_SEND_INTERVAL = "send_interval"

CONFIG_SCHEMA = (
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(TDSComponent),
            cv.Optional(CONF_SEND_INTERVAL): cv.int_,
            cv.Optional("inputTemperature"): sensor.sensor_schema(
                unit_of_measurement=UNIT_CELSIUS, 
                accuracy_decimals=2,
                device_class=DEVICE_CLASS_TEMPERATURE,
                state_class=STATE_CLASS_MEASUREMENT,
            ),
            cv.Optional("outputTemperature"): sensor.sensor_schema(
                unit_of_measurement=UNIT_CELSIUS, 
                accuracy_decimals=2,
                device_class=DEVICE_CLASS_TEMPERATURE,
                state_class=STATE_CLASS_MEASUREMENT,
            ),
            cv.Optional("inputTDS"): sensor.sensor_schema(
                unit_of_measurement=UNIT_MILLIGRAMS_PER_LITRE, 
                accuracy_decimals=2,
                device_class=DEVICE_CLASS_WATER,
                state_class=STATE_CLASS_MEASUREMENT,
            ),
            cv.Optional("outputTDS"): sensor.sensor_schema(
                unit_of_measurement=UNIT_MILLIGRAMS_PER_LITRE, 
                accuracy_decimals=2,
                device_class=DEVICE_CLASS_WATER,
                state_class=STATE_CLASS_MEASUREMENT,
            ),
        }
    )
    .extend(cv.COMPONENT_SCHEMA)
    .extend(uart.UART_DEVICE_SCHEMA)
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await uart.register_uart_device(var, config)

    if CONF_SEND_INTERVAL in config:
        cg.add(var.set_send_interval(config[CONF_SEND_INTERVAL]))
        
    if "inputTemperature" in config:
        sens = await sensor.new_sensor(config["inputTemperature"])
        cg.add(var.set_inputTemperature(sens))
    if "outputTemperature" in config:
        sens = await sensor.new_sensor(config["outputTemperature"])
        cg.add(var.set_outputTemperature(sens))
    if "inputTDS" in config:
        sens = await sensor.new_sensor(config["inputTDS"])
        cg.add(var.set_inputTDS(sens))
    if "outputTDS" in config:
        sens = await sensor.new_sensor(config["outputTDS"])
        cg.add(var.set_outputTDS(sens))

   
    
