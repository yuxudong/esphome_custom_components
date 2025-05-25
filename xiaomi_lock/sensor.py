import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import sensor, text_sensor, esp32_ble_tracker
from esphome.const import (
    CONF_BATTERY_LEVEL,
    CONF_MAC_ADDRESS,
    ICON_EMPTY,
    UNIT_PERCENT,
    CONF_ID,
    CONF_BINDKEY,
    DEVICE_CLASS_BATTERY,
    STATE_CLASS_MEASUREMENT,
)

CODEOWNERS = ["@Yuxudong"]

DEPENDENCIES = ["esp32_ble_tracker"]

xiaomi_lock_ns = cg.esphome_ns.namespace("xiaomi_lock")
XiaomiLock = xiaomi_lock_ns.class_(
    "XiaomiLock", esp32_ble_tracker.ESPBTDeviceListener, cg.Component
)

CONFIG_SCHEMA = (
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(XiaomiLock),
            cv.Required(CONF_BINDKEY): cv.bind_key,
            cv.Required(CONF_MAC_ADDRESS): cv.mac_address,
            cv.Optional("battlvl"): sensor.sensor_schema(
                unit_of_measurement=UNIT_PERCENT, 
                accuracy_decimals=0,
                device_class=DEVICE_CLASS_BATTERY,
                state_class=STATE_CLASS_MEASUREMENT,
            ),
            cv.Optional("battlvlts"): text_sensor.text_sensor_schema(),
            cv.Optional("doorevt"): text_sensor.text_sensor_schema(),
            cv.Optional("doorevtts"): text_sensor.text_sensor_schema(),
            cv.Optional("lockevt"): text_sensor.text_sensor_schema(),
            cv.Optional("lockevtts"): text_sensor.text_sensor_schema(),
            cv.Optional("bioevt"): text_sensor.text_sensor_schema(),
            cv.Optional("keyid"): text_sensor.text_sensor_schema(),
        }
    )
    .extend(esp32_ble_tracker.ESP_BLE_DEVICE_SCHEMA)
    .extend(cv.COMPONENT_SCHEMA)
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await esp32_ble_tracker.register_ble_device(var, config)

    cg.add(var.set_address(config[CONF_MAC_ADDRESS].as_hex))
    cg.add(var.set_bindkey(config[CONF_BINDKEY]))

    if "battlvl" in config:
        sens = await sensor.new_sensor(config["battlvl"])
        cg.add(var.set_battlvl(sens))
    if "battlvlts" in config:
        sens = await text_sensor.new_text_sensor(config["battlvlts"])
        cg.add(var.set_battlvlts(sens))
    if "doorevt" in config:
        sens = await text_sensor.new_text_sensor(config["doorevt"])
        cg.add(var.set_doorevt(sens))
    if "doorevtts" in config:
        sens = await text_sensor.new_text_sensor(config["doorevtts"])
        cg.add(var.set_doorevtts(sens))
    if "lockevt" in config:
        sens = await text_sensor.new_text_sensor(config["lockevt"])
        cg.add(var.set_lockevt(sens))
    if "lockevtts" in config:
        sens = await text_sensor.new_text_sensor(config["lockevtts"])
        cg.add(var.set_lockevtts(sens))
    if "bioevt" in config:
        sens = await text_sensor.new_text_sensor(config["bioevt"])
        cg.add(var.set_bioevt(sens))
    if "keyid" in config:
        sens = await text_sensor.new_text_sensor(config["keyid"])
        cg.add(var.set_keyid(sens))
   
    
