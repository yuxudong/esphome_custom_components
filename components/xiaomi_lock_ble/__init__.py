"""ESPHome 组件：米家高安全级 BLE 门锁连接开锁（xiaomi_lock_ble）。

与只解广播的 xiaomi_lock 组件并列使用：本组件用 ble_client 主动连接，
需要 LTMK（32B）+ 每次会话的 sessionKey，能真正驱动电机开锁。

合规：仅限本人所有、已完成米家账号绑定的门锁。
"""
import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import ble_client
import esphome.components.lock as lock_component
from esphome.const import CONF_ID

CODEOWNERS = ["@Yuxudong"]
DEPENDENCIES = ["ble_client", "esp32_ble_tracker", "lock"]
AUTO_LOAD = ["lock"]

CONF_LTMK = "ltmk"
CONF_CMD = "cmd"
CONF_STEP_TIMEOUT = "step_timeout_ms"
CONF_AUTH_TIMEOUT = "auth_timeout_ms"
CONF_SETTLE_MS = "settle_ms"
CONF_CTR_LO = "ctr_lo"
CONF_CTR_HI = "ctr_hi"

xiaomi_lock_ble_ns = cg.esphome_ns.namespace("xiaomi_lock_ble")
XiaomiLockBle = xiaomi_lock_ble_ns.class_(
    "XiaomiLockBle",
    cg.Component,
    ble_client.BLEClientNode,
    lock_component.Lock,
)

# cmd: 0 开锁 / 1 上锁 / 2 反锁（来自 APK 的 LockCmd 枚举）
CMD_VALUES = {"unlock": 0, "lock": 1, "anti_lock": 2}


def _validate_ltmk(value):
    """校验 LTMK 形如 64 位 hex（长度 + 合法字符，不做语义判断）。"""
    value = cv.string(value)
    if len(value) != 64:
        raise cv.Invalid("LTMK 必须是 64 位十六进制字符串（32 字节），实际 %d 位" % len(value))
    try:
        bytes.fromhex(value)
    except ValueError:
        raise cv.Invalid("LTMK 含非法十六进制字符")
    return value


CONFIG_SCHEMA = (
    lock_component.lock_schema(XiaomiLockBle)
    .extend(
        {
            cv.GenerateID(): cv.declare_id(XiaomiLockBle),
            cv.Required(CONF_LTMK): _validate_ltmk,  # 64 位 hex，建议 !secret
            cv.Optional(CONF_CMD, default="unlock"): cv.enum(CMD_VALUES, lower=True),
            cv.Optional(CONF_STEP_TIMEOUT, default=12000): cv.positive_int,
            cv.Optional(CONF_AUTH_TIMEOUT, default=20000): cv.positive_int,
            cv.Optional(CONF_SETTLE_MS, default=150): cv.positive_int,
            cv.Optional(CONF_CTR_LO): cv.int_range(min=0, max=0xFFFF),
            cv.Optional(CONF_CTR_HI, default=0): cv.int_range(min=0, max=0xFFFF),
        }
    )
    .extend(ble_client.BLE_CLIENT_SCHEMA)
    .extend(cv.COMPONENT_SCHEMA)
)


def _ensure_mbedtls_features() -> None:
    """在 codegen 阶段声明本组件直接用到的 mbedTLS 模块。

    ESPHome 2026.10 起把 ``CONFIG_MBEDTLS_CCM_C`` 归入 "TLS extras" 并由
    ``_reconcile_mbedtls_sdkconfig()`` 默认设为 false（理由是省 ~10KB flash）。
    但本组件在 TLS 之外直接使用 AES-CCM（登录确认帧 MIC / 0x1001 开锁帧），
    不声明就会在链接期报 ``undefined reference to mbedtls_ccm_init`` 等一串符号。
    P-256 ECDH 用到的 ``CONFIG_MBEDTLS_ECP_C`` 同理（BLE 栈目前会替我们打开，
    但显式声明可避免将来 BLE 侧 Kconfig 变化时突然失效）。

    两个 helper 都是 2026.10 引入的；旧版 ESPHome 没有这些 helper，也没有
    对应的裁剪逻辑，导入失败时静默跳过即可。用户若在 YAML 的
    ``sdkconfig_options`` 里显式设置，set_idf_sdkconfig_default 不会覆盖。
    """
    try:
        from esphome.components.esp32 import require_mbedtls_tls_extras

        require_mbedtls_tls_extras(["CONFIG_MBEDTLS_CCM_C"])
    except ImportError:
        pass
    try:
        from esphome.components.esp32 import require_mbedtls_ecp

        require_mbedtls_ecp()
    except ImportError:
        pass
    try:
        from esphome.components.esp32 import set_idf_sdkconfig_default

        # 兜底：require 只保证"不被关"，这里确保显式为 y（用户配置优先）。
        set_idf_sdkconfig_default("CONFIG_MBEDTLS_CCM_C", True)
        set_idf_sdkconfig_default("CONFIG_MBEDTLS_ECP_C", True)
    except ImportError:
        pass


async def to_code(config):
    _ensure_mbedtls_features()

    var = await lock_component.new_lock(config)
    await cg.register_component(var, config)
    await ble_client.register_ble_node(var, config)

    cg.add(var.set_ltmk(config[CONF_LTMK]))
    cg.add(var.set_cmd(config[CONF_CMD]))
    cg.add(var.set_step_timeout_ms(config[CONF_STEP_TIMEOUT]))
    cg.add(var.set_auth_timeout_ms(config[CONF_AUTH_TIMEOUT]))
    cg.add(var.set_settle_ms(config[CONF_SETTLE_MS]))
    if CONF_CTR_LO in config:
        cg.add(var.set_ctr_lo(config[CONF_CTR_LO]))
        cg.add(var.set_ctr_hi(config[CONF_CTR_HI]))
