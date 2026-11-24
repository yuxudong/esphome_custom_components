#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从「自己的小米账号」云端取回米家 BLE 门锁的 LTMK（长期主密钥）。

依据 MiHome 11.0.622 反编译（仅限本人所有、已完成绑定的门锁）：

  LockSecurePinUtil.java / DeviceApi.java
      POST /share/askbluetoothkey   data={"type":"own","did":"<did>","keyid":0}
      加密方式 Crypto.RC4（米家云端通用 RC4 签名，与 Xiaomi-cloud-tokens-extractor 相同）
      响应 {"key": "<hex>", "encrypt_type": 0|1}

  BleSecureConnectManager.java:100-115 / _m_j/xa0.java:43
      encrypt_type == 0 → LTMK = hexdecode(key)
      encrypt_type == 1 → LTMK = hexdecode( AES-128-CBC-Decrypt(
                              key = MD5(用户自己设置的「安全 PIN」),
                              iv  = 7aa4c68c590d4031b980d98b41023800,
                              ct  = hexdecode(key)) )
      其他值 → App 原样透传（未知算法，脚本会报错提示）

  java2/sources/_m_j/gc1.java:477 / :1256 / :1319
      OooOOo  = 解密, OooOo0o = 加密, OooOoOO = MD5(pin) 作 AES key
      _m_j/x1b.o0ooOoO() 返回常量 "4d4435" → hex decode → "MD5"

用法（先装依赖）：
  pip install requests cryptography          # 或 pycryptodome，二选一

  # 0) 离线自检，不需要账号和网络
  python get_ltmk.py --self-test

  # 0.5) 网络自检（遇到 SSLEOFError 时先跑这个）
  python get_ltmk.py --diag
  # 结论若显示「直连通、代理挂」→ 加 --no-proxy；脚本现已内置自动降级，直接跑也行。
  # 注意：Windows 注册表里的「系统代理」即使没有 HTTPS_PROXY 环境变量也会生效。
  # 其它：--proxy http://127.0.0.1:7890 显式走代理；--tls12 强制 TLS 1.2

  # 1) 账号密码登录（推荐，脚本会自动列出 xiaomi.lock.* 设备）
  python get_ltmk.py -u <小米账号> -p <密码> -s cn --pin <门锁安全PIN> --out ltmk.json

  # 2) 二维码登录（绕过密码/短信验证）
  #    脚本会把真二维码存成 mi_login_qr.png，Windows 下自动弹出图片查看器；
  #    手机扫码后【必须再点一次「确认登录」】，只扫不点不会返回。
  python get_ltmk.py --qr -s cn --pin <门锁安全PIN> --out ltmk.json
  #    可选：--qr-wait 180 调整等待秒数；--qr-file qr.png 改保存路径；
  #          --no-open-qr 不自动弹图片查看器

  # 3) 已有云端会话凭据时，跳过登录
  python get_ltmk.py --service-token <...> --ssecurity <...> --user-id <...> \
                     -s cn --did <did> --pin <门锁安全PIN>

  # 登录成功后会自动缓存会话到 ~/.mi_ltmk_session.json，之后重跑免扫码。
  #   --no-cache 不读不写；--clear-cache 删除缓存后退出；--session-file 改路径
  #   ⚠ 该文件等同云端登录态，请勿外传。

  # 只按 did 取、只看设备清单不取密钥；门锁不是 xiaomi.lock.* 也能自动识别
  python get_ltmk.py --list-only --list-all        # 列出账号下全部设备 + 型号分布
  python get_ltmk.py --mac <门锁MAC> --pin <PIN> --out ltmk.json   # MAC 优先全局匹配
  python get_ltmk.py --model-prefix lumi.lock. --pin <PIN> --out ltmk.json

⚠ LTMK 是这把锁的最高权限凭据，等价于「无限次开锁的钥匙」。
  不要贴到论坛、不要提交到 git、不用完请删掉输出文件。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import socket
import ssl
import string
import sys
import threading
import time
from collections import Counter
from typing import Any

try:
    import requests
    from requests.adapters import HTTPAdapter
    _HAS_REQUESTS = True
except ImportError:
    requests = None
    _HAS_REQUESTS = False

    class HTTPAdapter:  # 占位：离线模式（--self-test / --check-ltmk）不需要联网库
        pass

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ---------------------------------------------------------------- 密码学后端
# AES-128-CBC，优先 cryptography，其次 pycryptodome
_AES_BACKEND = None
try:
    from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, algorithms, modes
    _AES_BACKEND = "cryptography"
except ImportError:
    try:
        from Crypto.Cipher import AES as _PyCryptoAES
        _AES_BACKEND = "pycryptodome"
    except ImportError:
        _AES_BACKEND = None


def aes_cbc_crypt(key: bytes, iv: bytes, data: bytes, decrypt: bool) -> bytes:
    if _AES_BACKEND == "cryptography":
        c = _Cipher(algorithms.AES(key), modes.CBC(iv))
        ctx = c.decryptor() if decrypt else c.encryptor()
        return ctx.update(data) + ctx.finalize()
    if _AES_BACKEND == "pycryptodome":
        c = _PyCryptoAES.new(key, _PyCryptoAES.MODE_CBC, iv)
        return c.decrypt(data) if decrypt else c.encrypt(data)
    raise RuntimeError("需要 pip install cryptography（或 pycryptodome）")


class RC4:
    """纯 Python RC4，与 ARC4.new(key).encrypt() 完全等价，无需 pycryptodome。"""

    def __init__(self, key: bytes):
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = self.j = 0

    def crypt(self, data: bytes) -> bytes:
        out = bytearray()
        s = self.S
        for b in data:
            self.i = (self.i + 1) % 256
            self.j = (self.j + s[self.i]) % 256
            s[self.i], s[self.j] = s[self.j], s[self.i]
            out.append(b ^ s[(s[self.i] + s[self.j]) % 256])
        return bytes(out)


def encrypt_rc4(password_b64: str, text: str) -> str:
    r = RC4(base64.b64decode(password_b64))
    r.crypt(bytes(1024))                       # 米家固定丢弃前 1024 字节
    return base64.b64encode(r.crypt(text.encode())).decode()


def decrypt_rc4(password_b64: str, text: str) -> str:
    r = RC4(base64.b64decode(password_b64))
    r.crypt(bytes(1024))
    return r.crypt(base64.b64decode(text)).decode("utf-8", "replace")


# ---------------------------------------------------------------- PIN 解密 LTMK
LTMK_IV = bytes.fromhex("7aa4c68c590d4031b980d98b41023800")


def encrypt_ltmk(pin: str, ltmk_hex: str) -> str:
    """对应 gc1.OooOo0o(1, pin, ltmkHex)：AES-128-CBC / NoPadding / 固定 IV。"""
    key = hashlib.md5(pin.encode("utf-8")).digest()
    return aes_cbc_crypt(key, LTMK_IV, bytes.fromhex(ltmk_hex), decrypt=False).hex()


def decrypt_ltmk(encrypt_type: int, pin: str | None, key_hex: str) -> bytes:
    """返回 32 字节 LTMK。对应 BleSecureConnectManager.java:100-115。"""
    if encrypt_type == 0:
        return bytes.fromhex(key_hex)
    if encrypt_type != 1:
        raise ValueError(f"未知 encrypt_type={encrypt_type}（APK 只处理 0 和 1）")
    if not pin:
        raise ValueError("encrypt_type=1，需要 --pin 传入你在米家 App 里设置的门锁安全 PIN")
    aes_key = hashlib.md5(pin.encode("utf-8")).digest()
    plain_hex = aes_cbc_crypt(aes_key, LTMK_IV, bytes.fromhex(key_hex), decrypt=True).hex()
    return bytes.fromhex(plain_hex)


def check_ltmk_file(path: str, emit_header: str | None = None) -> int:
    """脱敏核对已保存的 ltmk.json：不联网、不打印 LTMK 明文。

    ⚠ 指纹/长度只能证明格式正确，不能证明 PIN 正确：encrypt_type=1 用
      AES-CBC/NoPadding，PIN 输错同样解出 32 字节。唯一可靠判据是 BLE 登录握手。
    """
    with open(path, "r", encoding="utf-8") as f:
        d = json.load(f)
    hx = str(d.get("ltmk_hex") or "")
    try:
        ltmk = bytes.fromhex(hx)
    except ValueError:
        print("[错误] ltmk_hex 不是合法 hex 字符串")
        return 2

    fp = hashlib.sha256(ltmk).hexdigest()
    did = str(d.get("did") or "")
    mac = str(d.get("mac") or "")
    bk = str(d.get("beaconkey") or "")
    print("=== ltmk.json 脱敏核对（不打印密钥明文）===")
    print(f"  文件          : {os.path.abspath(path)}")
    print(f"  did           : {did[:4]}...{did[-4:] if len(did) > 8 else ''}")
    print(f"  mac           : {mac[:8]}...{mac[-5:] if len(mac) > 13 else ''}")
    print(f"  model         : {d.get('model')}")
    print(f"  server        : {d.get('server')}")
    print(f"  encrypt_type  : {d.get('encrypt_type')}")
    print(f"  LTMK 长度     : {len(ltmk)} 字节  {'OK（32B）' if len(ltmk) == 32 else '异常！应为 32B'}")
    print(f"  LTMK 指纹     : sha256[:8] = {fp[:16]}   ← 这个值可以安全贴出来核对")
    print(f"  全零 / 全 FF  : {all(x == 0 for x in ltmk)} / {all(x == 0xff for x in ltmk)}")
    if not bk:
        print("  beaconkey     : 云端未提供")
    elif bk.lower() in ("f" * len(bk), "0" * len(bk)):
        print("  beaconkey     : 全 F 占位（该型号无 beaconkey）→ 保留组件里已有的 bindkey，别覆盖")
    else:
        print(f"  beaconkey     : {bk[:6]}...{bk[-6:]}  (len={len(bk)})")

    print("\n[注意] encrypt_type=1 的 AES-CBC/NoPadding 没有填充校验，PIN 输错也会得到 32 字节；")
    print("       长度 + 指纹只能证明「格式正确」，不能证明「PIN 正确」。")
    print("       唯一可靠判据：BLE 登录握手时设备是否接受登录确认帧（CRC32(设备公钥) 的 AES-CCM 密文）。")
    print("       旁证：米家 App 里长按蓝牙开锁能成功，说明云端 key 与 PIN 链路一致。")

    if emit_header:
        arr = ", ".join(f"0x{x:02x}" for x in ltmk)
        with open(emit_header, "w", encoding="utf-8") as f:
            f.write("/* 由 get_ltmk.py --check-ltmk 生成，含明文长期主密钥。\n"
                    " * 请勿提交 git / 勿外传，用完删除。仅用于本人已绑定的门锁。 */\n"
                    "#pragma once\n#include <cstdint>\n\n"
                    "static const uint8_t MI_LOCK_LTMK[32] = { " + arr + " };\n")
        print(f"\n[生成] {os.path.abspath(emit_header)}（含明文，权限收紧、用完删除）")

    print("\n[清理] ltmk.json / 会话缓存 ~/.mi_ltmk_session.json / mi_login_qr.png 都含敏感态，")
    print("       用完删除；清除缓存：python get_ltmk.py --clear-cache")
    return 0


# ---------------------------------------------------------------- TLS 兼容适配
class TLS12Adapter(HTTPAdapter):
    """强制 TLS 1.2 + 容忍服务端不发 close_notify。

    account.xiaomi.com 在部分网络/代理/OpenSSL 组合下会出现
    SSLEOFError(8, 'EOF occurred in violation of protocol')：
      · TLS 1.3 会话被中间设备提前 RST      → 强制降级到 TLS 1.2
      · 服务端不发 close_notify（Python 3.10+ 严格检查）→ OP_IGNORE_UNEXPECTED_EOF
      · 老 cipher 套件被拒                  → SECLEVEL=0
    """

    def __init__(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        except (AttributeError, ValueError):
            pass
        if hasattr(ssl, "OP_IGNORE_UNEXPECTED_EOF"):
            ctx.options |= ssl.OP_IGNORE_UNEXPECTED_EOF
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        self._ctx = ctx
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **kw):
        kw["ssl_context"] = self._ctx
        return super().init_poolmanager(connections, maxsize, block=block, **kw)

    def proxy_manager_for(self, proxy, **kw):
        kw["ssl_context"] = self._ctx
        return super().proxy_manager_for(proxy, **kw)


if _HAS_REQUESTS:
    _SSL_ERROR = requests.exceptions.SSLError
    _CONN_ERRORS = (
        requests.exceptions.SSLError,
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
    )
else:
    _SSL_ERROR = OSError
    _CONN_ERRORS = (OSError,)  # 离线模式（--self-test / --check-ltmk）不会走到这里


# ---------------------------------------------------------------- 米家云端 RC4 API
class MiCloud:
    def __init__(self, country: str = "cn", *, proxy: str | None = None,
                 no_proxy: bool = False, insecure: bool = False,
                 tls12: bool = False, retries: int = 3, timeout: int = 20):
        self.country = country
        self.s = requests.Session()
        self.retries = max(1, retries)
        self.timeout = timeout
        self._tls12 = False
        if no_proxy:
            self.s.trust_env = False          # 忽略 HTTP(S)_PROXY / ALL_PROXY 环境变量
        if proxy:
            self.s.proxies = {"http": proxy, "https": proxy}
        if insecure:
            self.s.verify = False
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
        self.agent = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(18))
            + "-"
            + "".join(random.choice("ABCDE") for _ in range(13))
            + " APP/com.xiaomi.mihome APPV/11.0.622"
        )
        self.device_id = "".join(random.choice(string.ascii_lowercase) for _ in range(6))
        self.user_id: str | None = None
        self.ssecurity: str | None = None
        self.service_token: str | None = None
        self.s.cookies.set("sdkVersion", "accountsdk-18.8.15", domain="mi.com")
        self.s.cookies.set("sdkVersion", "accountsdk-18.8.15", domain="xiaomi.com")
        self.s.cookies.set("deviceId", self.device_id, domain="mi.com")
        self.s.cookies.set("deviceId", self.device_id, domain="xiaomi.com")
        if tls12:
            self._mount_tls12()

    def _mount_tls12(self) -> None:
        if not self._tls12:
            self.s.mount("https://", TLS12Adapter())
            self._tls12 = True

    def _req(self, method: str, url: str, **kw):
        """带退避的连接层重试 + 链路自动降级。

        降级顺序：原链路 → 强制 TLS 1.2 → 忽略系统/环境代理改走直连。
        第 2 步：Windows 上 trust_env=True 还会读注册表里的「系统代理」，
        即使 HTTPS_PROXY 等环境变量为空；关掉它可绕开这类代理层问题。
        只重试「请求没到达服务端」的错误（SSL / Connection / Timeout），
        这类重试不会造成重复登录或重复开锁。
        """
        kw.setdefault("timeout", self.timeout)
        last = None
        for i in range(self.retries):
            try:
                return self.s.request(method, url, **kw)
            except _CONN_ERRORS as e:
                last = e
                if i == 0:
                    if not self._tls12:
                        self._mount_tls12()
                        print(f"[网络] {type(e).__name__} → 自动切换 TLS 1.2 重试：{str(e)[:100]}")
                    else:
                        print(f"[网络] {type(e).__name__} → 重试：{str(e)[:100]}")
                elif i == 1 and self.s.trust_env:
                    self.s.trust_env = False          # 绕开注册表/环境变量里的坏代理
                    print("[网络] 仍失败 → 忽略系统/环境代理，改走直连重试（效果同 --no-proxy）")
                time.sleep(0.8 * (i + 1))
        raise last

    # -------- 登录：与 Xiaomi-cloud-tokens-extractor 同一套流程 --------
    @staticmethod
    def _to_json(text: str) -> dict:
        return json.loads(text.replace("&&&START&&&", ""))

    def login_password(self, username: str, password: str) -> bool:
        h = {"User-Agent": self.agent, "Content-Type": "application/x-www-form-urlencoded"}
        r = self._req(
            "GET", "https://account.xiaomi.com/pass/serviceLogin",
            params={"sid": "xiaomiio", "_json": "true"},
            headers=h, cookies={"userId": username},
        )
        j = self._to_json(r.text)
        sign = j.get("_sign")
        if not sign:
            print("[登录] step1 失败：", str(j)[:300])
            return False

        fields = {
            "sid": "xiaomiio",
            "hash": hashlib.md5(password.encode()).hexdigest().upper(),
            "callback": "https://sts.api.io.mi.com/sts",
            "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
            "user": username,
            "_sign": sign,
            "_json": "true",
        }
        r = self._req(
            "POST", "https://account.xiaomi.com/pass/serviceLoginAuth2",
            headers=h, params=fields, allow_redirects=False,
        )
        j = self._to_json(r.text)
        if "notificationUrl" in j or "captchaUrl" in j:
            print("[登录] 触发二次验证/验证码，请改用 --qr 二维码登录：", str(j)[:300])
            return False
        if not j.get("ssecurity") or not j.get("location"):
            print("[登录] step2 失败（账号密码错误或被风控）：", str(j)[:300])
            return False
        self.ssecurity = j["ssecurity"]
        self.user_id = str(j.get("userId") or username)
        location = j["location"]
        r = self._req("GET", location, headers={"User-Agent": self.agent})
        self.service_token = r.cookies.get("serviceToken")
        return bool(self.service_token)

    def login_qr(self, qr_wait: int | None = None,
                 qr_file: str = "mi_login_qr.png", open_qr: bool = True) -> bool:
        """二维码登录。

        小米的 lp 是「真长轮询」：服务端把 HTTP 连接 hold 住直到手机端点确认
        （本机实测 45 秒无任何返回）。旧版每 10 秒就 timeout 打断连接并静默
        continue，ticket 被打断后可能直接 403，于是「扫码了但没反应」。
        这里改成：单次长连接保持到服务端返回 + 后台心跳线程打印进度。
        """
        h = {"User-Agent": self.agent,
             "Content-Type": "application/x-www-form-urlencoded"}
        r = self._req(
            "GET", "https://account.xiaomi.com/longPolling/loginUrl",
            params={
                "_qrsize": "480",
                "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
                "callback": "https://sts.api.io.mi.com/sts",
                "_hasLogo": "false",
                "sid": "xiaomiio",
                "serviceParam": "",
                "_locale": "zh_CN",
                "_dc": str(int(time.time() * 1000)),
            },
            headers=h,
        )
        try:
            j = self._to_json(r.text)
        except Exception:
            print("[登录] 二维码接口返回异常：", r.status_code, r.text[:300], flush=True)
            return False
        lp = j.get("lp")
        login_url = j.get("loginUrl")
        qr_url = j.get("qr")            # ← 旧版漏掉了真正的二维码图片地址
        timeout_s = int(j.get("timeout") or 300)
        wait_s = int(qr_wait or timeout_s)
        if not lp or not login_url:
            print("[登录] 获取二维码失败：", str(j)[:300], flush=True)
            return False

        # ---- 下载真正的二维码 PNG（实测返回 image/png 15 KB）----
        qr_path = None
        if qr_url:
            try:
                rq = self._req("GET", qr_url, headers={"User-Agent": self.agent})
                if rq.status_code == 200 and rq.content[:4] == b"\x89PNG":
                    qr_path = os.path.abspath(qr_file)
                    with open(qr_path, "wb") as f:
                        f.write(rq.content)
                    if open_qr:
                        try:
                            os.startfile(qr_path)   # Windows：自动弹图片查看器
                        except Exception:
                            pass
                else:
                    print(f"[二维码] 图片下载异常 HTTP {rq.status_code} "
                          f"{rq.headers.get('content-type')}", flush=True)
            except Exception as e:
                print("[二维码] 图片下载失败：", type(e).__name__, str(e)[:120], flush=True)

        print("\n" + "=" * 70, flush=True)
        print(f"  小米账号扫码登录（二维码有效期 {timeout_s} 秒）", flush=True)
        print("=" * 70, flush=True)
        if qr_path:
            print(f"  ① 二维码图片已保存：{qr_path}", flush=True)
            print("     用手机扫这张图" + ("（已尝试自动打开图片查看器）" if open_qr else ""),
                  flush=True)
        print(f"  ② 或手机浏览器打开：{login_url}", flush=True)
        if qr_url:
            print(f"  ③ 二维码图片 URL：{qr_url}", flush=True)
        print("\n  " + str(j.get("qrTips") or
                           "可用小米手机 设置 > 小米账号 扫码，或用任意扫码工具"), flush=True)
        print("  ⚠ 扫码后【必须再点一次「确认登录」】，只扫不点不会返回结果。", flush=True)
        print("  ⚠ 请扫本次运行生成的二维码，别扫旧的 / 别人贴的图。", flush=True)
        print(f"  等待确认（最多 {wait_s} 秒），期间每 5 秒打印一次心跳...\n", flush=True)

        # ---- 长轮询：一次连接 hold 到服务端返回 ----
        deadline = time.time() + wait_s
        round_no = 0
        got: dict | None = None
        while time.time() < deadline:
            round_no += 1
            remain = max(1, int(deadline - time.time()))
            print(f"[轮询] 第 {round_no} 轮：保持长连接，最多 {remain} 秒（请勿关闭窗口）",
                  flush=True)

            stop = threading.Event()

            def heartbeat(ev=stop):
                n = 0
                while not ev.wait(5):
                    n += 1
                    print(f"        ... 已等待 {n * 5}s，等你在手机上点「确认登录」",
                          flush=True)

            threading.Thread(target=heartbeat, daemon=True).start()
            try:
                rp = self.s.get(
                    lp, headers={"User-Agent": self.agent, "Referer": login_url},
                    timeout=min(remain, 300),
                )
            except requests.exceptions.Timeout:
                print(f"[轮询] 服务端长轮询超时（{remain}s），重新建立连接", flush=True)
                if not self._tls12:
                    self._mount_tls12()
                continue
            except _CONN_ERRORS as e:
                print(f"[轮询] 连接异常 {type(e).__name__}: {str(e)[:120]}", flush=True)
                if not self._tls12:
                    self._mount_tls12()
                    print("[轮询] 已切 TLS 1.2 重试", flush=True)
                elif self.s.trust_env:
                    self.s.trust_env = False
                    print("[轮询] 已忽略系统/环境代理改走直连重试", flush=True)
                time.sleep(1)
                continue
            finally:
                stop.set()

            body = rp.text.strip()
            print(f"[轮询] HTTP {rp.status_code}  返回 {len(body)} 字节", flush=True)
            if rp.status_code == 200 and body:
                try:
                    d = self._to_json(body)
                except Exception:
                    print("[轮询] 响应不是 JSON：", body[:200], flush=True)
                    continue
                if d.get("ssecurity"):
                    got = d
                    print("[轮询] 已收到登录确认 ✔", flush=True)
                    break
                # 扫码后、点确认前的状态推送（含 code/desc 之类）
                print(f"[轮询] 状态更新（可能已扫码、还没点确认）：{body[:200]}", flush=True)
                continue
            if rp.status_code in (401, 403, 404):
                print("[轮询] 二维码 ticket 已失效（长连接被打断或已过期）。", flush=True)
                print("       请 Ctrl+C 停掉，重新运行脚本生成新二维码再扫。", flush=True)
                return False
            time.sleep(1)
        else:
            print("[登录] 二维码超时未确认", flush=True)
            return False

        if not got:
            print("[登录] 二维码超时未确认", flush=True)
            return False

        self.ssecurity = got["ssecurity"]
        self.user_id = str(got.get("userId") or "")
        location = got["location"]
        r = self._req("GET", location,
                      headers={"content-type": "application/x-www-form-urlencoded",
                               "User-Agent": self.agent})
        self.service_token = r.cookies.get("serviceToken")
        if not self.service_token:
            print("[登录] 换取 serviceToken 失败：HTTP", r.status_code,
                  r.text[:200], flush=True)
        return bool(self.service_token)

    # -------- 云端 RC4 调用 --------
    def api_url(self, path: str) -> str:
        prefix = "" if self.country == "cn" else self.country + "."
        return f"https://{prefix}api.io.mi.com/app{path}"

    def signed_nonce(self, nonce: str) -> str:
        d = hashlib.sha256(base64.b64decode(self.ssecurity) + base64.b64decode(nonce)).digest()
        return base64.b64encode(d).decode()

    @staticmethod
    def gen_nonce() -> str:
        b = os.urandom(8) + int(time.time() * 1000 / 60000).to_bytes(4, "big")
        return base64.b64encode(b).decode()

    @staticmethod
    def enc_signature(url: str, signed_nonce: str, params: dict) -> str:
        parts = ["POST", url.split("com")[1].replace("/app/", "/")]
        parts += [f"{k}={v}" for k, v in params.items()]
        parts.append(signed_nonce)
        return base64.b64encode(hashlib.sha1("&".join(parts).encode()).digest()).decode()

    def api(self, path: str, data: dict) -> dict:
        url = self.api_url(path)
        params: dict[str, str] = {"data": json.dumps(data, separators=(",", ":"))}
        nonce = self.gen_nonce()
        sn = self.signed_nonce(nonce)
        params["rc4_hash__"] = self.enc_signature(url, sn, params)
        params = {k: encrypt_rc4(sn, v) for k, v in params.items()}
        params.update({
            "signature": self.enc_signature(url, sn, params),
            "ssecurity": self.ssecurity,
            "_nonce": nonce,
        })
        cookies = {
            "userId": str(self.user_id),
            "yetAnotherServiceToken": str(self.service_token),
            "serviceToken": str(self.service_token),
            "locale": "en_GB",
            "timezone": "GMT+08:00",
            "is_daylight": "0",
            "dst_offset": "0",
            "channel": "MI_APP_STORE",
        }
        headers = {
            "Accept-Encoding": "identity",
            "User-Agent": self.agent,
            "Content-Type": "application/x-www-form-urlencoded",
            "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
            "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
        }
        r = self._req("POST", url, headers=headers, cookies=cookies,
                      params=params, timeout=max(30, self.timeout))
        if r.status_code != 200:
            raise RuntimeError(f"{path} HTTP {r.status_code}: {r.text[:300]}")
        decoded = decrypt_rc4(self.signed_nonce(nonce), r.text)
        try:
            return json.loads(decoded)
        except json.JSONDecodeError:
            raise RuntimeError(f"{path} 响应不是 JSON（RC4 密钥/session 可能已失效）：{decoded[:300]}")

    # -------- 设备与 LTMK --------
    def list_devices(self) -> list[dict]:
        out: list[dict] = []
        homes = self.api("/v2/homeroom/gethome", {
            "fg": True, "fetch_share": True, "fetch_share_dev": True, "limit": 300, "app_ver": 7,
        })
        pairs: list[tuple[Any, Any]] = []
        for h in (homes.get("result") or {}).get("homelist") or []:
            pairs.append((h.get("id"), self.user_id))
        try:
            cnt = self.api("/v2/user/get_device_cnt", {"fetch_own": True, "fetch_share": True})
            for h in (cnt.get("result") or {}).get("share", {}).get("share_family") or []:
                pairs.append((h.get("home_id"), h.get("home_owner")))
        except Exception:
            pass
        seen = set()
        for home_id, owner in pairs:
            if (home_id, owner) in seen:
                continue
            seen.add((home_id, owner))
            try:
                dev = self.api("/v2/home/home_device_list", {
                    "home_owner": owner, "home_id": home_id, "limit": 200,
                    "get_split_device": True, "support_smart_home": True,
                })
                out.extend((dev.get("result") or {}).get("device_info") or [])
            except Exception as e:
                print("[设备] 读取家庭设备失败：", e)
        return out

    def ask_ltmk(self, did: str) -> tuple[str, int, dict]:
        raw = self.api("/share/askbluetoothkey", {"type": "own", "did": str(did), "keyid": 0})
        # 兼容 {"key":...} / {"result":{"key":...}} / {"data":{...}}
        candidates = [raw]
        for k in ("result", "data"):
            if isinstance(raw.get(k), dict):
                candidates.append(raw[k])
        for c in candidates:
            if c.get("key"):
                return c["key"], int(c.get("encrypt_type") or 0), raw
        raise RuntimeError("响应里没有 key 字段（设备可能未绑定蓝牙钥匙 / 非管理员 / did 不对）："
                           + json.dumps(raw, ensure_ascii=False)[:500])

    def get_beaconkey(self, did: str) -> str | None:
        try:
            r = self.api("/v2/device/blt_get_beaconkey", {"did": str(did), "pdid": 1})
            return (r.get("result") or {}).get("beaconkey")
        except Exception:
            return None


# ---------------------------------------------------------------- 自检
def self_test() -> None:
    print("=== 离线自检（不需账号/网络）===\n")
    assert _AES_BACKEND, "未找到 AES 后端"
    print(f"AES 后端: {_AES_BACKEND}")

    # 1) APK gc1.OooOOo / OooOo0o 的 PIN 加解密往返
    pin = "135790"
    ltmk = bytes(range(32))
    ct = encrypt_ltmk(pin, ltmk.hex())
    pt = decrypt_ltmk(1, pin, ct)
    assert pt == ltmk, "PIN 解密往返失败"
    assert hashlib.md5(pin.encode()).hexdigest() == hashlib.md5(b"135790").hexdigest()
    print(f"PIN              : {pin}")
    print(f"AES key(MD5 PIN) : {hashlib.md5(pin.encode()).hexdigest()}")
    print(f"IV               : {LTMK_IV.hex()}")
    print(f"LTMK 明文        : {ltmk.hex()}")
    print(f"云端 key(密文)   : {ct}")
    print("PIN 解密往返     : OK")

    # 2) encrypt_type=0 直通
    assert decrypt_ltmk(0, None, ltmk.hex()) == ltmk
    print("encrypt_type=0   : OK")

    # 3) RC4 与标准向量 / 1024 字节丢弃逻辑
    key = b"0123456789abcdef"
    r = RC4(key)
    r.crypt(bytes(1024))
    c = r.crypt(b"hello-mi-lock")
    r2 = RC4(key)
    r2.crypt(bytes(1024))
    assert r2.crypt(c) == b"hello-mi-lock"
    print("RC4 加解密往返   : OK")
    # 与 pycryptodome ARC4 对拍（如已安装）
    try:
        from Crypto.Cipher import ARC4
        ref = ARC4.new(key)
        ref.encrypt(bytes(1024))
        assert ref.encrypt(b"hello-mi-lock") == c
        print("RC4 与 ARC4 对拍 : OK")
    except ImportError:
        print("RC4 与 ARC4 对拍 : 跳过（未装 pycryptodome）")

    # 4) 端到端 mock：用独立参考实现核对 RC4 签名/加密/解密整条链路
    #    参考实现逐行照抄 Xiaomi-cloud-tokens-extractor 的
    #    generate_enc_signature / generate_enc_params / encrypt_rc4 / decrypt_rc4
    try:
        from Crypto.Cipher import ARC4 as _ARC4

        def ref_rc4(password_b64: str, data: bytes) -> bytes:
            r = _ARC4.new(base64.b64decode(password_b64))
            r.encrypt(bytes(1024))
            return r.encrypt(data)

        def ref_sig(url: str, sn: str, p: dict) -> str:
            parts = ["POST", url.split("com")[1].replace("/app/", "/")]
            parts += [f"{k}={v}" for k, v in p.items()]
            parts.append(sn)
            return base64.b64encode(hashlib.sha1("&".join(parts).encode()).digest()).decode()

        cloud = MiCloud("cn")
        cloud.ssecurity = base64.b64encode(b"0123456789abcdef" * 2).decode()
        cloud.service_token, cloud.user_id = "fake-token", "12345"
        payload = {"type": "own", "did": "blt.3.1abcdef", "keyid": 0}

        def fake_request(method, url, headers=None, cookies=None, params=None,
                         timeout=None, **kwargs):
            assert method == "POST", "应为 POST /share/askbluetoothkey"
            nonce, sn = params["_nonce"], cloud.signed_nonce(params["_nonce"])
            data_plain = ref_rc4(sn, base64.b64decode(params["data"])).decode()
            assert json.loads(data_plain) == payload, "data 字段 RC4 加密不一致"
            # 官方 generate_enc_params 会把刚插入的 rc4_hash__ 也一并 RC4 加密，
            # 所以取到的是密文，要先解回明文再比。
            rc4h_plain = ref_rc4(sn, base64.b64decode(params["rc4_hash__"])).decode()
            assert rc4h_plain == ref_sig(url, sn, {"data": data_plain}), "rc4_hash__ 不一致"
            p1 = {k: v for k, v in params.items() if k not in ("signature", "ssecurity", "_nonce")}
            assert params["signature"] == ref_sig(url, sn, p1), "signature 不一致"
            assert params["ssecurity"] == cloud.ssecurity
            resp = json.dumps({"code": 0, "result": {"key": "ab" * 32, "encrypt_type": 1}})
            text = base64.b64encode(ref_rc4(sn, resp.encode())).decode()
            return type("FakeResp", (), {"status_code": 200, "text": text})()

        cloud.s.request = fake_request
        got = cloud.api("/share/askbluetoothkey", payload)
        assert got["result"]["encrypt_type"] == 1
        print("端到端 RC4 签名  : OK（与 token_extractor 参考实现一致）")
    except ImportError:
        print("端到端 RC4 签名  : 跳过（未装 pycryptodome）")
    print("\n自检全部通过。真实凭据请用 -u/-p 或 --qr 登录获取。")


# ---------------------------------------------------------------- 网络自检
def diag(proxy: str | None = None, no_proxy: bool = False, insecure: bool = False,
         tls12: bool = False, timeout: int = 15) -> int:
    """不接触账号密码，定位 SSLEOFError / 连接失败到底是代理、直连还是 TLS 版本问题。"""
    print("=== 网络自检（不接触账号密码）===\n")
    print("Python       :", sys.version.split()[0], "|", ssl.OPENSSL_VERSION)
    print("requests     :", requests.__version__)
    env = {k: os.environ.get(k) for k in
           ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
            "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE") if os.environ.get(k)}
    print("代理/证书变量:", env or "(无)")
    try:
        from urllib.request import getproxies
        sys_proxies = getproxies()      # Windows 上会额外读注册表的「系统代理」
        print("实际生效代理 :", sys_proxies or "(无)")
        if sys_proxies and not any(k.endswith("PROXY") for k in env):
            print("  ↑ 环境变量里没有代理，但 Windows 注册表/系统代理仍在生效；"
                  "若「默认」失败而「强制直连」成功，多半就是它在作祟。")
    except Exception as e:
        print("实际生效代理 : 读取失败", e)
    for host in ("account.xiaomi.com", "api.io.mi.com", "sts.api.io.mi.com",
                 "c3.lp.account.xiaomi.com", "c3.account.xiaomi.com"):
        try:
            ips = sorted({r[4][0] for r in socket.getaddrinfo(host, 443)})
            print(f"DNS {host:26s}: {', '.join(ips[:4])}")
        except Exception as e:
            print(f"DNS {host:26s}: 失败 {e}")
    # 长轮询域名只做 TCP 连通探测：GET /lp 会 hold 住连接，不适合放在自检里
    try:
        t = time.time()
        with socket.create_connection(("c3.lp.account.xiaomi.com", 443), timeout=6):
            print(f"TCP c3.lp.account.xiaomi.com:443 : OK  {time.time()-t:.2f}s"
                  "  ← 二维码轮询要用这个域名")
    except Exception as e:
        print("TCP c3.lp.account.xiaomi.com:443 : FAIL", type(e).__name__, str(e)[:100])

    url = "https://account.xiaomi.com/pass/serviceLogin"
    h = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"}
    if no_proxy:
        variants = [("强制直连", False, False)]
    elif proxy:
        variants = [("指定代理", True, False), ("强制直连", False, False)]
    else:
        variants = [("默认(含系统代理)", True, False), ("强制直连", False, False),
                    ("默认+TLS1.2", True, True)]
    print()
    ok = 0
    results: dict[str, bool] = {}
    for label, trust, use_tls12 in variants:
        s = requests.Session()
        s.trust_env = trust
        if proxy and label == "指定代理":
            s.proxies = {"http": proxy, "https": proxy}
        if insecure:
            s.verify = False
        if tls12 or use_tls12:
            s.mount("https://", TLS12Adapter())
        try:
            t = time.time()
            r = s.get(url, params={"sid": "xiaomiio", "_json": "true"},
                      headers=h, timeout=timeout)
            try:
                has_sign = bool(MiCloud._to_json(r.text).get("_sign"))
            except Exception:
                has_sign = False
            good = r.status_code == 200 and has_sign
            results[label] = good
            ok += 1 if good else 0
            print(f"{label:18s} -> HTTP {r.status_code}  {len(r.text):5d}B  "
                  f"{time.time()-t:.2f}s  _sign={'有' if has_sign else '无'}")
        except Exception as e:
            results[label] = False
            print(f"{label:18s} -> FAIL {type(e).__name__}: {str(e)[:150]}")

    proxy_bad = any(k.startswith("默认") and not v for k, v in results.items())
    if results.get("强制直连") and proxy_bad:
        print("\n结论：系统/环境代理是元凶 —— 直连正常、走代理即失败。")
        print("      连接在代理的 CONNECT 阶段就被断开，所以 --tls12 无效，别再试 TLS 版本。")
        print("      直接跑脚本即可（已内置自动降级），或显式加 --no-proxy 更稳。")
    elif ok:
        print("\n结论：至少一条链路可用，用对应参数跑脚本即可。")
    else:
        print("\n结论：全部失败 → 换网络（手机热点）/ 关 VPN 或代理 / 校准系统时间后再试。")
    print("参数：--no-proxy 强制直连 · --proxy http://IP:端口 显式走代理 · --tls12 强制 TLS 1.2")
    return 0 if ok else 1


# ---------------------------------------------------------------- 云端会话缓存
# 登录一次就把 serviceToken / ssecurity / userId 存下来，避免设备筛选失败后
# 每重跑一次都要重新扫码（二维码 ticket 与会话绑定，脚本退出即作废）。
DEFAULT_SESSION_FILE = os.path.join(os.path.expanduser("~"), ".mi_ltmk_session.json")


def save_session(cloud: "MiCloud", path: str, server: str) -> None:
    if not (cloud.service_token and cloud.ssecurity and cloud.user_id):
        return
    data = {
        "serviceToken": cloud.service_token,
        "ssecurity": cloud.ssecurity,
        "userId": str(cloud.user_id),
        "server": server,
        "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        try:
            os.chmod(path, 0o600)          # Windows 上尽力而为
        except Exception:
            pass
        print(f"[会话] 已缓存到 {os.path.abspath(path)}，下次运行免扫码", flush=True)
        print("[会话] ⚠ 该文件等同云端登录态，请勿外传；--clear-cache 可删除", flush=True)
    except Exception as e:
        print("[会话] 缓存写入失败（不影响本次运行）：", type(e).__name__, str(e)[:100], flush=True)


def load_session(cloud: "MiCloud", path: str, server: str) -> bool:
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        if not (d.get("serviceToken") and d.get("ssecurity") and d.get("userId")):
            return False
        if d.get("server") and d["server"] != server:
            return False
        cloud.service_token = d["serviceToken"]
        cloud.ssecurity = d["ssecurity"]
        cloud.user_id = str(d["userId"])
        print(f"[登录] 复用缓存会话（{d.get('saved_at', '时间未知')}）：{os.path.abspath(path)}", flush=True)
        print("[登录] 若报鉴权失效，加 --clear-cache 清掉后重新登录", flush=True)
        return True
    except FileNotFoundError:
        return False
    except Exception as e:
        print("[会话] 缓存读取失败，将重新登录：", type(e).__name__, str(e)[:100], flush=True)
        return False


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="从自己的小米账号取回米家门锁 LTMK（仅限自有设备）")
    ap.add_argument("--self-test", action="store_true", help="离线验证 PIN 解密与 RC4 算法")
    ap.add_argument("-u", "--username", help="小米账号（邮箱/手机号/小米ID）")
    ap.add_argument("-p", "--password", help="小米账号密码")
    ap.add_argument("--qr", action="store_true", help="二维码登录（绕过密码/短信验证），自动保存并弹出二维码图片")
    ap.add_argument("--qr-wait", type=int, help="二维码等待秒数，默认用服务端返回的 timeout(300)")
    ap.add_argument("--qr-file", default="mi_login_qr.png", help="二维码图片保存路径")
    ap.add_argument("--no-open-qr", action="store_true", help="不自动弹出图片查看器，只保存文件")
    ap.add_argument("-s", "--server", default="cn", help="服务器区域，默认 cn")
    ap.add_argument("--service-token", help="已有 serviceToken（跳过登录）")
    ap.add_argument("--ssecurity", help="已有 ssecurity（跳过登录）")
    ap.add_argument("--user-id", help="已有 userId（跳过登录）")
    ap.add_argument("--did", help="门锁 did；不指定则自动列出并挑选")
    ap.add_argument("--mac", help="按 MAC 过滤设备（可不含冒号）；优先于型号匹配，在全部设备中查找")
    ap.add_argument("--model-prefix", default="xiaomi.lock.", help="设备型号前缀，默认 xiaomi.lock.；找不到时自动放宽为含 lock 的型号")
    ap.add_argument("--pin", help="米家 App 里设置的门锁安全 PIN（encrypt_type=1 时必需）")
    ap.add_argument("--list-only", action="store_true", help="只列设备，不取 LTMK")
    ap.add_argument("--list-all", action="store_true", help="列出账号下全部设备（did/model/mac/name）")
    ap.add_argument("--session-file", help=f"会话缓存路径，默认 {DEFAULT_SESSION_FILE}")
    ap.add_argument("--no-cache", action="store_true", help="不读也不写会话缓存，每次重新登录")
    ap.add_argument("--clear-cache", action="store_true", help="删除会话缓存后直接退出")
    ap.add_argument("--out", help="把结果保存为 JSON（请妥善保管）")
    ap.add_argument("--check-ltmk", metavar="LTMK_JSON",
                    help="脱敏核对已保存的 ltmk.json：不联网、不打印密钥明文，只输出长度/指纹/型号")
    ap.add_argument("--emit-header", metavar="HEADER_H",
                    help="配合 --check-ltmk 生成含 LTMK 字节数组的 C 头文件（含明文，用完删除）")
    ap.add_argument("--diag", action="store_true", help="网络自检：分别测代理/直连/TLS1.2，不接触账号")
    ap.add_argument("--proxy", help="显式指定代理，例如 http://127.0.0.1:7890")
    ap.add_argument("--no-proxy", action="store_true", help="忽略环境代理变量，强制直连")
    ap.add_argument("--insecure", action="store_true", help="跳过证书校验（仅排查中间人代理时用）")
    ap.add_argument("--tls12", action="store_true", help="强制 TLS 1.2（默认遇到 SSL 错误会自动启用并重试）")
    ap.add_argument("--retries", type=int, default=3, help="连接层重试次数，默认 3")
    ap.add_argument("--timeout", type=int, default=20, help="单次请求超时秒数，默认 20")
    a = ap.parse_args()

    if a.self_test:
        self_test()
        return 0
    if a.check_ltmk:
        return check_ltmk_file(a.check_ltmk, a.emit_header)
    if not _HAS_REQUESTS:
        sys.exit("缺少依赖：pip install requests cryptography（离线核对 --check-ltmk 不需要）")
    if a.diag:
        return diag(a.proxy, a.no_proxy, a.insecure, a.tls12, a.timeout)

    session_path = a.session_file or DEFAULT_SESSION_FILE
    if a.clear_cache:
        if os.path.exists(session_path):
            os.remove(session_path)
            print(f"[会话] 已删除缓存：{os.path.abspath(session_path)}")
        else:
            print("[会话] 缓存不存在，无需删除")
        return 0

    cloud = MiCloud(a.server, proxy=a.proxy, no_proxy=a.no_proxy,
                    insecure=a.insecure, tls12=a.tls12,
                    retries=a.retries, timeout=a.timeout)
    from_cache = False
    if a.service_token and a.ssecurity and a.user_id:
        cloud.service_token, cloud.ssecurity, cloud.user_id = a.service_token, a.ssecurity, a.user_id
        print("[登录] 使用命令行传入的已有云端会话凭据")
    elif not a.no_cache and load_session(cloud, session_path, a.server):
        from_cache = True
    elif a.qr:
        if not cloud.login_qr(a.qr_wait, a.qr_file, not a.no_open_qr):
            print("[提示] 若反复无响应，先 Ctrl+C 停掉再重跑（每次会生成新二维码）；"
                  "也可以先试账号密码登录 -u/-p。", flush=True)
            return 2
        print("[登录] 二维码登录成功")
    else:
        if not a.username or not a.password:
            ap.error("需要 -u/-p，或改用 --qr，或直接给 --service-token/--ssecurity/--user-id")
        if not cloud.login_password(a.username, a.password):
            return 2
        print("[登录] 账号密码登录成功")

    # 关键：登录成功立刻落盘，后续即使设备筛选失败也不用再扫一次码
    if not a.no_cache and not from_cache:
        save_session(cloud, session_path, a.server)

    devs = cloud.list_devices()
    if from_cache and not devs:
        print("[提示] 缓存会话可能已过期或家庭列表接口异常；加 --clear-cache 后重新登录",
              flush=True)

    def norm_mac(v: Any) -> str:
        return str(v or "").replace(":", "").replace("-", "").lower()

    target_mac = norm_mac(a.mac) if a.mac else None
    # ① MAC 最可靠：直接在「全部设备」里找，不受型号前缀限制
    mac_hits = [d for d in devs if target_mac and norm_mac(d.get("mac")) == target_mac]
    # ② 严格型号前缀
    strict = [d for d in devs if str(d.get("model") or "").startswith(a.model_prefix)]
    # ③ 自动放宽：lumi.lock.* / loock.lock.* / ydhome.lock.* / 名称含「锁」
    fuzzy = [d for d in devs
             if "lock" in str(d.get("model") or "").lower()
             or "锁" in str(d.get("name") or "")]

    if mac_hits:
        locks, why = mac_hits, f"按 MAC {a.mac} 在全部设备中命中"
    elif strict:
        locks, why = strict, f"型号前缀 {a.model_prefix}*"
        if a.mac:
            locks = [d for d in locks if norm_mac(d.get("mac")) == target_mac]
            why += f" + MAC {a.mac}"
    elif fuzzy:
        locks = fuzzy
        if a.mac:
            locks = [d for d in locks if norm_mac(d.get("mac")) == target_mac] or fuzzy
        why = "自动放宽匹配（型号含 lock / 名称含「锁」）"
        print(f"\n[提示] 严格前缀 {a.model_prefix}* 命中 0 台，已自动放宽。"
              "lumi.lock.* / loock.lock.* / ydhome.lock.* 与 xiaomi.lock.* 共用同一套高安全级 BLE 协议。",
              flush=True)
    else:
        locks, why = [], "未匹配到门锁"

    print(f"\n[设备] 共 {len(devs)} 台；{why} → {len(locks)} 台：", flush=True)
    for d in locks:
        print("  did={did}  model={model}  mac={mac}  name={name}  token={token}".format(
            did=d.get("did"), model=d.get("model"), mac=d.get("mac"),
            name=d.get("name"), token=(str(d.get("token"))[:12] + "...") if d.get("token") else "-",
        ), flush=True)

    models = Counter(str(d.get("model") or "(空)") for d in devs)
    print("\n[型号分布] " + ", ".join(f"{m}×{n}" for m, n in models.most_common(25)), flush=True)

    if a.list_all or not locks:
        if not locks:
            print("\n[提示] 下面列出全部设备，找到门锁后可用 --did / --mac / --model-prefix 指定：", flush=True)
        for d in devs:
            print("  did={did}  model={model}  mac={mac}  name={name}".format(
                did=d.get("did"), model=d.get("model"), mac=d.get("mac"),
                name=d.get("name"),
            ), flush=True)

    if a.list_only:
        return 0

    did = a.did
    if not did:
        if len(locks) == 1:
            did = str(locks[0]["did"])
        elif not locks:
            print("\n[错误] 没找到门锁设备；请用 --did <did> 或 --mac <MAC> 直接指定，"
                  "或 --model-prefix lumi.lock. 重跑（会话已缓存，无需再扫码）")
            return 3
        else:
            print("\n[提示] 有多台门锁，请用 --did <did> 指定（或 --mac <MAC> 过滤）")
            return 3
    print(f"\n[取密钥] POST /share/askbluetoothkey  did={did}  type=own  keyid=0")
    key_hex, enc_type, raw = cloud.ask_ltmk(str(did))
    print(f"  encrypt_type = {enc_type}")
    print(f"  key          = {key_hex[:24]}...{key_hex[-8:]}  (len={len(key_hex)})")
    print(f"  原始响应     = {json.dumps(raw, ensure_ascii=False)[:400]}")

    try:
        ltmk = decrypt_ltmk(enc_type, a.pin, key_hex)
    except Exception as e:
        print(f"\n[错误] 解密 LTMK 失败：{e}")
        print("[提示] 会话已缓存，补上 --pin <门锁安全PIN> 直接重跑即可，无需再扫码")
        return 4
    if len(ltmk) != 32:
        print(f"\n[警告] LTMK 长度 {len(ltmk)} 字节（正常应为 32），请核对 PIN 是否正确")
    if enc_type == 1:
        print("\n[注意] encrypt_type=1 用 AES-CBC/NoPadding，没有填充校验：")
        print("       PIN 输错同样会解出 32 字节，脚本无法离线判断 PIN 是否正确。")
        print("       唯一可靠判据是 BLE 登录握手：设备接受登录确认帧才算对；")
        print("       旁证是米家 App 里长按蓝牙开锁能成功。")

    print(f"\n  ★ LTMK (hex, 32B) = {ltmk.hex()}")
    print(f"  ★ LTMK (base64)   = {base64.b64encode(ltmk).decode()}")
    bk = cloud.get_beaconkey(str(did))
    if bk and bk.lower() in ("f" * len(bk), "0" * len(bk)):
        print("  （核对）beaconkey 云端返回全 F/全 0 占位：该型号没有 beaconkey，")
        print("           保留你组件里已有的 bindkey，不要用这个值覆盖。")
    elif bk:
        print(f"  （核对）beaconkey = {bk}  ← 应与你组件里已有的 bindkey 一致")

    result = {
        "did": str(did), "mac": next((d.get("mac") for d in devs if str(d.get("did")) == str(did)), None),
        "model": next((d.get("model") for d in devs if str(d.get("did")) == str(did)), None),
        "server": a.server, "encrypt_type": enc_type,
        "ltmk_hex": ltmk.hex(),
        "ltmk_sha256_8": hashlib.sha256(ltmk).hexdigest()[:16],  # 非敏感指纹，便于脱敏核对
        "beaconkey": bk,
    }
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"\n[保存] {os.path.abspath(a.out)}  ← 含最高权限凭据，用完请删除，切勿提交 git")

    print("\n下一步：把 ltmk_hex 填进 ESPHome 的连接层骨架，配合 P-256 ECDH 登录 → 0x1001 写 7 字节开锁帧。")
    print("提醒：仅限本人所有、已在自己米家账号下绑定的门锁。")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except _SSL_ERROR as e:
        print("[异常] SSLError", e)
        print("""
这是 TLS 握手/连接被提前断开，与账号密码、PIN、LTMK 算法无关。
脚本已自动尝试「切 TLS 1.2 → 绕开系统代理直连」；若仍失败，按序尝试：

  1) python get_ltmk.py --diag                 # 定位是代理、直连还是 TLS 版本问题
  2) python get_ltmk.py ... --no-proxy         # 忽略坏代理（含 Windows 注册表的系统代理）
  3) python get_ltmk.py ... --tls12            # 强制 TLS 1.2
  3b) 若 --diag 显示「直连通、代理挂」：关掉 VPN/Clash 或在 Windows 设置里关系统代理，
      仅加 --no-proxy 即可，--tls12 对代理断连无效
  4) 换网络（手机热点）；校准系统时间；确认浏览器能打开 https://account.xiaomi.com
  5) 实在不通：在能联网的机器上用 Xiaomi-cloud-tokens-extractor 取
     serviceToken / ssecurity / userId，再用 --service-token ... --ssecurity ...
     --user-id ... --did <did> 跳过登录，直接取 LTMK
""")
        sys.exit(1)
    except Exception as e:
        print("[异常]", type(e).__name__, e)
        sys.exit(1)
