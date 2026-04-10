"""
Криптографическое ядро uPass.
Всё вычисляется в памяти, ничего не хранится.
"""

import hashlib
import ctypes
import os
from argon2.low_level import hash_secret_raw, Type

# ─── Константы ────────────────────────────────────────────────────────────────

# Pepper — берётся из окружения; если не задан — используется дефолт (только для dev!)
_pepper_hex = os.getenv("PEPPER_HEX", "")
if _pepper_hex:
    _PEPPER: bytes = bytes.fromhex(_pepper_hex)
    if len(_PEPPER) < 16:
        raise ValueError("PEPPER_HEX должен быть не менее 16 байт (32 hex-символа)")
else:
    # Дефолтный pepper для разработки. В продакшене ОБЯЗАТЕЛЬНО задайте PEPPER_HEX в .env!
    _PEPPER = (
        b"\x7f\x3a\x9b\x2c\x4e\x1d\x8f\x05"
        b"\xa6\x7b\xc3\xd0\xe4\x92\x61\x3f"
        b"\x28\xd7\x04\xae\x5c\x83\xf1\x69"
        b"\x0b\xe5\x37\xca\x91\x4d\x76\x2e"
    )

ARGON2_MEMORY   = 65536  # 64 MB
ARGON2_TIME     = 4
ARGON2_PARALLEL = 2
ARGON2_HASH_LEN = 128    # 1024 бит — покрывает максимальную длину пароля (128 симв.)

CHARSET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~"
)
CHARSET_LEN    = len(CHARSET)
PASSWORD_LEN   = 64

# ─── Утилиты памяти ───────────────────────────────────────────────────────────

def _zero(buf: bytearray) -> None:
    """Best-effort обнуление bytearray через ctypes."""
    if not buf:
        return
    try:
        c_buf = (ctypes.c_char * len(buf)).from_buffer(buf)
        ctypes.memset(c_buf, 0, len(buf))
    except Exception:
        for i in range(len(buf)):
            buf[i] = 0


# ─── Ядро ─────────────────────────────────────────────────────────────────────

def _salt(domain: str) -> bytes:
    return hashlib.sha256(domain.encode()).digest()


def _derive(master_buf: bytearray, domain: str) -> bytearray:
    """
    Argon2id(secret = master || domain || pepper,
             salt   = SHA-256(domain))
    Возвращает bytearray — вызывающий обязан обнулить.
    """
    domain_buf = bytearray(domain.encode())
    secret     = bytearray(master_buf) + domain_buf + bytearray(_PEPPER)
    try:
        raw = hash_secret_raw(
            secret      = bytes(secret),
            salt        = _salt(domain),
            time_cost   = ARGON2_TIME,
            memory_cost = ARGON2_MEMORY,
            parallelism = ARGON2_PARALLEL,
            hash_len    = ARGON2_HASH_LEN,
            type        = Type.ID,
        )
        return bytearray(raw)
    finally:
        _zero(secret)
        _zero(domain_buf)


def _to_password(h: bytearray, length: int) -> str:
    n   = len(h)
    pwd = []
    for i in range(length):
        # 16-бит значение → снижает modulo bias
        val = h[i % n] | (h[(i + 1) % n] << 8)
        pwd.append(CHARSET[val % CHARSET_LEN])
    return "".join(pwd)


def generate(master: str, domain: str, length: int = PASSWORD_LEN) -> str:
    """Публичный API: принимает строки, возвращает пароль."""
    master_buf = bytearray(master.encode())
    try:
        h = _derive(master_buf, domain)
        try:
            return _to_password(h, length)
        finally:
            _zero(h)
    finally:
        _zero(master_buf)
