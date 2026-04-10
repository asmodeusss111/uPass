"""
Сбор статистики в памяти. Нет БД — всё сбрасывается при рестарте.
"""

import time
import asyncio
import httpx
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Deque

# ── Типы ─────────────────────────────────────────────────────────

@dataclass
class RequestRecord:
    ts:           float
    ip:           str
    domain:       str       # пустая строка для random
    kind:         str       # "deterministic" | "random"
    response_ms:  float = 0.0
    country:      str   = "?"
    ip_full:      str   = ""  # полный IP (только если включена анонимизация)

@dataclass
class FailedLogin:
    ts: float
    ip: str

@dataclass
class RateHitRecord:
    ts: float
    ip: str

# ── Хранилище ─────────────────────────────────────────────────────

_start_time = time.time()

_log:          Deque[RequestRecord] = deque(maxlen=200)
_failed_logins: Deque[FailedLogin]  = deque(maxlen=100)
_rate_hit_log:  Deque[RateHitRecord]= deque(maxlen=500)

_counters:  dict[str, int]   = defaultdict(int)
_rate_hits: dict[str, int]   = defaultdict(int)
_geo_cache: dict[str, str]   = {}
_GEO_CACHE_MAX = 2000

# Заблокированные IP (persistent до рестарта)
_blocked_ips: set[str] = set()

# Порог алерта — хитов rate limit за последний час
RATE_ALERT_THRESHOLD = 10

# ── Запросы ───────────────────────────────────────────────────────

def record_request(ip: str, domain: str, kind: str, response_ms: float = 0.0, ip_full: str = "") -> RequestRecord:
    rec = RequestRecord(ts=time.time(), ip=ip, domain=domain, kind=kind, response_ms=response_ms, ip_full=ip_full)
    _log.append(rec)
    _counters["total"] += 1
    _counters[kind]    += 1
    return rec


def record_rate_hit(ip: str) -> None:
    _counters["rate_limited"] += 1
    _rate_hits[ip]            += 1
    _rate_hit_log.append(RateHitRecord(ts=time.time(), ip=ip))


def record_failed_login(ip: str) -> None:
    _failed_logins.append(FailedLogin(ts=time.time(), ip=ip))
    _counters["failed_logins"] += 1

# ── Чтение данных ─────────────────────────────────────────────────

def get_counters() -> dict:
    return dict(_counters)


def get_recent(n: int = 50) -> list[RequestRecord]:
    items = list(_log)
    return items[max(0, len(items) - n):][::-1]


def get_uptime() -> float:
    return time.time() - _start_time


def get_avg_response_ms() -> dict[str, float]:
    """Среднее время ответа по типам запросов."""
    det_times = [r.response_ms for r in _log if r.kind == "deterministic" and r.response_ms > 0]
    rnd_times = [r.response_ms for r in _log if r.kind == "random"        and r.response_ms > 0]
    return {
        "deterministic": round(sum(det_times) / len(det_times), 1) if det_times else 0.0,
        "random":        round(sum(rnd_times) / len(rnd_times),  1) if rnd_times else 0.0,
    }


def get_top_domains(n: int = 10) -> list[tuple[str, int]]:
    counts: dict[str, int] = defaultdict(int)
    for r in _log:
        if r.domain:
            counts[r.domain] += 1
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]


def get_top_countries(n: int = 10) -> list[tuple[str, int]]:
    counts: dict[str, int] = defaultdict(int)
    for r in _log:
        counts[r.country] += 1
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]


def get_unique_ips(n: int = 20) -> list[tuple[str, str, int]]:
    counts: dict[str, int] = defaultdict(int)
    country_map: dict[str, str] = {}
    for r in _log:
        counts[r.ip] += 1
        country_map[r.ip] = r.country
    result = [(ip, country_map[ip], cnt) for ip, cnt in counts.items()]
    return sorted(result, key=lambda x: x[2], reverse=True)[:n]


def get_rate_hits(n: int = 10) -> list[tuple[str, int]]:
    return sorted(_rate_hits.items(), key=lambda x: x[1], reverse=True)[:n]


def get_rate_hits_last_hour() -> int:
    """Количество rate limit хитов за последний час."""
    cutoff = time.time() - 3600
    return sum(1 for r in _rate_hit_log if r.ts >= cutoff)


def get_failed_logins(n: int = 50) -> list[FailedLogin]:
    return list(reversed(list(_failed_logins)))[:n]


def get_failed_logins_last_hour() -> int:
    cutoff = time.time() - 3600
    return sum(1 for f in _failed_logins if f.ts >= cutoff)

# ── IP блокировка ─────────────────────────────────────────────────

def block_ip(ip: str) -> None:
    _blocked_ips.add(ip)


def unblock_ip(ip: str) -> None:
    _blocked_ips.discard(ip)


def is_blocked(ip: str) -> bool:
    return ip in _blocked_ips


def get_blocked_ips() -> list[str]:
    return sorted(_blocked_ips)

# ── Сброс ─────────────────────────────────────────────────────────

def clear_stats() -> None:
    _log.clear()
    _failed_logins.clear()
    _rate_hit_log.clear()
    _counters.clear()
    _rate_hits.clear()
    _geo_cache.clear()
    # Заблокированные IP НЕ сбрасываем

# ── Гео-резолвинг ─────────────────────────────────────────────────

async def _resolve_country(rec: RequestRecord) -> None:
    ip = rec.ip
    if ip in ("127.0.0.1", "::1", "unknown"):
        rec.country = "Localhost"
        return
    if ip in _geo_cache:
        rec.country = _geo_cache[ip]
        return
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}?fields=country")
            country = r.json().get("country", "?")
            if len(_geo_cache) >= _GEO_CACHE_MAX:
                # Evict oldest entry
                _geo_cache.pop(next(iter(_geo_cache)))
            _geo_cache[ip] = country
            rec.country    = country
    except Exception:
        rec.country = "?"


def resolve_country_bg(rec: RequestRecord) -> None:
    asyncio.create_task(_resolve_country(rec))
