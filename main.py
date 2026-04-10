"""
uPass — Backend (FastAPI)
Запуск: uvicorn main:app --reload
"""

import time
import secrets
import hmac
import logging
import os
import platform
import ipaddress
from collections import defaultdict
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import psutil
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Form
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature
from pydantic import BaseModel, field_validator

import crypto
import stats as st

load_dotenv()

# ── Конфиг ────────────────────────────────────────────────────────
ADMIN_USER   = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASS   = os.getenv("ADMIN_PASSWORD", "changeme123")
SECRET_KEY   = os.getenv("SECRET_KEY", "dev-secret-key")
SESSION_COOKIE = "upass_admin"

# Whitelist IP для /admin (пусто = разрешены все)
_wl_raw = os.getenv("ADMIN_WHITELIST", "").strip()
ADMIN_WHITELIST: set[str] = {ip.strip() for ip in _wl_raw.split(",") if ip.strip()}

RATE_ALERT_THRESHOLD = int(os.getenv("RATE_ALERT_THRESHOLD", "10"))
HTTPS_ONLY           = os.getenv("HTTPS_ONLY",    "false").lower() == "true"
IP_ANONYMIZE         = os.getenv("IP_ANONYMIZE",  "false").lower() == "true"
TRUSTED_PROXY        = os.getenv("TRUSTED_PROXY", "").strip()
# TRUST_PROXY=true — доверять X-Forwarded-For без проверки IP прокси (для Railway/Render/etc.)
TRUST_PROXY          = os.getenv("TRUST_PROXY",   "false").lower() == "true"
SECURITY_CONTACT     = os.getenv("SECURITY_CONTACT", "mailto:security@example.com")
# REVEAL_PASSWORD — отдельный пароль для просмотра полных IP в /admin/requests
REVEAL_PASSWORD      = os.getenv("REVEAL_PASSWORD", "").strip()
_tz_name = os.getenv("TZ", "UTC")
try:
    APP_TZ = ZoneInfo(_tz_name)
except ZoneInfoNotFoundError:
    APP_TZ = timezone.utc

signer = URLSafeTimedSerializer(SECRET_KEY)

# ── Логирование ───────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger("upass")

# ── Rate limiting ─────────────────────────────────────────────────
_RATE_WINDOW    = 60
_RATE_LIMIT     = 10
_RATE_STORE_MAX = 10_000
_rate_store: dict[str, list[float]] = defaultdict(list)


def _check_rate(ip: str) -> None:
    now = time.monotonic()
    # Чистим устаревшие записи если хранилище разросшееся
    if len(_rate_store) > _RATE_STORE_MAX:
        stale = [k for k, v in _rate_store.items()
                 if not v or now - v[-1] > _RATE_WINDOW]
        for k in stale:
            del _rate_store[k]
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < _RATE_WINDOW]
    if len(_rate_store[ip]) >= _RATE_LIMIT:
        st.record_rate_hit(ip)
        raise HTTPException(status_code=429, detail="Слишком много запросов. Подождите минуту.")
    _rate_store[ip].append(now)


# ── Login lockout ──────────────────────────────────────────────────
_LOGIN_ATTEMPT_WINDOW = 900   # 15 минут
_LOGIN_MAX_ATTEMPTS   = 5
_login_attempts: dict[str, list[float]] = defaultdict(list)


def _check_login_lockout(ip: str) -> None:
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip]
                           if now - t < _LOGIN_ATTEMPT_WINDOW]
    if len(_login_attempts[ip]) >= _LOGIN_MAX_ATTEMPTS:
        oldest    = min(_login_attempts[ip])
        remaining = int(oldest + _LOGIN_ATTEMPT_WINDOW - now)
        raise HTTPException(
            status_code=429,
            detail=f"Слишком много попыток входа. Подождите {remaining} с.",
        )


def _record_login_failure(ip: str) -> None:
    _login_attempts[ip].append(time.time())
    st.record_failed_login(ip)


# ── Схемы ─────────────────────────────────────────────────────────

class GenerateRequest(BaseModel):
    master_password: str
    domain: str
    length: int = crypto.PASSWORD_LEN

    @field_validator("master_password")
    @classmethod
    def master_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("master_password не может быть пустым")
        if len(v) > 1024:
            raise ValueError("master_password слишком длинный")
        return v

    @field_validator("domain")
    @classmethod
    def domain_not_empty(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            raise ValueError("domain не может быть пустым")
        if len(v) > 253:
            raise ValueError("domain слишком длинный")
        return v

    @field_validator("length")
    @classmethod
    def length_range(cls, v: int) -> int:
        if not (16 <= v <= 128):
            raise ValueError("length должен быть от 16 до 128")
        return v


class RandomRequest(BaseModel):
    length: int = crypto.PASSWORD_LEN

    @field_validator("length")
    @classmethod
    def length_range(cls, v: int) -> int:
        if not (16 <= v <= 128):
            raise ValueError("length должен быть от 16 до 128")
        return v


class GenerateResponse(BaseModel):
    password: str
    length: int
    charset_size: int
    entropy_bits: float


# ── Приложение ────────────────────────────────────────────────────

app = FastAPI(title="uPass", docs_url=None, redoc_url=None)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"]  = "nosniff"
        h["X-Frame-Options"]         = "DENY"
        h["X-XSS-Protection"]        = "1; mode=block"
        h["Referrer-Policy"]         = "strict-origin-when-cross-origin"
        h["Cross-Origin-Opener-Policy"]   = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        h["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), interest-cohort=()"
        )
        h["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
        if HTTPS_ONLY:
            h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Отклоняем запросы с телом > 64 КБ — защита от DoS."""
    _MAX_BYTES = 65_536

    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and int(cl) > self._MAX_BYTES:
            return JSONResponse(
                status_code=413,
                content={"detail": "Тело запроса слишком большое (макс. 64 КБ)"},
            )
        return await call_next(request)


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(BodySizeLimitMiddleware)

STATIC_DIR    = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=APP_TZ).strftime("%H:%M:%S")

templates.env.filters["ts"] = _fmt_ts


# ── Сессия и доступ ───────────────────────────────────────────────

def _get_session(request: Request) -> str | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        return signer.loads(token, max_age=86400)
    except BadSignature:
        return None


def _require_admin(request: Request) -> None:
    ip = _get_ip(request)
    # Whitelist проверка
    if ADMIN_WHITELIST and ip not in ADMIN_WHITELIST:
        raise HTTPException(status_code=403, detail="Доступ запрещён")
    if _get_session(request) != "admin":
        raise HTTPException(status_code=303, headers={"Location": "/admin/login"})


def _get_ip(request: Request) -> str:
    client = request.client.host if request.client else "unknown"
    if TRUST_PROXY or (TRUSTED_PROXY and client == TRUSTED_PROXY):
        # TRUST_PROXY=true: платформы вроде Railway/Render сами зачищают XFF от клиента
        # TRUSTED_PROXY=<ip>: доверяем только конкретному прокси
        xff = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if xff:
            try:
                ipaddress.ip_address(xff)
                return xff
            except ValueError:
                pass
    return client


def _anonymize_ip(ip: str) -> str:
    """Маскирует последний октет IPv4 или последние 64 бита IPv6."""
    if not IP_ANONYMIZE or ip in ("unknown", "localhost"):
        return ip
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0"
        # IPv6: обнуляем последние 64 бита
        net = ipaddress.IPv6Network(f"{ip}/64", strict=False)
        return str(net.network_address)
    except ValueError:
        return ip


# ── Основные роуты ────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(content=html)


@app.post("/generate", response_model=GenerateResponse)
async def generate_password(req: GenerateRequest, request: Request) -> GenerateResponse:
    ip = _get_ip(request)
    if st.is_blocked(ip):
        raise HTTPException(status_code=403, detail="Доступ заблокирован")
    _check_rate(ip)
    log.info("generate  domain=%s  ip=%s", req.domain, ip)

    t0 = time.perf_counter()
    password = crypto.generate(req.master_password, req.domain, req.length)
    ms = round((time.perf_counter() - t0) * 1000, 1)

    rec = st.record_request(_anonymize_ip(ip), req.domain, "deterministic", response_ms=ms,
                            ip_full=ip if IP_ANONYMIZE else "")
    st.resolve_country_bg(rec)

    bits = (crypto.CHARSET_LEN - 1).bit_length()
    return GenerateResponse(
        password     = password,
        length       = req.length,
        charset_size = crypto.CHARSET_LEN,
        entropy_bits = round(req.length * bits, 1),
    )


@app.post("/generate/random", response_model=GenerateResponse)
async def generate_random(req: RandomRequest, request: Request) -> GenerateResponse:
    ip = _get_ip(request)
    if st.is_blocked(ip):
        raise HTTPException(status_code=403, detail="Доступ заблокирован")
    _check_rate(ip)
    log.info("generate_random  length=%d  ip=%s", req.length, ip)

    t0 = time.perf_counter()
    password = "".join(secrets.choice(crypto.CHARSET) for _ in range(req.length))
    ms = round((time.perf_counter() - t0) * 1000, 1)

    rec = st.record_request(_anonymize_ip(ip), "", "random", response_ms=ms,
                            ip_full=ip if IP_ANONYMIZE else "")
    st.resolve_country_bg(rec)

    bits = (crypto.CHARSET_LEN - 1).bit_length()
    return GenerateResponse(
        password     = password,
        length       = req.length,
        charset_size = crypto.CHARSET_LEN,
        entropy_bits = round(req.length * bits, 1),
    )


# ── Admin: авторизация ────────────────────────────────────────────

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request) -> HTMLResponse:
    if _get_session(request) == "admin":
        return RedirectResponse("/admin", status_code=302)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/admin/login", response_class=HTMLResponse)
async def admin_login(request: Request,
                      username: str = Form(...),
                      password: str = Form(...)) -> HTMLResponse:
    ip = _get_ip(request)
    _check_login_lockout(ip)
    _check_rate(ip)
    user_ok = hmac.compare_digest(username, ADMIN_USER)
    pass_ok = hmac.compare_digest(password, ADMIN_PASS)
    if user_ok and pass_ok:
        _login_attempts.pop(ip, None)   # сбрасываем счётчик неудачных попыток
        token = signer.dumps("admin")
        resp  = RedirectResponse("/admin", status_code=302)
        resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="strict",
                        secure=HTTPS_ONLY, max_age=86400)
        return resp
    _record_login_failure(ip)
    log.warning("failed_login  ip=%s  user=%s", ip, username)
    remaining_attempts = _LOGIN_MAX_ATTEMPTS - len(_login_attempts[ip])
    return templates.TemplateResponse(request, "login.html", {
        "error":    "Неверный логин или пароль",
        "attempts": remaining_attempts,
    })


@app.get("/admin/logout")
async def admin_logout() -> RedirectResponse:
    resp = RedirectResponse("/admin/login", status_code=302)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# ── Admin: дашборд ────────────────────────────────────────────────

def _uptime_str(seconds: float) -> str:
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    if h:  return f"{h}ч {m}м"
    if m:  return f"{m}м {s}с"
    return f"{s}с"


def _build_alerts() -> list[dict]:
    alerts = []
    hits = st.get_rate_hits_last_hour()
    if hits >= RATE_ALERT_THRESHOLD:
        alerts.append({
            "level": "red",
            "text":  f"Rate limit: {hits} блокировок за последний час (порог: {RATE_ALERT_THRESHOLD})",
        })
    failed = st.get_failed_logins_last_hour()
    if failed >= 3:
        alerts.append({
            "level": "gold",
            "text":  f"Подозрительная активность: {failed} неудачных попыток входа за час",
        })
    return alerts


@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request) -> HTMLResponse:
    _require_admin(request)
    avg_ms = st.get_avg_response_ms()
    return templates.TemplateResponse(request, "admin.html", {
        "counters":      st.get_counters(),
        "recent":        st.get_recent(30),
        "top_domains":   st.get_top_domains(8),
        "top_countries": st.get_top_countries(8),
        "rate_hits":     st.get_rate_hits(8),
        "uptime":        _uptime_str(st.get_uptime()),
        "avg_det_ms":    avg_ms["deterministic"],
        "avg_rnd_ms":    avg_ms["random"],
        "blocked_ips":   st.get_blocked_ips(),
        "failed_logins": st.get_failed_logins(10),
        "alerts":        _build_alerts(),
        "rate_hits_hour":st.get_rate_hits_last_hour(),
        "failed_hour":   st.get_failed_logins_last_hour(),
    })


@app.get("/admin/requests", response_class=HTMLResponse)
async def admin_requests(request: Request) -> HTMLResponse:
    _require_admin(request)
    return templates.TemplateResponse(request, "requests.html", {
        "records":        st.get_recent(200),
        "reveal_enabled": bool(REVEAL_PASSWORD),
    })


class RevealRequest(BaseModel):
    ts:       float
    password: str


@app.post("/admin/reveal-ip")
async def admin_reveal_ip(request: Request, body: RevealRequest) -> JSONResponse:
    _require_admin(request)
    if not REVEAL_PASSWORD:
        raise HTTPException(status_code=404)
    if not hmac.compare_digest(body.password, REVEAL_PASSWORD):
        raise HTTPException(status_code=403, detail="Неверный пароль")
    for rec in st.get_recent(200):
        if abs(rec.ts - body.ts) < 0.001:
            return JSONResponse({"ip": rec.ip_full or rec.ip})
    raise HTTPException(status_code=404, detail="Запись не найдена")


@app.get("/admin/geo", response_class=HTMLResponse)
async def admin_geo(request: Request) -> HTMLResponse:
    _require_admin(request)
    countries  = st.get_top_countries(20)
    unique_ips = st.get_unique_ips(20)
    max_cnt    = countries[0][1] if countries else 1
    return templates.TemplateResponse(request, "geo.html", {
        "countries":  countries,
        "unique_ips": unique_ips,
        "max_cnt":    max_cnt,
    })


@app.get("/admin/security", response_class=HTMLResponse)
async def admin_security(request: Request) -> HTMLResponse:
    _require_admin(request)
    return templates.TemplateResponse(request, "security.html", {
        "blocked_ips":   st.get_blocked_ips(),
        "failed_logins": st.get_failed_logins(50),
        "rate_hits":     st.get_rate_hits(20),
        "alerts":        _build_alerts(),
        "failed_hour":   st.get_failed_logins_last_hour(),
        "rate_hits_hour":st.get_rate_hits_last_hour(),
        "threshold":     RATE_ALERT_THRESHOLD,
        "whitelist":     sorted(ADMIN_WHITELIST) if ADMIN_WHITELIST else [],
    })


def _validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


@app.post("/admin/block")
async def admin_block_ip(request: Request, ip: str = Form(...)) -> RedirectResponse:
    _require_admin(request)
    ip = ip.strip()
    if not _validate_ip(ip):
        raise HTTPException(status_code=400, detail="Неверный формат IP-адреса")
    st.block_ip(ip)
    log.warning("blocked_ip  ip=%s", ip)
    return RedirectResponse("/admin/security", status_code=302)


@app.post("/admin/unblock")
async def admin_unblock_ip(request: Request, ip: str = Form(...)) -> RedirectResponse:
    _require_admin(request)
    st.unblock_ip(ip.strip())
    log.info("unblocked_ip  ip=%s", ip)
    return RedirectResponse("/admin/security", status_code=302)


@app.post("/admin/clear")
async def admin_clear(request: Request) -> RedirectResponse:
    _require_admin(request)
    st.clear_stats()
    return RedirectResponse("/admin", status_code=302)


# ── Admin: сервер ─────────────────────────────────────────────────

@app.get("/admin/server", response_class=HTMLResponse)
async def admin_server(request: Request) -> HTMLResponse:
    _require_admin(request)
    proc = psutil.Process()
    vm   = psutil.virtual_memory()
    return templates.TemplateResponse(request, "server.html", {
        "cpu":        psutil.cpu_percent(interval=0.1),
        "ram_used":   round(vm.used  / 1024**2),
        "ram_total":  round(vm.total / 1024**2),
        "ram_pct":    vm.percent,
        "proc_ram":   round(proc.memory_info().rss / 1024**2, 1),
        "python":     platform.python_version(),
        "platform":   platform.system(),
        "uptime":     _uptime_str(st.get_uptime()),
        "argon_mem":  crypto.ARGON2_MEMORY // 1024,
        "argon_time": crypto.ARGON2_TIME,
        "argon_par":  crypto.ARGON2_PARALLEL,
    })


# ── Публичные служебные файлы ─────────────────────────────────────

@app.get("/robots.txt", response_class=PlainTextResponse, include_in_schema=False)
async def robots_txt() -> str:
    return (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /admin/\n"
        "Disallow: /generate\n"
        "Disallow: /generate/\n"
    )


@app.get("/.well-known/security.txt", response_class=PlainTextResponse, include_in_schema=False)
async def security_txt() -> str:
    return (
        f"Contact: {SECURITY_CONTACT}\n"
        "Preferred-Languages: ru, en\n"
        "Encryption: none\n"
        "Policy: Пожалуйста, сообщайте об уязвимостях ответственно.\n"
        "Hiring: false\n"
    )


# ── Error handlers ────────────────────────────────────────────────

@app.exception_handler(HTTPException)
async def http_handler(request: Request, exc: HTTPException) -> JSONResponse | RedirectResponse:
    if exc.status_code == 303:
        return RedirectResponse(exc.headers["Location"], status_code=302)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(Exception)
async def generic_handler(request: Request, exc: Exception) -> JSONResponse:
    log.error("unhandled  %s: %s", type(exc).__name__, exc)
    return JSONResponse(status_code=500, content={"detail": "Внутренняя ошибка сервера"})
