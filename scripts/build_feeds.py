#!/usr/bin/env python3
"""Build pre-filtered RU / EU / ETC MTProto lists. Formal checks only — no TCP to proxies."""

from __future__ import annotations

import base64
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

USER_AGENT = "MTProSearch-feeds/1.0"
CONNECT_READ_TIMEOUT = 20
ALLOWED_PORTS = {443, 8443, 853}
HOST_OK = re.compile(r"^[A-Za-z0-9._~-]+$")
IPV6 = re.compile(r"^\[[0-9a-fA-F:]+]$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
TG_LINE = re.compile(r"tg://proxy\?|t\.me/proxy", re.I)

RU_WHITELIST = [
    "vk.com", "vk.ru", "userapi.com", "max.ru", "sberbank", "sber.ru", "sberonline", "online.sber",
    "tinkoff", "vtb.ru", "alfabank", "alfa-bank", "gosuslugi", "nalog.gov", "nalog.ru", "mos.ru",
    "yandex", "ya.ru", "dzen.ru", "mail.ru", "ok.ru", "rutube", "kinopoisk", "ozon.ru",
    "ozonusercontent", "wildberries", "wb.ru", "avito.ru", "hh.ru", "cian.ru", "microsoft.ru",
    "mts.ru", "beeline.ru", "megafon.ru", "1c.ru", "1c.com", "1c.", "petrovich", "x5.ru", "x5.",
    "game.ru", "dns-shop", "magnit.ru",
]
INTL_WHITELIST = [
    "steampowered", "cloudflare", "hetzner", "windowsupdate", "google.com", "microsoft.com",
    "yahoo", "deepseek", "yektanet", "bale.ai", "zoom.us",
]
WIDE_WHITELIST = RU_WHITELIST + INTL_WHITELIST
BLOCKED = ["instagram", "facebook", "twitter", "x.com", "bbc", "meduza", "linkedin", "torproject", "tor."]

AUTHOR_URLS = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGProto/main/proxies.txt",
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/protocols/mtproto.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
]

ETC_URLS = [
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
    "https://mtpro.xyz/api/?type=mtproto-ru",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no1.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no2.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no3.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no4.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no5.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no6.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no7.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no8.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no9.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no10.txt",
    "https://raw.githubusercontent.com/iwh3n/tg-proxy/refs/heads/main/proxys/All_Proxys.txt",
    "https://raw.githubusercontent.com/kubiknubika/my-tg-proxies/refs/heads/main/data/proxies.json",
    "https://raw.githubusercontent.com/shablin/mtproto-proxy/refs/heads/main/data/valid_proxy.json",
    "https://raw.githubusercontent.com/helptmoop/Free-Telegram-Proxies/refs/heads/main/global-iran-russia-proxies.txt",
    "https://raw.githubusercontent.com/helptmoop/Free-Telegram-Proxies/refs/heads/main/turkmenistan-global-iran-russia.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/MTProto.txt",
    "https://raw.githubusercontent.com/McDaived/ProxyDaiv/refs/heads/main/public/proxies.json",
    "https://raw.githubusercontent.com/klondike0x/mtp4tg-proxies/refs/heads/main/all_proxies.txt",
    "https://raw.githubusercontent.com/weltimistar777-crypto/MTProxy/refs/heads/main/proxy.txt",
    "https://raw.githubusercontent.com/Therealwh/MTPproxyLIST/refs/heads/main/verified/proxy_all_verified.txt",
    "https://raw.githubusercontent.com/Therealwh/MTPproxyLIST/refs/heads/main/verified/proxy_all_tme_verified.txt",
    "https://raw.githubusercontent.com/Airuop/MTProtoCollector/refs/heads/main/proxy/mtproto.json",
    "https://raw.githubusercontent.com/blog1703/tgonline/refs/heads/main/proxies.txt",
    "https://moonlunavpn.com/proxies.txt",
    "https://moonlunavpn.com/proxies.json",
]


def github(user: str, repo: str, branch: str, path: str) -> list[str]:
    return [
        f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}",
        f"https://cdn.jsdelivr.net/gh/{user}/{repo}@{branch}/{path}",
    ]


@dataclass
class Proxy:
    host: str
    port: int
    secret: str
    sni: str
    link: str

    @property
    def host_port(self) -> str:
        return f"{self.host}|{self.port}"


def fetch_url(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=CONNECT_READ_TIMEOUT) as resp:
        if resp.status != 200:
            raise OSError(f"HTTP {resp.status}")
        raw = resp.read()
    if not raw:
        raise OSError("empty body")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


def fetch_first(urls: list[str]) -> tuple[str | None, str | None, str | None]:
    last_err: str | None = None
    for url in urls:
        try:
            return fetch_url(url), url, None
        except Exception as exc:
            last_err = f"{type(exc).__name__}: {exc}"
            print(f"  skip {url}: {last_err}", file=sys.stderr)
    return None, None, last_err


def percent_decode(value: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(value):
        if value[i] == "%" and i + 2 < len(value):
            try:
                out.append(chr(int(value[i + 1 : i + 3], 16)))
                i += 3
                continue
            except ValueError:
                pass
        out.append(value[i])
        i += 1
    return "".join(out)


def decode_bytes(text: str) -> bytes | None:
    text = percent_decode(text.strip())
    if not text:
        return None
    if len(text) % 2 == 0 and HEX_RE.fullmatch(text):
        try:
            return bytes.fromhex(text)
        except ValueError:
            return None
    padded = text.replace("-", "+").replace("_", "/")
    pad = (-len(padded)) % 4
    padded += "=" * pad
    try:
        return base64.b64decode(padded)
    except Exception:
        return None


def decode_sni(raw: bytes) -> str | None:
    cleaned = bytes(b for b in raw if b != 0)
    if not cleaned or any(b < 33 or b > 126 for b in cleaned):
        return None
    sni = cleaned.decode("ascii").strip().lower()
    return sni if sni and "." in sni else None


def parse_secret(secret: str) -> str | None:
    data = decode_bytes(secret)
    if not data or len(data) < 18 or data[0] != 0xEE:
        return None
    key = data[1:17]
    if not key or all(b == 0 for b in key) or all(b == 0xAA for b in key):
        return None
    return decode_sni(data[17:])


def is_valid_host(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    return bool(HOST_OK.fullmatch(host) or IPV6.fullmatch(host))


def parse_line(line: str) -> Proxy | None:
    trimmed = line.strip()
    if not trimmed or trimmed.startswith("#"):
        return None
    if trimmed.startswith("tg://"):
        candidate = trimmed
    elif "t.me/proxy" in trimmed.lower():
        candidate = trimmed if trimmed.lower().startswith("http") else f"https://{trimmed}"
    else:
        return None
    parsed = urlparse(candidate)
    scheme = (parsed.scheme or "").lower()
    host_part = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    if scheme == "tg":
        if host_part != "proxy" and not candidate.lower().startswith("tg://proxy"):
            return None
    elif scheme in ("http", "https"):
        if "t.me" not in host_part or "proxy" not in path:
            return None
    else:
        return None
    query = parse_qs(parsed.query, keep_blank_values=True)
    server = percent_decode((query.get("server") or [""])[0]).strip().rstrip(".").lower()
    port_s = (query.get("port") or [""])[0].strip()
    secret = percent_decode((query.get("secret") or query.get("Secret") or [""])[0]).strip()
    if not is_valid_host(server) or not secret:
        return None
    try:
        port = int(port_s)
    except ValueError:
        return None
    if port not in ALLOWED_PORTS:
        return None
    sni = parse_secret(secret)
    if not sni:
        return None
    link = f"tg://proxy?server={server}&port={port}&secret={secret}"
    return Proxy(server, port, secret, sni, link)


def walk_json(obj: object) -> list[str]:
    found: list[str] = []
    if isinstance(obj, str):
        if TG_LINE.search(obj):
            found.append(obj)
        return found
    if isinstance(obj, dict):
        for key in ("secret", "Secret", "link", "url", "proxy"):
            val = obj.get(key)
            if isinstance(val, str):
                found.extend(walk_json(val))
        for val in obj.values():
            found.extend(walk_json(val))
        return found
    if isinstance(obj, list):
        for item in obj:
            found.extend(walk_json(item))
    return found


def extract_lines(body: str) -> list[str]:
    stripped = body.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(stripped)
            extra = walk_json(data)
            if extra:
                return extra
        except json.JSONDecodeError:
            pass
    return body.splitlines()


def accepted(proxy: Proxy, markers: list[str]) -> bool:
    sni = proxy.sni.lower()
    if any(m in sni for m in BLOCKED):
        return False
    return any(m in sni for m in markers)


def collect(urls_groups: list[list[str]], markers: list[str]) -> tuple[dict[str, Proxy], dict]:
    unique: dict[str, Proxy] = {}
    ok = 0
    fail = 0
    for urls in urls_groups:
        body, used, err = fetch_first(urls)
        if body is None:
            fail += 1
            print(f"FAIL {urls[0]} ({err})", file=sys.stderr)
            continue
        ok += 1
        print(f"OK   {used}", file=sys.stderr)
        for line in extract_lines(body):
            proxy = parse_line(line)
            if proxy is None or not accepted(proxy, markers):
                continue
            unique.setdefault(proxy.host_port, proxy)
    return unique, {"ok": ok, "fail": fail, "kept": len(unique)}


def write_list(path: Path, proxies: dict[str, Proxy]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [p.link for p in proxies.values()]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    feeds_dir = root / "feeds"

    ru_urls = [github("kort0881", "telegram-proxy-collector", "main", "proxy_ru.txt")] + [
        [u] for u in AUTHOR_URLS
    ]
    eu_urls = [github("kort0881", "telegram-proxy-collector", "main", "proxy_eu.txt")] + [
        [u] for u in AUTHOR_URLS
    ]
    etc_urls = [github("kort0881", "telegram-proxy-collector", "main", "proxy_all.txt")] + [
        [u] for u in ETC_URLS
    ]

    print("=== RU ===", file=sys.stderr)
    ru, ru_stats = collect(ru_urls, RU_WHITELIST)
    print("=== EU ===", file=sys.stderr)
    eu, eu_stats = collect(eu_urls, WIDE_WHITELIST)
    print("=== ETC ===", file=sys.stderr)
    etc_raw, etc_stats = collect(etc_urls, WIDE_WHITELIST)

    ru_eu_keys = set(ru) | set(eu)
    etc = {k: v for k, v in etc_raw.items() if k not in ru_eu_keys}
    subtracted = len(etc_raw) - len(etc)

    write_list(feeds_dir / "proxy-ru.txt", ru)
    write_list(feeds_dir / "proxy-eu.txt", eu)
    write_list(feeds_dir / "proxy-etc.txt", etc)

    meta = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ports": sorted(ALLOWED_PORTS),
        "dedupe": "host|port",
        "ru": ru_stats,
        "eu": eu_stats,
        "etc": {**etc_stats, "kept": len(etc), "subtracted_ru_eu": subtracted},
    }
    (feeds_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(meta, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
