#!/usr/bin/env python3
"""HMAC-probe only feeds/check.txt (disappeared from open sources). Never the live pool.

One connection at a time, pause between hosts, cap about an hour — hundreds
fit without looking like a scan.
"""

from __future__ import annotations

import json
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import build_feeds as feeds
from faketls import CHECK_TIMEOUT_SEC, probe_hmac

GAP_SEC = 2.0
GAP_JITTER_SEC = 2.0
MAX_RUN_SEC = 50 * 60


def load_links(path: Path) -> dict[str, feeds.Proxy]:
    if not path.exists():
        return {}
    out: dict[str, feeds.Proxy] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        proxy = feeds.parse_line(line)
        if proxy is None or not feeds.accepted(proxy):
            continue
        out.setdefault(proxy.host_port, proxy)
    return out


def probe(due: dict[str, feeds.Proxy]) -> dict[str, bool]:
    results: dict[str, bool] = {}
    if not due:
        return results
    keys = list(due)
    random.shuffle(keys)
    started = time.monotonic()
    for index, key in enumerate(keys):
        if time.monotonic() - started >= MAX_RUN_SEC:
            left = len(keys) - index
            print(f"HMAC stop after {MAX_RUN_SEC}s, {left} wait until next run", file=sys.stderr)
            break
        if index:
            time.sleep(GAP_SEC + random.random() * GAP_JITTER_SEC)
        proxy = due[key]
        key_bytes = feeds.secret_key(proxy.secret)
        ok = bool(key_bytes) and probe_hmac(
            proxy.host, proxy.port, key_bytes, proxy.sni, CHECK_TIMEOUT_SEC
        )
        results[key] = ok
        print(f"HMAC {index + 1}/{len(keys)} {key} {'ok' if ok else 'no'}", file=sys.stderr)
    return results


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    feeds_dir = root / "feeds"
    ru_path = feeds_dir / "proxy-ru.txt"
    en_path = feeds_dir / "proxy-en.txt"
    check_path = feeds_dir / "check.txt"
    archive_path = feeds_dir / "archive.json"
    meta_path = feeds_dir / "meta.json"

    live = load_links(ru_path)
    live.update(load_links(en_path))
    queued = load_links(check_path)
    # Open-source lists are the user's job. Never HMAC a host still in ru/en.
    due = {key: proxy for key, proxy in queued.items() if key not in live}
    skipped = len(queued) - len(due)
    print(f"=== check.txt {len(queued)} (skip live {skipped}) ===", file=sys.stderr)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    results = probe(due)
    alive_n = sum(1 for ok in results.values() if ok)
    deferred = len(due) - len(results)
    print(f"HMAC alive {alive_n}/{len(results)} (deferred {deferred})", file=sys.stderr)

    ru = load_links(ru_path)
    en = load_links(en_path)
    archive = feeds.load_archive(archive_path)
    for key, ok in results.items():
        proxy = due[key]
        entry = archive.get(key) if isinstance(archive.get(key), dict) else {"link": proxy.link}
        entry["link"] = proxy.link
        entry["last_checked"] = stamp
        if ok:
            entry["last_ok"] = stamp
            if feeds.is_ru_sni(proxy.sni):
                ru.setdefault(key, proxy)
            else:
                en.setdefault(key, proxy)
        archive[key] = feeds.compact_entry(entry)

    feeds.write_list(ru_path, ru)
    feeds.write_list(en_path, en)
    archive_path.write_text(
        json.dumps(
            {"proxies": {key: feeds.compact_entry(archive[key]) for key in sorted(archive)}},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    meta = {}
    if meta_path.exists():
        try:
            loaded = json.loads(meta_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                meta = loaded
        except json.JSONDecodeError:
            meta = {}
    archive_stats = meta.get("archive") if isinstance(meta.get("archive"), dict) else {}
    archive_stats.update(
        {
            "probed": len(results),
            "alive": alive_n,
            "deferred": deferred,
            "skipped_live": skipped,
        }
    )
    meta["archive"] = archive_stats
    meta["ru"] = {"kept": len(ru)}
    meta["en"] = {"kept": len(en)}
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "probed": len(results),
                "alive": alive_n,
                "deferred": deferred,
                "ru": len(ru),
                "en": len(en),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
