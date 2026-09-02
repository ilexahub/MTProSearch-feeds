# MTProSearch-feeds

Готовые списки MTProto-прокси для [Выручайки](https://github.com/ilexahub/MTProSearch).

GitHub Actions каждые 4 часа обходит публичные источники, разбирает `tg://proxy` / `t.me/proxy` и пишет три текстовых файла. **Живость не проверяется** — HMAC и `req_pq` делает приложение с сети телефона.

## Файлы

| Файл | Что внутри |
|------|------------|
| [feeds/proxy-ru.txt](feeds/proxy-ru.txt) | kort `proxy_ru` + 4 авторских списка, узкая RU-маска SNI |
| [feeds/proxy-eu.txt](feeds/proxy-eu.txt) | kort `proxy_eu` + 4 авторских, широкая маска |
| [feeds/proxy-etc.txt](feeds/proxy-etc.txt) | upstream kort + `proxy_all`, минус host:port из RU и EU |
| [feeds/meta.json](feeds/meta.json) | время сборки и счётчики |

## Формальные проверки (без обращения к прокси)

- валидная ссылка и FakeTLS-секрет с SNI
- порт **443**, **8443** или **853** (DNS-over-TLS)
- SNI не в чёрном списке; RU — узкий белый список, EU/Прочие — широкий
- уникальность по `host\|port` (первая подходящая строка)

## Скачать

```
https://raw.githubusercontent.com/ilexahub/MTProSearch-feeds/main/feeds/proxy-ru.txt
https://cdn.jsdelivr.net/gh/ilexahub/MTProSearch-feeds@main/feeds/proxy-ru.txt
```

То же для `proxy-eu.txt` и `proxy-etc.txt`.

Собрать локально: `python scripts/build_feeds.py`.
