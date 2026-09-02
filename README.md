# MTProSearch-feeds

Готовые списки MTProto-прокси для [Выручайки](https://github.com/ilexahub/MTProSearch).

GitHub Actions три раза в сутки (06:19, 14:19, 22:19 МСК) обходит публичные источники, разбирает `tg://proxy` / `t.me/proxy` (и встроенный список с [mtpro.xyz/mtproto](https://mtpro.xyz/mtproto)) и пишет два канонических файла. **Живость не проверяется** — HMAC и `req_pq` делает приложение с сети телефона.

## Файлы

| Файл | Что внутри |
|------|------------|
| [feeds/proxy-ru.txt](feeds/proxy-ru.txt) | FakeTLS, порты 443/8443/853, SNI из русского белого списка |
| [feeds/proxy-en.txt](feeds/proxy-en.txt) | то же формально, все остальные SNI (международные и серые) |
| [feeds/proxy-eu.txt](feeds/proxy-eu.txt) | копия EN — для старых APK |
| [feeds/proxy-etc.txt](feeds/proxy-etc.txt) | копия EN — для старых APK |
| [feeds/meta.json](feeds/meta.json) | время сборки и счётчики |

Источники сливаются в один пул: три корневых файла kort0881, `verified/proxy_us_verified.txt`, `verified/proxy_asia_verified.txt` и 32 сырых URL. География корта файл не выбирает — режет SNI.

## Формальные проверки (без обращения к прокси)

- валидная ссылка и FakeTLS-секрет с SNI
- порт **443**, **8443** или **853** (DNS-over-TLS)
- SNI не в чёрном списке
- уникальность по `host\|port` (первая подходящая строка)
- корзина: маркер `RU_WHITELIST` → RU, иначе EN (`beboo.ru` в RU)

Белая международная маска в сборщике **не** отсекает EN. Серое в EN режет приложение галкой **TrueMask**.

## Скачать

```
https://raw.githubusercontent.com/ilexahub/MTProSearch-feeds/main/feeds/proxy-ru.txt
https://cdn.jsdelivr.net/gh/ilexahub/MTProSearch-feeds@main/feeds/proxy-ru.txt
```

То же для `proxy-en.txt`. `proxy-eu.txt` и `proxy-etc.txt` — копии EN.

Собрать локально: `python scripts/build_feeds.py`.
