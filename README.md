# v2rayNG WL

Android-клиент V2Ray/Xray на базе [v2rayNG](https://github.com/2dust/v2rayNG) с инструментами для проверки профилей и удобной работы с подписками.

[![API](https://img.shields.io/badge/API-24%2B-yellow.svg)](https://developer.android.com/about/versions/lollipop)
![Release](https://img.shields.io/github/v/release/elizqmill/v2rayNG?include_prereleases)

---

## Скачать

Готовые подписанные APK — в разделе [Releases](https://github.com/elizqmill/v2rayNG/releases).

| Файл | Для чего |
|---|---|
| `arm64-v8a` | большинство современных телефонов |
| `armeabi-v7a` | старые устройства |
| `x86_64` / `x86` | эмуляторы, планшеты на Intel |
| `universal` | все архитектуры сразу, крупнее по размеру |

---

## Возможности

Всё из оригинального v2rayNG (VLESS / VMess / Trojan / Shadowsocks / SOCKS / HTTP / WireGuard / Hysteria2, маршрутизация, разделение по приложениям, тёмная тема, виджет, быстрый переключатель) плюс:

### 🔍 Поиск стабильных профилей

Главный экран → меню ⋮ → **«Поиск стабильных профилей (проверка БС)»**.

Зачем: у белых списков 2-го типа пингуется всё подряд, но скорость порезана до десятков КБ/с. Проверка задержки при этом бессмысленна.

Два этапа за один запуск:

1. **Реальный пинг** каждого профиля через временное ядро (не ICMP/TCP-пинг, а полноценный HTTP-замер). Параллельно, число потоков берётся из настройки «Параллельная проверка задержки». Профили, у которых задержка уже известна, заново не проверяются.
2. **Замер скорости** — для каждого живого профиля поднимается отдельное ядро и качается тестовый файл с Cloudflare (есть зеркала-фолбэки). Одновременно живут максимум 8 ядер, чтобы не ронять активный VPN.

Что вы увидите после проверки:

| Пример | Цвет | Значение |
|---|---|---|
| `3.4 MB/s` | 🟢 | скорость ≥ ~1 МБ/с |
| `420 KB/s` | 🟠 | 200 КБ/с…1 МБ/с — пользоваться можно |
| `18 KB/s` / `0 KB/s` | 🔴 | шейпинг белого списка |

- Пинг при замере скорости **не перезаписывается** — зелёные цифры остаются цифрами.
- У проверенного профиля всегда есть числовая скорость, прочерков нет.
- Меню ⋮ → **«Сортировать по скорости»**: быстрые сверху, непроверенные и мёртвые внизу.
- Прогресс с этапами: `ping 45/90`, затем `speed 12/90`.

Настройки (Настройки → «Поиск по белым спискам»):

| Параметр | По умолчанию | Диапазон |
|---|---|---|
| Таймаут TCP-пинга, мс | 1000 | 300–10000 |
| Размер тестового файла, МБ | 10 | 1–100 |
| Таймаут скачивания, с | 10 | 3–120 |
| Прогонов на профиль | 2 | 1–10 |

Логика вердикта простая: не успел скачать файл целиком за таймаут во всех прогонах — линия с шейпингом.

### 🔄 Конвертеры подписок

В настройках каждой подписки два независимых тумблера (по умолчанию выключены):

**Base64 → текст**
Тело подписки приходит как base64-блоб? При обновлении оно декодируется в обычный список ссылок. Работает и для цельного блоба, и для построчного; обычный текст не трогается.

**Кастомные в ссылки**
Подписка отдаёт JSON вместо ссылок? Профили конвертируются в обычные `vless://` / `vmess://` / `ss://` / `trojan://` / `hysteria2://` / `tuic://` / `socks://` / `http://` и редактируются штатным интерфейсом, а не руками в JSON.

Поддерживаемые форматы входа:
- xray-outbounds (`outbounds[].settings.vnext/servers`, streamSettings, Reality)
- sing-box outbounds (`type/server/server_port/tls.reality/transport`)
- магазинные полные конфиги построчно, включая Hysteria v1/v2 (`protocol:"hysteria"` + `hysteriaSettings`)
- вперемешку: ссылки и JSON в одном теле

Несконвертируемое не выбрасывается — остаётся кастомным профилем.

---

## Сборка из исходников

### Требования

- JDK 17+
- Android SDK: platform `android-36+`, build-tools, platform-tools
- Android NDK (путь в переменной окружения `NDK_HOME`) — нужен для нативной части
- Git

### Шаги

```bash
# 1. Клонировать вместе с сабмодулями
git clone --recurse-submodules https://github.com/elizqmill/v2rayNG.git
cd v2rayNG

# 2. Ядро libv2ray: взять свежий AAR из релизов апстрима
#    https://github.com/2dust/AndroidLibXrayLite/releases
mkdir -p V2rayNG/app/libs
curl -L -o V2rayNG/app/libs/libv2ray.aar \
  "https://github.com/2dust/AndroidLibXrayLite/releases/latest/download/libv2ray.aar"

# 3. Нативный hev-tunnel (нужен NDK_HOME)
bash compile-hevtun.sh
cp -r libs V2rayNG/app/

# 4. Собрать
cd V2rayNG
./gradlew assembleFdroidRelease      # или assemblePlaystoreRelease
# обе раздачи сразу:
./gradlew assembleRelease
```

Готовые APK: `V2rayNG/app/build/outputs/apk/<flavor>/release/`.

### Подпись

Release-сборки подписываются параметрами Gradle:

```bash
./gradlew assemblePlaystoreRelease \
  -Pandroid.injected.signing.store.file=/path/to/keystore.jks \
  -Pandroid.injected.signing.store.password=STORE_PASS \
  -Pandroid.injected.signing.key.alias=KEY_ALIAS \
  -Pandroid.injected.signing.key.password=KEY_PASS
```

Debug-варианты собираются без подписи: `./gradlew assembleFdroidDebug`.

### IDE

Просто откройте каталог `V2rayNG` в Android Studio (после шагов 1–3) и нажмите Run.

---

## Кредиты

- [2dust/v2rayNG](https://github.com/2dust/v2rayNG) — базовый клиент
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) · [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core) — ядра
- [WINGS-N/WINGSV](https://github.com/WINGS-N/WINGSV) — подход автопоиска с замером скорости
- [Omegaplexx/Happwner](https://github.com/Omegaplexx/Happwner) — конвертер содержимого подписок
