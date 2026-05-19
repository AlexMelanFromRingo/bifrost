# bifrost

**SOCKS5-прокси + TUN-based VPN поверх overlay-сети
[norn-rs](https://github.com/AlexMelanFromRingo/norn-rs).** Каждый байт
прикладного трафика идёт по end-to-end шифрованному mesh-стриму между взаимно-
аутентифицированными пирами, со sliding-window ARQ — стрим переживает
multi-hop relay'и и потери пакетов.

> 🇬🇧 [English version](README.md)

---

## TL;DR

```text
                                ┌────────────────────────────────┐
                                │  bifrost-vpnd  exit mode       │
┌────────────────────┐          │  ┌───────────┐   ┌──────────┐  │
│  bifrost-vpnd      │          │  │ MeshMux   │──▶│ TUN+NAT  │──▶ Интернет
│   client mode      │   norn   │  │ + ARQ     │   │ MASQUER. │  │
│ ┌────┐ ┌────────┐  ├─────────▶│  └───────────┘   └──────────┘  │
│ │ TUN│─│MeshMux │  │  mesh    └────────────────────────────────┘
│ └────┘ └────────┘  │
└────────────────────┘
```

* **`bifrost-socks5d`** — SOCKS5 v5 прокси, который туннелирует каждый CONNECT
  через mesh-пира. Два режима (`client`, `exit`) в одном бинарнике.
* **`bifrost-vpnd`** — TUN-based VPN. Три режима (`mesh`, `exit`, `client`):
  exit-ноды выдают IPv4-лизы из приватной подсети и MASQUERAD'ят исходящий
  трафик; client-ноды получают по одному адресу и туннелируют весь (или
  выборочный) трафик через выбранный exit.

Оба используют **`bifrost-core`** — frame codec, MeshMux-демультиплексор,
MeshStream (AsyncRead + AsyncWrite поверх best-effort mesh datagram) и
sliding-window ARQ, который превращает ненадёжный datagram-канал в
надёжный байтовый поток.

---

## Статус

| Компонент                    | Состояние | Покрытие                                |
|------------------------------|-----------|-----------------------------------------|
| Frame codec v2               | ✅ done   | 7 roundtrip + reject-тестов             |
| Reliability layer (ARQ)      | ✅ done   | 13 unit-тестов, multi-hop docker e2e    |
| `bifrost-socks5d` client     | ✅ done   | local + docker e2e (1 MB, sha256)       |
| `bifrost-socks5d` exit       | ✅ done   | docker e2e с NetEm 30 ms / 1 % loss     |
| `bifrost-vpnd` mesh          | ✅ v0.1   | norn-rs `tun-support`                   |
| `bifrost-vpnd` exit (NAT)    | ✅ done   | docker e2e с NetEm; SHA-256 совпадает   |
| `bifrost-vpnd` client        | ✅ done   | docker e2e                              |
| IPv6 egress (NAT66)          | ✅ done   | 4 unit-теста; dual-stack EgressHello    |
| Karn/Partridge SRTT/RTTVAR   | ✅ done   | RFC 6298; 5 unit-тестов                 |
| Trust-weighted exit pick     | ✅ done   | `EgressPolicy::Auto`; 8 unit-тестов     |
| Multi-exit per stream        | ✅ done   | happy-eyeballs racing (race_exits=3)    |
| mDNS exit discovery          | ✅ done   | `_bifrost-exit._tcp.local.`             |
| Prometheus exporter          | ✅ done   | per-candidate weight/trust/RTT          |
| `bifrost-ctl` admin CLI      | ✅ done   | JSON RPC поверх UNIX-сокета             |
| Mobile build (Android/iOS)   | ⏸ потом  | только x86_64 + aarch64 Linux           |

---

## Архитектура

```
┌─────────────────────────────────────────────────────────────────────┐
│ Приложение                                                          │
│  (curl, браузер, ssh, и т.д.)                                       │
├─────────────────────────────────────────────────────────────────────┤
│ kernel TCP / SOCKS5-сокет / TUN-устройство                          │
├─────────────────────────────────────────────────────────────────────┤
│ bifrost-socks5d  │  bifrost-vpnd                                    │
│  (SOCKS5-сервер) │   (TUN reader + writer + egress NAT)             │
├─────────────────────────────────────────────────────────────────────┤
│ bifrost-core                                                        │
│  MeshStream  (AsyncRead + AsyncWrite, MTU-нарезанные Data-фреймы)   │
│  reliability (per-stream seq + cumulative ACK + retransmit tick)    │
│  MeshMux     (один read-loop демультиплексит (peer, sid) → channel) │
├─────────────────────────────────────────────────────────────────────┤
│ norn-rs PacketConn                                                  │
│  best-effort datagram канал, адресация 32-байтным ed25519 pub key   │
│  hop-by-hop ChaCha20-Poly1305 сессии, K=3 spanning-tree routing     │
└─────────────────────────────────────────────────────────────────────┘
```

`bifrost-core` намеренно тонкий: он не знает про SOCKS5 или VPN — просто
превращает lossy mesh-datagram в надёжный байтовый поток. Демоны живут поверх.

---

## Сборка

```sh
# Нужен Rust 1.85+ (norn-rs требует 1.88 из-за rcgen, в Docker-образе 1.90).
git clone https://github.com/AlexMelanFromRingo/bifrost
cd bifrost
cargo build --release --workspace
```

Бинари окажутся в `target/release/bifrost-socks5d` и
`target/release/bifrost-vpnd`. VPN-демону нужна фича `tun` (включена по умолч.):

```sh
cargo build --release -p bifrost-vpnd --features tun
```

Крейт path-зависит от `../norn-rs`, так что клонируй рядом:

```text
~/code/
├── norn-rs/      # https://github.com/AlexMelanFromRingo/norn-rs
└── bifrost/      # этот репозиторий
```

---

## Quick start: SOCKS5-стенд

Две ноды на одной машине — exit и client.

```sh
# 1. Сгенерируй exit config (private key, listen-адрес, и т.п.)
./target/release/bifrost-socks5d genconfig --exit > exit.toml
chmod 600 exit.toml

# 2. Подправь exit.toml: listen, admin_socket, tun_name (опционально).
# Запусти exit:
RUST_LOG=info ./target/release/bifrost-socks5d run -c exit.toml
```

В логе exit'а будет напечатан его pub_key (`our pub_key=…`). Скопируй его.

```sh
# 3. Сгенерируй client config и впиши туда pub_key exit'а.
./target/release/bifrost-socks5d genconfig > client.toml
chmod 600 client.toml

# В client.toml:
#   socks5_listen = "127.0.0.1:1080"
#   [node] peers = ["tcp://<exit-host>:9001"]
#   [egress]
#   mode = "exit"
#   exits = [
#     { pub_key = "<exit-pub-key-hex>", tag = "primary" },
#   ]

RUST_LOG=info ./target/release/bifrost-socks5d run -c client.toml
```

Проверь:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

CONNECT идёт end-to-end зашифрованным через mesh; на target'е виден исходящий
IP exit'а.

---

## Quick start: VPN-стенд

Три ноды — exit (делает NAT), client (получает лиз), и любой сервис который ты
хочешь достичь. **CAP_NET_ADMIN обязателен на обоих демонах** — нужны TUN'ы и
правка iptables; на bare metal запускай под root или дай бинарю capability:

```sh
sudo setcap cap_net_admin+ep ./target/release/bifrost-vpnd
```

```sh
# ── exit-сторона ──
./target/release/bifrost-vpnd genconfig --exit > exit.toml
chmod 600 exit.toml
# Дефолты: pool 10.55.0.0/24, egress_iface eth0, tun bifrost-eg0.
# Подправь, если egress-интерфейс не eth0.
RUST_LOG=info ./target/release/bifrost-vpnd run -c exit.toml
# Скопируй "our pub_key=..." из лога.

# ── client-сторона ──
./target/release/bifrost-vpnd genconfig --client > client.toml
chmod 600 client.toml
# В client.toml:
#   [node] peers = ["tcp://<exit-host>:9001"]
#   [egress] mode = "exit"
#            exits = [{ pub_key = "<exit-pub-key-hex>", tag = "main" }]
#   [client] install_default_route = true   # перехватить default-route
RUST_LOG=info ./target/release/bifrost-vpnd run -c client.toml
```

Client получает IPv4-лиз (дефолт `10.55.0.2`+) и default-route на TUN exit'а.
Каждый IPv4-пакет до destination'а вне egress-подсети заворачивается в
mesh-фрейм, отправляется на exit, пишется в exit's TUN, NAT'ится ядром и
вылетает из публичного интерфейса. Ответы идут обратно автоматически
(Linux conntrack делает обратный NAT; bifrost — обратную mesh-маршрутизацию
по выделенному адресу).

---

## Справочник конфигов

Все конфиги — TOML и **обязаны быть `chmod 600`** — там лежит ed25519
private key. Демоны откажутся загружать что-то более открытое.

Общие поля `[node]` (унаследованы от `norn-rs`):

| Поле                     | Смысл                                                  |
|--------------------------|--------------------------------------------------------|
| `private_key`            | 64 hex-символа = 32-байтный ed25519 секрет.            |
| `listen`                 | Список `tcp://addr:port` для приёма пиров.             |
| `peers`                  | Список `tcp://addr:port` для статических дайл.         |
| `tun_name`               | Имя mesh-TUN (напр. `"norn0"`); авто-отключается в exit/client режимах `bifrost-vpnd`. |
| `admin_socket`           | UNIX-сокет для admin-команд (`nornctl`-стиль).         |
| `multicast_enabled`      | UDP-multicast peer discovery в LAN.                    |
| `mdns_enabled`           | mDNS / DNS-SD peer discovery (`_norn._tcp.local`).     |
| `metrics_addr`           | `host:port` для Prometheus `/metrics`.                 |
| `min_peer_difficulty_bits` | Sybil-resistance threshold. 0 = выключено.          |

Специфика `bifrost-socks5d`:

```toml
mode = "client"                    # или "exit"
socks5_listen = "127.0.0.1:1080"   # только client mode

[egress]
mode = "exit"                      # "exit" — round-robin, "auto" —
                                   # взвешенный, "mesh" — без выхода
exits = [
  { pub_key = "abcd...32 bytes hex", tag = "primary" },
  { pub_key = "ef01...32 bytes hex", tag = "backup" },
]
```

**`auto`** использует формулу `Weight = Trust / (RTT_ms + Penalty_ms + 1)`
для выбора exit'а. Trust + RTT берутся из живой `PeerStats` norn-rs
(обновление каждые 10с). Провалившийся CONNECT накидывает штраф +1с
на 2 минуты — больной exit сам отступает в тень. Выбор НЕ
детерминированный: взвешенный random среди топ-5 — это размазывает
нагрузку и предотвращает «громящее стадо» к одному low-RTT exit'у.

Специфика `bifrost-vpnd` (exit mode):

```toml
mode = "exit"

[exit]
tun_name       = "bifrost-eg0"
pool_base      = "10.55.0.0"
pool_prefix    = 24                # /24 = 253 лиза
egress_iface   = "eth0"            # интерфейс под MASQUERADE
# Опциональный dual-stack: каждый клиент получает парные v4+v6 лизы.
# Хост-индекс 2 в /24 соответствует хост-индексу 2 в /64 → у одного
# клиента совпадающие адреса в обоих стеках. Без v6_pool_base — v4-only.
# v6_pool_base   = "fd55:0:0:1::"
# v6_pool_prefix = 64
```

Специфика `bifrost-vpnd` (client mode):

```toml
mode = "client"

[client]
tun_name              = "bifrost-eg0"
install_default_route = true        # выключено по умолчанию; opt-in
```

См. `examples/*.toml` для готовых шаблонов.

---

## Docker-стенды

Два end-to-end harness'а лежат в `tests/docker/`:

```sh
# SOCKS5 e2e: 3 сервиса (exit + client + httpd target), NetEm 30 ms±5 ms /
# 1 % loss на каждый контейнер, 1 MiB download + кросс-проверка SHA-256.
bash tests/docker/run.sh

# VPN e2e: тот же 3-сервисный топология, exit запускает egress TUN + MASQUERADE,
# client получает IPv4-лиз, curl запускается ВНУТРИ client-контейнера и скрипт
# проверяет что target видит eth0 IP EXIT'а (= NAT доказан).
bash tests/docker/run-vpn.sh
```

Оба скрипта обрабатывают two-phase startup (сначала exit, скрапим pub_key,
потом client/target с env-проводкой) и гасят кластер на выходе. Поставь
`BIFROST_KEEP=1` чтобы оставить кластер живым для инспекции:

```sh
BIFROST_KEEP=1 bash tests/docker/run-vpn.sh
docker logs bifrost-vpn-client
docker exec bifrost-vpn-client ip route
# Когда нагляделся:
cd tests/docker && BIFROST_EXIT_PUBKEY=00 docker compose -f docker-compose.vpn.yml down -v
```

Последние замеры (debug-кластер, x86_64):

| Тест                                   | Время  | Скорость   |
|----------------------------------------|--------|------------|
| 1 MiB SOCKS5, без NetEm (loopback)     | 0.17 s | ~24 MB/s   |
| 1 MiB SOCKS5, NetEm 30 ms±5 ms / 1 %   | 3.0 s  | ~340 KB/s  |
| 256 KiB VPN, NetEm 30 ms±5 ms / 1 %    | ~1 s   | ~250 KB/s  |

---

## Wire protocol (v2)

```
┌───────┬───────┬──────────────┬────────────────────────────────┐
│  ver  │ kind  │  stream_id   │     body (variable)            │
│  1 B  │  1 B  │ 4 B big-end. │                                │
└───────┴───────┴──────────────┴────────────────────────────────┘
```

| Kind | Hex  | Body                                                                |
|------|------|---------------------------------------------------------------------|
| Open | 0x01 | ATYP (0x01 v4 / 0x03 domain / 0x04 v6 / 0xfe egress) + addr + port  |
| Data | 0x02 | `seq` (4 B) + payload                                                |
| Close| 0x03 | `seq` (4 B) — позиция FIN-байта                                     |
| Reset| 0x04 | 1-байт код                                                          |
| OpenAck | 0x05 | 1-байт reply code (зеркалит SOCKS5 REP)                         |
| Ack  | 0x06 | `ack` (4 B) + `win` (4 B) — cumulative ACK + advertised window      |

Reliability-слой трактует Data и Close как единое sequence space (Close
занимает один виртуальный байт), поэтому peer ACK строго после
`local_close_seq` гарантирует, что FIN дошёл. Потерянные Close'ы
ретрансмитятся с тем же RTO-doubling back-off что и Data — никаких
тихо-полу-открытых стримов.

---

## Модель безопасности

Что протокол **защищает**:

* **End-to-end confidentiality + integrity** между двумя концами mesh-стрима.
  Каждый байт шифруется ChaCha20-Poly1305 сессиями norn-rs; relay'и по пути
  видят только ciphertext-with-routing-tag, не plaintext.
* **Аутентификация пиров**: каждый mesh-хоп — authenticated handshake,
  привязанный к ed25519 pub_key пира. Подделанные пиры детектятся на
  setup'е, не после утечки данных.
* **Replay & reorder resistance** на mesh-слое (norn-rs сессии нумеруют
  пакеты) и на bifrost-слое (per-stream seq + cumulative ACK отбрасывает
  дубликаты и собирает фреймы в порядке).

Что протокол **не защищает**:

* **Traffic analysis**. Размеры фреймов MTU-pad'ятся внутри norn-rs, но
  форма HTTP-запроса всё ещё видна на локальном проводе. Для анонимности
  бери Tor.
* **Malicious exits**. Оператор exit'а видит расшифрованный application-
  трафик на выходе (это SOCKS5 / NAT'нутый пакет, не чёрный ящик). Выбирай
  exit'ы которым доверяешь; пользуйся TLS end-to-end (HTTPS), чтобы даже
  враждебный exit видел только ciphertext.
* **DoS-стойкость под флудом**. Bifrost унаследовал per-IP handshake throttle
  от norn-rs, но своего не добавляет. Заваленный exit будет аккуратно ронять
  CONNECT'ы, но не отрежет атакующего.

---

## Операционные инструменты

* **`bifrost-ctl`** — admin CLI поверх UNIX-сокета демона
  (`[bifrost].admin_socket` в конфиге). Команды:
  `status`, `exits`, `peers`, `penalty <pk>`, `reset-penalty <pk>`,
  `reset-all-penalties`, `reload`. По умолчанию — таблицы;
  `--json` отдаёт сырой envelope для скриптов. Дефолтный
  socket: `/tmp/bifrost-socks5d-ctl.sock`.

  **`bifrost-ctl reload`** перечитывает конфиг с диска и
  hot-применяет reloadable поля: дельта `[egress].exits`
  (добавление/удаление по pub_key, mDNS-открытые сохраняются),
  плюс `race_exits` и `race_timeout_ms`. Смена режима,
  listen-адресов и ротация ключей всё ещё требуют рестарта.

* **Prometheus экспортер** — `[bifrost].metrics_addr` (например
  `127.0.0.1:9099`) отдаёт per-candidate gauges:
  `bifrost_exit_{weight,trust,rtt_ms,penalty_ms,stats_known}` с
  лейблами `pub_key`/`tag`. Loopback настойчиво рекомендуется
  (pub_keys в лейблах = утечка).

* **mDNS-обнаружение** — exit'ы рекламируют
  `_bifrost-exit._tcp.local.` с `pk=<64hex>` в TXT; Auto-клиенты
  browse'ят и автоматически добавляют в пул (тег `mDNS`). Eviction
  при `ServiceRemoved`. Управление: `[bifrost].mdns_discovery`.

* **Happy-eyeballs racing** — каждый CONNECT гоняет OPEN-фрейм
  параллельно по `race_exits` лучшим exit'ам и берёт первого
  ответившего успехом. `race_exits = 1` отключает racing;
  `race_timeout_ms` ограничивает гонку.

## Производительность

Реальный WAN-замер, 2026-05-18 / 19, single-stream throughput с
домашнего UA WSL2-клиента до Oracle Cloud NL exit (~55 мс RTT,
~50 Mbit/s aggregate TCP cap — подтверждено `iperf3 -P 8`):

| путь | iter 1 (стартовый) | iter 10 (сейчас) | raw TCP |
|---|---:|---:|---:|
| SOCKS5 single-stream | 33 Mbit/s | **45 Mbit/s** (92% от raw TCP) | 48 Mbit/s |
| L3 VPN single-stream | 0.9 Mbit/s + 25 MB timeouts | **40 Mbit/s** (80% от raw TCP) | 48 Mbit/s |
| VPN p50 latency | 575 мс | **151 мс** | — |
| VPN sustained 20 с | 3 chunks | **43 chunks** | — |

Десять итераций подняли L3 VPN с «еле живой» до ~80% raw TCP на
той же линии. Полный путь с бенчмарками и trade-off'ами на каждой
итерации — в [HISTORY.md](HISTORY.md). Текущий потолок — сама WAN,
не bifrost; графики и сырые данные —
[real-WAN-репорт](https://github.com/AlexMelanFromRingo/bifrost/tree/master/bifrost-wan-test-2026-05-18).

Главные конфигурируемые ручки под throughput:

* **`MAX_PARALLEL_LINKS_PER_PEER`** в `norn-rs::router` (по умолчанию 8).
  Перечисли тот же `tcp://host:port` URI N раз в `[node].peers` —
  норн откроет N параллельных TCP/QUIC к этому peer'у. Каждое со
  своим CUBIC cwnd; round-robin в `send_to_peer` агрегирует. Самый
  большой win на per-packet-pipeline нагрузках (L3 VPN).
* **`MAX_RX_BUF_CAP`** в `bifrost-core::reliability` (по умолчанию 32 MB).
  Окно reliability на поток — автотюнится с 256 KB к 2 × BDP.
  Затрагивает SOCKS5 / stream-трафик; `Frame::Datagram` fast-path
  у `bifrost-vpnd` его минует.
* **Coalescing-окно** в `bifrost-vpnd::egress`
  (`COALESCE_DRAIN_TIMEOUT = 500 µs`,
  `MAX_COALESCED_PACKETS = 16`). Батчит IP-пакеты в одну
  Datagram-фрейм для L3 VPN.

## Roadmap

Полный список следующих шагов — в [ROADMAP.md](ROADMAP.md)
(kernel-side GSO/GRO на TUN, sendmmsg-батчинг, multi-core
crypto-pool, Android NDK).

## Известные ограничения

* Bifrost-специфичный Prometheus listener в момент binding'а на
  холодном старте демона может изредка гонять норн-handshake под
  нагрузкой (видно в свежем docker testbed'е). Docker compose в
  `tests/docker/run.sh` поэтому по умолчанию выставляет
  `BIFROST_DISABLE_METRICS=1`; в проде встречается реже,
  workaround — включать endpoint после того, как в логах появится
  `connected to peer` (через `bifrost-ctl` после установления
  первой сессии).

---

## Лицензия

MIT. См. [LICENSE](LICENSE).
