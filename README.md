# MINT Starter Kit — Infrastruktur Hybrid

> **v9.2.6 — perbaikan bug + Grafana ditulis ulang untuk PERBANDINGAN**
> **Grafana**: dashboard baru `MINT - Traffic Monitor (perbandingan)` memakai
> metrik 15 dtk yang SAMA dengan halaman *Grafik PPS* di web, sehingga angka
> keduanya bisa dibandingkan langsung. Isi: ringkasan status, tabel
> perbandingan node (sekarang vs baseline normal vs threshold), bar rasio
> terhadap threshold (100% = batas ALERT), grafik PPS / B/s / ukuran paket,
> distribusi trafik, total B/s *sekarang vs 5 menit lalu* (pembanding bisa
> diganti), panel per-node dengan garis threshold, timeline skenario S1–S4,
> dan riwayat ALERT. Refresh 2 dtk.
> **Bug diperbaiki**: (1) data Influx dulu hanya ditulis saat node mengirim →
> garis Grafana patah-patah/"ngestak"; kini 1 titik/detik/node (termasuk
> node diam & node terdaftar yang belum kirim); (2) tag `mac` berganti
> "-"/MAC asli → satu node terpecah jadi 2 seri; tag dihapus, diganti `node`;
> (3) hitungan Event ALERT di Grafana kegandaan 3x; (4) penulisan Influx
> sinkron di thread deteksi → kini antrean + thread latar; (5) Telegram
> sinkron (timeout 5 dtk) membekukan analyzer saat internet putus → kini
> non-blocking; (6) node yang berhenti mengirim tidak pernah keluar dari
> ALERT → `engine.tick()` tiap detik; status node diam tidak lagi membeku;
> (7) `pps_15s` melonjak palsu setelah jeda panjang (pembagi salah);
> (8) cooldown alert dulu tidak berfungsi → kini event cooldown tidak
> dikirim ke Telegram; (9) PCAP sesi gagal (`struct.error`) untuk payload
> S3 > 64 KB → dipecah per segmen TCP 1400 B; (10) skenario S3 dari
> `attack_sim.py` menyerang `iot/suhu` padahal seharusnya `iot/kamera`;
> (11) tombol STOP serangan tertimpa status "dihentikan/gagal".
> **Setelah upgrade**: data lama di InfluxDB tidak punya tag `node`, jadi
> tidak tampil di dashboard baru. Bila ingin bersih: `docker compose down -v`
> lalu `mulai_stack.bat`.
> **Keamanan**: `.env` berisi token bot Telegram — ganti (revoke) token itu
> lewat @BotFather sebelum zip ini dibagikan.

Starter kit implementasi proyek **MINT (MQTT Injection & Network Traffic-analyzer)**
sesuai *Spesifikasi Teknis Sistem MINT* (dokumen pendamping proposal).

> **v9.2.5 — perbaikan menyeluruh hasil uji v9.2.1** (semua bug lapangan):
> **(1) PCAP sesi tidak pernah kosong lagi** — perekam sesi baru (menu
> **Sesi & Dataset**) murni Python tanpa tshark/Wireshark: setiap pesan MQTT
> yang sampai ke broker ditulis sebagai paket Ethernet/IP/TCP/MQTT-PUBLISH
> yang valid (checksum lengkap, MAC & IP node asli dari `devices.json`) ke
> `captures/<label>.pcap`, plus dataset CSV window 1 detik ber-skema sama
> dengan `dataset_BASE.csv`. Perekam lama bergantung tshark + hak admin +
> interface yang benar sehingga menghasilkan file kosong. **(2) peringatan
> serangan tampil di SEMUA halaman** (fix "S4 multiburst: nilai berubah tapi
> tidak ada warning") — toast merah + bunyi lembut begitu alert baru muncul
> di halaman mana pun, lencana jumlah ALERT di sidebar, dan halaman Serangan
> kini punya panel **Deteksi Realtime** (banner + status per node + log
> event — dulu halaman itu tidak menampilkan indikator deteksi sama sekali).
> **(3) grafik responsif 15 detik** (fix "payload size tidak realtime") —
> metrik bergulir `pps_15s`/`bps_15s`/`avg_pkt_size_15s`: lonjakan S1/S3/S4
> terlihat dalam 1–2 detik (dulu menunggu rata-rata 2 menit ~30 detik);
> kartu "Ukuran payload rata-rata" baru di Beranda + garis threshold kini di
> TIGA panel grafik (PPS, B/s, ukuran paket); doughnut distribusi memakai
> `bps_15s` sehingga tidak melompat liar antar detik + persentase per node.
> **(4) threshold LIVE dari menu Pengaturan** — ubah nilai per node per
> metrik, tersimpan ke `thresholds.json` dan langsung berlaku tanpa restart:
> status node, garis threshold grafik, dan warna kartu node ikut berubah
> dalam 1–2 detik (episode ALERT berjalan tidak di-reset); ada juga tombol
> kalibrasi ulang dari `dataset_BASE.csv`. **(5) firmware Node 3 (kamera)
> jauh lebih cepat** — buffer ganda (`fb_count=2` + `CAMERA_GRAB_LATEST`,
> tidak lagi menunggu expose frame baru), foto VGA ~8–16 KB (separuh ukuran
> lama), socket timeout 4 dtk + publish diulang 1x bila gagal. **(6) bug
> lama dibetulkan**: ping node kini PARALEL (satu node mati tidak lagi
> membuat node lain ikut tampak offline — anti-flapping), trafik IP
> broker/server sendiri disaring dari daftar node (server tidak lagi muncul
> sebagai node "TAK TERDAFTAR"). **(7) halaman baru**: **Log Sistem**
> (gabungan log internal + event deteksi + riwayat serangan/sesi, saringan +
> unduh `.txt`) dan **Pengaturan** (threshold + akun + Telegram); UI sidebar
> bergrup Utama/Monitoring/Pengujian/Sistem; `CARA_JALANIN.md` dihapus
> (panduan cukup README + menu Bantuan); Grafana dashboard ditandai v9.2.5.
>
> **v9.1 — perbaikan dua masalah uji lapangan**:
> **(1) analyzer tidak lagi mati karena `PermissionError: [WinError 5]`** —
> penulisan `run/state.json` kini tahan kunci: `os.replace()` dicoba 6x
> (jeda 50 ms), gagal maka ditulis langsung ke berkas tujuan, masih terkunci
> maka penulisan detik itu dilewati dengan peringatan (dashboard membaca
> state.json tiap detik; di Windows tabrakan baca-tulis membuat
> `jalankan_analyzer.bat` crash — sekarang tidak lagi). Berlaku juga untuk
> `alerts.jsonl`. **(2) firmware 4 node diperkuat agar node 2/3/4 kembali
> online**: IP statis kini persis `devices.json` (.102–.105), kredensial WiFi
> satu sumber (node 3/4 sebelumnya memakai SSID berbeda), **fallback DHCP**
> bila IP statis bentrok, `WiFi.setSleep(false)` agar MQTT tidak
> tersendat-sendat, **LWT retained + diagnostik rc berbahasa jelas**,
> **self-healing** (WiFi putus >60 dtk → sambung ulang; MQTT mati >5 menit →
> ESP restart sendiri), heartbeat node 2 tetap kirim walau sensor gagal,
> kamera node 3 tidak fatal saat init gagal + re-init otomatis, sensor node 4
> di-coba ulang otomatis, dan interval semua node 10 dtk selaras threshold.
>
> **v9.0 — MERGER FINAL (v8.3 + oprek anggota, jaringan satu sumber kebenaran)**:
> **grafik halus “MINTS”** di semua halaman (kurva spline kubik monoton tanpa
> overshoot, glow lembut, area gradient, titik ujung berdenyut, titik baru
> tumbuh mulus, sumbu-X mengalir ala Grafana — layout kartu tidak berubah);
> **kendali Telegram dari web** — Token Bot & Chat ID kini diisi langsung di
> modal Pengaturan (admin saja, CSRF, token ter-mask), tersimpan ke `.env` dan
> langsung aktif tanpa restart; **jaringan dirapikan tanpa celah**: broker =
> `192.168.7.101` (laptop server), node ESP32-1..4 = `192.168.7.102–105`
> berurutan (tidak ada lagi bentrok IP node-vs-server; semua firmware,
> simulator, attack_sim, bantuan, dan README disamakan); **S3 payload
> >200 KB** (default acak 200–300 KB, maks 512) sesuai Tabel 3.6.2 proposal,
> target default `iot/kamera`; **interval baseline semua node 10 dtk** selaras
> kalibrasi threshold BASE; **paket makin lengkap**: firmware 4 node ESP32
> siap-upload, simulator sensor natural (`feeder_sensor.py`), broker Python
> tanpa Docker (`broker_amqtt.py`), alat uji performa (`uji_performa.py`) +
> 3 CSV hasil uji, dataset uji nyata BASE/S1–S4, 13 screenshot bukti end-to-end,
> dan panduan lengkap `README.md` + menu Bantuan di dashboard.
>
> **v8.3** — grafik PPS jadi warga kelas satu:
> **menu “Grafana” DIGANTI “Grafik PPS”** (`/pps`): 4 panel realtime —
> PPS per perangkat (dengan garis threshold putus + nilai terkini di ujung
> garis), Byte/s, doughnut distribusi trafik, dan rata-rata ukuran paket —
> plus tabel node (IP, topik, total pesan); **refresh 1 detik** seperti
> referensi, tanpa iframe/CDN sehingga tetap jalan di lab tanpa internet
> (rute `/grafana` lama dialihkan otomatis ke `/pps`); **Beranda** kartu node
> kini menampilkan **angka PPS besar** + nilai sensor live + **IP & topik**
> tiap node (info IP yang sempat hilang), grafik PPS live diperjelas dengan
> legenda bernilai live, garis threshold, dan label puncak; **S3 payload
> diperluas hingga >200 KB** (keterangan, ukuran acak default 200–300 KB,
> contoh bantuan) sesuai Tabel 3.6.2 proposal; **riwayat serangan memakai jam server
> lengkap dengan tanggal** (`start_str`) — bukan lagi jam browser tanpa
> tanggal, konsisten dengan menu Anomali & Dataset.
>
> **v8.2** — perbaikan hasil uji lapangan:
> **metrik tshark + MQTT kini DIGABUNG** (sebelumnya saling meniadakan —
> serangan dari menu Serangan tidak terlihat karena paket server→broker tidak
> lewat interface fisik; kini pasti terlihat di grafik Beranda, banner, dan
> menu Anomali), **heartbeat state** (banner Beranda tidak lagi macet
> “MENUNGGU DATA” padahal node terhubung), **menu Grafana ikut host**
> (iframe memakai host yang dipakai membuka dashboard — tidak lagi
> “localhost refused to connect” saat dibuka dari laptop lain), **target
> serangan berupa dropdown semua node**, **kolom “serangan” di dataset
> anomali** (integrasi menu Serangan ↔ Anomali; window saat uji berjalan
> ditandai S1–S4), dan **waktu replay demo digeser ke jam server** sehingga
> menu Anomali selalu realtime.
>
> **v8.1** — versi “maksimal, minim revisi”: **analyzer kini terintegrasi di
> dalam dashboard** (cukup `jalankan_dashboard.bat` — PPS/BPS langsung terbaca,
> pakai tshark bila ada, **fallback MQTT** bila Wireshark belum terpasang),
> menu **Serangan** untuk menjalankan S1–S4 langsung dari web (pengganti
> mengetik di Serial Monitor/CMD) + **Tes Sistem** satu klik, menu **Grafana**
> yang menampilkan grafik Grafana ter-embed di dashboard, dan notifikasi
> Telegram **PPS+BPS digabung menjadi satu pesan**.
>
> **v8** — pembaruan dari hasil uji lapangan: metrik kartu node kini memakai
> **rata-rata bergerak 2 menit** (`pps_2m`/`bps_2m`, tidak lagi berkedip 0),
> foto kamera **anti-flicker** + **riwayat 10 foto terakhir**, konfigurasi
> terpusat di **`.env`**, interval node **realtime** (3/2/2 dtk; kamera 10 dtk),
> panel **Grafana diperbaiki** agar cocok dengan skema data analyzer, dan
> simulator serangan **`scripts/attack_sim.py`** (S1-S4) siap dipakai.

Versi v6 menggabungkan kekuatan dua proyek: mesin deteksi adaptif MINT
(threshold median+MAD, aturan 2-of-3) dan keamanan dashboard ala
*IoT Traffic Monitor* (CSRF, anti brute-force, ganti sandi), plus logo MINT,
grafik PPS live, dan panel **Pemakaian Server**.

## Isi Paket

```
mint-starter/
├── cek_lingkungan.bat           # 1 klik: cek Python/tshark/Docker/port
├── mulai_stack.bat              # 1 klik: docker compose up -d
├── jalankan_analyzer.bat        # 1 klik: deteksi real-time (tanya interface + InfluxDB)
├── jalankan_dashboard.bat       # 1 klik: web dashboard :5000
├── jalankan_demo.bat            # 1 klik: demo replay serangan + dashboard
├── .env                         # KONFIGURASI TERPUSAT: token Telegram + InfluxDB
├── docker-compose.yml           # Mosquitto + InfluxDB + Grafana (Docker)
├── devices.json                # REGISTRY: broker 192.168.7.101 + identitas 4 node
├── mosquitto/
│   └── mosquitto.conf          # Konfigurasi broker (payload 128 MB utk S3)
├── grafana/
│   └── provisioning/
│       ├── datasources/
│       │   └── influxdb.yml    # Datasource InfluxDB auto-provisioned
│       └── dashboards/
│           ├── dashboards.yml
│           └── mint-traffic.json   # Dashboard awal (PPS, BPS, status)
├── analyzer/                   # MODUL DETEKSI (threshold, real-time)
│   ├── detection.py            #   Mesin aturan: 2-of-3, override 5x, recovery
│   ├── tshark_io.py            #   Jembatan ke tshark + agregasi window 1 detik
│   ├── pcap_analyzer.py        #   pcap -> CSV metrik (BASE & dataset berlabel)
│   ├── threshold_baseline.py   #   CSV BASE -> thresholds.json (median+3x1,4826xMAD)
│   ├── live_analyzer.py        #   Analyzer real-time (live / pcap / replay)
│   └── notifier.py             #   Notifikasi Telegram (opsional)
├── dashboard/
│   ├── app.py                  # Web dashboard Flask :5000 — 10 halaman + API
│   │                           #   + ANALYZER TERINTEGRASI (tshark+MQTT digabung)
│   │                           #   + kendali serangan S1-S4 dari web (v8.1)
│   │                           #   + PEREKAM SESI PCAP/CSV mandiri (v9.2.5)
│   │                           #   + API threshold live / log sistem (v9.2.5)
│   ├── add_user.py             # Kelola pengguna dashboard
│   ├── users.json              # Pengguna + password hash
│   ├── static/
│   │   ├── logo.jpg            # Logo MINT (halaman login)
│   │   ├── logo-small.jpg      # Logo MINT (navbar)
│   │   └── favicon.png
│   └── templates/
│       ├── base.html           # Layout bersama: SIDEBAR bergrup, tema, toast ALERT
│       ├── login.html          # Login (mendukung kedua tema)
│       ├── index.html          # Beranda: KPI + kartu node minimalis + grafik PPS
│       ├── nodes.html          # Node: sensor realtime + foto live kamera
│       ├── anomali.html        # Anomali & Dataset: window > threshold + unduh
│       ├── serang.html         # Serangan: kendali S1-S4 + DETEKSI REALTIME (v9.2.5)
│       ├── sesi.html           # Sesi & Dataset: rekam PCAP+CSV tanpa tshark (v9.2.5)
│       ├── log.html            # Log Sistem: log + event + riwayat + unduh (v9.2.5)
│       ├── pengaturan.html     # Pengaturan: threshold LIVE + akun + Telegram (v9.2.5)
│       ├── pps.html            # Grafik PPS: 4 panel realtime refresh 1 dtk (v8.3)
│       ├── server.html         # Server: CPU/RAM/disk + layanan + log
│       └── bantuan.html        # Bantuan: panduan, metrik, skenario, FAQ
├── scripts/
│   ├── check_env.py            # Cek kesiapan host (termasuk broker via IP LAN)
│   ├── test_publish.py         # Simulator 4 perangkat -> broker 192.168.7.101
│   ├── test_subscribe.py       # Verifikasi pesan masuk
│   ├── run_session.py          # (LEGACY) sesi via tshark — utk laptop dgn Wireshark
│   │                           #   v9.2.5: pakai menu 'Sesi & Dataset' (tanpa tshark)
│   ├── attack_sim.py           # Simulator serangan S1-S4 (jalankan di laptop penyerang)
│   ├── plot_compare.py         # Grafik perbandingan antar sesi (PNG)
│   └── mint_cam_demo.jpg       # Foto demo kamera (dipakai --foto)
├── data/
│   ├── demo_normal.csv         # Data demo: 5 menit traffic normal (subnet 7.x)
│   └── demo_serangan.csv       # Data demo: S1 + S3 + S4 (mode replay)
├── thresholds.json             # Threshold hasil kalibrasi demo
├── captures/                   # Tempat berkas .pcap per sesi
├── run/                        # state.json + alerts.jsonl + anomaly_windows.csv
└── requirements.txt            # Dependensi Python host
```

## Konfigurasi Terpusat: `.env`

Mulai v8, **semua konfigurasi sensitif/opsional ada di file `.env`** di akar
folder (dibaca otomatis oleh `dashboard/app.py` dan `analyzer/live_analyzer.py`;
butuh `python-dotenv` — sudah di requirements.txt):

```ini
TELEGRAM_BOT_TOKEN=8964745728:AAEJ...     # bot notifikasi alert
TELEGRAM_CHAT_ID=1209134629               # chat id penerima
# MINT_INFLUX_URL=http://localhost:8086   # aktifkan baris ini bila berbeda
# MINT_INFLUX_TOKEN=...
# MINT_INFLUX_ORG=mint
# MINT_INFLUX_BUCKET=traffic
```

Uji cepat: masuk dashboard → menu **Pengaturan** → **Kirim Pesan Tes**.
> Jangan menaruh `set TELEGRAM_...` di file `.bat` — nilai di `.bat`
> **mengunci** nilai `.env` (dotenv tidak menimpa variabel yang sudah ada).

## Mengapa Hybrid (Docker + Host)?

**tshark WAJIB berjalan di host Windows**, bukan di container. Docker Desktop
menjalankan container di VM dengan jaringan bridge/NAT sehingga tshark dalam
container tidak bisa menangkap paket ESP32 pada interface Wi-Fi fisik, dan
alamat MAC asli perangkat hilang. Lihat spesifikasi Bab 2.3.

| Layanan | Lingkungan | Port |
|---|---|---|
| Mosquitto | Docker | 1883 |
| InfluxDB 2.x | Docker | 8086 |
| Grafana | Docker | 3000 |
| tshark + Wireshark | Host | - |
| Analyzer Python | Host | - |
| Web dashboard Flask | Host | 5000 |

## Langkah Instalasi (Windows + Docker Desktop)

### 1. Nyalakan infrastruktur Docker

```bat
docker compose up -d
docker ps
```

Pastikan `mint-mosquitto`, `mint-influxdb`, `mint-grafana` berstatus `Up`.
Pantau log broker: `docker logs -f mint-mosquitto`.

### 2. Siapkan Python host

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

> Instal juga **Wireshark** (memuat tshark + Npcap) dari wireshark.org, lalu
> pastikan `C:\Program Files\Wireshark` ada di PATH.

### 3. Periksa kesiapan

```bat
python scripts\check_env.py
```

### 4. Uji traffic normal (dari laptop, meniru 4 ESP32)

Terminal 1 (subscriber/pengamat):

```bat
python scripts\test_subscribe.py
```

Terminal 2 (publisher/simulator):

```bat
python scripts\test_publish.py --duration 120
python scripts\test_publish.py --foto --duration 120   % varian: kamera kirim JPEG asli %
```

Buka **http://localhost:3000** (admin / mintadmin) — dashboard MINT tampil.
Buka **http://localhost:8086** (mint / mintpass123) untuk eksplorasi InfluxDB.

> Panel Grafana mulai terisi setelah modul analyzer Python ditulis dan mulai
> menulis ke bucket `traffic` (measurement `traffic_metrics`).

### 5. Uji perekaman tshark (di host)

```bat
tshark -D                        % daftar interface, catat nama Wi-Fi/Ethernet
mkdir captures
tshark -i <NOMOR-INTERFACE> -f "port 1883" -w captures\uji_awal.pcap
```

Jalankan `test_publish.py` di terminal lain selama 60 detik, hentikan tshark
(Ctrl+C), lalu buka `captures\uji_awal.pcap` di Wireshark — filter `mqtt`
untuk melihat pesan PUBLISH per topik.

## Menjalankan Analyzer & Web Dashboard Flask

### Cara 1-klik (Windows — disarankan saat demo)

```bat
mulai_stack.bat          # nyalakan Mosquitto+InfluxDB+Grafana (sekali; opsional)
jalankan_dashboard.bat   # SEKALI SAJA: dashboard + analyzer terintegrasi -> :5000
```

> Sejak v8.1 **tidak perlu lagi menjalankan analyzer terpisah** — PPS/BPS
> langsung terbaca: memakai **tshark** bila Wireshark terpasang (interface
> terdeteksi otomatis; pakai `MINT_IFACE` bila salah tebak), atau **fallback
> MQTT** (metrik dihitung dari pesan yang diterima dashboard) bila tshark
> tidak ada. Sumber metrik aktif tertulis di panel Kesehatan Sistem Beranda
> dan bisa diperiksa lewat **Tes Sistem** di menu Serangan.

Atau untuk **demo tanpa perangkat** cukup satu file:

```bat
jalankan_demo.bat        # buka dashboard + putar replay serangan 10x
```

### Cara manual (2 terminal)

```
[Terminal 1] docker compose up -d          # infrastruktur (sekali saja, opsional)
[Terminal 2] python dashboard\app.py       # dashboard + analyzer -> http://localhost:5000
```

`jalankan_analyzer.bat` / `live_analyzer.py` tetap tersedia untuk sesi
**mandiri** (rekam pcap, kalibrasi threshold, replay) — jalankan saat
dashboard **tidak** dipakai; begitu analyzer eksternal aktif, analyzer
terintegrasi otomatis standby dan kembali mengambil alih setelahnya.

Dashboard dilindungi **login berlapis**: password ter-hash, token CSRF,
anti brute-force (5x gagal -> IP dikunci 5 menit), auto-logout 30 menit,
dan ganti sandi lewat menu **Pengaturan**.
Akun bawaan: `admin / mintadmin`, plus akun
tim (`faizul`, `mahdi`, `naufal`, `steven` — sandi `mint123`).
Kelola pengguna: `python dashboard\add_user.py nama sandi [--admin]`.

Setelah masuk, dashboard terbagi menjadi **8 halaman** (menu atas), masing-masing
bisa dipakai dalam **tema gelap maupun terang** (tombol bulan/matahari di
kanan atas; pilihan tersimpan di browser):

- **Beranda** — banner status sistem, KPI (node terhubung / PPS / BPS / alert
  aktif), **kartu node dengan angka PPS besar** (merah saat lewat threshold)
  plus nilai sensor terakhir (suhu, jarak, cahaya, thumbnail foto kamera)
  dan **IP & topik tiap node**, grafik PPS live per node (legenda bernilai
  live + garis threshold + label puncak; canvas bawaan browser, tanpa CDN),
  log deteksi, dan panel kesehatan sistem.
- **Node** — detail tiap perangkat: pembacaan sensor **realtime** via MQTT
  (JSON maupun teks), **foto live ESP32-CAM** (badge merah LIVE; saat node
  sempat putus, foto terakhir tetap tampil dengan badge abu-abu TERAKHIR)
  beserta **strip riwayat 10 foto terakhir** yang bisa diklik untuk dibuka
  penuh, sparkline PPS 2 menit, metrik + threshold, identitas
  (IP/MAC/topik/lokasi/PIC), dan riwayat event node.
- **Anomali & Dataset** — semua window 1-detik yang **melebihi threshold**
  (`run/anomaly_windows.csv`, tercatat otomatis selama analyzer jalan), event
  ALERT/RECOVERY, daftar berkas `data/*.csv`, plus tombol **unduh CSV/JSON**
  untuk bukti pengujian (Bab 6 laporan).
- **Serangan** *(baru v8.1)* — kendali skenario **S1–S4 langsung dari web**:
  pilih kartu skenario, ketik topik target (bebas), atur rate/durasi/ukuran
  payload, tekan **MULAI SERANGAN** (atau **STOP**). Keluaran attack_sim.py
  tampil langsung, ada riwayat serangan, dan **Tes Sistem** satu klik yang
  memeriksa broker/subscribe/tshark/sumber metrik/InfluxDB/Grafana/Telegram.
  Menggantikan kebiasaan mengetik perintah di Serial Monitor atau CMD.
- **Grafik PPS** *(baru v8.3, menggantikan menu Grafana)* — **4 panel
  realtime refresh 1 detik**: Packet Rate per Perangkat (PPS, dengan garis
  threshold putus + nilai terkini di ujung garis), Byte Rate (B/s), doughnut
  distribusi trafik per node, dan rata-rata ukuran paket — plus tabel node
  realtime (IP, topik, PPS, B/s, total pesan). Tanpa Docker/iframe/CDN;
  paling pas dipakai memantau uji serangan secara langsung. Grafana asli
  tetap tersedia terpisah di `localhost:3000` via `mulai_stack.bat`.
- **Server** — pemakaian CPU/RAM/disk/jaringan (butuh `psutil`), status layanan
  Mosquitto/InfluxDB/Grafana, hasil ping node, dan log sistem.
- **Bantuan** — panduan lengkap: 5 langkah cepat, cara membaca tiap halaman,
  penjelasan metrik & threshold (median+3x1,4826xMAD, 2-of-3), skenario S1-S4,
  dan FAQ.

**Status kehadiran node bersifat aktual**: digabung dari ping ICMP (tiap 5 detik),
umur pesan MQTT terakhir, LWT/topik status, dan trafik yang dilihat
analyzer — perangkat yang mati tertandai OFFLINE dalam ≤ 15 detik, dan saat
tidak ada perangkat menyala penghitung node terhubung menunjukkan **0**.
Node asing yang publish ke `iot/#` tanpa terdaftar di `devices.json` ditandai
**TAK TERDAFTAR**.

### A. Demo cepat tanpa perangkat / tanpa tshark (mode REPLAY)

Data uji sudah disertakan (`data/demo_serangan.csv` berisi S1 flooding,
S3 payload 100 KB, dan S4 multi-perangkat dalam satu sesi):

```bat
python analyzer\live_analyzer.py --replay data\demo_serangan.csv --speed 10
python dashboard\app.py
```

Buka **http://localhost:5000** — banner berubah jadi *SERANGAN TERDETEKSI*
saat skenario diputar, lengkap dengan log ALERT/RECOVERY dan perkiraan skenario.
`--speed 10` berarti 10x lebih cepat (sesi 260 detik selesai dalam ~26 detik).
Selama replay berjalan, setiap window yang melebihi threshold juga otomatis
tercatat — buka halaman **Anomali & Dataset** lalu klik *Unduh* untuk
menyimpan CSV/JSON-nya.

> Agar foto kamera live ikut teruji tanpa perangkat: jalankan simulator
> `python scripts\test_publish.py --foto` bersamaan dengan replay.

### B. Pemantauan nyata (mode LIVE)

1. Cari nomor interface: `tshark -D`
   - Simulator di laptop yang sama (broker Docker di 192.168.7.101): pilih
     nama kartu Wi-Fi/Ethernet laptop (bukan loopback, karena simulator kini
     menargetkan IP LAN sebagaimana ESP32)
   - ESP32 fisik via Wi-Fi: pilih nama kartu Wi-Fi Anda
2. Jalankan analyzer: `python analyzer\live_analyzer.py --iface <NOMOR>`
3. Biarkan berjalan; setiap detik metrik per perangkat dievaluasi.

> Saat tshark pertama kali menangkap paket, Windows Firewall mungkin meminta
> izin — pilih *Allow*. Instal Wireshark **beserta Npcap** (centang opsi
> loopback agar simulator di localhost bisa ditangkap).

## Menghubungkan ESP32 ke Broker (IP 192.168.7.101)

Firmware ESP32 sudah menunjuk ke `192.168.7.101:1883`. Agar langsung nyambung:

1. **Pastikan IP laptop = 192.168.7.101** — cek dengan `ipconfig` (kolom
   *IPv4 Address* pada kartu Wi-Fi). Bila belum, set IP statis di
   *Settings > Network > Wi-Fi > IP assignment* atau buat DHCP reservation
   di router. (Alternatif: ubah `broker_ip` di `devices.json` mengikuti IP
   laptop saat ini — firmware ESP32 juga harus ikut diubah.)
2. **Izinkan port 1883 di Windows Firewall** (jalankan sekali sebagai admin):

   ```bat
   netsh advfirewall firewall add rule name="MQTT 1883" dir=in action=allow protocol=TCP localport=1883
   ```

3. **Cek kesiapan**: `python scripts\check_env.py` — baris Mosquitto akan
   memeriksa jalur 127.0.0.1 **dan** 192.168.7.101 (jalur yang dipakai ESP32),
   serta membandingkan IP laptop dengan `broker_ip`.
4. **Daftarkan node** di `devices.json` agar kartu infonya lengkap: sesuaikan
   `ip`, `mac` (opsional, terisi otomatis dari traffic), `name`, `sensor`,
   `location`, `topic`, `interval_s`, dan `owner` tiap node.
5. Uji dari ESP32: nyalakan perangkat, amati `docker logs -f mint-mosquitto`
   (muncul baris *New connection from 192.168.7.x*), lalu buka dashboard —
   payload sensor terakhir tampil di kartu node.

> Dashboard juga otomatis subscribe `iot/#` untuk menampilkan payload terakhir
> (butuh `paho-mqtt`, sudah di requirements.txt). Broker tujuan bisa dioverride
> dengan `set MINT_BROKER_HOST=...` bila berbeda dari `devices.json`.

### Interval node: realtime vs baseline

`devices.json` dan firmware MINT-node-firmware kini memakai **interval realtime**
untuk uji konektivitas & demo (sesuai keputusan tim):

| Node | Topik | Interval sekarang (realtime) | Interval BASELINE resmi (Tabel 4) |
|---|---|---|---|
| ESP32-1 DHT22 | iot/suhu | 3 detik | 10 detik |
| ESP32-2 HC-SR04 | iot/jarak | 2 detik | 15 detik |
| ESP32-3 ESP32-CAM | iot/kamera | **10 detik** | 60 detik |
| ESP32-4 BH1750 | iot/cahaya | 2 detik | 5 detik |

Saat pengambilan **BASELINE resmi** (sebelum kalibrasi threshold), ubah
`INTERVAL_MS` di firmware tiap node DAN `interval_s` di `devices.json` ke kolom
kanan agar statistik dasar sesuai desain penelitian.

### InfluxDB & Grafana — Cara Pengoperasian

InfluxDB 2.7 dan Grafana 11 sudah dikonfigurasi otomatis oleh
`docker-compose.yml` (tanpa perlu setup manual):

1. **Nyalakan**: `mulai_stack.bat` (atau `docker compose up -d`). InfluxDB
   menginisialisasi dirinya sendiri: org `mint`, bucket `traffic`, token
   `mint-super-secret-token-change-me` (lihat kredensial di bawah).
2. **Aktifkan penulisan metrik**: jalankan analyzer dengan opsi `--influx` —
   cara termudah lewat `jalankan_analyzer.bat`, jawab **y** saat ditanya
   "Kirim metrik ke InfluxDB+Grafana?". Analyzer menulis 2 measurement:
   - `traffic_metrics` — field `pps`, `bps`, `avg_pkt_size`, `topics` per
     perangkat per window 1 detik (data mentah; Grafana yang menghaluskan)
   - `alerts` — satu titik per event ALERT (tag device/metric/type)
3. **Buka Grafana**: http://localhost:3000 (admin / mintadmin). Dashboard
   **MINT - Traffic Monitor** otomatis termuat dari provisioning dengan
   6 panel: PPS per perangkat, BPS, ukuran paket rata-rata, jumlah anomali,
   alert per perangkat+metrik, dan total pesan. Semua panel memakai datasource
   InfluxDB-MINT (uid `influxdb-mint`) yang juga auto-provisioned.
4. **Eksplorasi data mentah**: http://localhost:8086 (mint / mintpass123) →
   *Data Explorer* → bucket `traffic`. Contoh kueri Flux:

   ```flux
   from(bucket: "traffic")
     |> range(start: -15m)
     |> filter(fn: (r) => r._measurement == "traffic_metrics" and r._field == "pps")
     |> aggregateWindow(every: 10s, fn: mean, createEmpty: false)
   ```

5. **Reset data** (mulai bersih): `docker compose down -v` lalu `up -d`
   (volume `influxdb_data` ikut terhapus).

> Ya — InfluxDB **sudah mendukung** dashboard v8: nilai default `MINT_INFLUX_*`
> di kode sama persis dengan inisialisasi docker-compose, sehingga baris
> InfluxDB di `.env` boleh tetap dikomentari.

### Menjalankan Skenario Serangan S1-S4 (pengujian nyata)

**Cara termudah (baru v8.1) — dari web dashboard, tanpa mengetik perintah:**

1. Jalankan `jalankan_dashboard.bat`, login, buka menu **Serangan**.
2. Tekan **Jalankan Tes** untuk memastikan komponen hijau.
3. Pilih kartu skenario (S1–S4), ketik topik target bila perlu, atur
   rate/durasi/ukuran, tekan **MULAI SERANGAN**.
4. Pantau hasilnya: banner Beranda, grafik PPS, halaman Anomali, notifikasi
   Telegram (PPS+BPS satu pesan), dan menu Grafana.
5. Tekan **STOP** kapan saja untuk menghentikan.

> Serangan dari web dijalankan **dari laptop server** (IP-nya = IP server).
> Untuk pengujian dua laptop yang sesuai proposal, pakai cara berikut.

**Cara klasik — 2 laptop** di jaringan lab yang sama: laptop **server**
(192.168.7.101, menjalankan stack + dashboard + analyzer terintegrasi) dan
laptop **penyerang** (bebas IP-nya, cukup Python + paho-mqtt).

Di laptop **server** (sesi berlabel — pcap + deteksi + dataset CSV otomatis):

```bat
python scripts\run_session.py S1 120 --iface Wi-Fi
```

Di laptop **penyerang** (salin folder `scripts/attack_sim.py` + `devices.json`,
lalu dari folder itu):

```bat
python attack_sim.py S1                 % flooding iot/suhu 100 msg/dtk x 60 dtk %
python attack_sim.py S2                 % burst berulang %
python attack_sim.py S3 --size 60       % payload 60 KB dari topik suhu %
python attack_sim.py S4 --duration 10   % 4 topik serentak %
python attack_sim.py --list             % lihat semua parameter default %
```

Setelah selesai: dataset ada di `data\dataset_S1.csv`, bukti mentah di
`captures\S1.pcap`, event di halaman **Anomali & Dataset**, dan grafik
perbandingan: `python scripts\plot_compare.py data\dataset_BASE.csv data\dataset_S1.csv`.

**Dua mode atribusi IP** (pilih sesuai tujuan pengujian):
- **Mode bebas** — IP laptop penyerang tampil sebagai node `TAK TERDAFTAR`
  yang flooding: menguji deteksi injeksi perangkat asing.
- **Mode menyamar** (mengikuti kisah demo_serangan.csv) — matikan node fisik
  target, lalu set IP statis laptop penyerang = IP node itu (mis.
  192.168.7.102). Serangan tercatat SEBAGAI node yang dibajak, threshold
  perangkat yang berlaku adalah threshold node tersebut.

### C. Kalibrasi threshold dari sesi BASE (sekali per testbed)

Cara cepat memakai sesi berlabel (**pcap + deteksi live + dataset CSV sekaligus**):

```bat
python scripts\run_session.py BASE 1800 --iface Wi-Fi
```

Sesi berhenti otomatis setelah 1800 detik (atau Ctrl+C), lalu `data\dataset_BASE.csv`
dibuat otomatis dari pcap. Lanjut kalibrasi:

```bat
python analyzer\threshold_baseline.py --csv data\dataset_BASE.csv --out thresholds.json
```

Ulangi untuk `BASE2` (gabungkan: `--csv data\dataset_BASE.csv data\dataset_BASE2.csv`).
Setelah `thresholds.json` dibuat, analyzer otomatis memakainya.

Grafik perbandingan antar sesi (untuk laporan/Bab 6):

```bat
python scripts\plot_compare.py data\dataset_BASE.csv data\dataset_S1.csv
```

Menghasilkan `grafik_perbandingan.png` (PPS + throughput KB/s per perangkat,
garis putus-putus = sesi serangan, garis penuh = sesi normal).

### D. Opsi lanjutan

| Opsi | Fungsi |
|---|---|
| `--influx` | Tulis metrik + alert ke InfluxDB (bucket `traffic`) — juga bisa lewat prompt `jalankan_analyzer.bat` |
| `--pcap captures\uji.pcap` | Evaluasi cepat sebuah sesi tanpa replay |
| `.env`: `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | Kirim alert via bot Telegram (jangan pakai `set` di .bat — mengunci nilai .env) |
| `set MINT_RUN_DIR=C:\minta\run` | Pindahkan folder `run/` (state & alert) |
| `python dashboard\app.py --port 5001` | Ganti port dashboard |

### E. Troubleshooting

| Gejala | Penyebab & solusi |
|---|---|
| `ModuleNotFoundError: No module named 'flask'` | `pip install flask` (atau ulangi `pip install -r requirements.txt`) — pastikan venv aktif |
| `ModuleNotFoundError: No module named 'psutil'` | `pip install psutil` — tanpa ini dashboard tetap jalan, hanya panel CPU/RAM/disk yang kosong |
| Login: "IP dikunci" | Salah sandi 5x dalam 5 menit. Tunggu 5 menit atau restart dashboard (`jalankan_dashboard.bat`) |
| Lupa sandi dashboard | `python dashboard\add_user.py admin sandibaru --admin` (atau hapus `dashboard\users.json` lalu restart — kembali ke bawaan) |
| ESP32 tidak bisa connect ke broker | Cek 3 hal: IP laptop = 192.168.7.101 (`ipconfig`), firewall izinkan TCP 1883, `docker ps` broker Up. Lihat `docker logs mint-mosquitto` |
| Payload sensor tidak muncul di kartu node | `broker_ip` di devices.json ≠ IP laptop → samakan, atau `set MINT_BROKER_HOST=<ip laptop>`; pastikan paho-mqtt terpasang |
| Dashboard "MENUNGGU DATA" | Analyzer belum jalan / salah interface. Cek `run\state.json` ada isinya |
| Foto kamera tidak tampil | Payload harus JPEG asli (diawali byte FF D8 — firmware ESP32-CAM standar sudah begitu). Uji tanpa perangkat: `python scripts\test_publish.py --foto` |
| Status node selalu OFFLINE padahal menyala | Samakan IP di `devices.json` dengan IP asli ESP32 (lihat serial monitor); pastikan satu subnet & firewall tidak memblokir ping. Sumber bukti kehadiran tertulis kecil di kartu node |
| Halaman Anomali kosong | Window hanya tercatat bila analyzer jalan + thresholds.json terkalibrasi + ada trafik melebihi threshold. Mode demo otomatis mengisinya |
| "tshark tidak dikenal" | PATH belum memuat `C:\Program Files\Wireshark`. **Setelah mengubah PATH, wajib buka terminal BARU** (terminal lama tidak otomatis ikut). Analyzer v4+ tetap jalan tanpa PATH karena otomatis memeriksa lokasi umum |
| Wireshark terinstal tapi `tshark` tetap tak dikenal | Installer Wireshark **tidak menambahkan PATH secara default** — normal. Jalankan cepat di terminal: `set "PATH=%PATH%;C:\Program Files\Wireshark"` |
| PPS selalu 0 di mode live | Interface salah: simulator/ESP32 lewat kartu **Wi-Fi/Ethernet** (bukan loopback lagi, karena target kini IP LAN) |
| PPS/BPS/total pesan di kartu node = 0 padahal sensor tampil | Nilai metrik datang dari **analyzer** (`run\state.json`), bukan dari MQTT. Jalankan `jalankan_analyzer.bat` (interface Wi-Fi) — sensor tetap tampil karena sumbernya beda. Kartu memakai rata-rata 2 menit (`pps_2m`) sehingga stabil, bukan berkedip 0-1 |
| Foto kamera "kadang muncul kadang tidak" | v8 sudah memperbaiki: cache browser 3 dtk (tidak unduh ulang tiap rebuild DOM), validasi frame FF D8..FF D9 di firmware, client MQTT unik per dashboard. Pastikan firmware node kamera versi terbaru & jangan jalankan 2 jendela dashboard lama sekaligus |
| Tombol "Kirim Pesan Tes" gagal | Isi `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` di `.env`, restart dashboard, pastikan pernah `/start` ke bot. JANGAN set variabel Telegram di `.bat` (mengunci nilai .env) |
| Port 5000 terpakai | `python dashboard\app.py --port 5001` |
| Panel Grafana kosong | Jalankan analyzer dengan `--influx` (jawab **y** di `jalankan_analyzer.bat`) agar metrik ditulis ke bucket `traffic` |

## Kredensial (ganti sebelum presentasi!)

| Layanan | User | Password |
|---|---|---|
| Dashboard MINT | admin | mintadmin |
| Dashboard MINT | faizul / mahdi / naufal / steven | mint123 |
| Grafana | admin | mintadmin |
| InfluxDB | mint | mintpass123 |
| Token InfluxDB | - | mint-super-secret-token-change-me |

Testbed terisolasi memakai `allow_anonymous true` pada Mosquitto — **hanya
untuk jaringan lab**, jangan digunakan di jaringan kampus/produksi.

## Langkah Selanjutnya (roadmap spesifikasi Bab 8)

1. Rakit 4 ESP32 + sensor, firmware mode normal.  *(sudah ada: paket MINT-node-firmware.zip)*
2. Rekam 2 sesi BASE 30 menit, hitung threshold (`analyzer/threshold_baseline.py`).  *(alur siap)*
3. Modul skenario S1-S4 (parameter Bab 4).  *(sudah ada: `scripts/attack_sim.py` + alur 2 laptop di atas)*
4. Analyzer real-time: ekstraksi fitur -> deteksi -> InfluxDB.  *(sudah ada: `analyzer/live_analyzer.py` + `--influx`)*
5. Web dashboard Flask + bot Telegram.  *(sudah ada: `dashboard/app.py` multi-halaman — beranda/node/anomali/server/bantuan, tema gelap-terang, sensor & foto realtime + riwayat 10 foto, menu unduh dataset; notifikasi via `.env`)*
6. Dataset CSV berlabel (skema Bab 6) + evaluasi (Bab 7).  *(alur siap: `--label` di `pcap_analyzer.py`; window anomali live otomatis ke `run/anomaly_windows.csv`)*
