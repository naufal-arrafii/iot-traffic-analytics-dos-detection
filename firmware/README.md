# Firmware ESP32 — Paket FAIZUL (IoT Endpoint & Traffic Generation)

> **v9.1** — firmware diperkuat hasil uji lapangan (node 2/3/4 sempat
> OFFLINE): IP statis persis `devices.json` (.102–.105), kredensial WiFi
> satu sumber kebenaran (semua node sama, edit blok KONFIGURASI),
> **fallback DHCP** bila IP statis gagal/bentrok, `WiFi.setSleep(false)`,
> LWT retained, diagnostik rc MQTT berbahasa jelas, **self-healing**
> (WiFi >60 dtk → reconnect; MQTT >5 menit → `ESP.restart()`), heartbeat
> node 2 tetap kirim walau sensor gagal, kamera node 3 non-fatal + re-init
> otomatis, sensor node 4 retry otomatis, LED indikator status di GPIO 2
> (CAM: GPIO 33), dan interval 10 dtk selaras kalibrasi threshold v9.

Empat sketch siap-upload untuk luaran **(a) prototipe 4 node ESP32** dan
**(b) firmware publish MQTT** sesuai proposal (Bab 3.4 & Tabel 3.3.1).
IP statis, topik, interval, dan format JSON **sudah mengikuti `devices.json`**
dengan skema proposal: core server `192.168.7.101` (laptop server), ESP32 `192.168.7.102–105`.

| Folder sketch | Node | Sensor | Topik | Pola kirim | Library ekstra |
|---|---|---|---|---|---|
| `ESP32_1_DHT22/` | ESP32-1 · 192.168.7.102 | DHT22 (suhu & RH) | `iot/suhu` | periodik 10 dtk | DHT sensor library (Adafruit) |
| `ESP32_2_HCSR04/` | ESP32-2 · 192.168.7.103 | HC-SR04 (jarak) | `iot/jarak` | **event-based** (pintu/gerakan) + heartbeat 10 dtk (baseline v9) | — |
| `ESP32_3_CAM/` | ESP32-3 · 192.168.7.104 | OV2640 JPEG | `iot/kamera` | periodik 10 dtk (~15–30 KB) | — (built-in esp_camera) |
| `ESP32_4_BH1750/` | ESP32-4 · 192.168.7.105 | BH1750 (lux) | `iot/cahaya` | periodik 10 dtk | BH1750 (Christopher Laws) |

Semua sketch memakai **PubSubClient** ke broker `192.168.7.101:1883` (TCP, tanpa
TLS sesuai batasan proposal), **IP statis** via `WiFi.config()` (fallback DHCP
otomatis bila gagal), **LWT**
status (`iot/<x>/status` → `online`/`offline` retained), dan **watchdog
self-healing** agar node pulih sendiri tanpa dicabut-colok ulang.

## Langkah upload (per node)

1. Arduino IDE 2.x → **Boards Manager** → install **esp32 by Espressif Systems**.
2. **Library Manager** → install `PubSubClient` + library sensor (tabel atas).
3. Buka folder sketch-nya (nama folder = nama sketch), pilih board:
   - ESP32 DevKit V1 → **"ESP32 Dev Module"**
   - ESP32-CAM → **"AI Thinker ESP32-CAM"**
4. Edit 2 baris di atas tiap sketch: `WIFI_SSID` dan `WIFI_PASS` (router lab).
5. Upload, buka **Serial Monitor 115200**, pastikan: WiFi OK → MQTT tersambung
   → baris `[PUBLISH]` muncul sesuai interval.
6. Verifikasi dari laptop server: `python scripts\test_subscribe.py --count 10`.

## Catatan penting

- **QoS**: PubSubClient mengirim publish **QoS 0**. Untuk eksperimen QoS 1
  (sesuai tabel registry), gunakan library **ArduinoMqttClient**
  (`beginMessage(topik, retained, 1)`) — struktur program sama.
- **HC-SR04 adalah 5V**: ECHO wajib lewat pembagi tegangan (1kΩ + 2kΩ) ke GPIO18.
- **ESP32-CAM**: butuh buffer besar → sketch sudah memanggil
  `mqtt.setBufferSize(48*1024)`; bila publish gagal, turunkan `jpeg_quality`
  (mis. 15) atau `frame_size` ke `FRAMESIZE_VGA`. Gagal init kamera TIDAK
  fatal — node tetap online dan firmware me-re-init kamera otomatis.
  Catu daya wajib 5V ≥2A (brownout = restart terus-menerus).
- **Router wajib 2,4 GHz**: ESP32 tidak mendukung 5 GHz — bila router
  dual-band, sambungkan ke SSID band 2,4 GHz.
- **IP DHCP tercetak di Serial** berarti IP statis gagal (bentrok) — catat IP
  itu lalu perbarui `devices.json` agar dashboard cocok.
- **Wajib dites di hardware**: ini kerangka siap-upload, bukan jaminan jalan
  tanpa penyesuaian wiring/power (ESP32-CAM butuh suplai 5V stabil).
- Sebelum hardware siap, tim tetap bisa uji penuh pakai simulator
  `scripts/test_publish.py` (format payload sama persis).
