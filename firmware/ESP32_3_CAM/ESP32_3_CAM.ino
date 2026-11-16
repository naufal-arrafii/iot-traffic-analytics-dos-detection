/*
 * ================================================================
 *  MINT — Node 3 : KAMERA (AI-Thinker ESP32-CAM + OV2640) [FIRMWARE v9.2.5]
 * ----------------------------------------------------------------
 *  Topik data   : iot/kamera  -> JPEG biner (QoS 0), ~8-16 KB per foto
 *  Topik status : iot/kamera/status -> "online" (retain) / "offline" (LWT)
 *  IP statis    : 192.168.7.104  (registry devices.json v9)
 *  Broker       : 192.168.7.101 : 1883 (laptop server, Mosquitto)
 *
 *  PERBAIKAN v9.2.5 (foto tiba JAUH LEBIH CEPAT — keluhan "delay berat"):
 *   1. fb_count = 2 + CAMERA_GRAB_LATEST : buffer GANDA — sensor menangkap
 *      frame berikutnya sambil frame sebelumnya dikirim, esp_camera_fb_get()
 *      tidak lagi menunggu expose baru (sumber utama jeda 200-500 ms).
 *   2. Resolusi VGA 640x480 q12 (~8-16 KB, sebelumnya SVGA ~15-30 KB):
 *      waktu kirim lewat udara berkurang ~ separuh — pada WiFi padat
 *      (4 node + broker + dashboard) inilah yang mempercepat paling terasa.
 *      Ganti ke FRAMESIZE_SVHA bila butuh lebih tajam.
 *   3. setSocketTimeout(4 dtk): publish gagal cepat terdeteksi (tidak menggantung
 *      dan menyumbat keepalive) + publish DIULANG 1x bila gagal — foto tidak
 *      hilang diam-diam.
 *   4. mqtt.loop() ikut dipanggil di sela retry agar keepalive tetap hidup.
 *
 *  Perbaikan v9.1 (dipertahankan):
 *   - IP statis .104 sesuai devices.json + kredensial WiFi disamakan.
 *   - Kamera gagal init tidak mengganggu koneksi; re-init otomatis 5x gagal.
 *   - xclk 10 MHz, fallback DHCP, WiFi.setSleep(false), LWT retained,
 *     self-healing restart.
 *
 *  CATATAN PENTING HARDWARE:
 *   - ESP32-CAM gampang BROWNOUT (restart sendiri) bila catu daya lemah:
 *     pakai 5V >= 2A (bukan power dari USB FTDI yang kecil).
 *   - Flashing: tahan GPIO0 ke GND saat upload, lepas lalu tekan RST.
 *   - LED merah bawaan (GPIO 33, aktif-RENDAH) dipakai indikator status.
 *
 *  Library: PubSubClient (Nick O'Leary).
 *  Board: "AI Thinker ESP32-CAM" (Package ESP32 by Espressif).
 * ================================================================
 */

// ---------------------- KONFIGURASI (EDIT INI) ----------------------
const char* WIFI_SSID  = "MINT-LAB";       // <-- GANTI: nama WiFi lab
const char* WIFI_PASS  = "mintlab2026";    // <-- GANTI: password WiFi lab

IPAddress NODE_IP  (192, 168, 7, 104);     // ESP32-3 (devices.json)
IPAddress NODE_GW  (192, 168, 7, 1);
IPAddress NODE_MASK(255, 255, 255, 0);
IPAddress NODE_DNS (192, 168, 7, 1);

const char* MQTT_HOST = "192.168.7.101";   // laptop server (broker)
const int   MQTT_PORT = 1883;

const char* TOPIC_DATA   = "iot/kamera";
const char* TOPIC_STATUS = "iot/kamera/status";
const char* CLIENT_ID    = "mint-node3-kamera";

const uint32_t INTERVAL_MS = 10000UL;      // foto tiap 10 dtk (baseline v9)

// LED merah di belakang board CAM: aktif RENDAH
#define PIN_LED    33
#define LED_ON     LOW
#define LED_OFF    HIGH
// ---------------------------------------------------------------------

#include "esp_camera.h"
#include <WiFi.h>
#include <PubSubClient.h>

/* ---------- Pin AI-Thinker ESP32-CAM (standar) ---------- */
#define PWDN_GPIO_NUM  32
#define RESET_GPIO_NUM -1
#define XCLK_GPIO_NUM   0
#define SIOD_GPIO_NUM  26
#define SIOC_GPIO_NUM  27
#define Y9_GPIO_NUM    35
#define Y8_GPIO_NUM    34
#define Y7_GPIO_NUM    39
#define Y6_GPIO_NUM    36
#define Y5_GPIO_NUM    21
#define Y4_GPIO_NUM    19
#define Y3_GPIO_NUM    18
#define Y2_GPIO_NUM     5
#define VSYNC_GPIO_NUM 25
#define HREF_GPIO_NUM  23
#define PCLK_GPIO_NUM  22

WiFiClient net;
PubSubClient mqtt(net);

bool   camOk = false, pakaiStatis = true;
uint8_t gagalFrame = 0;
uint32_t tWiFiDown = 0, tMqttDown = 0, tCobaMqtt = 0, lastPub = 0;

void setLED(bool nyala) { digitalWrite(PIN_LED, nyala ? LED_ON : LED_OFF); }

/* ---------- Kamera: init + re-init pemulihan ---------- */
bool initKamera() {
  camera_config_t cfg = {};
  cfg.ledc_channel = LEDC_CHANNEL_0;
  cfg.ledc_timer   = LEDC_TIMER_0;
  cfg.pin_d0 = Y2_GPIO_NUM;  cfg.pin_d1 = Y3_GPIO_NUM;
  cfg.pin_d2 = Y4_GPIO_NUM;  cfg.pin_d3 = Y5_GPIO_NUM;
  cfg.pin_d4 = Y6_GPIO_NUM;  cfg.pin_d5 = Y7_GPIO_NUM;
  cfg.pin_d6 = Y8_GPIO_NUM;  cfg.pin_d7 = Y9_GPIO_NUM;
  cfg.pin_xclk = XCLK_GPIO_NUM;
  cfg.pin_pclk = PCLK_GPIO_NUM;
  cfg.pin_vsync = VSYNC_GPIO_NUM;
  cfg.pin_href  = HREF_GPIO_NUM;
  cfg.pin_sccb_sda = SIOD_GPIO_NUM;
  cfg.pin_sccb_scl = SIOC_GPIO_NUM;
  cfg.pin_pwdn  = PWDN_GPIO_NUM;
  cfg.pin_reset = RESET_GPIO_NUM;
  cfg.xclk_freq_hz = 10000000;            // 10 MHz: lebih stabil (fix v9.1)
  cfg.pixel_format = PIXFORMAT_JPEG;
  cfg.frame_size   = FRAMESIZE_VGA;      // 640x480 -> JPEG ~8-16 KB (fix v9.2.5:
                                          // kirim ~2x lebih cepat; ganti ke
                                          // FRAMESIZE_SVGA bila mau lebih tajam)
  cfg.jpeg_quality = 12;                  // 10-63; makin kecil makin besar
  cfg.fb_count     = 2;                   // fix v9.2.5: buffer ganda — ambil
                                          // frame berikutnya tanpa menunggu
  cfg.grab_mode    = CAMERA_GRAB_LATEST;
  return esp_camera_init(&cfg) == ESP_OK;
}

/* ---------- WiFi: statis -> fallback DHCP -> auto-reconnect ---------- */
void sambungkanWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);                   // frame/MQTT tidak tersendat
  if (pakaiStatis) WiFi.config(NODE_IP, NODE_GW, NODE_MASK, NODE_DNS);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.printf("[WiFi] menyambung ke \"%s\" (%s) ", WIFI_SSID,
                pakaiStatis ? "IP statis" : "DHCP");
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000UL) {
    delay(250); Serial.print(".");
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf(" OK — IP: %s\n", WiFi.localIP().toString().c_str());
    if (!pakaiStatis)
      Serial.println("[WiFi] CATAT: IP DHCP di atas, perbarui devices.json");
  } else if (pakaiStatis) {
    Serial.println("\n[WiFi] GAGAL dengan IP statis (bentrok?) — coba DHCP...");
    pakaiStatis = false;
    WiFi.disconnect(true, true);
    delay(300);
    sambungkanWiFi();
  } else {
    Serial.println("\n[WiFi] masih gagal — cek SSID/password, ulangi nanti");
  }
}

/* ---------- MQTT: LWT + diagnostik rc ---------- */
bool sambungkanMQTT() {
  Serial.printf("[MQTT] menyambung ke %s:%d ... ", MQTT_HOST, MQTT_PORT);
  if (mqtt.connect(CLIENT_ID, TOPIC_STATUS, 0, true, "offline")) {
    mqtt.publish(TOPIC_STATUS, "online", true);
    Serial.println("TERHUBUNG (LWT aktif)");
    lastPub = millis() - INTERVAL_MS;     // foto pertama SEGERA
    return true;
  }
  int rc = mqtt.state();
  Serial.printf("\n[MQTT] gagal rc=%d — ", rc);
  if      (rc == -2) Serial.println("broker tidak terjangkau: cek IP broker/"
                                    "Mosquitto jalan/ping 192.168.7.101");
  else if (rc == -3) Serial.println("koneksi TCP terputus");
  else if (rc == -4) Serial.println("timeout: sinyal WiFi lemah/broker sibuk");
  else               Serial.println("periksa jaringan & broker");
  return false;
}

/* ---------- Perawatan koneksi ---------- */
void rawatKoneksi() {
  uint32_t kini = millis();

  if (WiFi.status() != WL_CONNECTED) {
    setLED(false);
    if (tWiFiDown == 0) tWiFiDown = kini;
    if (kini - tWiFiDown > 60000UL) {
      Serial.println("[WiFi] terputus >60 dtk — menyambung ulang...");
      tWiFiDown = 0;
      sambungkanWiFi();
    }
    return;
  }
  tWiFiDown = 0;

  if (!mqtt.connected()) {
    setLED(false);
    if (tMqttDown == 0) tMqttDown = kini;
    if (kini - tMqttDown > 300000UL) {
      Serial.println("[MQTT] mati >5 menit — me-restart ESP32...");
      ESP.restart();
    }
    if (kini - tCobaMqtt >= 3000UL) {
      tCobaMqtt = kini;
      if (sambungkanMQTT()) tMqttDown = 0;
    }
    return;
  }
  tMqttDown = 0;
  setLED(true);
  mqtt.loop();
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_LED, OUTPUT);
  setLED(false);

  camOk = initKamera();                 // gagal kamera TIDAK fatal (v9.1)
  Serial.println(camOk ? "[CAM] kamera siap"
                       : "[CAM] init gagal — node tetap online, "
                         "akan coba re-init otomatis");

  sambungkanWiFi();

  mqtt.setBufferSize(48 * 1024);        // muat JPEG + overhead MQTT
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setKeepAlive(30);
  mqtt.setSocketTimeout(4);             // fix v9.2.5: gagal cepat, tak menggantung
}

void loop() {
  rawatKoneksi();
  if (!mqtt.connected()) { delay(100); return; }

  if (millis() - lastPub >= INTERVAL_MS) {
    lastPub = millis();

    if (!camOk) {                       // coba pulihkan kamera tiap interval
      camOk = initKamera();
      if (!camOk) { Serial.println("[CAM] re-init masih gagal"); return; }
      Serial.println("[CAM] kamera pulih lewat re-init");
    }

    camera_fb_t *fb = esp_camera_fb_get();
    if (!fb) {
      Serial.println("[CAM] ambil frame gagal");
      if (++gagalFrame >= 5) {          // pemulihan total kamera (v9.1)
        Serial.println("[CAM] 5x gagal — deinit + init ulang...");
        esp_camera_deinit();
        camOk = initKamera();
        gagalFrame = 0;
      }
      return;
    }
    gagalFrame = 0;

    /* fix v9.2.5: kirim JPEG + ULANGI sekali bila gagal — foto tidak
       hilang diam-diam; mqtt.loop() dipanggil di sela agar keepalive hidup */
    bool ok = mqtt.publish(TOPIC_DATA, fb->buf, fb->len);
    if (!ok) {
      mqtt.loop();
      delay(150);
      ok = mqtt.publish(TOPIC_DATA, fb->buf, fb->len);
    }
    Serial.printf("[PUBLISH] JPEG %u KB -> %s (%s, %lu ms sejak ambil)\n",
                  fb->len / 1024, TOPIC_DATA, ok ? "ok" : "GAGAL",
                  millis() - lastPub);
    esp_camera_fb_return(fb);
    setLED(false); delay(60); setLED(true);
  }
}
