/*
 * ================================================================
 *  MINT — Node 1 : SUHU (ESP32 DevKit V1 + DHT22)   [FIRMWARE v9.1]
 * ----------------------------------------------------------------
 *  Topik data   : iot/suhu   -> {"device":"ESP32-1","sensor":"DHT22",
 *                                "suhu_c":28.4,"kelembaban_pct":70.2,"ts":123}
 *  Topik status : iot/suhu/status -> "online" (retain) / "offline" (LWT)
 *  IP statis    : 192.168.7.102  (registry devices.json v9)
 *  Broker       : 192.168.7.101 : 1883 (laptop server, Mosquitto)
 *
 *  PERBAIKAN v9.1 (mengapa node sering tampak OFFLINE):
 *   1. IP statis kini SESUAI devices.json (.102) — sebelumnya firmware
 *      lama memakai IP lain sehingga ping dashboard tidak pernah sampai.
 *   2. Kredensial WiFi DISAMAKAN semua node (satu sumber kebenaran).
 *   3. Bila IP statis gagal (bentrok/ditolak router) -> otomatis
 *      berpindah ke DHCP agar node tetap online (IP baru tampil di
 *      Serial Monitor; catat lalu perbarui devices.json).
 *   4. WiFi.setSleep(false): modem-sleep bawaan ESP32 bikin MQTT
 *      lambat/terputus-putus — dimatikan.
 *   5. Self-healing: WiFi hilang >60 dtk -> sambung ulang; MQTT mati
 *      >5 menit -> ESP restart sendiri (tidak perlu cabut colokan).
 *   6. LWT retained: broker mengumumkan "offline" otomatis saat node
 *      mati mendadak, dan "online" saat bangun.
 *   7. Interval 10 dtk = baseline kalibrasi threshold v9 (devices.json).
 *
 *  Library (Arduino IDE > Library Manager):
 *    - PubSubClient (Nick O'Leary)
 *    - "DHT sensor library" (Adafruit) + "Adafruit Unified Sensor"
 *  Board: "ESP32 Dev Module" | Upload 921600 | Serial Monitor 115200
 * ================================================================
 */

// ---------------------- KONFIGURASI (EDIT INI) ----------------------
const char* WIFI_SSID  = "MINT-LAB";       // <-- GANTI: nama WiFi lab
const char* WIFI_PASS  = "mintlab2026";    // <-- GANTI: password WiFi lab

IPAddress NODE_IP  (192, 168, 7, 102);     // ESP32-1 (devices.json)
IPAddress NODE_GW  (192, 168, 7, 1);       // gateway = router
IPAddress NODE_MASK(255, 255, 255, 0);
IPAddress NODE_DNS (192, 168, 7, 1);

const char* MQTT_HOST = "192.168.7.101";   // laptop server (broker)
const int   MQTT_PORT = 1883;

const char* TOPIC_DATA   = "iot/suhu";
const char* TOPIC_STATUS = "iot/suhu/status";
const char* CLIENT_ID    = "mint-node1-suhu";

const uint32_t INTERVAL_MS = 10000UL;      // baseline 10 dtk (threshold v9)

const uint8_t PIN_DHT = 4;                 // DATA DHT22
const uint8_t PIN_LED = 2;                 // LED bawaan DevKit
// ---------------------------------------------------------------------

#include <WiFi.h>
#include <PubSubClient.h>
#include <DHT.h>

#define DHTTYPE DHT22
DHT dht(PIN_DHT, DHTTYPE);
WiFiClient net;
PubSubClient mqtt(net);

bool   pakaiStatis = true;      // false bila sudah jatuh ke DHCP
uint32_t tWiFiDown = 0, tMqttDown = 0, tCobaMqtt = 0, lastPub = 0;

void setLED(bool nyala) { digitalWrite(PIN_LED, nyala ? HIGH : LOW); }

/* ---------- WiFi: statis -> fallback DHCP -> auto-reconnect ---------- */
void sambungkanWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);                       // MQTT responsif (fix v9.1)
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
    WiFi.disconnect(true, true);              // hapus konfigurasi statis
    delay(300);
    sambungkanWiFi();                         // ulangi lewat DHCP
  } else {
    Serial.println("\n[WiFi] masih gagal — cek SSID/password, ulangi nanti");
  }
}

/* ---------- MQTT: LWT + diagnostik rc dalam bahasa jelas ---------- */
bool sambungkanMQTT() {
  Serial.printf("[MQTT] menyambung ke %s:%d ... ", MQTT_HOST, MQTT_PORT);
  if (mqtt.connect(CLIENT_ID, TOPIC_STATUS, 0, true, "offline")) {
    mqtt.publish(TOPIC_STATUS, "online", true);   // lahir sebagai online
    Serial.println("TERHUBUNG (LWT aktif)");
    lastPub = millis() - INTERVAL_MS;             // kirim data pertama SEGERA
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

/* ---------- Perawatan koneksi: dipanggil tiap loop ---------- */
void rawatKoneksi() {
  uint32_t kini = millis();

  if (WiFi.status() != WL_CONNECTED) {
    setLED(false);
    if (tWiFiDown == 0) tWiFiDown = kini;
    if (kini - tWiFiDown > 60000UL) {            // self-healing WiFi
      Serial.println("[WiFi] terputus >60 dtk — menyambung ulang...");
      tWiFiDown = 0;
      sambungkanWiFi();
    }
    return;                                      // tanpa WiFi tak ada MQTT
  }
  tWiFiDown = 0;

  if (!mqtt.connected()) {
    setLED(false);
    if (tMqttDown == 0) tMqttDown = kini;
    if (kini - tMqttDown > 300000UL) {           // self-healing total
      Serial.println("[MQTT] mati >5 menit — me-restart ESP32...");
      ESP.restart();
    }
    if (kini - tCobaMqtt >= 3000UL) {            // coba tiap 3 dtk
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
  dht.begin();

  sambungkanWiFi();

  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setKeepAlive(30);
  mqtt.setSocketTimeout(5);
  mqtt.setBufferSize(512);          // cukup utk JSON sensor
}

void loop() {
  rawatKoneksi();

  if (!mqtt.connected()) { delay(100); return; }

  if (millis() - lastPub >= INTERVAL_MS) {
    lastPub = millis();

    // baca DHT22 dgn percobaan ulang (sensor kadang gagal sekali)
    float suhu = NAN, rh = NAN;
    for (int i = 0; i < 3 && isnan(suhu); i++) {
      suhu = dht.readTemperature();
      rh   = dht.readHumidity();
      if (isnan(suhu) || isnan(rh)) { delay(500); suhu = NAN; }
    }
    if (isnan(suhu) || isnan(rh)) {
      Serial.println("[DHT22] baca gagal 3x — dilewati (dtk berikutnya)");
      return;
    }

    String p = "{\"device\":\"ESP32-1\",\"sensor\":\"DHT22\"";
    p += ",\"suhu_c\":" + String(suhu, 1);
    p += ",\"kelembaban_pct\":" + String(rh, 1);
    p += ",\"ts\":" + String(millis() / 1000) + "}";

    bool ok = mqtt.publish(TOPIC_DATA, p.c_str());
    Serial.println("[PUBLISH] " + p + (ok ? "" : " (GAGAL)"));
    setLED(false); delay(60); setLED(true);      // kedip singkat = kirim
  }
}
