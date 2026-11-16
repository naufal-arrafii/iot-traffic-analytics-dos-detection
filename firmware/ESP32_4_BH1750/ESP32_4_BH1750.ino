/*
 * ================================================================
 *  MINT — Node 4 : CAHAYA (ESP32 DevKit V1 + BH1750)  [FIRMWARE v9.1]
 * ----------------------------------------------------------------
 *  Topik data   : iot/cahaya -> {"device":"ESP32-4","sensor":"BH1750",
 *                                "lux":173.4,"ts":123}
 *  Topik status : iot/cahaya/status -> "online" (retain) / "offline" (LWT)
 *  IP statis    : 192.168.7.105  (registry devices.json v9)
 *  Broker       : 192.168.7.101 : 1883 (laptop server, Mosquitto)
 *
 *  PERBAIKAN v9.1:
 *   1. IP statis .105 SESUAI devices.json (firmware lama memakai IP
 *      lain -> ping dashboard gagal -> node tampak OFFLINE).
 *   2. Sensor BH1750 tidak terdeteksi saat boot TIDAK fatal: node
 *      tetap online, sensor di-coba ulang otomatis tiap 5 dtk.
 *   3. Fallback DHCP bila IP statis gagal + WiFi.setSleep(false).
 *   4. Self-healing: WiFi >60 dtk -> reconnect; MQTT >5 menit -> restart.
 *   5. Interval 10 dtk = baseline kalibrasi threshold v9 (devices.json).
 *
 *  Wiring I2C: SDA=GPIO21, SCL=GPIO22, VCC=3V3, GND.
 *  Library (Library Manager): PubSubClient + BH1750 (Christopher Laws).
 *  Board: "ESP32 Dev Module" | Upload 921600 | Serial Monitor 115200
 * ================================================================
 */

// ---------------------- KONFIGURASI (EDIT INI) ----------------------
const char* WIFI_SSID  = "MINT-LAB";       // <-- GANTI: nama WiFi lab
const char* WIFI_PASS  = "mintlab2026";    // <-- GANTI: password WiFi lab

IPAddress NODE_IP  (192, 168, 7, 105);     // ESP32-4 (devices.json)
IPAddress NODE_GW  (192, 168, 7, 1);
IPAddress NODE_MASK(255, 255, 255, 0);
IPAddress NODE_DNS (192, 168, 7, 1);

const char* MQTT_HOST = "192.168.7.101";   // laptop server (broker)
const int   MQTT_PORT = 1883;

const char* TOPIC_DATA   = "iot/cahaya";
const char* TOPIC_STATUS = "iot/cahaya/status";
const char* CLIENT_ID    = "mint-node4-cahaya";

const uint32_t INTERVAL_MS = 10000UL;      // baseline 10 dtk (threshold v9)

const uint8_t PIN_SDA  = 21;
const uint8_t PIN_SCL  = 22;
const uint8_t PIN_LED  = 2;
// ---------------------------------------------------------------------

#include <Wire.h>
#include <BH1750.h>
#include <WiFi.h>
#include <PubSubClient.h>

BH1750 luxMeter;
WiFiClient net;
PubSubClient mqtt(net);

bool   sensorOk = false, pakaiStatis = true;
uint32_t tWiFiDown = 0, tMqttDown = 0, tCobaMqtt = 0, lastPub = 0, tSensor = 0;

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
    lastPub = millis() - INTERVAL_MS;         // kirim data pertama SEGERA
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

  Wire.begin(PIN_SDA, PIN_SCL);
  sensorOk = luxMeter.begin(BH1750::CONTINUOUS_HIGH_RES_MODE);
  if (!sensorOk)                 // tidak fatal (v9.1): retry otomatis
    Serial.println("[BH1750] belum terdeteksi — akan dicoba ulang otomatis");

  sambungkanWiFi();

  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setKeepAlive(30);
  mqtt.setSocketTimeout(5);
  mqtt.setBufferSize(512);
}

void loop() {
  rawatKoneksi();
  if (!mqtt.connected()) { delay(100); return; }

  uint32_t kini = millis();

  // sensor belum siap? coba ulang tiap 5 dtk (fix v9.1)
  if (!sensorOk && kini - tSensor >= 5000UL) {
    tSensor = kini;
    sensorOk = luxMeter.begin(BH1750::CONTINUOUS_HIGH_RES_MODE);
    if (sensorOk) Serial.println("[BH1750] sensor terdeteksi (pulih)");
  }

  if (millis() - lastPub >= INTERVAL_MS) {
    lastPub = millis();
    if (!sensorOk) { Serial.println("[BH1750] belum siap — dilewati"); return; }

    float lux = luxMeter.readLightLevel();    // 0.1-65535 lx
    if (lux < 0) { Serial.println("[BH1750] baca gagal"); return; }

    String p = "{\"device\":\"ESP32-4\",\"sensor\":\"BH1750\"";
    p += ",\"lux\":" + String(lux, 1);
    p += ",\"ts\":" + String(millis() / 1000) + "}";

    bool ok = mqtt.publish(TOPIC_DATA, p.c_str());
    Serial.println("[PUBLISH] " + p + (ok ? "" : " (GAGAL)"));
    setLED(false); delay(60); setLED(true);
  }
}
