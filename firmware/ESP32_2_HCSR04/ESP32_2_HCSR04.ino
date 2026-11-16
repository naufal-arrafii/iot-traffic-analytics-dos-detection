/*
 * ================================================================
 *  MINT — Node 2 : JARAK (ESP32 DevKit V1 + HC-SR04)  [FIRMWARE v9.1]
 * ----------------------------------------------------------------
 *  Topik data   : iot/jarak  -> {"device":"ESP32-2","sensor":"HC-SR04",
 *                                "jarak_cm":45.2,"event":"heartbeat","ts":123}
 *  Topik status : iot/jarak/status -> "online" (retain) / "offline" (LWT)
 *  IP statis    : 192.168.7.103  (registry devices.json v9)
 *  Broker       : 192.168.7.101 : 1883 (laptop server, Mosquitto)
 *
 *  Perilaku publish (sesuai proposal, smart door lock):
 *   - EVENT: kirim saat jarak < 50 cm ("pintu_buka") atau berubah >10 cm
 *   - HEARTBEAT: tiap 10 dtk walau tidak ada kejadian (baseline v9,
 *     selaras devices.json interval_s=10 dan kalibrasi threshold)
 *
 *  PERBAIKAN v9.1:
 *   1. IP statis .103 SESUAI devices.json (firmware lama memakai IP
 *      lain -> ping dashboard gagal -> node tampak OFFLINE).
 *   2. Heartbeat TETAP dikirim walau sensor gagal baca (jarak_cm=-1,
 *      event "sensor_error") supaya status node jelas di dashboard.
 *   3. Fallback DHCP bila IP statis gagal + WiFi.setSleep(false).
 *   4. Self-healing: WiFi >60 dtk -> reconnect; MQTT >5 menit -> restart.
 *   5. Interval/event = baseline kalibrasi threshold v9.
 *
 *  Wiring HC-SR04:
 *    VCC  -> VIN (5V)   <-- HC-SR04 butuh 5V agar ukurannya stabil
 *    GND  -> GND
 *    TRIG -> GPIO 5
 *    ECHO -> GPIO 18    <-- WAJIB via pembagi tegangan 1k + 2k (5V->3.3V)!
 *
 *  Library: PubSubClient (Nick O'Leary). Sensor dibaca manual (pulseIn).
 *  Board: "ESP32 Dev Module" | Upload 921600 | Serial Monitor 115200
 * ================================================================
 */

// ---------------------- KONFIGURASI (EDIT INI) ----------------------
const char* WIFI_SSID  = "MINT-LAB";       // <-- GANTI: nama WiFi lab
const char* WIFI_PASS  = "mintlab2026";    // <-- GANTI: password WiFi lab

IPAddress NODE_IP  (192, 168, 7, 103);     // ESP32-2 (devices.json)
IPAddress NODE_GW  (192, 168, 7, 1);
IPAddress NODE_MASK(255, 255, 255, 0);
IPAddress NODE_DNS (192, 168, 7, 1);

const char* MQTT_HOST = "192.168.7.101";   // laptop server (broker)
const int   MQTT_PORT = 1883;

const char* TOPIC_DATA   = "iot/jarak";
const char* TOPIC_STATUS = "iot/jarak/status";
const char* CLIENT_ID    = "mint-node2-jarak";

const uint32_t HEARTBEAT_MS = 10000UL;     // heartbeat 10 dtk (baseline v9)
const float    AMBANG_PINTU = 50.0;        // cm — di bawah ini "pintu_buka"
const float    DELTA_GERAK  = 10.0;        // cm — perubahan berarti
const uint32_t MIN_EVENT_MS = 1000UL;      // jeda minimal antar event

const uint8_t PIN_TRIG = 5;
const uint8_t PIN_ECHO = 18;               // lewat pembagi tegangan!
const uint8_t PIN_LED  = 2;
// ---------------------------------------------------------------------

#include <WiFi.h>
#include <PubSubClient.h>

WiFiClient net;
PubSubClient mqtt(net);

bool   pakaiStatis = true;
float  jarakTerakhir = -1.0;
uint32_t tWiFiDown = 0, tMqttDown = 0, tCobaMqtt = 0, tEvent = 0, tBeat = 0;

void setLED(bool nyala) { digitalWrite(PIN_LED, nyala ? HIGH : LOW); }

float bacaJarakCm() {
  digitalWrite(PIN_TRIG, LOW);  delayMicroseconds(3);
  digitalWrite(PIN_TRIG, HIGH); delayMicroseconds(10);
  digitalWrite(PIN_TRIG, LOW);
  long d = pulseIn(PIN_ECHO, HIGH, 30000);   // timeout 30 ms
  if (d == 0) return NAN;                    // tidak ada pantulan
  return d * 0.0343 / 2.0;                   // kecepatan suara
}

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
    tBeat = millis() - HEARTBEAT_MS;            // heartbeat pertama SEGERA
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

void kirimEvent(const char* jenis, float jarak) {
  String p = "{\"device\":\"ESP32-2\",\"sensor\":\"HC-SR04\"";
  p += ",\"jarak_cm\":" + String(jarak, 1);
  p += ",\"event\":\"" + String(jenis) + "\"";
  p += ",\"ts\":" + String(millis() / 1000) + "}";
  bool ok = mqtt.publish(TOPIC_DATA, p.c_str());
  Serial.println("[PUBLISH:" + String(jenis) + "] " + p + (ok ? "" : " (GAGAL)"));
  setLED(false); delay(60); setLED(true);
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_TRIG, OUTPUT);
  pinMode(PIN_ECHO, INPUT);
  pinMode(PIN_LED, OUTPUT);
  setLED(false);

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
  float jarak = bacaJarakCm();

  bool adaGerakan = (!isnan(jarak) && jarakTerakhir > 0 &&
                     fabs(jarak - jarakTerakhir) > DELTA_GERAK);
  bool pintuBuka  = (!isnan(jarak) && jarak < AMBANG_PINTU);

  /* EVENT: kirim saat pintu terdeteksi / jarak berubah signifikan */
  if ((!isnan(jarak)) && (pintuBuka || adaGerakan) &&
      (kini - tEvent) > MIN_EVENT_MS) {
    tEvent = kini;
    kirimEvent(pintuBuka ? "pintu_buka" : "gerakan", jarak);
  }

  /* HEARTBEAT tiap 30 dtk — TETAP jalan walau sensor gagal (fix v9.1):
   * jarak -1 + event "sensor_error" => dashboard tahu node hidup tapi
   * sensornya bermasalah, bukan node yang mati. */
  if (kini - tBeat >= HEARTBEAT_MS) {
    tBeat = kini;
    if (!isnan(jarak)) kirimEvent("heartbeat", jarak);
    else               kirimEvent("sensor_error", -1.0);
  }

  if (!isnan(jarak)) jarakTerakhir = jarak;
  delay(120);
}
