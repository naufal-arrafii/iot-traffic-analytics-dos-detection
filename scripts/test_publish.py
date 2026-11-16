#!/usr/bin/env python3
"""MINT - Simulator traffic normal 4 perangkat ESP32 dari laptop.

Tujuan: memverifikasi infrastruktur (broker, perekaman, dashboard) SEBELUM
perangkat ESP32 fisik dirakit. Profil sesuai Tabel 3.1 Spesifikasi Teknis MINT:

  ESP32-1 (DHT22)   : publish periodik 10 detik, JSON suhu/kelembaban, QoS 1
  ESP32-2 (HC-SR04) : heartbeat 15 detik + event acak, JSON jarak, QoS 1
  ESP32-3 (ESP32-CAM): publish periodik 60 detik, payload 15-25 KB, QoS 0
  ESP32-4 (BH1750)  : publish periodik 5 detik, JSON intensitas cahaya, QoS 1

Pemakaian:
  python scripts/test_publish.py               # jalan tanpa batas (Ctrl+C stop)
  python scripts/test_publish.py --duration 60 # berhenti setelah 60 detik
  python scripts/test_publish.py --foto        # kamera kirim JPEG asli (uji foto live)
"""
import argparse
import json
import os
import random
import threading
import time

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion

BROKER_HOST = "192.168.7.101"   # = server laptop (sesuai devices.json / firmware ESP32)
BROKER_PORT = 1883
FOTO_JPEG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mint_cam_demo.jpg")

DEVICES = [
    # Interval baseline FINAL (v9): SEMUA node 10 dtk — selaras proposal
    # (Bab 3.4/Tabel 3.6.2), devices.json, firmware/, dan kalibrasi threshold
    # BASE. ESP32-2 di firmware asli event-based (2-6 dtk); simulator memakai
    # 10 dtk agar mudah diuji.
    {"id": "ESP32-1", "topic": "iot/suhu", "interval": 10, "qos": 1},
    {"id": "ESP32-2", "topic": "iot/jarak", "interval": 10, "qos": 1},
    {"id": "ESP32-3", "topic": "iot/kamera", "interval": 10, "qos": 0},
    {"id": "ESP32-4", "topic": "iot/cahaya", "interval": 10, "qos": 1},
]

stop_event = threading.Event()
sent_counter = {"total": 0}
lock = threading.Lock()


def log(dev, msg):
    print(f"[{time.strftime('%H:%M:%S')}] {dev}: {msg}", flush=True)


_jpeg_cache = None


def make_photo_payload():
    """JPEG asli (mint_cam_demo.jpg) + segmen komentar berisi stempel waktu.

    Segmen komentar JPEG (marker FF FE) diabaikan decoder tapi membuat tiap
    publish memiliki byte/ukuran unik -- meniru kamera live sungguhan.
    Dipakai oleh opsi --foto.
    """
    global _jpeg_cache
    if _jpeg_cache is None:
        try:
            with open(FOTO_JPEG, "rb") as f:
                _jpeg_cache = f.read()
        except OSError:
            _jpeg_cache = None
    if not _jpeg_cache:
        # fallback: teks palsu bila berkas foto demo tidak ada
        return "JPEG-FAKE|" + "x" * random.randint(15 * 1024, 25 * 1024)
    cmt = (f"MINT-CAM {time.strftime('%Y-%m-%d %H:%M:%S')}"
           f" #{make_photo_payload.seq}").encode()
    make_photo_payload.seq += 1
    seg = b"\xff\xfe" + (len(cmt) + 2).to_bytes(2, "big") + cmt
    return _jpeg_cache[:2] + seg + _jpeg_cache[2:]


make_photo_payload.seq = 1


def make_payload(dev, foto=False):
    """Bangun payload sesuai karakter sensor masing-masing."""
    if dev["id"] == "ESP32-1":
        return json.dumps({
            "device": "ESP32-1", "sensor": "DHT22",
            "suhu_c": round(random.uniform(28.0, 32.0), 1),
            "kelembaban_pct": round(random.uniform(60.0, 80.0), 1),
            "ts": int(time.time()),
        })
    if dev["id"] == "ESP32-2":
        return json.dumps({
            "device": "ESP32-2", "sensor": "HC-SR04",
            "jarak_cm": round(random.uniform(30.0, 200.0), 1),
            "event": random.choice(["heartbeat", "pintu_buka"]),
            "ts": int(time.time()),
        })
    if dev["id"] == "ESP32-3":
        if foto:                      # JPEG asli -> tampil sebagai foto live
            return make_photo_payload()
        # Payload besar meniru JPEG ~15-25 KB (byte acak dengan header palsu)
        size = random.randint(15 * 1024, 25 * 1024)
        return "JPEG-FAKE|" + "x" * size
    if dev["id"] == "ESP32-4":
        return json.dumps({
            "device": "ESP32-4", "sensor": "BH1750",
            "lux": round(random.uniform(100.0, 900.0), 1),
            "ts": int(time.time()),
        })
    raise ValueError(dev["id"])


def device_loop(client, dev, foto=False):
    """Loop publish satu perangkat sampai stop_event diset."""
    # Selingi start agar pesan antar perangkat tidak menumpuk di detik yang sama
    time.sleep(random.uniform(0.1, 1.5))
    while not stop_event.is_set():
        payload = make_payload(dev, foto=foto)
        info = client.publish(dev["topic"], payload, qos=dev["qos"])
        if info.rc == mqtt.MQTT_ERR_SUCCESS:
            with lock:
                sent_counter["total"] += 1
            size_kb = len(payload) / 1024
            log(dev["id"], f"publish {size_kb:.1f} KB ke {dev['topic']} (QoS {dev['qos']})")
        else:
            log(dev["id"], f"GAGAL publish rc={info.rc}")
        # Event tambahan acak untuk ESP32-2 (meniru trigger pintu)
        wait = dev["interval"]
        if dev["id"] == "ESP32-2" and random.random() < 0.3:
            wait = random.uniform(2.0, 6.0)
        stop_event.wait(wait)


def main():
    ap = argparse.ArgumentParser(description="Simulator traffic normal MINT")
    ap.add_argument("--duration", type=int, default=0,
                    help="durasi detik (0 = tanpa batas, Ctrl+C untuk berhenti)")
    ap.add_argument("--host", default=BROKER_HOST)
    ap.add_argument("--port", type=int, default=BROKER_PORT)
    ap.add_argument("--foto", action="store_true",
                    help="kamera mengirim JPEG asli (uji fitur foto live dashboard)")
    args = ap.parse_args()

    client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id="mint-simulator")
    client.on_connect = lambda c, u, f, rc, props=None: print(
        f"[{time.strftime('%H:%M:%S')}] Terhubung ke broker {args.host}:{args.port} (rc={rc})",
        flush=True)
    client.connect(args.host, args.port, keepalive=60)
    client.loop_start()

    threads = [threading.Thread(target=device_loop, args=(client, d),
                                kwargs={"foto": args.foto}, daemon=True)
               for d in DEVICES]
    for t in threads:
        t.start()
    log("SIM", "4 perangkat simulasi berjalan"
        + (" (kamera: JPEG asli --foto)" if args.foto else "")
        + ". Ctrl+C untuk berhenti.")

    try:
        if args.duration > 0:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        time.sleep(0.5)
        client.loop_stop()
        client.disconnect()
        log("SIM", f"Selesai. Total pesan terkirim: {sent_counter['total']}")


if __name__ == "__main__":
    main()
