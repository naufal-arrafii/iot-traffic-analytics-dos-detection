#!/usr/bin/env python3
"""MINT demo — feeder sensor MQTT simulasi 4 node ESP32 (sesuai devices.json).

Node (interval baseline ~10 dtk sesuai proposal):
  ESP32-1  DHT22      iot/suhu    tiap 10 dtk         {"suhu": .., "kelembaban": ..}
  ESP32-2  HC-SR04    iot/jarak   event-based 2-6 dtk {"jarak": ..}
  ESP32-3  ESP32-CAM  iot/kamera  tiap 10 dtk         foto JPEG ~20 KB
  ESP32-4  BH1750     iot/cahaya  tiap 10 dtk         {"cahaya": ..}

Nilai sensor dibuat natural (gelombang halus + derau kecil) supaya grafik
terlihat hidup. Status LWT "online" di-publish retained ke iot/<x>/status.
"""
import io
import json
import math
import random
import signal
import sys
import time

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion

from PIL import Image, ImageDraw, ImageFilter

BROKER = ("127.0.0.1", 1883)
T0 = time.time()
running = True


def seed_random():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else None
    random.seed(seed)


def wave(period_s, amp, base, phase=0.0):
    """Nilai natural: gelombang campuran + derau kecil."""
    t = time.time() - T0
    v = (math.sin(2 * math.pi * t / period_s + phase) * 0.7 +
         math.sin(2 * math.pi * t / (period_s * 0.37) + phase * 2) * 0.3)
    return base + v * amp + random.uniform(-amp * 0.06, amp * 0.06)


def make_cam_jpeg(seq):
    """Foto JPEG 'koridor' sintetis ~18-24 KB dengan stempel waktu."""
    w, h = 640, 480
    img = Image.new("RGB", (w, h))
    d = ImageDraw.Draw(img)
    # langit-langit & lantai koridor (perspektif sederhana)
    for y in range(h):
        r = int(38 + 52 * y / h)
        g = int(44 + 50 * y / h)
        b = int(56 + 46 * y / h)
        d.line([(0, y), (w, y)], fill=(r, g, b))
    # cahaya di ujung koridor
    cx, cy = w // 2 + int(40 * math.sin(seq / 7)), h // 2 - 30
    for rad, col in ((150, (210, 225, 235)), (100, (235, 240, 245)),
                     (55, (250, 252, 255))):
        d.ellipse([cx - rad, cy - rad // 2, cx + rad, cy + rad // 2], fill=col)
    img = img.filter(ImageFilter.GaussianBlur(6))
    d = ImageDraw.Draw(img)
    # dinding kiri/kanan
    d.polygon([(0, 0), (cx - 70, cy - 60), (cx - 70, cy + 70), (0, h)],
              fill=(26, 30, 40))
    d.polygon([(w, 0), (cx + 70, cy - 60), (cx + 70, cy + 70), (w, h)],
              fill=(30, 34, 45))
    # pintu di sepanjang koridor
    for i in range(3):
        x0 = 40 + i * 130
        d.rectangle([x0, 200 + i * 12, x0 + 60, 400], fill=(18, 22, 30),
                    outline=(60, 70, 85))
        d.rectangle([w - x0 - 60, 200 + i * 12, w - x0, 400],
                    fill=(20, 24, 33), outline=(60, 70, 85))
    # stempel waktu CCTV
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    d.rectangle([8, 8, 250, 40], fill=(0, 0, 0))
    d.text((14, 14), f"CAM-01 {stamp}", fill=(240, 240, 240))
    d.rectangle([w - 120, h - 34, w - 8, h - 8], fill=(0, 0, 0))
    d.text((w - 112, h - 30), f"#{seq:05d}", fill=(220, 220, 220))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=72, optimize=True)
    data = buf.getvalue()
    # sesuaikan ukuran target 18-24 KB lewat kualitas ulang bila perlu
    if len(data) > 24500:
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=55, optimize=True)
        data = buf.getvalue()
    return data


class Feeder:
    def __init__(self):
        self.cl = mqtt.Client(CallbackAPIVersion.VERSION2,
                              client_id="mint-feeder")
        self.cl.on_connect = self._on_connect
        self.cl.on_disconnect = self._on_disconnect
        self.seq = 0
        self.suhu_t = 0
        self.jarak_t = 0
        self.jarak_next = 3.0
        self.cam_t = 0
        self.cahaya_t = 0

    def _on_connect(self, *a):
        print("[feeder] tersambung ke broker", flush=True)

    def _on_disconnect(self, *a):
        print("[feeder] terputus — coba lagi…", flush=True)

    def pub(self, topic, payload, retain=False):
        self.cl.publish(topic, payload, qos=0, retain=retain)

    def start(self):
        self.cl.connect(*BROKER, keepalive=30)
        self.cl.loop_start()
        # LWT/status retained: semua node online
        for t in ("iot/suhu", "iot/jarak", "iot/kamera", "iot/cahaya"):
            self.pub(f"{t}/status", "online", retain=True)
        while running:
            now = time.time()
            self.seq += 1
            if now - self.suhu_t >= 10:
                self.suhu_t = now
                self.pub("iot/suhu", json.dumps({
                    "suhu": round(wave(180, 2.2, 27.5), 1),
                    "kelembaban": round(wave(240, 4.0, 66.0, 1.2), 1),
                }))
            if now - self.jarak_t >= self.jarak_next:
                self.jarak_t = now
                self.jarak_next = random.uniform(2, 6)   # event-based
                self.pub("iot/jarak", json.dumps({
                    "jarak": round(max(3, wave(95, 26, 78)), 1)}))
            if now - self.cam_t >= 10:
                self.cam_t = now
                self.pub("iot/kamera", make_cam_jpeg(self.seq))
            if now - self.cahaya_t >= 10:
                self.cahaya_t = now
                self.pub("iot/cahaya", json.dumps({
                    "cahaya": round(max(0, wave(300, 130, 420)), 0)}))
            time.sleep(0.4)


def main():
    seed_random()
    f = Feeder()
    f.start()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda *a: sys.exit(0))
    main()
