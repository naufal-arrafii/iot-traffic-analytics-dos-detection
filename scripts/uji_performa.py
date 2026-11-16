#!/usr/bin/env python3
"""MINT - Alat uji performa jaringan MQTT (jobdesk Steven: QoS, latency, throughput, packet loss).

Cara kerja: satu script membuka DUA klien ke broker —
  1. SUBSCRIBER : menerima pesan uji, mencatat waktu kedatangan.
  2. PUBLISHER  : mengirim pesan uji berisi stempel waktu + payload seukuran --size.
Karena publisher & subscriber berjalan di mesin yang sama, selisih waktu
kirim-terima adalah latency end-to-end melalui broker (publish -> broker -> deliver).

Contoh:
  python scripts/uji_performa.py                                   # normal: QoS 0, 10 msg/dtk, 256 B, 60 dtk
  python scripts/uji_performa.py --qos 1 --duration 60             # perbandingan QoS 1
  python scripts/uji_performa.py --rate 100 --size 4096 --csv hasil_uji/beban.csv
  python scripts/uji_performa.py --host 192.168.7.10
"""
import argparse
import csv
import json
import os
import statistics
import sys
import threading
import time

try:
    import paho.mqtt.client as mqtt
    from paho.mqtt.enums import CallbackAPIVersion
except ImportError:
    print("[!] paho-mqtt belum terpasang: pip install paho-mqtt")
    sys.exit(1)

TOPIC = "uji/performa"


def broker_default():
    try:
        with open(os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "devices.json"), encoding="utf-8") as f:
            return json.load(f).get("broker_ip", "192.168.7.101")
    except OSError:
        return "192.168.7.101"


def main():
    ap = argparse.ArgumentParser(description="Uji performa broker MQTT (MINT)")
    ap.add_argument("--host", default=broker_default(), help="IP broker (default dari devices.json)")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--qos", type=int, default=0, choices=[0, 1], help="QoS pengiriman uji")
    ap.add_argument("--rate", type=float, default=10.0, help="pesan per detik")
    ap.add_argument("--size", type=int, default=256, help="ukuran payload (byte)")
    ap.add_argument("--duration", type=int, default=60, help="durasi uji (detik)")
    ap.add_argument("--csv", default=None, help="simpan hasil agregat ke file CSV")
    args = ap.parse_args()

    recv = []          # [(t_terima, t_kirim)]
    lock = threading.Lock()
    stop = time.time() + args.duration

    def on_message(_c, _u, msg):
        try:
            t_kirim = json.loads(msg.payload.decode())["ts"]
        except Exception:
            return
        if t_kirim <= 0:
            return
        with lock:
            recv.append((time.time(), t_kirim))

    # --- subscriber
    sub = mqtt.Client(CallbackAPIVersion.VERSION2, client_id="uji-perf-sub")
    sub.on_message = on_message
    sub.connect(args.host, args.port, keepalive=30)
    sub.subscribe(TOPIC, qos=args.qos)
    sub.loop_start()

    payload_pad = "#" * max(0, args.size - 80)

    def make_client(name):
        c = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=name)
        c.connect(args.host, args.port, keepalive=30)
        c.loop_start()
        return c

    # --- publisher
    pub = make_client("uji-perf-pub")
    time.sleep(0.5)

    sent = 0
    interval = 1.0 / args.rate if args.rate > 0 else 0
    print(f"[i] Uji performa -> {args.host}:{args.port} | QoS {args.qos} | "
          f"{args.rate} msg/dtk | payload {args.size} B | {args.duration} dtk")
    t0 = time.time()
    try:
        while time.time() < stop:
            pub.publish(TOPIC, json.dumps({"ts": time.time(), "pad": payload_pad}), qos=args.qos)
            sent += 1
            time.sleep(interval)
    except KeyboardInterrupt:
        pass

    time.sleep(1.5)                       # beri waktu pesan terakhir sampai
    with lock:
        received = list(recv)
    t_akhir = time.time()
    durasi = t_akhir - t0

    lat_ms = [(tr - tk) * 1000.0 for tr, tk in received]
    total_bytes = sum(args.size for _ in received)
    loss = max(0.0, (sent - len(received)) / sent * 100.0) if sent else 0.0

    print("\n================ HASIL UJI PERFORMA ================")
    print(f"Broker               : {args.host}:{args.port}")
    print(f"QoS                  : {args.qos}")
    print(f"Pesan terkirim       : {sent}")
    print(f"Pesan diterima       : {len(received)}")
    print(f"Packet loss          : {loss:.2f} %")
    if lat_ms:
        print(f"Latency avg/min/max  : {statistics.mean(lat_ms):.1f} / "
              f"{min(lat_ms):.1f} / {max(lat_ms):.1f} ms")
        print(f"Latency median/p95   : {statistics.median(lat_ms):.1f} / "
              f"{sorted(lat_ms)[int(len(lat_ms)*0.95)-1 if len(lat_ms) > 1 else 0]:.1f} ms")
    else:
        print("Latency              : tidak ada pesan diterima!")
    print(f"Throughput           : {len(received)/durasi:.1f} msg/dtk | "
          f"{total_bytes/1024.0/durasi:.1f} KB/dtk")
    print("====================================================")
    print("[i] Lanjutkan uji manual: ping node->broker, uji flood (S1/S4), "
          "uji reconnect, dan pantau docker logs -f mint-mosquitto")

    if args.csv:
        os.makedirs(os.path.dirname(os.path.abspath(args.csv)) or ".", exist_ok=True)
        baru = not os.path.exists(args.csv)
        with open(args.csv, "a", newline="") as f:
            w = csv.writer(f)
            if baru:
                w.writerow(["waktu", "host", "qos", "rate", "size", "durasi",
                            "terkirim", "diterima", "loss_pct",
                            "lat_avg_ms", "lat_min_ms", "lat_max_ms",
                            "throughput_msgs", "throughput_kbps"])
            w.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), args.host, args.qos,
                        args.rate, args.size, f"{durasi:.1f}", sent, len(received),
                        f"{loss:.2f}",
                        f"{statistics.mean(lat_ms):.1f}" if lat_ms else "-",
                        f"{min(lat_ms):.1f}" if lat_ms else "-",
                        f"{max(lat_ms):.1f}" if lat_ms else "-",
                        f"{len(received)/durasi:.1f}",
                        f"{total_bytes/1024.0/durasi:.1f}"])
        print(f"[i] Hasil disimpan: {args.csv}")

    pub.loop_stop(); sub.loop_stop()
    pub.disconnect(); sub.disconnect()


if __name__ == "__main__":
    main()
