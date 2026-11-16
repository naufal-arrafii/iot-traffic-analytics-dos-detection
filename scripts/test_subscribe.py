#!/usr/bin/env python3
"""MINT - Subscriber verifikasi pesan dari seluruh topik iot/#.

Menampilkan setiap pesan dengan stempel waktu, topik, ukuran, dan QoS.
Cocok dijalankan di terminal terpisah bersama test_publish.py untuk
memastikan broker meneruskan pesan dengan benar.

Pemakaian:
  python scripts/test_subscribe.py
  python scripts/test_subscribe.py --count 20   # berhenti setelah 20 pesan
"""
import argparse
import time

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion


def main():
    ap = argparse.ArgumentParser(description="Subscriber verifikasi MINT")
    ap.add_argument("--host", default="192.168.7.101")   # server laptop (sama seperti firmware ESP32)
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--count", type=int, default=0,
                    help="berhenti setelah N pesan (0 = tanpa batas)")
    args = ap.parse_args()

    received = {"n": 0}

    def on_connect(client, userdata, flags, rc, props=None):
        print(f"Terhubung (rc={rc}); subscribe iot/# ...", flush=True)
        client.subscribe("iot/#", qos=1)

    def on_message(client, userdata, msg):
        received["n"] += 1
        size = len(msg.payload)
        preview = msg.payload[:60].decode("utf-8", errors="replace")
        if size > 60:
            preview += "..."
        print(f"[{time.strftime('%H:%M:%S')}] {msg.topic} | {size} B | {preview}",
              flush=True)
        if args.count and received["n"] >= args.count:
            client.disconnect()

    client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id="mint-observer")
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(args.host, args.port, keepalive=60)

    try:
        client.loop_forever()
    except KeyboardInterrupt:
        pass
    print(f"Total pesan diterima: {received['n']}")


if __name__ == "__main__":
    main()
