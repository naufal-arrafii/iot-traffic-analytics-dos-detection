#!/usr/bin/env python3
"""MINT - Analisis offline berkas .pcap menjadi metrik per window 1 detik (CSV).

Dipakai untuk:
  1. Sesi BASE  -> CSV yang menjadi masukan threshold_baseline.py
  2. Sesi uji   -> dataset berlabel (skema Spesifikasi Teknis Bab 6)

Pemakaian:
  python analyzer/pcap_analyzer.py --pcap captures/base1.pcap --out data/base1_metrics.csv
  python analyzer/pcap_analyzer.py --pcap captures/s1_l2.pcap --label S1 --out data/s1_l2.csv
"""
import argparse
import csv
import os

from tshark_io import iter_pcapan

COLS = ["ts", "label", "device", "mac", "n_publish", "n_connect",
        "bytes", "avg_pkt_size", "topics", "retrans", "topic_last"]


def analyze(pcap, label="-"):
    """Yield baris metrik per (detik, perangkat) dari berkas pcap."""
    agg_sec = None
    buf = {}
    for pkt in iter_pcapan(pcap):
        sec = int(pkt["ts"])
        if agg_sec is None:
            agg_sec = sec
        if sec != agg_sec:
            for row in _flush(agg_sec, buf, label):
                yield row
            agg_sec, buf = sec, {}
        key = pkt["ip"]
        d = buf.setdefault(key, {"mac": pkt["mac"] or "-", "n_publish": 0,
                                 "n_connect": 0, "bytes": 0, "topics": set(),
                                 "retrans": 0, "topic_last": "-"})
        if pkt["msgtype"] == 3:
            d["n_publish"] += 1
            d["bytes"] += pkt["frame_len"]
            if pkt["topic"]:
                d["topics"].add(pkt["topic"])
                d["topic_last"] = pkt["topic"]
            if pkt["retrans"]:
                d["retrans"] += 1
        elif pkt["msgtype"] == 1:
            d["n_connect"] += 1
    if agg_sec is not None:
        for row in _flush(agg_sec, buf, label):
            yield row


def _flush(sec, buf, label):
    for ip, d in buf.items():
        n = d["n_publish"]
        yield {"ts": sec, "label": label, "device": ip, "mac": d["mac"],
               "n_publish": n, "n_connect": d["n_connect"], "bytes": d["bytes"],
               "avg_pkt_size": round(d["bytes"] / n, 1) if n else 0.0,
               "topics": len(d["topics"]), "retrans": d["retrans"],
               "topic_last": d["topic_last"]}


def main():
    ap = argparse.ArgumentParser(description="Ekstraksi metrik window 1 detik dari pcap")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", required=True, help="berkas CSV keluaran")
    ap.add_argument("--label", default="-",
                    help="label sesi: BASE / S1 / S2 / S3 / S4 (untuk dataset)")
    args = ap.parse_args()

    n = 0
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        for row in analyze(args.pcap, args.label):
            w.writerow(row)
            n += 1
    print(f"Selesai: {n} baris metrik -> {args.out} (label={args.label})")


if __name__ == "__main__":
    main()
