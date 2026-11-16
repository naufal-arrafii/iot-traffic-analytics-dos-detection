#!/usr/bin/env python3
"""MINT - Grafik perbandingan antar sesi (adaptasi plot_compare.py IoT Traffic Monitor).

Membaca satu atau beberapa CSV hasil analyzer (pcap_analyzer.py / live sesi)
lalu menggambar perbandingan packet rate (PPS) dan throughput (BPS) per
perangkat, diberi warna berbeda per kombinasi (perangkat, label).

Contoh:
  python scripts/plot_compare.py data/demo_normal.csv data/demo_serangan.csv
  python scripts/plot_compare.py data/dataset_BASE.csv data/dataset_S1.csv --out grafik_S1.png

Format CSV yang dibaca (keluaran analyzer/pcap_analyzer.py):
  ts,label,device,mac,n_publish,n_connect,bytes,avg_pkt_size,topics,retrans,topic_last
"""
import argparse
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser(description="Grafik perbandingan sesi MINT")
    ap.add_argument("csv", nargs="+", help="file CSV dataset (boleh lebih dari satu)")
    ap.add_argument("--out", default="grafik_perbandingan.png",
                    help="nama file PNG keluaran (default: grafik_perbandingan.png)")
    args = ap.parse_args()

    frames = []
    for f in args.csv:
        if not os.path.exists(f):
            print(f"[!] tidak ditemukan: {f}")
            sys.exit(1)
        df = pd.read_csv(f)
        df["_sumber"] = os.path.basename(f)
        frames.append(df)
    data = pd.concat(frames, ignore_index=True)

    if "ts" not in data.columns or "n_publish" not in data.columns:
        print("[!] format CSV tidak dikenali (harus keluaran pcap_analyzer.py)")
        sys.exit(1)

    data["ts"] = pd.to_numeric(data["ts"], errors="coerce")
    data = data.dropna(subset=["ts"])
    if data.empty:
        print("[!] tidak ada baris data")
        sys.exit(1)
    t0 = data["ts"].min()
    data["detik"] = (data["ts"] - t0).astype(int)

    keys = data.groupby(["device", "label"]).size().reset_index()[["device", "label"]]
    if len(keys) == 0:
        print("[!] tidak ada data perangkat")
        sys.exit(1)

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8), sharex=True,
                                   constrained_layout=True)
    cmap = plt.get_cmap("tab10")

    for i, row in keys.iterrows():
        dev, lab = row["device"], row["label"]
        d = data[(data["device"] == dev) & (data["label"] == lab)].sort_values("detik")
        style = "-" if str(lab).upper().startswith("B") else "--"
        label = f"{dev} [{lab}]"
        ax1.plot(d["detik"], d["n_publish"], style, marker=".", linewidth=1.2,
                 markersize=3, color=cmap(i % 10), label=label)
        ax2.plot(d["detik"], d["bytes"] / 1024.0, style, marker=".", linewidth=1.2,
                 markersize=3, color=cmap(i % 10), label=label)

    ax1.set_ylabel("PUBLISH per detik (PPS)")
    ax1.set_title("MINT — Perbandingan Traffic Normal vs Skenario Serangan")
    ax1.grid(alpha=0.3)
    ax1.legend(fontsize=8, ncol=2, loc="upper left")

    ax2.set_ylabel("Throughput (KB/s)")
    ax2.set_xlabel("Detik ke- sesi")
    ax2.grid(alpha=0.3)

    fig.savefig(args.out, dpi=150)
    print(f"[OK] grafik tersimpan: {os.path.abspath(args.out)}")
    print(f"     {len(keys)} kurva dari {len(args.csv)} file CSV")


if __name__ == "__main__":
    main()
