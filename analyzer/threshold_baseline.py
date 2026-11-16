#!/usr/bin/env python3
"""MINT - Hitung threshold dari metrik sesi BASE (Spesifikasi Teknis Bab 5).

Rumus per perangkat per metrik:  threshold = median + k * 1.4826 * MAD
Dengan pengaman untuk sebaran nol (MAD = 0, khas perangkat periodik):
  * threshold minimal = floor absolut per metrik
  * bila MAD = 0      : threshold = median + 50% + 1

Hanya window yang memiliki PUBLISH yang dievaluasi (window kosong diabaikan)
agar perangkat jarang-kirim (mis. ESP32-CAM tiap 60 s) tidak menghasilkan
threshold palsu bernilai 0.

Pemakaian:
  python analyzer/threshold_baseline.py --csv data/base1_metrics.csv data/base2_metrics.csv
  python analyzer/threshold_baseline.py --csv data/base1_metrics.csv --k 3 --out thresholds.json
"""
import argparse
import json
import statistics

import pandas as pd

FLOORS = {"pps": 2.0, "bps": 4096.0, "avg_pkt_size": 4096.0}


def _threshold(values, k, floor):
    """Hitung median + k*1.4826*MAD dengan pengaman sebaran nol."""
    med = statistics.median(values)
    mad = statistics.median([abs(v - med) for v in values])
    if mad > 0:
        thr = med + k * 1.4826 * mad
    else:
        thr = med * 1.5 + 1.0
    thr = max(thr, floor, med + 1.0)
    return {
        "median": round(med, 1), "mad": round(mad, 1),
        "max_observed": round(max(values), 1),
        "threshold": round(thr, 1), "k": k, "floor": floor,
    }


def compute(csv_paths, k=3.0):
    frames = [pd.read_csv(p) for p in csv_paths]
    df = pd.concat(frames, ignore_index=True)
    df = df[df["n_publish"] > 0]          # hanya window aktif
    metrics = {"pps": "n_publish", "bps": "bytes", "avg_pkt_size": "avg_pkt_size"}
    devices = {}
    for ip, g in df.groupby("device"):
        devices[ip] = {"mac": str(g["mac"].mode().iat[0]) if len(g) else "-"}
        for metric, col in metrics.items():
            devices[ip][metric] = _threshold(g[col].astype(float).tolist(), k, FLOORS[metric])
    # fallback global: nilai tertinggi antar perangkat (untuk perangkat tak dikenal)
    glob = {}
    for metric in metrics:
        vals = [d[metric]["threshold"] for d in devices.values()] or [FLOORS[metric]]
        glob[metric] = round(max(vals) * 1.5, 1)
    return {
        "generated": True,
        "source_csv": [str(p) for p in csv_paths],
        "n_windows": int(len(df)),
        "params": {
            "k": k, "floors": FLOORS,
            "cooldown_s": 30.0, "recovery_s": 60.0,
            "metrics": {
                "pps":          {"lookback": 3, "confirm": 2, "override": 5.0},
                "bps":          {"lookback": 3, "confirm": 2, "override": 5.0},
                "avg_pkt_size": {"lookback": 1, "confirm": 1, "override": 3.0},
            },
        },
        "devices": devices,
        "global": glob,
    }


def main():
    ap = argparse.ArgumentParser(description="Kalkulator threshold baseline MINT")
    ap.add_argument("--csv", nargs="+", required=True,
                    help="satu atau lebih berkas metrik CSV hasil pcap_analyzer.py")
    ap.add_argument("--out", default="thresholds.json")
    ap.add_argument("--k", type=float, default=3.0)
    args = ap.parse_args()

    result = compute(args.csv, k=args.k)
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Threshold ditulis ke {args.out}  "
          f"({result['n_windows']} window aktif, k={args.k})\n")
    print(f"{'Perangkat':<18}{'Metrik':<14}{'Median':>9}{'MAD':>8}{'Max':>10}{'THR':>10}")
    for ip, dev in result["devices"].items():
        for metric in ("pps", "bps", "avg_pkt_size"):
            m = dev[metric]
            print(f"{ip:<18}{metric:<14}{m['median']:>9}{m['mad']:>8}"
                  f"{m['max_observed']:>10}{m['threshold']:>10}")
    print(f"\nFallback perangkat tak dikenal (global): {result['global']}")


if __name__ == "__main__":
    main()
