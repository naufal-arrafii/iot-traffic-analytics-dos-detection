#!/usr/bin/env python3
"""MINT - Jalankan 1 sesi pengujian berlabel (adaptasi run_session.py IoT Traffic Monitor).

  *** CATATAN v9.2.5: skrip ini LEGACY (butuh tshark/Wireshark). ***
  Cara utama merekam sesi sekarang adalah menu "Sesi & Dataset" di dashboard
  (http://localhost:5000/sesi) — perekam mandiri murni Python yang MENJAMIN
  PCAP + CSV terisi tanpa tshark. Skrip ini tetap disediakan untuk laptop
  yang MEMANG punya Wireshark dan ingin capture level NIC penuh (termasuk
  paket non-MQTT).

Satu perintah untuk tiga hal sekaligus:
  1. tshark merekam paket mentah  -> captures/<label>.pcap
  2. analyzer live mendeteksi     -> run/state.json + alerts.jsonl + dashboard
  3. setelah berhenti, dataset CSV -> data/dataset_<label>.csv (untuk Bab 6)

Pemakaian:
  python scripts/run_session.py <label> [durasi_detik] [--iface Wi-Fi]
Contoh:
  python scripts/run_session.py BASE 300
  python scripts/run_session.py S1 120 --iface Wi-Fi

Tekan Ctrl+C untuk menghentikan lebih awal (dataset tetap dibuat).
"""
import argparse
import os
import signal
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from analyzer.tshark_io import resolve_tshark  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Sesi pengujian berlabel MINT")
    ap.add_argument("label", help="nama sesi, contoh: BASE, S1, S2, S3, S4")
    ap.add_argument("durasi", nargs="?", type=int, default=None,
                    help="durasi sesi dalam detik (default: sampai Ctrl+C)")
    ap.add_argument("--iface", default=os.environ.get("MINT_IFACE", "Wi-Fi"),
                    help="interface capture (default: Wi-Fi, atau env MINT_IFACE)")
    args = ap.parse_args()

    tshark = resolve_tshark()
    if not tshark:
        print("[!] tshark tidak ditemukan — install Wireshark / tambahkan PATH")
        sys.exit(1)

    cap_dir = os.path.join(ROOT, "captures")
    os.makedirs(cap_dir, exist_ok=True)
    pcap = os.path.join(cap_dir, f"{args.label}.pcap")

    # --- 1. perekam pcap
    rec = subprocess.Popen([tshark, "-i", args.iface, "-w", pcap],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[pcap]    merekam ke {pcap} (interface: {args.iface})")

    # --- 2. analyzer live
    ana = subprocess.Popen([sys.executable,
                            os.path.join(ROOT, "analyzer", "live_analyzer.py"),
                            "--iface", args.iface],
                           cwd=ROOT)
    print(f"[analyzer] live_analyzer berjalan (PID {ana.pid})")
    print("[info]    tekan Ctrl+C untuk menghentikan sesi\n")

    def berhenti(*_):
        print("\n[stop] menghentikan sesi...")
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, berhenti)
    try:
        if args.durasi:
            end = time.time() + args.durasi
            while time.time() < end and ana.poll() is None:
                time.sleep(0.5)
        else:
            while ana.poll() is None:
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        for p in (ana, rec):
            if p.poll() is None:
                p.terminate()
        for p in (ana, rec):
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()

    # --- 3. dataset CSV dari pcap
    out_csv = os.path.join(ROOT, "data", f"dataset_{args.label}.csv")
    print(f"\n[dataset] memproses {os.path.basename(pcap)} -> {os.path.relpath(out_csv, ROOT)}")
    r = subprocess.run([sys.executable,
                        os.path.join(ROOT, "analyzer", "pcap_analyzer.py"),
                        "--pcap", pcap, "--out", out_csv, "--label", args.label],
                       cwd=ROOT)
    if r.returncode == 0 and os.path.exists(out_csv):
        print(f"[OK] sesi '{args.label}' selesai:")
        print(f"     pcap    : {os.path.relpath(pcap, ROOT)}")
        print(f"     dataset : {os.path.relpath(out_csv, ROOT)}")
        print(f"     grafik  : python scripts/plot_compare.py data/dataset_BASE.csv {os.path.relpath(out_csv, ROOT)}")
    else:
        print("[!] pembuatan dataset gagal — pcap tetap tersimpan, jalankan manual:")
        print(f"    python analyzer/pcap_analyzer.py --pcap \"{pcap}\" --out \"{out_csv}\" --label {args.label}")


if __name__ == "__main__":
    main()
