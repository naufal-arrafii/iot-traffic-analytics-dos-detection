#!/usr/bin/env python3
"""MINT - Pemeriksa kesiapan lingkungan host.

Memeriksa prasyarat host Windows sesuai arsitektur hybrid (Bab 2.3 spesifikasi):
  1. Versi Python
  2. Paket Python wajib (paho-mqtt, pandas, influxdb-client, flask)
  3. tshark: di PATH, atau di lokasi instalasi umum (dipakai otomatis oleh analyzer)
  4. Broker Mosquitto dapat dijangkau (port 1883)
  5. InfluxDB dapat dijangkau (port 8086)
  6. Grafana dapat dijangkau (port 3000)
"""
import json
import os
import shutil
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "analyzer"))
from tshark_io import resolve_tshark  # noqa: E402


def _ip_laptop():
    """IP LAN laptop ini (untuk info bila tidak sama dengan broker_ip)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def broker_ip():
    d = {}
    try:
        with open(os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "devices.json")) as f:
            d = json.load(f)
    except Exception:
        pass
    return d.get("broker_ip", "192.168.7.101")


def _reachable(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

OK, BAD, WARN = "[OK]  ", "[GAGAL]", "[CEK] "

checks = []


def report(label, ok, detail=""):
    marks = OK if ok is True else (BAD if ok is False else WARN)
    print(f"{marks}{label}" + (f" - {detail}" if detail else ""))
    checks.append(ok is not False)


def main():
    print("=== Pemeriksaan Lingkungan Host MINT ===\n")

    # 1. Python
    v = sys.version_info
    report("Python", v >= (3, 10), f"{v.major}.{v.minor}.{v.micro}")

    # 2. Paket Python wajib
    for mod, name in [("paho.mqtt.client", "paho-mqtt"),
                      ("pandas", "pandas"),
                      ("influxdb_client", "influxdb-client"),
                      ("flask", "flask (dashboard)")]:
        try:
            __import__(mod)
            report(f"Paket {name}", True)
        except ImportError:
            report(f"Paket {name}", False, "pip install -r requirements.txt")

    # Opsional (grafik/analisis lanjutan) - tidak menghalangi
    try:
        import matplotlib  # noqa: F401
        report("Paket matplotlib (opsional)", True)
    except ImportError:
        report("Paket matplotlib (opsional)", None, "pip install matplotlib")

    # Opsional (panel Pemakaian Server di dashboard)
    try:
        import psutil  # noqa: F401
        report("Paket psutil (opsional)", True, "utk panel Pemakaian Server")
    except ImportError:
        report("Paket psutil (opsional)", None,
               "pip install psutil (CPU/RAM/disk di dashboard)")

    # 3. tshark: PATH -> lokasi umum (installer Wireshark Windows TIDAK
    #    menambahkan PATH secara default; analyzer tetap bisa memakai lokasi umum)
    exe = resolve_tshark()
    in_path = bool(shutil.which("tshark"))
    if exe and in_path:
        report("tshark ditemukan di PATH", True, exe)
    elif exe:
        report("tshark ditemukan (di luar PATH)", True,
               f"{exe} - analyzer otomatis memakai lokasi ini; "
               f"agar bisa diketik manual: set \"PATH=%PATH%;{os.path.dirname(exe)}\" "
               f"lalu buka terminal baru")
    else:
        report("tshark tidak ditemukan", False,
               "Instal Wireshark (wireshark.org, ikutkan Npcap). Bila sudah "
               "terinstal, tambahkan foldernya ke PATH lalu buka terminal BARU.")

    # 4-6. Port layanan (broker dicek di 127.0.0.1 DAN IP LAN yang dipakai ESP32)
    broker_lan = broker_ip()
    myip = _ip_laptop()
    if myip and myip != broker_lan:
        report(f"IP laptop ini = {myip}, devices.json broker_ip = {broker_lan}", None,
               "Bila firmware ESP32 menunjuk ke " + broker_lan + ", samakan: "
               "set IP statis/DHCP reservation laptop menjadi " + broker_lan
               + " atau ubah broker_ip di devices.json")
    for port, svc in [(1883, "Mosquitto"), (8086, "InfluxDB"), (3000, "Grafana")]:
        hosts = ["127.0.0.1"]
        detail = ""
        if port == 1883:
            hosts.append(broker_lan)
        ok = False
        for h in hosts:
            try:
                with socket.create_connection((h, port), timeout=2):
                    ok = True
                    detail = f"{h}:{port}"
                    break
            except OSError:
                continue
        if ok:
            if port == 1883 and not _reachable(broker_lan, port):
                report(f"{svc} (port {port}) dapat dijangkau", True,
                       f"127.0.0.1 OK, tapi {broker_lan} TIDAK terjangkau - "
                       f"ESP32 tidak akan bisa connect! Cek: IP laptop = {broker_lan}? "
                       f"Windows Firewall izinkan TCP 1883")
            else:
                report(f"{svc} (port {port}) dapat dijangkau", True, detail or "127.0.0.1")
        else:
            report(f"{svc} (port {port}) dapat dijangkau", False, "docker compose up -d")

    print()
    if all(checks):
        print("Lingkungan SIAP. Lanjutkan dengan:")
        print("  jalankan_demo.bat      (demo replay + dashboard, 1 klik)")
        print("  jalankan_analyzer.bat  (deteksi real-time dari Wi-Fi)")
        print("  jalankan_dashboard.bat (web dashboard :5000, login admin/mintadmin)")
    else:
        print("Ada item GAGAL - selesaikan dulu sebelum lanjut.")
        sys.exit(1)


if __name__ == "__main__":
    main()
