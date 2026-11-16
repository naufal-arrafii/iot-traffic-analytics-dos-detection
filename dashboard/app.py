#!/usr/bin/env python3
"""MINT — Web dashboard Flask v9.2.5: sesi rekam tanpa tshark + threshold
live + peringatan serangan di semua halaman.

Perubahan penting v9.2.5 (perbaikan hasil uji lapangan v9.2.1):
  * SESI REKAM TANPA DEPENDENSI: perekam sesi baru (menu "Sesi & Dataset")
    membangun PCAP yang VALID sendiri dari setiap pesan MQTT yang dilihat
    broker (paket Ethernet/IP/TCP/MQTT-PUBLISH tersintesis lengkap dgn
    checksum, MAC & IP node asli dari devices.json) — file .pcap TIDAK
    PERNAH lagi kosong walau tshark/Wireshark tidak terpasang. Dataset CSV
    window 1-detik (skema sama dgn dataset_BASE.csv) ditulis langsung.
  * PERINGATAN SERANGAN DI SEMUA HALAMAN (fix "S4 tidak ada warning"):
    toast merah + bunyi lembut muncul di halaman APA PUN begitu alert baru
    terdeteksi; halaman Serangan kini punya panel "Deteksi Realtime"
    (status per node + log event) — sebelumnya halaman itu tidak
    menampilkan indikator deteksi sama sekali.
  * THRESHOLD LIVE DARI WEB: menu Pengaturan (admin) mengubah threshold
    per node per metrik — tersimpan ke thresholds.json dan langsung
    berlaku pada window BERIKUTNYA tanpa restart: status node, garis
    threshold di grafik, dan warna kartu node ikut berubah otomatis.
  * GRAFIK RESPONSIF 15 DETIK (fix "payload size tidak realtime"): metrik
    bergulir _15s (pps/bps/avg_pkt_size) — lonjakan S1/S3/S4 tampak dalam
    1-2 detik; doughnut distribusi memakai bps_15s sehingga tidak melompat
    liar antar detik + persentase per node.
  * ANTI-FLAPPING NODE: ping ICMP dijalankan PARALEL per node (sebelumnya
    berurutan — satu node mati membuat siklus >15 dtk sehingga node lain
    tampak ikut offline); TTL kehadiran dinaikkan ke 20 dtk.
  * SERVER TIDAK DIHITUNG NODE: trafik dari IP broker/server sendiri
    disaring dari daftar perangkat (bug lama: laptop server muncul
    sebagai node "TAK TERDAFTAR").
  * Halaman baru: /sesi (Sesi & Dataset), /pengaturan (threshold + akun +
    Telegram), /log (Log Sistem lengkap dgn filter + unduh).

Perubahan penting v9.1 (stabilisasi uji lapangan):
  * STATE.JSON TAHAN KUNCI (fix PermissionError [WinError 5]).
  * FIRMWARE 4 NODE diperkuat: IP statis, fallback DHCP, LWT retained,
    self-healing restart. Node 3 (kamera) v9.2.5: buffer ganda + VGA —
    foto tiba jauh lebih cepat.

Halaman:
  /            Beranda         — KPI, kartu node, grafik PPS 15 dtk, log deteksi
  /nodes       Node            — detail node, foto live, sparkline, threshold
  /pps         Grafik PPS      — 4 panel realtime (PPS, B/s, distribusi, ukuran)
  /anomali     Anomali & Dataset — event + window > threshold, ekspor
  /serang      Serangan (Uji)  — kendali S1-S4 + panel Deteksi Realtime
  /sesi        Sesi & Dataset  — rekam sesi berlabel: PCAP + CSV + unduhan
  /server      Server          — pemakaian CPU/RAM/disk, layanan
  /log         Log Sistem      — log internal + event + riwayat serangan
  /pengaturan  Pengaturan      — threshold live, akun, Telegram
  /bantuan     Bantuan         — panduan, metrik, skenario, FAQ

Jalankan:
  python dashboard/app.py            # buka http://localhost:5000 (login dulu)
  python dashboard/app.py --port 5001

Akun bawaan: admin / mintadmin (ubah lewat menu Pengaturan atau add_user.py).
"""
import argparse
import atexit
import csv
import functools
import io
import json
import os
import platform
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from collections import deque
from datetime import datetime

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

from flask import (Flask, Response, jsonify, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BASE)
RUN_DIR = os.environ.get("MINT_RUN_DIR", os.path.join(ROOT, "run"))
DATA_DIR = os.path.join(ROOT, "data")
DEVICES_PATH = os.path.join(ROOT, "devices.json")
USERS_PATH = os.path.join(BASE, "users.json")
THRESHOLDS_PATH = os.path.join(ROOT, "thresholds.json")
SECRET_FILE = os.path.join(BASE, ".secret_key")

# modul analyzer dipakai ulang oleh analyzer terintegrasi (v8.1)
sys.path.insert(0, os.path.join(ROOT, "analyzer"))
import detection                                       # noqa: E402
import tshark_io                                       # noqa: E402
from live_analyzer import InfluxWriter, Output        # noqa: E402
from notifier import telegram_enabled                  # noqa: E402

STARTED = time.time()
LOGS = []                      # log sistem internal (tampil di halaman Server)

# sesi login: auto-logout setelah sekian menit idle
SESSION_MENIT = 30
# brute-force protection: N kali gagal dalam WINDOW detik -> IP dikunci LOCKOUT detik
LOGIN_MAX_FAILS = 5
LOGIN_WINDOW = 300
LOGIN_LOCKOUT = 300

app = Flask(__name__)
app.config.update(
    PERMANENT_SESSION_LIFETIME=SESSION_MENIT * 60,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


# ---------------------------------------------------------------------- util
def _read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def _secret_key():
    """Kunci session: dibuat sekali lalu disimpan agar login bertahan restart."""
    try:
        with open(SECRET_FILE, "rb") as f:
            key = f.read()
        if key:
            return key
    except OSError:
        pass
    key = os.urandom(32)
    with open(SECRET_FILE, "wb") as f:
        f.write(key)
    return key


app.secret_key = _secret_key()


def broker_ip():
    d = _read_json(DEVICES_PATH, {})
    return os.environ.get("MINT_BROKER_HOST") or d.get("broker_ip", "192.168.7.101")


def _log(msg):
    """Catat ke log sistem internal (tampil di halaman Server)."""
    text = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(text)
    LOGS.append(text)
    del LOGS[:-80]


# ============================================================== sensor parsing
# pemetaan nama field payload -> (label tampilan, satuan)
_READING_KEYS = [
    ("Suhu", ("suhu", "suhu_c", "temp", "temperature"), "°C"),
    ("Kelembaban", ("kelembaban", "kelembaban_pct", "hum", "humidity", "rh"), "%"),
    ("Jarak", ("jarak", "jarak_cm", "distance"), "cm"),
    ("Cahaya", ("cahaya", "lux", "light", "illuminance"), "lux"),
]
_TOPIC_HINT = {"suhu": ("Suhu", "°C"), "jarak": ("Jarak", "cm"),
               "cahaya": ("Cahaya", "lux")}


def _parse_readings(topic, raw):
    """Ubah payload MQTT menjadi daftar pembacaan sensor [{label, value, unit}].

    Mendukung JSON (nama field bebas: suhu/suhu_c/temp, lux/cahaya, dst.) dan
    teks polos berisi satu angka. Return None bila tidak ada angka yang dikenal.
    """
    hint = topic.rsplit("/", 1)[-1].lower() if topic else ""
    out = []
    try:
        data = json.loads(raw)
    except Exception:
        data = None
    if isinstance(data, dict):
        for label, keys, unit in _READING_KEYS:
            for k in keys:
                v = data.get(k)
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    out.append({"label": label, "value": v, "unit": unit})
                    break
        if not out:                      # fallback: field numerik pertama
            for k, v in data.items():
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    out.append({"label": k, "value": v, "unit": ""})
                    break
        return out or None
    txt = raw[:60].decode("utf-8", errors="replace").strip()
    try:
        val = float(txt)
    except ValueError:
        return None
    label, unit = _TOPIC_HINT.get(hint, (hint.capitalize() or "Nilai", ""))
    return [{"label": label, "value": val, "unit": unit}]


# ------------------------------------------------------------------ MQTT cache
class MqttCache:
    """Thread latar: subscribe iot/# lalu menyimpan data terakhir per topik.

    Menyimpan tiga hal:
      * latest[topic]  : {ts, size, readings, text}  -> nilai sensor realtime
      * photos[topic]  : {bytes, ts, count, size}    -> foto JPEG live (ESP32-CAM)
      * status[topic]  : ("ONLINE"/"OFFLINE", ts)    -> LWT / topik .../status

    Bila paho-mqtt tidak terpasang atau broker tidak terjangkau, fitur ini
    dinonaktifkan diam-diam (dashboard tetap berfungsi dari state.json).
    """

    _STATUS_SUFFIX = ("/status", "/lwt", "/avail", "/will", "/state")
    _OFFLINE_WORDS = ("offline", "mati", "down", "lost", "disconnected", "0", "false")
    _ONLINE_WORDS = ("online", "hidup", "up", "connected", "1", "true")

    def __init__(self, host, port=1883):
        self.host, self.port = host, port
        self.latest = {}          # topic -> {ts, size, readings, text}
        self.photos = {}          # topic -> {bytes, ts, count, size, history[]}
        self.status = {}          # topic dasar -> (kondisi, ts)
        self.connected = False
        self.enabled = False
        self.rx_count = 0
        self.photo_history_max = 10   # jumlah foto terakhir yang disimpan per topik
        # v9.2.5: hook perekam sesi — callable(ts, topic, raw_bytes) dipanggil
        # untuk SETIAP pesan data (bukan status/LWT). Perekam sesi memakai ini
        # untuk menulis PCAP + jendela CSV tanpa subscription tambahan.
        self.hooks = []
        # antrean metrik utk analyzer terintegrasi: (ts, topic, ukuran_byte)
        # per pesan non-status — di-drain thread IntegratedAnalyzer tiap detik.
        # deque thread-safe utk append/popleft (CPython); maxlen menahan banjir.
        self.metric_q = deque(maxlen=50000)
        try:
            import paho.mqtt.client as mqtt
            from paho.mqtt.enums import CallbackAPIVersion
            self.enabled = True
            self._mqtt = mqtt
            self._ver = CallbackAPIVersion.VERSION2
        except ImportError:
            return
        # client id UNIK per proses: dua jendela dashboard yang sama-sama
        # jalan tidak saling menendang dari broker (penyebab foto/live
        # "kadang muncul kadang tidak" saat ada dashboard ganda)
        self._cid = (f"mint-dashboard-{os.getpid()}-"
                     f"{secrets.token_hex(3)}")
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                c = self._mqtt.Client(self._ver, client_id=self._cid)
                c.on_connect = self._on_connect
                c.on_disconnect = self._on_disconnect
                c.on_message = self._on_message
                # v9.2.6: sambung ulang cepat (maks 5 dtk). Default paho
                # menambah jeda hingga 120 dtk setelah putus berulang, jadi
                # footer "payload live" hilang lama setelah serangan berat.
                c.reconnect_delay_set(min_delay=1, max_delay=5)
                c.connect(self.host, self.port, keepalive=60)
                c.loop_forever(retry_first_connection=True)
            except Exception:
                self.connected = False
                time.sleep(10)   # coba lagi tiap 10 detik

    def _on_connect(self, client, userdata, flags, rc, props=None):
        self.connected = (rc == 0)
        if self.connected:
            client.subscribe("iot/#", qos=0)
            _log(f"MQTT cache tersambung ke broker {self.host}:{self.port}")

    def _on_disconnect(self, *a):
        self.connected = False

    def _on_message(self, client, userdata, msg):
        raw = msg.payload
        topic = msg.topic or "?"
        now = time.time()
        self.rx_count += 1

        # topik status / LWT: ".../status", ".../lwt", dst.
        base = topic
        for suf in self._STATUS_SUFFIX:
            if topic.endswith(suf):
                base = topic[: -len(suf)]
                break
        else:
            base = None
        if base is not None:
            txt = raw[:40].decode("utf-8", errors="replace").strip().lower()
            if txt in self._OFFLINE_WORDS:
                self.status[base] = ("OFFLINE", now)
            elif txt in self._ONLINE_WORDS:
                self.status[base] = ("ONLINE", now)
            return

        # metrik terintegrasi: catat SEMUA pesan data (sensor + foto) agar
        # PPS/BPS tetap terbaca walaupun tshark tidak tersedia
        self.metric_q.append((now, topic, len(raw)))

        # v9.2.5: umpankan pesan ke perekam sesi (bila sedang merekam).
        # Dibungkus try agar perekam yang error tidak mengganggu cache.
        for hook in self.hooks:
            try:
                hook(now, topic, raw)
            except Exception:
                pass

        # foto JPEG (magic bytes FF D8) -> simpan bytes terakhir + riwayat
        if raw[:2] == b"\xff\xd8" and raw[-2:] == b"\xff\xd9":
            prev = self.photos.get(topic, {})
            seq = prev.get("count", 0) + 1
            hist = prev.get("history", [])
            hist.append({"seq": seq, "bytes": raw, "ts": now,
                         "size": len(raw)})
            if len(hist) > self.photo_history_max:
                hist.pop(0)
            self.photos[topic] = {"bytes": raw, "ts": now, "count": seq,
                                  "size": len(raw), "history": hist}
            self.latest[topic] = {"ts": now, "size": len(raw),
                                  "readings": None, "text": "(foto JPEG)"}
            return

        # payload sensor biasa
        entry = {"ts": now, "size": len(raw),
                 "readings": _parse_readings(topic, raw), "text": None}
        if entry["readings"] is None:
            txt = raw[:80].decode("utf-8", errors="replace")
            entry["text"] = txt if len(raw) <= 80 else txt[:60] + "…"
        self.latest[topic] = entry

    # -------------------------------------------------------------- akses
    def by_topic(self, topic):
        return self.latest.get(topic)

    def photo(self, topic, seq=None):
        ph = self.photos.get(topic)
        if not ph:
            return None
        if seq is not None:
            for it in ph.get("history", []):
                if it["seq"] == seq:
                    return it
            return None
        return ph

    def photo_history(self, topic):
        """Metadata riwayat foto (tanpa bytes) utk ditampilkan di dashboard."""
        ph = self.photos.get(topic)
        if not ph:
            return []
        return [{"seq": it["seq"], "age": int(time.time() - it["ts"]),
                 "size": it["size"]} for it in ph.get("history", [])]

    def status_of(self, topic):
        return self.status.get(topic)


CACHE = MqttCache(broker_ip())


# ------------------------------------------------ analyzer terintegrasi (v8.1)
def _detect_iface():
    """Cari interface capture: variabel MINT_IFACE dulu, lalu tebak dari tshark -D."""
    env = os.environ.get("MINT_IFACE")
    if env:
        return env
    exe = tshark_io.resolve_tshark()
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "-D"], capture_output=True, text=True,
                             timeout=15).stdout or ""
    except Exception:
        return None
    names = []
    for line in out.splitlines():
        m = re.match(r"^\s*\d+\.\s+(.+?)\s*(?:\([^)]*\))?\s*$", line)
        low = line.lower()
        if m and "loopback" not in low and "bluetooth" not in low \
                and "adapter for" not in low:
            names.append(m.group(1).strip())
    for want in ("wi-fi", "wifi", "wlan", "wireless", "ethernet", "eth"):
        for n in names:
            if want in n.lower():
                return n
    return names[0] if names else None


class IntegratedAnalyzer:
    """Analyzer real-time DI DALAM proses dashboard (v8.1, digabung v8.2).

    Sumber metrik (sejak v8.2 KEDUANYA dipakai sekaligus, per detik per
    perangkat diambil nilai terbesar agar tidak dihitung dua kali):
      1. tshark live capture  — interface terdeteksi otomatis (MINT_IFACE utk
         manual). Perangkat dikenali dari IP: cocok dengan pcap/InfluxDB/
         Grafana dan serangan dari laptop lain.
      2. subscribe MQTT iot/# — pesan yang sampai ke broker (perangkat dari
         topik via devices.json). Menyelamatkan serangan dari web (paket
         server->broker tidak lewat NIC fisik) dan kondisi tshark buta
         (interface salah / tanpa hak admin).
    Arbitrasi: bila state.json sedang ditulis analyzer eksternal yang masih
    segar (jalankan_analyzer.bat / mode replay demo), thread ini standby dan
    menyerahkan kendali; aktif otomatis lagi setelah analyzer itu berhenti.
    """

    def __init__(self, cache):
        self.cache = cache
        self.engine = self._make_engine()
        self.out = Output(RUN_DIR, self.engine, "mqtt")
        self.influx = None
        self.source = None            # "tshark:<iface>" | "mqtt" | None
        self.iface = _detect_iface()
        self.tshark_failed = not tshark_io.resolve_tshark()
        self._paused = False          # analyzer eksternal sedang aktif
        self._stop = False
        self._proc = None
        self._proc_lock = threading.Lock()
        # ---- v8.2: penggabungan dua sumber metrik ----
        self._tq = deque()            # jendela tshark yang baru saja tutup
        self._tq_lock = threading.Lock()
        self._pend = {}               # sec -> {device: baris gabungan}
        self._last_sec = 0            # detik terakhir yang sudah diproses
        self._last_handle_ts = 0.0    # waktu _handle/heartbeat terakhir
        self._tshark_last_row = 0.0   # waktu tshark terakhir menghasilkan baris
        self._blind_warned = False
        atexit.register(self._shutdown)
        if self.tshark_failed:
            _log("tshark tidak ditemukan — metrik PPS/BPS memakai fallback MQTT "
                 "(instal Wireshark utk capture per-IP)")
        threading.Thread(target=self._tshark_loop, daemon=True).start()
        threading.Thread(target=self._dispatch, daemon=True).start()

    # ---------------------------------------------------------- setup
    @staticmethod
    def _make_engine():
        thresholds = _read_json(THRESHOLDS_PATH, {})
        if not thresholds.get("devices"):
            _log("thresholds.json belum terkalibrasi — memakai fallback global "
                 "(jalankan threshold_baseline.py utk hasil terbaik)")
        return detection.ThresholdEngine(thresholds, thresholds.get("params"))

    def _init_influx(self):
        """InfluxDB opsional: 'auto' (default) hanya aktif bila terjangkau."""
        mode = os.environ.get("MINT_INFLUX", "auto").strip().lower()
        if mode in ("0", "off", "false", "no"):
            return None
        if mode not in ("1", "on", "true", "yes"):
            url = os.environ.get("MINT_INFLUX_URL", "http://localhost:8086")
            try:
                with urllib.request.urlopen(url.rstrip("/") + "/health",
                                            timeout=2) as r:
                    if r.status != 200:
                        return None
            except Exception:
                return None
        w = InfluxWriter()
        return w if w.ok else None

    # ---------------------------------------------------------- arbitrasi
    def _external_fresh(self):
        """True bila state.json sedang ditulis analyzer lain (masih segar)."""
        st = _read_json(os.path.join(RUN_DIR, "state.json"), None)
        if not st:
            return False
        src = str(st.get("source", ""))
        if src == "mqtt" or src.startswith("tshark:"):
            return False                      # milik thread ini
        wall = st.get("wall_ts") or st.get("updated_ts") or 0
        return 0 <= time.time() - wall <= 6

    # ---------------------------------------------------------- pipeline
    def _handle(self, rows, source, ts=None):
        """Satu detik selesai: deteksi + state.json + alerts + Telegram + Influx.

        v9.2.6: dipanggil SETIAP detik (rows boleh kosong) agar (a) grafik
        Grafana punya titik tiap detik untuk tiap node, (b) recovery node
        yang diam tetap dievaluasi (engine.tick), (c) status node idle
        diperbarui.
        """
        if ts is None:
            if not rows:
                return
            ts = rows[0]["ts"]
        self._last_handle_ts = time.time()
        events = []
        for r in rows:
            events += self.engine.update_window(r["ts"], r["device"],
                                                r["mac"], r)
        events += self.engine.tick(ts)
        self.out.source = source
        devices = self.out.write_state(ts, rows)
        self.out.append_alerts(events)
        # v8.2: tandai window dengan kode uji serangan web yang sedang jalan
        label = None
        atk = globals().get("ATTACK")
        if atk is not None:
            try:
                if atk.running() and atk.info:
                    label = atk.info.get("kode")
            except Exception:
                label = None
        if rows:
            self.out.log_anomaly_windows(self.engine, rows, serangan=label)
        Output.print_window(ts, rows, events, verbose=False)
        if self.influx:
            self.influx.write_second(ts, devices, self.engine,
                                     {"kode": label} if label else None)
            for ev in events:
                self.influx.write_alert(ev)

    def _mqtt_rows(self):
        """Drain antrean pesan MqttCache -> {detik: [baris window per perangkat]}.

        Topik dipetakan ke IP node lewat devices.json; topik asing menjadi
        perangkat 'topic:<nama>' (tampil sebagai TAK TERDAFTAR).
        """
        if not self.cache.enabled:
            return {}
        reg = _read_json(DEVICES_PATH, {})
        topic2ip = {n.get("topic"): n["ip"] for n in reg.get("nodes", [])
                    if n.get("topic") and n.get("ip")}
        per_sec = {}
        q = self.cache.metric_q
        while q:
            try:
                ts, topic, size = q.popleft()
            except IndexError:
                break
            dev = topic2ip.get(topic) or ("topic:" + topic)
            d = per_sec.setdefault(int(ts), {}).setdefault(dev, {
                "n": 0, "bytes": 0, "topics": set(), "last": topic})
            d["n"] += 1
            d["bytes"] += size
            d["topics"].add(topic)
            d["last"] = topic
        out = {}
        for sec, devs in per_sec.items():
            rows = []
            for dev, d in devs.items():
                rows.append({
                    "ts": sec, "device": dev, "mac": "-",
                    "n_publish": d["n"], "n_connect": 0, "bytes": d["bytes"],
                    "avg_pkt_size": round(d["bytes"] / d["n"], 1),
                    "topics": len(d["topics"]), "retrans": 0,
                    "topic_last": d["last"],
                })
            out[sec] = rows
        return out

    @staticmethod
    def _drain_quietly(q):
        while q:
            try:
                q.popleft()
            except IndexError:
                break

    def _merge_pend(self, r):
        """Gabungkan satu baris window ke buffer per detik (v8.2).

        tshark dan MQTT sering melihat pesan yang sama (node -> broker);
        ambil nilai TERBESAR per detik per perangkat supaya tidak dihitung
        dua kali — sekaligus menyelamatkan trafik yang HANYA terlihat salah
        satu sumber (serangan web terlihat MQTT saja; penyerang laptop lain
        terlihat tshark saja).
        v9.2.5: trafik dari IP broker/server sendiri DIABAIKAN — paket
        server<->broker (subscribe dashboard, feeder, dsb.) bukan trafik
        node dan dulu membuat server muncul sebagai node "TAK TERDAFTAR".
        """
        if r["device"] == broker_ip():
            return                      # server/broker bukan node yang dipantau
        sec = int(r["ts"])
        if sec <= self._last_sec:
            return                      # detik sudah diproses (data terlambat)
        dev = r["device"]
        d = self._pend.setdefault(sec, {}).get(dev)
        if d is None:
            self._pend[sec][dev] = dict(r)
            return
        if r["n_publish"] > d["n_publish"]:
            d["n_publish"] = r["n_publish"]
            d["bytes"] = r["bytes"]
            d["avg_pkt_size"] = r.get("avg_pkt_size") or 0
        if r.get("mac") not in (None, "", "-"):
            d["mac"] = r["mac"]
        if (r.get("topic_last") or "-") != "-":
            d["topic_last"] = r["topic_last"]
        d["topics"] = max(d.get("topics") or 0, r.get("topics") or 0)
        d["n_connect"] = max(d.get("n_connect") or 0, r.get("n_connect") or 0)
        d["retrans"] = max(d.get("retrans") or 0, r.get("retrans") or 0)

    # ---------------------------------------------------------- thread tshark
    def _tshark_loop(self):
        while not self._stop:
            if self._paused or self.tshark_failed or not self.iface:
                time.sleep(2)
                continue
            try:
                proc = tshark_io.open_live(self.iface)
            except Exception as e:
                _log(f"tshark gagal dimulai ({e.__class__.__name__}) — "
                     f"lanjut fallback MQTT")
                self.tshark_failed = True
                return
            with self._proc_lock:
                self._proc = proc
            self.source = f"tshark:{self.iface}"
            _log(f"Analyzer terintegrasi aktif: tshark capture di '{self.iface}'")
            agg = tshark_io.WindowAggregator()
            try:
                for line in proc.stdout:
                    if self._stop or self._paused:
                        break
                    pkt = tshark_io.parse_line(line)
                    if not pkt:
                        continue
                    sec = int(pkt["ts"])
                    if agg.cur_sec is not None and sec != agg.cur_sec:
                        rows = agg.close()
                        if rows:
                            # v8.2: jangan proses langsung — serahkan ke
                            # _dispatch agar bisa digabung dengan metrik MQTT
                            # untuk detik yang sama
                            self._tshark_last_row = time.time()
                            with self._tq_lock:
                                self._tq.append(rows)
                        agg.cur_sec = sec
                    agg.add(pkt)
            except Exception as e:
                _log(f"loop tshark berhenti: {e}")
            finally:
                try:
                    proc.terminate()
                except Exception:
                    pass
                with self._proc_lock:
                    self._proc = None
            if self._paused:
                continue                    # ditidurkan arbitrasi -> bangun lagi
            # mati sendiri (mis. hak akses kurang / interface salah)
            _log("tshark berhenti sendiri — metrik lanjut via MQTT. "
                 "Coba jalankan CMD sebagai Administrator / cek MINT_IFACE.")
            self.tshark_failed = True
            return

    # ---------------------------------------------------------- thread dispatcher
    def _dispatch(self):
        """Detik-demidetik: arbitrasi + GABUNG tshark & MQTT + tulis state.

        Sejak v8.2 kedua sumber dipakai bersama (sebelumnya saling
        meniadakan): jendela tshark dan pesan MQTT digabung per detik per
        perangkat, lalu dievaluasi setelah detik itu lewat (jeda 2 detik
        memberi waktu jendela tshark menutup). Heartbeat menjaga state.json
        tetap segar ketika trafik sedang kosong sehingga banner Beranda
        tidak macet di "MENUNGGU DATA".
        """
        next_influx_try = 0.0
        while not self._stop:
            now = time.time()
            if self.influx is None and now >= next_influx_try:
                self.influx = self._init_influx()
                if self.influx:
                    _log("Metrik terhubung ke InfluxDB — grafik Grafana "
                         "akan terisi otomatis")
                next_influx_try = now + 30
            ext = self._external_fresh()
            if ext != self._paused:
                self._paused = ext
                if ext:
                    _log("Analyzer eksternal aktif — analyzer terintegrasi standby")
                    with self._proc_lock:
                        if self._proc:
                            try:
                                self._proc.terminate()
                            except Exception:
                                pass
            q = self.cache.metric_q
            if self._paused:
                self._drain_quietly(q)      # jangan menumpuk data basi
                with self._tq_lock:
                    self._tq.clear()
                self._pend.clear()
                time.sleep(1)
                continue
            # 1) jendela tshark yang sudah tutup -> buffer gabungan
            with self._tq_lock:
                windows = []
                while self._tq:
                    windows.append(self._tq.popleft())
            for rows in windows:
                for r in rows:
                    self._merge_pend(r)
            # 2) pesan MQTT (pelengkap / satu-satunya sumber) -> buffer
            for _sec, rows in self._mqtt_rows().items():
                for r in rows:
                    self._merge_pend(r)
            # 3) proses detik yang sudah lewat -> deteksi + state.json
            with self._proc_lock:
                tshark_alive = self._proc is not None
            cutoff = int(now) - 2
            ready = [x for x in self._pend if x <= cutoff]
            if ready or self.out.last_window:
                # detik KOSONG ikut diproses (maks 5 detik ke belakang) agar
                # tiap node punya titik per detik di InfluxDB/Grafana
                start = self._last_sec + 1 if self._last_sec else min(ready or [cutoff])
                secs = sorted(set(ready) | set(range(max(start, cutoff - 5),
                                                     cutoff + 1)))
                for sec in secs:
                    if sec <= self._last_sec:
                        self._pend.pop(sec, None)
                        continue
                    merged = self._pend.pop(sec, {})
                    rows = [merged[d] for d in sorted(merged)]
                    self._last_sec = sec
                    self.source = (f"tshark:{self.iface}"
                                   if tshark_alive and self.iface else "mqtt")
                    self._handle(rows, self.source, sec)
            # 4) tshark jalan tapi tidak menangkap apa pun -> beri petunjuk
            if (tshark_alive and not self._blind_warned
                    and self._last_handle_ts and self._tshark_last_row
                    and now - self._tshark_last_row > 90
                    and now - self._last_handle_ts < 10):
                self._blind_warned = True
                _log("tshark aktif tetapi belum menangkap paket — metrik tetap "
                     "jalan dari gabungan MQTT. Bila pcap/Grafana juga kosong, "
                     "jalankan CMD sebagai Administrator atau set MINT_IFACE "
                     "(daftar interface: tshark -D).")
            time.sleep(1.0)

    # ---------------------------------------------------------- API kecil
    def describe(self):
        with self._proc_lock:
            alive = self._proc is not None
        if self._paused:
            label = "standby — analyzer eksternal sedang jalan"
        elif alive and self.source and self.source.startswith("tshark:"):
            if self._tshark_last_row and time.time() - self._tshark_last_row <= 90:
                label = f"tshark ({self.source[7:]}) + MQTT digabung — terintegrasi"
            else:
                label = (f"tshark ({self.source[7:]}) belum menangkap paket — "
                         "metrik dari gabungan MQTT")
        elif self.source == "mqtt":
            label = "MQTT langsung (fallback, tanpa tshark)"
        else:
            label = "menunggu pesan/data pertama"
        return {"source": self.source, "label": label, "paused": self._paused,
                "iface": self.iface, "influx": bool(self.influx),
                "tshark_available": bool(tshark_io.resolve_tshark())}

    def _shutdown(self):
        self._stop = True
        with self._proc_lock:
            if self._proc:
                try:
                    self._proc.terminate()
                except Exception:
                    pass


INTEGRATED = IntegratedAnalyzer(CACHE)


# ------------------------------------------------ kendali serangan web (v8.1)
class AttackManager:
    """Jalankan & awasi scripts/attack_sim.py (S1-S4) dari halaman /serang.

    Serangan dijalankan sebagai subprocess terpisah dari laptop SERVER —
    menggantikan kebiasaan mengetik perintah di Serial Monitor. Untuk demo
    dua laptop (penyerang terpisah), tetap pakai CLI attack_sim.py di laptop
    penyerang agar IP penyerang beda dari server.
    """

    # jaga sinkron dengan skenario di scripts/attack_sim.py
    SKENARIO = {
        "S1": {"nama": "High-frequency publish (flooding)",
               "rate": 100, "duration": 60, "target": "iot/suhu"},
        "S2": {"nama": "Message burst (gelombang 50 pesan)",
               "rate": 100, "duration": 90, "target": "iot/suhu"},
        "S3": {"nama": "Payload abnormal / oversized (>200 KB, sesuai proposal)",
               "rate": 1, "duration": 60, "target": "iot/kamera"},
        "S4": {"nama": "Multi-device burst (4 topik serentak)",
               "rate": 50, "duration": 10, "target": None},
    }

    def __init__(self):
        self.lock = threading.Lock()
        self.proc = None
        self.info = None                    # serangan berjalan / terakhir
        self.output = deque(maxlen=250)     # baris keluaran attack_sim
        self.history = []                   # riwayat (maks 50)
        self._stopped_by_user = False

    def running(self):
        return bool(self.proc and self.proc.poll() is None)

    def start(self, kode, target=None, rate=None, duration=None, size=None):
        with self.lock:
            if self.running():
                return False, "Serangan masih berjalan — tekan STOP dulu."
            cfg = self.SKENARIO.get(kode)
            if not cfg:
                return False, f"Skenario tidak dikenal: {kode}"
            cmd = [sys.executable,
                   os.path.join(ROOT, "scripts", "attack_sim.py"), kode,
                   "--host", str(broker_ip())]
            if target:
                cmd += ["--target", target]
            if rate:
                cmd += ["--rate", str(int(rate))]
            if duration:
                cmd += ["--duration", str(int(duration))]
            if size:
                cmd += ["--size", str(int(size))]
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            try:
                self.proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace",
                    cwd=ROOT, creationflags=flags)
            except OSError as e:
                return False, f"Gagal menjalankan attack_sim.py: {e}"
            self.output.clear()
            self._stopped_by_user = False
            self.info = {
                "kode": kode, "nama": cfg["nama"],
                "target": target or cfg["target"] or "4 topik node",
                "rate": rate or cfg["rate"],
                "duration": duration or cfg["duration"],
                "size": size, "host": str(broker_ip()),
                "start": time.time(), "status": "berjalan",
                # v8.3: waktu SERVER lengkap dgn tanggal utk riwayat — bukan
                # jam browser (agar konsisten dgn menu Anomali & Dataset)
                "start_str": time.strftime("%d-%m-%Y %H:%M:%S"),
                "pid": self.proc.pid, "elapsed": 0,
            }
            self.history.insert(0, dict(self.info))
            del self.history[50:]
            _log(f"Serangan {kode} dimulai dari web "
                 f"(target={self.info['target']}, rate={self.info['rate']}/s, "
                 f"durasi={self.info['duration']} dtk)")
            threading.Thread(target=self._pump, daemon=True).start()
            return True, f"Skenario {kode} dimulai — pantau grafik PPS di Beranda."

    def _pump(self):
        proc = self.proc
        try:
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    self.output.append(line)
        except Exception:
            pass
        code = proc.wait()
        if self.info:
            self.info["elapsed"] = round(time.time() - self.info["start"], 1)
            if self._stopped_by_user:
                self.info["status"] = "dihentikan"
            else:
                self.info["status"] = "selesai" if code == 0 else "gagal"
            self.info["last_line"] = next(
                (l for l in reversed(list(self.output))
                 if "SELESAI" in l or "total" in l.lower()), "")
            if self.history:
                self.history[0].update(
                    {k: self.info[k] for k in
                     ("elapsed", "status", "last_line") if k in self.info})
            _log(f"Serangan {self.info['kode']} {self.info['status']} "
                 f"({self.info['elapsed']} dtk)")

    def stop(self):
        with self.lock:
            if not self.running():
                return False, "Tidak ada serangan yang sedang berjalan."
            self._stopped_by_user = True
            try:
                self.proc.terminate()
            except Exception:
                pass
            if self.info:
                self.info["status"] = "dihentikan"
            _log(f"Serangan {self.info['kode'] if self.info else '?'} "
                 f"dihentikan dari web")
            return True, "Perintah STOP terkirim."

    def status(self):
        run = self.running()
        info = dict(self.info) if self.info else None
        if info and run:
            info["elapsed"] = round(time.time() - info["start"], 1)
        return {"running": run, "info": info,
                "output": list(self.output)[-40:],
                "history": self.history[:20],
                "skenario": {k: dict(v) for k, v in self.SKENARIO.items()}}


ATTACK = AttackManager()


# ------------------------------------------------ perekam sesi (v9.2.5)
class SessionRecorder:
    """Rekam sesi pengujian berlabel: PCAP + dataset CSV — TANPA tshark.

    Sumber data: hook MqttCache (setiap pesan data iot/# yang sampai ke
    broker). Dua keluaran per sesi:
      captures/<label>.pcap    — PCAP VALID: paket Ethernet/IP/TCP/MQTT
                                 tersintesis lengkap dgn checksum, MAC & IP
                                 node asli dari devices.json — bisa dibuka
                                 langsung di Wireshark.
      data/dataset_<label>.csv — metrik window 1 detik, skema SAMA dengan
                                 dataset_BASE.csv (siap untuk plot_compare.py
                                 dan threshold_baseline.py).

    Kenapa disintesis? tshark live capture butuh Wireshark terpasang + hak
    admin + interface yang benar — di laptop uji tanpa Wireshark hasilnya
    berkas .pcap KOSONG sementara CSV tetap terisi (bug v9.2.1). Dengan
    sintesis dari sisi broker, PCAP selalu berisi SEMUA pesan yang benar
    benar diproses sistem — termasuk serangan dari web yang lewat loopback
    dan tak terlihat NIC fisik.
    """

    CSV_COLS = ["ts", "label", "device", "mac", "n_publish", "n_connect",
                "bytes", "avg_pkt_size", "topics", "retrans", "topic_last"]

    # ------------------------------------------------------------ PCAP util
    @staticmethod
    def _pcap_global_hdr():
        # magic little-endian, v2.4, tz 0, sigfigs 0, snaplen 256 KB, Ethernet
        return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)

    @staticmethod
    def _mac_bytes(s):
        try:
            b = bytes(int(x, 16) for x in s.split(":"))
            return b if len(b) == 6 else b"\x02\x00\x00\x00\x00\xff"
        except Exception:
            return b"\x02\x00\x00\x00\x00\xff"

    @staticmethod
    def _cksum(data):
        """Checksum Internet (IP/TCP) satu kali jalan."""
        if len(data) & 1:
            data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return (~s) & 0xFFFF

    @staticmethod
    def _mqtt_varint(n):
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | 0x80 if n else b)
            if not n:
                return bytes(out)

    @classmethod
    def _mqtt_publish(cls, topic, payload):
        body = struct.pack("!H", len(topic)) + topic.encode() + payload
        return b"\x30" + cls._mqtt_varint(len(body)) + body

    @classmethod
    def _mqtt_connect(cls, client_id):
        cid = client_id.encode()
        vh = struct.pack("!H", 4) + b"MQTT" + bytes([4, 0x02]) \
            + struct.pack("!H", 30)          # level 3.1.1, clean-start, ka 30 dtk
        body = vh + struct.pack("!H", len(cid)) + cid
        return b"\x10" + cls._mqtt_varint(len(body)) + body

    def _frame(self, src_mac, dst_mac, src_ip, dst_ip, sport, seq, tcp_payload):
        """Satu paket Ethernet/IPv4/TCP lengkap dgn checksum."""
        tcp_hdr = struct.pack("!HHIIBBHHH", sport, 1883, seq & 0xFFFFFFFF, 1,
                              0x50, 0x18, 8192, 0, 0)   # doff=5, PSH|ACK
        tcp = tcp_hdr + tcp_payload
        pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) \
            + struct.pack("!BBH", 0, 6, len(tcp))
        tcp_ck = self._cksum(pseudo + tcp)
        tcp = tcp[:16] + struct.pack("!H", tcp_ck) + tcp[18:]
        total = 20 + len(tcp)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 6, 0,
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        ip = ip[:10] + struct.pack("!H", self._cksum(ip)) + ip[12:]
        eth = dst_mac + src_mac + b"\x08\x00"
        pkt = eth + ip + tcp
        return pkt

    # ------------------------------------------------------------ siklus hidup
    def __init__(self, cache):
        self.cache = cache
        self.lock = threading.Lock()
        self.active = None          # dict sesi berjalan
        self.history = []           # riwayat sesi (maks 30)
        atexit.register(self._atexit)

    def _registry(self):
        reg = _read_json(DEVICES_PATH, {})
        t2n = {n.get("topic"): n for n in reg.get("nodes", []) if n.get("topic")}
        return reg, t2n

    def _paths(self, label):
        """Tentukan berkas keluaran; auto-suffix bila sudah ada."""
        cap = os.path.join(ROOT, "captures")
        dat = DATA_DIR
        os.makedirs(cap, exist_ok=True)
        os.makedirs(dat, exist_ok=True)
        pcap = os.path.join(cap, f"{label}.pcap")
        csvp = os.path.join(dat, f"dataset_{label}.csv")
        n = 2
        while os.path.exists(pcap) or os.path.exists(csvp):
            pcap = os.path.join(cap, f"{label}_{n}.pcap")
            csvp = os.path.join(dat, f"dataset_{label}_{n}.csv")
            n += 1
        return pcap, csvp

    def start(self, label, durasi=None):
        with self.lock:
            if self.active:
                return False, "Masih ada sesi berjalan — hentikan dulu."
            if not re.fullmatch(r"[A-Za-z0-9_\-]{1,24}", label or ""):
                return False, ("Label sesi tidak valid (1-24 karakter: "
                               "huruf/angka/garis bawah). Contoh: BASE, S1, S4.")
            if durasi is not None and not 10 <= durasi <= 7200:
                return False, "Durasi harus 10-7200 detik."
            pcap, csvp = self._paths(label)
            try:
                f = open(pcap, "wb")
                f.write(self._pcap_global_hdr())
                f.flush()
            except OSError as e:
                return False, f"Gagal membuat berkas PCAP: {e}"
            reg, t2n = self._registry()
            self.active = {
                "label": label, "start": time.time(), "durasi": durasi,
                "start_str": time.strftime("%d-%m-%Y %H:%M:%S"),
                "pcap": pcap, "csv": csvp, "fh": f,
                "reg": reg, "t2n": t2n,
                "streams": {},        # dev -> {ip, mac, sport, seq, connect}
                "windows": {},        # sec -> dev -> {n, bytes, topics, last}
                "n_msg": 0, "n_bytes": 0, "devices": {},
                "fake_idx": 0, "stopped": None,
            }
            self.cache.hooks.append(self._on_msg)
        _log(f"Sesi rekam '{label}' DIMULAI — PCAP: {os.path.basename(pcap)} "
             f"(perekam mandiri, tanpa tshark)")
        if durasi:
            threading.Thread(target=self._auto_stop, args=(durasi,),
                             daemon=True).start()
        return True, (f"Sesi '{label}' mulai direkam — PCAP & CSV terisi "
                      "otomatis dari trafik broker.")

    def _auto_stop(self, durasi):
        time.sleep(durasi)
        with self.lock:
            if self.active and not self.active.get("stopped"):
                self._stop_locked(auto=True)

    # ---------------------------------------------- hook: dipanggil tiap pesan
    def _on_msg(self, ts, topic, raw):
        """Tulis satu paket PUBLISH tersintesis + akumulasi window CSV.

        Dijalankan di thread jaringan paho — harus cepat dan tidak pernah
        melempar exception (pemanggil sudah memakai try/except).
        """
        sesi = self.active
        if sesi is None or sesi.get("stopped"):
            return
        reg_map = sesi["t2n"].get(topic)
        if reg_map:
            dev = reg_map.get("ip", "?")
            mac = self._mac_bytes(reg_map.get("mac", ""))
            ip = dev
        else:
            # topik tak terdaftar (indikasi injeksi) -> IP tiruan stabil 10.99.x
            st = sesi["streams"].get("topic:" + topic)
            if st is None:
                sesi["fake_idx"] += 1
                i = sesi["fake_idx"]
                ip = f"10.99.99.{i}"
                mac = bytes((0x02, 0x00, 0x00, 0x99, 0x99, i & 0xFF))
            else:
                ip, mac = st["ip"], st["mac"]
            dev = "topic:" + topic
        st = sesi["streams"].get(dev)
        if st is None:
            st = sesi["streams"][dev] = {
                "ip": ip, "mac": mac, "sport": 40000 + (len(sesi["streams"]) * 137) % 15000,
                "seq": 1, "connect": False,
            }
        pkts = []
        if not st["connect"]:                       # satu CONNECT utas realisme
            st["connect"] = True
            pkts.append(self._mqtt_connect("mint-" + re.sub(r"\W+", "-", dev)[-20:]))
        pkts.append(self._mqtt_publish(topic, raw))
        broker_mac = b"\x02\x00\x00\x00\x00\x01"
        try:
            MSS = 1400      # v9.2.6: payload S3 (>200 KB) dipecah per segmen TCP;
            for pl in pkts:  # dulu 1 paket raksasa -> struct.error (panjang IP > 65535)
                for off in range(0, len(pl), MSS):
                    seg = pl[off:off + MSS]
                    pkt = self._frame(st["mac"], broker_mac, st["ip"],
                                      broker_ip(), st["sport"], st["seq"], seg)
                    sesi["fh"].write(struct.pack("<IIII", int(ts),
                                                 int((ts % 1) * 1e6),
                                                 len(pkt), len(pkt)) + pkt)
                    st["seq"] += len(seg)
            if sesi["n_msg"] % 20 == 0:               # flush berkala: ukuran tumbuh live
                sesi["fh"].flush()
        except (OSError, ValueError):
            pass                                     # disk penuh dll: rekam CSV tetap jalan
        # window CSV
        sec = int(ts)
        w = sesi["windows"].setdefault(sec, {}).setdefault(dev, {
            "mac": reg_map.get("mac", "-") if reg_map else "-",
            "n": 0, "bytes": 0, "topics": set(), "last": topic,
            "connect": 0})
        w["n"] += 1
        w["bytes"] += len(raw)
        w["topics"].add(topic)
        w["last"] = topic
        if pkts and w["connect"] == 0 and st["connect"]:
            w["connect"] = 1                          # CONNECT disintesis utk pesan pertama
        sesi["n_msg"] += 1
        sesi["n_bytes"] += len(raw)
        d = sesi["devices"].setdefault(dev, {"n": 0, "bytes": 0})
        d["n"] += 1
        d["bytes"] += len(raw)

    # ------------------------------------------------------------ stop + CSV
    def _stop_locked(self, auto=False):
        sesi = self.active
        if not sesi or sesi.get("stopped"):
            return
        try:
            self.cache.hooks.remove(self._on_msg)
        except ValueError:
            pass
        sesi["stopped"] = time.time()
        try:
            sesi["fh"].flush()
            sesi["fh"].close()
        except OSError:
            pass
        # tulis dataset CSV dari jendela terkumpul
        n_rows = 0
        try:
            with open(sesi["csv"], "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(self.CSV_COLS)
                for sec in sorted(sesi["windows"]):
                    for dev in sorted(sesi["windows"][sec]):
                        d = sesi["windows"][sec][dev]
                        w.writerow([sec, sesi["label"], dev, d["mac"], d["n"],
                                    d["connect"], d["bytes"],
                                    round(d["bytes"] / d["n"], 1),
                                    len(d["topics"]), 0, d["last"]])
                        n_rows += 1
        except OSError as e:
            _log(f"Sesi '{sesi['label']}': gagal menulis CSV — {e}")
        info = self.info_dict(sesi)
        info.update({"status": "selesai (otomatis)" if auto else "selesai",
                     "csv_rows": n_rows})
        sesi["final"] = info
        self.history.insert(0, info)
        del self.history[30:]
        self.active = None
        _log(f"Sesi rekam '{sesi['label']}' SELESAI: {sesi['n_msg']} pesan, "
             f"PCAP {info['pcap_size']:,} B, CSV {n_rows} baris "
             f"-> {os.path.basename(sesi['csv'])}")

    def stop(self):
        with self.lock:
            if not self.active:
                return False, "Tidak ada sesi yang sedang merekam."
            self._stop_locked()
            return True, (f"Sesi berhenti — {self.history[0]['n_msg']} pesan "
                          f"rekam. Cek daftar berkas di bawah.")

    def _atexit(self):
        with self.lock:
            if self.active:
                self._stop_locked()

    # ------------------------------------------------------------ laporan UI
    def info_dict(self, sesi):
        try:
            pcap_size = os.stat(sesi["pcap"]).st_size
        except OSError:
            pcap_size = 0
        return {
            "label": sesi["label"], "start_str": sesi["start_str"],
            "n_msg": sesi["n_msg"], "n_bytes": sesi["n_bytes"],
            "pcap_size": pcap_size,
            "pcap_name": os.path.basename(sesi["pcap"]),
            "csv_name": os.path.basename(sesi["csv"]),
            "devices": {d: {"n": v["n"], "bytes": v["bytes"]}
                        for d, v in sorted(sesi["devices"].items())},
        }

    def status(self):
        with self.lock:
            run = bool(self.active and not self.active.get("stopped"))
            out = {"running": run, "info": None,
                   "history": [dict(h) for h in self.history[:12]],
                   "files": self.files()}          # dibaca tanpa lock rekam
        if run:
            sesi = self.active
            info = self.info_dict(sesi)
            info.update({
                "elapsed": round(time.time() - sesi["start"], 1),
                "durasi": sesi["durasi"],
                "sisa": (round(sesi["durasi"] - (time.time() - sesi["start"]))
                         if sesi["durasi"] else None),
            })
            out["info"] = info
        return out

    def files(self):
        """Daftar PCAP (captures/) + dataset CSV (data/) utk tabel unduhan."""
        out = []
        for folder, kind in ((os.path.join(ROOT, "captures"), "pcap"),
                             (DATA_DIR, "csv")):
            if not os.path.isdir(folder):
                continue
            for name in sorted(os.listdir(folder)):
                p = os.path.join(folder, name)
                ext = name.lower().rsplit(".", 1)[-1]
                if not os.path.isfile(p) or ext != kind:
                    continue
                st = os.stat(p)
                rows = ""
                if kind == "csv":
                    try:
                        with open(p, "rb") as f:
                            rows = max(0, sum(1 for _ in f) - 1)
                    except OSError:
                        pass
                out.append({"name": name, "kind": kind, "size": st.st_size,
                            "mtime": int(st.st_mtime), "rows": rows,
                            "rel": os.path.relpath(p, ROOT).replace("\\", "/")})
        return sorted(out, key=lambda x: -x["mtime"])


RECORDER = SessionRecorder(CACHE)


# ---------------------------------------------------------------- ping watcher
class PingWatcher:
    """Kehadiran node via ICMP ping — agar status ON/OFF aktual tanpa menunggu
    interval publish (kamera 60 dtk pun terdeteksi dalam <= 15 detik).

    v9.2.5 ANTI-FLAPPING: ping dijalankan PARALEL satu thread per node.
    Sebelumnya ping berurutan — bila satu node mati/timeout 4 dtk, siklus
    penuh molor >15 dtk sehingga node lain ikut terancam "OFFLINE" padahal
    hidup (kehadiran TTL 15 dtk terlampaui). Kini semua node diping pada
    saat yang sama, timeout per ping 1,2 dtk, TTL 20 dtk.

    Nonaktifkan dengan variabel lingkungan MINT_PING=0.
    """

    def __init__(self, interval=5.0, ttl=20.0):
        self.interval = interval
        self.ttl = ttl
        self.last_ok = {}          # ip -> ts ping terakhir yang berhasil
        self.enabled = os.environ.get("MINT_PING", "1") != "0"
        self._lock = threading.Lock()
        if self.enabled:
            threading.Thread(target=self._run, daemon=True).start()

    @staticmethod
    def _targets():
        reg = _read_json(DEVICES_PATH, {})
        return [n["ip"] for n in reg.get("nodes", []) if n.get("ip")]

    def _ping(self, ip):
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", "1200", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        try:
            return subprocess.run(cmd, capture_output=True, timeout=2).returncode == 0
        except Exception:
            return False

    def _ping_node(self, ip):
        if self._ping(ip):
            with self._lock:
                self.last_ok[ip] = time.time()

    def _run(self):
        while True:
            try:
                # v9.2.5: PARALEL — satu thread per node, digabung maks 2,5 dtk
                ips = self._targets()
                threads = [threading.Thread(target=self._ping_node, args=(ip,))
                           for ip in ips]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=2.5)
            except Exception:
                pass
            time.sleep(self.interval)

    def age(self, ip):
        """Umur (detik) ping berhasil terakhir; None = belum pernah."""
        with self._lock:
            t = self.last_ok.get(ip)
        return (time.time() - t) if t else None


PINGER = PingWatcher()


# ------------------------------------------------- status layanan (background)
SERVICES = {}          # nama -> {"ok", "host", "port", "checked"}


def _check_tcp(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def service_watcher():
    """Cek status Mosquitto / InfluxDB / Grafana tiap 10 detik (non-blocking)."""
    while True:
        b = broker_ip()
        for name, host, port in (
            ("Mosquitto (MQTT)", b, 1883),
            ("InfluxDB", "127.0.0.1", 8086),
            ("Grafana", "127.0.0.1", 3000),
        ):
            ok = _check_tcp(host, port)
            SERVICES[name] = {"ok": ok, "host": host, "port": port,
                              "checked": int(time.time())}
        time.sleep(10)


threading.Thread(target=service_watcher, daemon=True).start()


# ------------------------------------------------------------- pemakaian server
class ServerStats:
    """Snapshot pemakaian sumber daya server (cache 3 detik, non-blocking)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._cache = None
        self._ts = 0.0
        self._prev_net = None      # (ts, bytes_sent, bytes_recv)

    def snapshot(self):
        with self._lock:
            now = time.time()
            if self._cache and now - self._ts < 3.0:
                return self._cache
            s = {
                "psutil": HAS_PSUTIL,
                "hostname": platform.node() or "server",
                "os": f"{platform.system()} {platform.release()}",
                "python": platform.python_version(),
                "broker_ip": broker_ip(),
                "dashboard_uptime": int(now - STARTED),
                "services": dict(SERVICES),
            }
            if HAS_PSUTIL:
                vm = psutil.virtual_memory()
                dk = psutil.disk_usage(ROOT)
                net = psutil.net_io_counters()
                up = down = 0.0
                if self._prev_net:
                    dt = now - self._prev_net[0]
                    if dt > 0:
                        up = max(0, net.bytes_sent - self._prev_net[1]) / dt
                        down = max(0, net.bytes_recv - self._prev_net[2]) / dt
                self._prev_net = (now, net.bytes_sent, net.bytes_recv)
                s.update({
                    "cpu_percent": psutil.cpu_percent(interval=None),
                    "cpu_cores": psutil.cpu_count() or 1,
                    "ram_percent": vm.percent,
                    "ram_used": vm.used, "ram_total": vm.total,
                    "disk_percent": dk.percent,
                    "disk_used": dk.used, "disk_total": dk.total,
                    "boot_ts": int(psutil.boot_time()),
                    "net_sent": net.bytes_sent, "net_recv": net.bytes_recv,
                    "net_up_bps": up, "net_down_bps": down,
                })
            self._cache, self._ts = s, now
            return s


STATS = ServerStats()
if HAS_PSUTIL:
    psutil.cpu_percent(interval=None)   # priming: pemanggilan pertama selalu 0


# ---------------------------------------------------------------------- auth
def load_users():
    return _read_json(USERS_PATH, {"users": []})["users"]


def save_users(users):
    with open(USERS_PATH, "w") as f:
        json.dump({"users": users}, f, indent=2)


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


def check_csrf():
    tok = request.form.get("_csrf", "")
    return bool(tok) and tok == session.get("_csrf")


@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token}


# percobaan login gagal per IP: {ip: [timestamp, ...]}
LOGIN_FAILS = {}
LOGIN_FAIL_LOCK = threading.Lock()


def ip_locked(ip):
    """Kembalikan sisa detik penguncian IP (0 = tidak terkunci)."""
    now = time.time()
    with LOGIN_FAIL_LOCK:
        fails = [t for t in LOGIN_FAILS.get(ip, []) if now - t < LOGIN_WINDOW]
        LOGIN_FAILS[ip] = fails
        if len(fails) >= LOGIN_MAX_FAILS:
            return max(int(LOGIN_LOCKOUT - (now - fails[-1])), 0)
    return 0


def record_fail(ip):
    now = time.time()
    with LOGIN_FAIL_LOCK:
        fails = [t for t in LOGIN_FAILS.get(ip, []) if now - t < LOGIN_WINDOW]
        fails.append(now)
        LOGIN_FAILS[ip] = fails


def clear_fails(ip):
    with LOGIN_FAIL_LOCK:
        LOGIN_FAILS.pop(ip, None)


@app.after_request
def security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"
    if request.path.startswith("/api/"):
        # kecuali foto JPEG: boleh di-cache 3 detik (anti-flicker foto live,
        # lihat docstring /api/photo) — metode: route sendiri sudah memasang
        # header private max-age=3, jangan ditimpa di sini
        if not resp.headers.get("Cache-Control", "").startswith("private"):
            resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect(url_for("index"))
    error, sisa = None, 0
    if request.method == "POST":
        if not check_csrf():
            error = "Sesi tidak valid — muat ulang halaman lalu coba lagi."
        else:
            ip = request.remote_addr or "?"
            sisa = ip_locked(ip)
            if sisa > 0:
                error = (f"Terlalu banyak percobaan gagal. "
                         f"IP dikunci — coba lagi dalam {sisa} detik.")
            else:
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                user = next((u for u in load_users()
                             if u["username"] == username), None)
                if user and check_password_hash(user["password_hash"], password):
                    session.clear()
                    session.permanent = True          # aktifkan timer 30 menit
                    session["user"] = username
                    session["role"] = user.get("role", "operator")
                    session["login_at"] = datetime.now().strftime("%H:%M:%S")
                    clear_fails(ip)
                    _log(f"Login berhasil: {username} (IP {ip})")
                    dest = request.args.get("next") or url_for("index")
                    if not dest.startswith("/") or dest.startswith("//"):
                        dest = url_for("index")
                    return redirect(dest)
                record_fail(ip)
                sisa = ip_locked(ip)
                _log(f"Login gagal untuk '{username}' (IP {ip})")
                error = "Nama pengguna atau kata sandi salah."
                if sisa > 0:
                    error = (f"Terlalu banyak percobaan gagal. "
                             f"IP dikunci selama {sisa} detik.")
    return render_template("login.html", error=error, sisa=sisa)


@app.route("/logout")
def logout():
    user = session.get("user")
    session.clear()
    if user:
        _log(f"Logout: {user}")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------- views
@app.route("/")
@login_required
def index():
    return render_template("index.html", user=session.get("user"),
                           role=session.get("role"), page="beranda")


@app.route("/nodes")
@login_required
def nodes_page():
    return render_template("nodes.html", user=session.get("user"),
                           role=session.get("role"), page="node")


@app.route("/anomali")
@login_required
def anomali_page():
    return render_template("anomali.html", user=session.get("user"),
                           role=session.get("role"), page="anomali")


@app.route("/server")
@login_required
def server_page():
    return render_template("server.html", user=session.get("user"),
                           role=session.get("role"), page="server")


@app.route("/bantuan")
@login_required
def bantuan_page():
    return render_template("bantuan.html", user=session.get("user"),
                           role=session.get("role"), page="bantuan")


@app.route("/serang")
@login_required
def serang_page():
    return render_template("serang.html", user=session.get("user"),
                           role=session.get("role"), page="serang")


@app.route("/pps")
@login_required
def pps_page():
    """Grafik PPS realtime — 4 panel (PPS, B/s, distribusi, ukuran paket)."""
    return render_template("pps.html", user=session.get("user"),
                           role=session.get("role"), page="pps")


@app.route("/grafana")
@login_required
def grafana_redirect():
    """v8.3: menu Grafana diganti Grafik PPS — alihkan rute lama."""
    return redirect("/pps")


@app.route("/sesi")
@login_required
def sesi_page():
    """v9.2.5: Sesi & Dataset — rekam sesi berlabel (PCAP + CSV)."""
    return render_template("sesi.html", user=session.get("user"),
                           role=session.get("role"), page="sesi")


@app.route("/pengaturan")
@login_required
def pengaturan_page():
    """v9.2.5: Pengaturan — threshold live, akun, Telegram."""
    return render_template("pengaturan.html", user=session.get("user"),
                           role=session.get("role"), page="pengaturan")


@app.route("/log")
@login_required
def log_page():
    """v9.2.5: Log Sistem — log internal + event deteksi + riwayat."""
    return render_template("log.html", user=session.get("user"),
                           role=session.get("role"), page="log")


# ------------------------------------------------------ API: sesi rekam (v9.2.5)
@app.route("/api/session/start", methods=["POST"])
@login_required
def api_session_start():
    """Mulai merekam sesi berlabel — PCAP + CSV tanpa tshark."""
    if not check_csrf():
        return jsonify({"ok": False, "msg": "Token CSRF tidak valid."}), 400
    label = (request.form.get("label") or "").strip()
    durasi = (request.form.get("durasi") or "").strip()
    try:
        durasi = int(durasi) if durasi else None
    except ValueError:
        return jsonify({"ok": False, "msg": "Durasi harus angka (detik)."}), 400
    ok, msg = RECORDER.start(label, durasi)
    return jsonify({"ok": ok, "msg": msg})


@app.route("/api/session/stop", methods=["POST"])
@login_required
def api_session_stop():
    if not check_csrf():
        return jsonify({"ok": False, "msg": "Token CSRF tidak valid."}), 400
    ok, msg = RECORDER.stop()
    return jsonify({"ok": ok, "msg": msg})


@app.route("/api/session/status")
@login_required
def api_session_status():
    return jsonify(RECORDER.status())


@app.route("/api/session/download")
@login_required
def api_session_download():
    """Unduh PCAP (captures/) atau dataset CSV (data/) — anti path traversal."""
    rel = (request.args.get("rel") or "").strip().replace("\\", "/")
    if not re.fullmatch(r"(captures|data)/[\w\-+. ]+", rel):
        return jsonify({"error": "path tidak valid"}), 400
    path = os.path.join(ROOT, rel)
    if not os.path.isfile(path):
        return jsonify({"error": "berkas tidak ditemukan"}), 404
    return send_file(path, as_attachment=True,
                     download_name=os.path.basename(path))


# ------------------------------------------------------ API: threshold (v9.2.5)
_METRIC_LABEL = {"pps": "PPS (pesan/dtk)", "bps": "BPS (byte/dtk)",
                 "avg_pkt_size": "Rata-rata ukuran payload (byte)"}


@app.route("/api/thresholds")
@login_required
def api_thresholds_get():
    """Snapshot threshold utk halaman Pengaturan (+ nilai live per node)."""
    th = _read_json(THRESHOLDS_PATH, {})
    state = _read_json(os.path.join(RUN_DIR, "state.json"), None)
    live = {}
    if state:
        for ip, d in state.get("devices", {}).items():
            if ip == broker_ip():
                continue
            live[ip] = {"pps": d.get("pps_15s", 0), "bps": d.get("bps_15s", 0),
                        "avg_pkt_size": d.get("avg_pkt_size_15s", 0),
                        "status": d.get("status", "OK")}
    return jsonify({"thresholds": th, "live": live,
                    "broker_ip": broker_ip(),
                    "metric_label": _METRIC_LABEL})


@app.route("/api/thresholds", methods=["POST"])
@login_required
def api_thresholds_set():
    """Ubah threshold dari halaman Pengaturan — LIVE tanpa restart.

    Field form: thr_<ip-dgn-strip>_<metrik>=nilai (mis.
    thr_192-168-7-102_pps=4.5). Hanya admin. Perubahan:
      1. ditulis ke thresholds.json (persisten, ditandai "manual"),
      2. dipanggilkan ke engine yang sedang jalan via reload_thresholds()
         -> berlaku pada window BERIKUTNYA: status node, garis threshold
         grafik, dan warna kartu node mengikuti pada poll /api/state
         berikutnya (1-2 detik).
    """
    if session.get("role") != "admin":
        return jsonify({"ok": False,
                        "msg": "Hanya admin yang boleh mengubah threshold."}), 403
    if not check_csrf():
        return jsonify({"ok": False, "msg": "Token CSRF tidak valid."}), 400
    th = _read_json(THRESHOLDS_PATH, {})
    if not isinstance(th.get("devices"), dict):
        th["devices"] = {}
    changed, rejected = [], []
    for key, val in request.form.items():
        m = re.fullmatch(r"thr_((?:\d{1,3}-){3}\d{1,3})_(pps|bps|avg_pkt_size)", key)
        if not m or key == "_csrf":
            continue
        ip = m.group(1).replace("-", ".")
        metric = m.group(2)
        try:
            v = float(val)
        except (TypeError, ValueError):
            rejected.append(f"{ip} {metric}: '{val}' bukan angka")
            continue
        if not (0 < v <= 10_000_000):
            rejected.append(f"{ip} {metric}: nilai harus > 0")
            continue
        dev = th["devices"].setdefault(ip, {})
        if "mac" not in dev:
            reg = _read_json(DEVICES_PATH, {})
            node = next((n for n in reg.get("nodes", []) if n.get("ip") == ip), {})
            dev["mac"] = node.get("mac", "-")
        slot = dev.setdefault(metric, {})
        lama = slot.get("threshold")
        slot["threshold"] = round(v, 2)
        changed.append(f"{ip} {metric}: {lama} -> {round(v, 2)}")
    if not changed:
        return jsonify({"ok": False,
                        "msg": "; ".join(rejected) or "Tidak ada perubahan valid."}), 400
    th["manual"] = True
    th["manual_ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(THRESHOLDS_PATH, "w", encoding="utf-8") as f:
            json.dump(th, f, indent=4)
    except OSError as e:
        return jsonify({"ok": False, "msg": f"Gagal menulis thresholds.json: {e}"}), 500
    # terapkan LANGSUNG ke engine yang sedang berjalan (tanpa restart)
    INTEGRATED.engine.reload_thresholds(th)
    _log("Threshold diubah dari Pengaturan (live): " + "; ".join(changed))
    msg = ("Tersimpan & langsung berlaku — indikator dashboard (status, garis "
           "threshold grafik, warna node) menyusul dalam 1-2 detik.")
    if rejected:
        msg += " Ditolak: " + "; ".join(rejected)
    return jsonify({"ok": True, "msg": msg, "changed": changed})


@app.route("/api/thresholds/reset", methods=["POST"])
@login_required
def api_thresholds_reset():
    """Kembalikan threshold hasil kalibrasi dataset_BASE.csv (median+3MAD)."""
    if session.get("role") != "admin":
        return jsonify({"ok": False,
                        "msg": "Hanya admin yang boleh mengkalibrasi ulang."}), 403
    if not check_csrf():
        return jsonify({"ok": False, "msg": "Token CSRF tidak valid."}), 400
    base_csv = os.path.join(DATA_DIR, "dataset_BASE.csv")
    if not os.path.isfile(base_csv):
        return jsonify({"ok": False,
                        "msg": "data/dataset_BASE.csv tidak ditemukan — "
                               "rekam sesi BASE dulu di menu Sesi & Dataset."}), 404
    try:
        sys.path.insert(0, os.path.join(ROOT, "analyzer"))
        import threshold_baseline
        th = threshold_baseline.compute([base_csv])
    except Exception as e:
        return jsonify({"ok": False,
                        "msg": f"Kalibrasi gagal ({e.__class__.__name__}: {e}) — "
                               "pastikan pandas terpasang (pip install pandas)."}), 500
    try:
        with open(THRESHOLDS_PATH, "w", encoding="utf-8") as f:
            json.dump(th, f, indent=4)
    except OSError as e:
        return jsonify({"ok": False, "msg": f"Gagal menulis thresholds.json: {e}"}), 500
    INTEGRATED.engine.reload_thresholds(th)
    _log("Threshold dikalibrasi ulang dari dataset_BASE.csv (median+3*1.4826*MAD)")
    return jsonify({"ok": True,
                    "msg": "Threshold dikalibrasi ulang dari dataset_BASE.csv "
                           "dan langsung berlaku."})


# ------------------------------------------------------ API: log sistem (v9.2.5)
@app.route("/api/logs")
@login_required
def api_logs():
    """Log internal + event deteksi + riwayat serangan/sesi utk halaman Log."""
    q = (request.args.get("q") or "").lower()
    logs = LOGS[-300:]
    if q:
        logs = [l for l in logs if q in l.lower()]
    alerts = _tail_alerts(os.path.join(RUN_DIR, "alerts.jsonl"), 200)
    atk = ATTACK.status()
    sesi = RECORDER.status()
    return jsonify({
        "logs": logs[::-1],                     # terbaru dulu
        "alerts": alerts[::-1],
        "attack_history": atk.get("history", []),
        "sessions": sesi.get("history", []),
        "counts": {"logs": len(LOGS), "alerts": len(alerts)},
        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })


@app.route("/api/logs/export")
@login_required
def api_logs_export():
    """Unduh gabungan log sistem (teks) utk lampiran laporan."""
    alerts = _tail_alerts(os.path.join(RUN_DIR, "alerts.jsonl"), 2000)
    lines = [f"LOG SISTEM MINT v9.2.5 — diekspor "
             f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "=" * 64, "",
             "--- Log internal dashboard ---"]
    lines += LOGS[-300:]
    lines += ["", "--- Event deteksi (alerts.jsonl, terbaru terakhir) ---"]
    lines += [f"{a.get('time')} {a.get('kind')} {a.get('device')} "
              f"{a.get('metric')}={a.get('value')} thr={a.get('threshold')} "
              f"({a.get('ratio')}x)" for a in alerts]
    body = "\n".join(lines)
    resp = Response(body, mimetype="text/plain")
    resp.headers["Content-Disposition"] = (
        'attachment; filename="mint_logs_%s.txt"'
        % datetime.now().strftime("%Y%m%d_%H%M%S"))
    return resp


# ---------------------------------------------------------------- API: state
def _readings_view(entry):
    """Ringkas pembacaan sensor terakhir untuk kartu node."""
    if not entry:
        return None
    out = {"age": int(time.time() - entry["ts"]), "size": entry["size"]}
    if entry.get("readings"):
        out["items"] = [{"label": r["label"], "value": r["value"],
                         "unit": r["unit"]} for r in entry["readings"][:4]]
    elif entry.get("text"):
        out["text"] = entry["text"]
    else:
        out["text"] = "(biner)"
    return out


def _presence(ip, reg_node, topic, state_dev, state_age):
    """Status kehadiran node: (kondisi, sumber bukti).

    Urutan bukti: LWT/status topik -> ping ICMP -> pesan MQTT terakhir ->
    trafik yang dilihat analyzer. Tidak ada bukti segar = OFFLINE.
    """
    now = time.time()
    # 1) LWT / topik status (paling otoritatif utk status MQTT)
    st = CACHE.status_of(topic) if topic else None
    entry = CACHE.by_topic(topic) if topic else None
    if st and st[0] == "OFFLINE":
        # pesan sensor yang lebih baru dari LWT = sudah sambung lagi
        if not (entry and entry["ts"] > st[1]):
            return "OFFLINE", "lwt"
    # 2) ping ICMP (interval 5 dtk, dianggap hidup <= 15 dtk)
    if PINGER.enabled:
        a = PINGER.age(ip)
        if a is not None and 0 <= a <= PINGER.ttl:
            return "ONLINE", "ping"
    # 3) umur pesan MQTT terakhir (grace mengikuti interval publish node)
    if entry:
        iv = reg_node.get("interval_s") or 0
        grace = max(2.5 * iv, 15.0) if iv else 45.0
        if 0 <= now - entry["ts"] <= grace:
            return "ONLINE", "mqtt"
    # 4) trafik dilihat analyzer (state.json segar + last_seen baru)
    if state_age is not None and 0 <= state_age <= 6 and state_dev:
        ls = state_dev.get("last_seen")
        if ls and 0 <= now - ls <= 30:
            return "ONLINE", "trafik"
    return "OFFLINE", None


@app.route("/api/state")
@login_required
def api_state():
    state = _read_json(os.path.join(RUN_DIR, "state.json"), None)
    alerts = _tail_alerts(os.path.join(RUN_DIR, "alerts.jsonl"))
    thresholds = _read_json(THRESHOLDS_PATH, {})
    reg = _read_json(DEVICES_PATH, {})
    reg_by_ip = {n["ip"]: n for n in reg.get("nodes", [])}
    reg_by_topic = {n.get("topic"): n for n in reg.get("nodes", []) if n.get("topic")}
    now = time.time()
    # kesegaran state dihitung dari jam dinding (wall_ts) agar mode replay
    # (yang memakai waktu maya) tetap dinilai benar oleh dashboard
    wall = (state.get("wall_ts") or state.get("updated_ts")) if state else None
    state_age = (now - wall) if wall else None
    analyzer_active = bool(state_age is not None and 0 <= state_age <= 6)

    # gabungkan: node terdaftar + perangkat yang terlihat di trafik analyzer
    seen = dict(state.get("devices", {})) if state else {}
    # v9.2.5: IP broker/server sendiri BUKAN node yang dipantau — singkirkan
    # (bug lama: laptop server muncul sebagai node "TAK TERDAFTAR").
    seen.pop(broker_ip(), None)
    ips = [ip for ip in dict.fromkeys(list(reg_by_ip) + list(seen))
           if ip != broker_ip()]

    nodes = {}
    for ip in ips:
        s = seen.get(ip, {})
        r = reg_by_ip.get(ip) or reg_by_topic.get(s.get("topic_last"), {}) or {}
        topic = r.get("topic") or s.get("topic_last") or "-"
        thr_dev = thresholds.get("devices", {}).get(ip, {})
        presence, psrc = _presence(ip, r, topic, s, state_age)
        entry = CACHE.by_topic(topic) if topic != "-" else None
        ph = CACHE.photo(topic) if topic != "-" else None
        nodes[ip] = {
            "registered": ip in reg_by_ip or bool(r),
            "name": r.get("name", ip),
            "sensor": r.get("sensor", "-"),
            "location": r.get("location", "-"),
            "owner": r.get("owner", "-"),
            "interval_s": r.get("interval_s"),
            "ip": ip, "mac": s.get("mac", "-"),
            "topic": topic,
            "status": s.get("status", "OFFLINE"),
            "presence": presence, "presence_src": psrc,
            "last_msg_age": int(now - entry["ts"]) if entry else None,
            "alerts": s.get("alerts", []),
            "pps": s.get("pps", 0), "bps": s.get("bps", 0),
            "avg_pkt_size": s.get("avg_pkt_size", 0),
            "pps_2m": s.get("pps_2m", 0), "bps_2m": s.get("bps_2m", 0),
            "avg_pkt_size_2m": s.get("avg_pkt_size_2m", 0),
            # v9.2.5: jendela 15 dtk — grafik & kartu node responsif (S1/S3/S4
            # terlihat 1-2 dtk, bukan ~30 dtk seperti rata-rata 2 menit)
            "pps_15s": s.get("pps_15s", 0), "bps_15s": s.get("bps_15s", 0),
            "avg_pkt_size_15s": s.get("avg_pkt_size_15s", 0),
            "last_seen": s.get("last_seen"),
            "first_seen": s.get("first_seen"),
            "total_publish": s.get("total_publish", 0),
            "thresholds": {m: v["threshold"] for m, v in thr_dev.items()
                           if isinstance(v, dict)},
            "readings": _readings_view(entry),
            "photo": ({"age": int(now - ph["ts"]), "size": ph["size"],
                       "count": ph["count"]} if ph else None),
            "photo_history": CACHE.photo_history(topic) if topic != "-" else [],
            "events": [a for a in reversed(alerts) if a["device"] == ip][-5:],
        }

    # topik MQTT aktif yang tidak terdaftar di devices.json (indikasi injeksi)
    reg_topics = set(reg_by_topic)
    for topic, entry in CACHE.latest.items():
        if topic in reg_topics:
            continue        # topik terdaftar sudah diproses lewat registry IP
        ph = CACHE.photo(topic)
        key = f"topic:{topic}"
        live = {
            "registered": False, "name": topic, "sensor": "TAK TERDAFTAR",
            "location": "-", "owner": "-", "interval_s": None,
            "ip": "-", "mac": "-", "topic": topic, "status": "OFFLINE",
            "presence": ("ONLINE" if 0 <= now - entry["ts"] <= 45
                          else "OFFLINE"),
            "presence_src": "mqtt",
            "last_msg_age": int(now - entry["ts"]),
            "readings": _readings_view(entry),
            "photo": ({"age": int(now - ph["ts"]), "size": ph["size"],
                       "count": ph["count"]} if ph else None),
            "photo_history": CACHE.photo_history(topic),
        }
        if key in nodes:
            # perangkat topik ini sudah punya entri dari metrik analyzer
            # (fallback MQTT) -> perbarui bidang live saja, JANGAN timpa
            # pps/bps/total yang sudah dihitung
            nodes[key].update(live)
            nodes[key]["registered"] = False
            nodes[key]["sensor"] = "TAK TERDAFTAR"
            continue
        nodes[key] = {
            **live,
            "alerts": [], "pps": 0, "bps": 0, "avg_pkt_size": 0,
            "pps_2m": 0, "bps_2m": 0, "avg_pkt_size_2m": 0,
            "pps_15s": 0, "bps_15s": 0, "avg_pkt_size_15s": 0,
            "last_seen": None, "first_seen": None, "total_publish": 0,
            "thresholds": {}, "events": [],
        }

    system = "MENUNGGU DATA"
    if state and state_age is not None and 0 <= state_age <= 10:
        n_alert = sum(1 for n in nodes.values() if n["status"] == "ALERT")
        system = "SERANGAN TERDETEKSI" if n_alert else "NORMAL"
    n_online = sum(1 for n in nodes.values() if n["presence"] == "ONLINE")

    return jsonify({
        "updated": state.get("updated") if state else None,
        "updated_ts": int(wall) if wall else 0,
        "system": system,
        "analyzer_active": analyzer_active,
        "metric_source": INTEGRATED.describe(),
        "attack": {"running": ATTACK.running(),
                   "kode": (ATTACK.info or {}).get("kode"),
                   "elapsed": (ATTACK.info or {}).get("elapsed", 0)},
        "telegram_enabled": telegram_enabled(),
        "broker_ip": broker_ip(),
        "mqtt_cache": {"enabled": CACHE.enabled, "connected": CACHE.connected,
                       "rx_count": CACHE.rx_count},
        "ping": {"enabled": PINGER.enabled},
        "global": {
            "pps": (state.get("global", {}).get("pps", 0) if state else
                    sum(n["pps"] for n in nodes.values())),
            "bps": (state.get("global", {}).get("bps", 0) if state else
                    sum(n["bps"] for n in nodes.values())),
            "pps_2m": (state.get("global", {}).get("pps_2m", 0) if state else
                       round(sum(n["pps_2m"] for n in nodes.values()), 2)),
            "bps_2m": (state.get("global", {}).get("bps_2m", 0) if state else
                       sum(n["bps_2m"] for n in nodes.values())),
            "pps_15s": (state.get("global", {}).get("pps_15s", 0) if state else
                        round(sum(n["pps_15s"] for n in nodes.values()), 2)),
            "bps_15s": (state.get("global", {}).get("bps_15s", 0) if state else
                        sum(n["bps_15s"] for n in nodes.values())),
            "devices": len(nodes), "online": n_online,
        },
        "nodes": nodes,
        "alerts": [a for a in alerts if a.get("kind") == "ALERT"][-50:],
        "scenario": _infer_scenario(alerts),
        "thresholds_ready": bool(thresholds.get("generated")),
        "user": session.get("user"),
    })


@app.route("/api/photo")
@login_required
def api_photo():
    """Foto JPEG dari sebuah topik (dipakai <img> di halaman Node).

    Tanpa parameter seq = foto TERBARU. Dengan ?seq=N = foto ke-N dari
    riwayat (lihat /api/photo/history).

    Header cache privat 3 detik: halaman Node membangun ulang DOM tiap 2
    detik; tanpa cache browser akan mengunduh ulang foto dari nol setiap
    kali sehingga gambar sempat blank ("kadang muncul kadang tidak").
    Dengan cache 3 dtk, pembangunan ulang DOM memakai gambar cache; foto
    baru tetap diambil oleh penyegar berkala (cache-buster tiap 5 dtk).
    """
    topic = request.args.get("topic", "")
    if not re.fullmatch(r"[A-Za-z0-9_\-+/]+", topic or " "):
        return jsonify({"error": "topik tidak valid"}), 400
    seq = request.args.get("seq", "").strip()
    ph = CACHE.photo(topic, int(seq) if seq.isdigit() else None)
    if not ph:
        return jsonify({"error": "belum ada foto"}), 404
    resp = Response(ph["bytes"], mimetype="image/jpeg")
    resp.headers["Cache-Control"] = "private, max-age=3"
    return resp


@app.route("/api/photo/history")
@login_required
def api_photo_history():
    """Daftar metadata riwayat foto terakhir sebuah topik (maks. 10)."""
    topic = request.args.get("topic", "")
    if not re.fullmatch(r"[A-Za-z0-9_\-+/]+", topic or " "):
        return jsonify({"error": "topik tidak valid"}), 400
    return jsonify({"topic": topic,
                    "history": CACHE.photo_history(topic)})


# ------------------------------------------------------- API: anomali & dataset
_ALERT_COLS = ["time", "device", "mac", "type", "metric", "kind",
               "value", "threshold", "ratio", "hint"]
_WINDOW_COLS = ["ts", "waktu", "device", "mac", "n_publish", "bytes",
                "avg_pkt_size", "topics", "topic_last", "metrik_lebihi",
                "serangan"]


def _tail_alerts(path, limit=300):
    try:
        with open(path) as f:
            lines = f.readlines()[-limit:]
        return [json.loads(x) for x in lines if x.strip()]
    except Exception:
        return []


def _tail_csv(path, limit=500):
    """Baca CSV dari baris terakhir (terbaru) — dipakai anomaly_windows.csv."""
    try:
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
        return rows[-limit:][::-1]
    except Exception:
        return []


def _dataset_files():
    out = []
    if os.path.isdir(DATA_DIR):
        for name in sorted(os.listdir(DATA_DIR)):
            p = os.path.join(DATA_DIR, name)
            if not (os.path.isfile(p) and name.lower().endswith(".csv")):
                continue
            try:
                st = os.stat(p)
                with open(p, newline="", errors="replace") as f:
                    n_rows = max(0, sum(1 for _ in f) - 1)
                out.append({"name": name, "size": st.st_size,
                            "mtime": int(st.st_mtime), "rows": n_rows})
            except OSError:
                continue
    return out


@app.route("/api/anomalies")
@login_required
def api_anomalies():
    """Data untuk halaman Anomali & Dataset: event, window > threshold, berkas."""
    events = _tail_alerts(os.path.join(RUN_DIR, "alerts.jsonl"), 500)
    windows = _tail_csv(os.path.join(RUN_DIR, "anomaly_windows.csv"), 500)
    n_alert = sum(1 for e in events if e.get("kind") == "ALERT")
    # v8.2: status uji serangan web -> integrasi menu Serangan <-> Anomali
    attack = {"running": False}
    try:
        if ATTACK.running() and ATTACK.info:
            attack = {"running": True, "kode": ATTACK.info.get("kode"),
                      "target": ATTACK.info.get("target"),
                      "elapsed": round(time.time() - ATTACK.info["start"], 1)}
    except Exception:
        pass
    return jsonify({
        "events": events[::-1],          # terbaru di depan
        "windows": windows,
        "files": _dataset_files(),
        "attack": attack,
        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "stats": {
            "events": len(events),
            "alerts": n_alert,
            "recovery": len(events) - n_alert,
            "windows": len(windows),
            "files": len(_dataset_files()),
        },
    })


@app.route("/api/anomalies/export")
@login_required
def api_anomalies_export():
    """Unduh dataset anomali: ?type=events|windows&format=csv|json."""
    typ = request.args.get("type", "events")
    fmt = request.args.get("format", "csv")
    if typ not in ("events", "windows") or fmt not in ("csv", "json"):
        return jsonify({"error": "parameter tidak valid"}), 400
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if typ == "events":
        data = _tail_alerts(os.path.join(RUN_DIR, "alerts.jsonl"), 100000)
        cols, fname = _ALERT_COLS, f"mint_anomali_event_{stamp}.{fmt}"
    else:
        data = _tail_csv(os.path.join(RUN_DIR, "anomaly_windows.csv"), 100000)
        data = data[::-1]               # kembali urutan lama->baru utk dataset
        cols, fname = _WINDOW_COLS, f"mint_anomali_window_{stamp}.{fmt}"

    if fmt == "json":
        body = json.dumps(data, ensure_ascii=False, indent=2)
        resp = Response(body, mimetype="application/json")
    else:
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for row in data:
            w.writerow({k: row.get(k, "") for k in cols})
        resp = Response(buf.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    return resp


@app.route("/api/dataset/download")
@login_required
def api_dataset_download():
    """Unduh berkas dataset dari folder data/ (hanya .csv, anti path traversal)."""
    name = request.args.get("name", "")
    if not re.fullmatch(r"[\w\-+. ]+", name) or not name.lower().endswith(".csv"):
        return jsonify({"error": "nama berkas tidak valid"}), 400
    path = os.path.join(DATA_DIR, name)
    if not os.path.isfile(path):
        return jsonify({"error": "berkas tidak ditemukan"}), 404
    return send_file(path, as_attachment=True, download_name=name)


@app.route("/api/server")
@login_required
def api_server():
    """Pemakaian server + log sistem (dipakai halaman Server)."""
    s = dict(STATS.snapshot())
    s["syslog"] = LOGS[-12:]
    s["mqtt_cache"] = {"enabled": CACHE.enabled, "connected": CACHE.connected,
                       "rx_count": CACHE.rx_count}
    s["ping"] = {"enabled": PINGER.enabled,
                 "nodes": {ip: (PINGER.age(ip) is not None
                                and PINGER.age(ip) <= PINGER.ttl)
                           for ip in PingWatcher._targets()}}
    return jsonify(s)


@app.route("/api/telegram/test", methods=["POST"])
@login_required
def api_telegram_test():
    if not check_csrf():
        return jsonify({"ok": False, "msg": "Token CSRF tidak valid."}), 400
    try:
        sys.path.insert(0, os.path.join(ROOT, "analyzer"))
        from notifier import send_telegram   # noqa: E402
    except Exception:
        return jsonify({"ok": False,
                        "msg": "Modul analyzer/notifier.py tidak ditemukan."})
    ok = send_telegram(wait=True, text=f"[MINT] Tes notifikasi dari dashboard "
                       f"({datetime.now().strftime('%H:%M:%S')})")
    msg = ("Terkirim — cek aplikasi Telegram." if ok else
           "Gagal — cek variabel TELEGRAM_BOT_TOKEN dan TELEGRAM_CHAT_ID.")
    _log("Tes notifikasi Telegram: " + ("berhasil" if ok else "gagal"))
    return jsonify({"ok": ok, "msg": msg})


def _simpan_env(path, pasangan):
    """Perbarui/sisipkan pasangan KEY=VALUE di .env tanpa merusak baris lain."""
    baris = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            baris = f.read().splitlines()
    sisa = dict(pasangan)
    for i, b in enumerate(baris):
        k = b.split("=", 1)[0].strip()
        if k in sisa:
            baris[i] = f"{k}={sisa.pop(k)}"
    for k, v in sisa.items():
        baris.append(f"{k}={v}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(baris) + "\n")


# ------------------------------------------------ API: konfigurasi Telegram (v9)
@app.route("/api/telegram/config", methods=["GET", "POST"])
@login_required
def api_telegram_config():
    """Lihat status / simpan Token Bot & Chat ID Telegram dari web.

    POST  : tulis ke .env (persisten) + os.environ (efektif SEGERA,
            tanpa restart dashboard). Hanya admin.
    GET   : status ter-mask (token tidak pernah dikirim utuh ke browser).
    """
    env_path = os.path.join(ROOT, ".env")
    if request.method == "GET":
        if session.get("role") != "admin":
            return jsonify({"ok": False, "msg": "Hanya admin."}), 403
        tok = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        cid = os.environ.get("TELEGRAM_CHAT_ID", "")
        masked = (tok[:6] + "…" + tok[-4:]) if len(tok) >= 12 else ""
        return jsonify({"ok": True, "aktif": telegram_enabled(),
                        "token_masked": masked, "chat_id": cid})
    if session.get("role") != "admin":
        return jsonify({"ok": False,
                        "msg": "Hanya admin yang boleh mengubah bot Telegram."}), 403
    if not check_csrf():
        return jsonify({"ok": False, "msg": "Token CSRF tidak valid."}), 400
    token = (request.form.get("token") or "").strip()
    chat = (request.form.get("chat_id") or "").strip()
    if token and ":" not in token:
        return jsonify({"ok": False,
                        "msg": "Format token salah. Contoh: 123456789:AAExx… "
                               "(salin dari @BotFather)."}), 400
    if chat and not chat.lstrip("-").isdigit():
        return jsonify({"ok": False,
                        "msg": "Chat ID harus angka (boleh minus untuk grup)."}), 400
    if not token or not chat:
        return jsonify({"ok": False,
                        "msg": "Token dan Chat ID wajib diisi keduanya."}), 400
    try:
        _simpan_env(env_path, {"TELEGRAM_BOT_TOKEN": token,
                               "TELEGRAM_CHAT_ID": chat})
    except OSError as e:
        return jsonify({"ok": False, "msg": f"Gagal menulis .env: {e}"}), 500
    os.environ["TELEGRAM_BOT_TOKEN"] = token
    os.environ["TELEGRAM_CHAT_ID"] = chat
    _log("Konfigurasi Telegram diperbarui dari web (admin).")
    # kirim pesan konfirmasi langsung pakai konfigurasi baru
    sys.path.insert(0, os.path.join(ROOT, "analyzer"))
    from notifier import send_telegram   # noqa: E402
    tes = send_telegram(wait=True, text=f"[MINT] Bot Telegram baru AKTIF — dikirim dari "
                        f"dashboard ({datetime.now().strftime('%H:%M:%S')}).")
    return jsonify({"ok": True,
                    "msg": ("Tersimpan & TERKIRIM — cek aplikasi Telegram."
                            if tes else
                            "Tersimpan di .env, tetapi pengiriman uji gagal — "
                            "cek token/chat_id atau koneksi internet.")})


# ------------------------------------------------------ API: serangan (v8.1)
@app.route("/api/attack/start", methods=["POST"])
@login_required
def api_attack_start():
    """Mulai skenario serangan S1-S4 dari web (subprocess attack_sim.py)."""
    if not check_csrf():
        return jsonify({"ok": False, "msg": "Token CSRF tidak valid."}), 400
    f = request.form
    kode = (f.get("kode") or "").strip().upper()
    target = (f.get("target") or "").strip() or None
    if target and not re.fullmatch(r"[A-Za-z0-9_\-+/]+", target):
        return jsonify({"ok": False, "msg": "Topik target tidak valid."}), 400
    try:
        rate = int(f.get("rate") or 0) or None
        duration = int(f.get("duration") or 0) or None
        size = int(f.get("size") or 0) or None
    except ValueError:
        return jsonify({"ok": False,
                        "msg": "Rate/durasi/ukuran harus berupa angka."}), 400
    if rate is not None and not 1 <= rate <= 500:
        return jsonify({"ok": False,
                        "msg": "Rate harus 1-500 pesan/detik."}), 400
    if duration is not None and not 5 <= duration <= 600:
        return jsonify({"ok": False, "msg": "Durasi harus 5-600 detik."}), 400
    if size is not None and not 1 <= size <= 512:
        return jsonify({"ok": False,
                        "msg": "Ukuran payload 1-512 KB (>200 KB sesuai proposal)."}), 400
    # parameter ukuran payload hanya berlaku utk skenario S3 (payload besar)
    if kode != "S3":
        size = None
    ok, msg = ATTACK.start(kode, target=target, rate=rate,
                           duration=duration, size=size)
    return jsonify({"ok": ok, "msg": msg})


@app.route("/api/attack/stop", methods=["POST"])
@login_required
def api_attack_stop():
    if not check_csrf():
        return jsonify({"ok": False, "msg": "Token CSRF tidak valid."}), 400
    ok, msg = ATTACK.stop()
    return jsonify({"ok": ok, "msg": msg})


@app.route("/api/attack/status")
@login_required
def api_attack_status():
    return jsonify(ATTACK.status())


@app.route("/api/system/test")
@login_required
def api_system_test():
    """Diagnostik satu klik seluruh komponen (halaman Serangan & Server)."""
    hasil = []
    b = broker_ip()
    ok = _check_tcp(b, 1883)
    hasil.append({"nama": f"Broker MQTT ({b}:1883)", "ok": ok,
                  "catatan": "terjangkau" if ok else
                  "jalankan mulai_stack.bat / mosquitto"})
    hasil.append({"nama": "Subscribe iot/# (sensor live)",
                  "ok": CACHE.connected,
                  "catatan": (f"{CACHE.rx_count} pesan diterima"
                              if CACHE.connected else "cache belum tersambung")})
    exe = tshark_io.resolve_tshark()
    hasil.append({"nama": "tshark (Wireshark)", "ok": bool(exe),
                  "catatan": (f"interface terdeteksi: {INTEGRATED.iface or '-'}"
                              if exe else
                              "tidak terpasang — metrik otomatis pakai "
                              "fallback MQTT (tetap jalan)")})
    d = INTEGRATED.describe()
    hasil.append({"nama": "Sumber metrik PPS/BPS", "ok": bool(d["source"]),
                  "catatan": d["label"]})
    i_live = _check_tcp("127.0.0.1", 8086)
    hasil.append({"nama": "InfluxDB (:8086)", "ok": i_live,
                  "catatan": ("menerima metrik (Grafana siap)"
                              if INTEGRATED.influx else
                              "hidup — tunggu koneksi otomatis" if i_live else
                              "jalankan mulai_stack.bat (opsional)")})
    gok = _check_tcp("127.0.0.1", 3000)
    hasil.append({"nama": "Grafana (:3000)", "ok": gok,
                  "catatan": ("grafik siap di menu Grafana" if gok else
                              "jalankan mulai_stack.bat (opsional)")})
    tge = telegram_enabled()
    hasil.append({"nama": "Notifikasi Telegram", "ok": tge,
                  "catatan": ("aktif — alert PPS+BPS digabung 1 pesan"
                              if tge else
                              "isi TELEGRAM_BOT_TOKEN & TELEGRAM_CHAT_ID "
                              "di file .env")})
    return jsonify({"hasil": hasil,
                    "waktu": datetime.now().strftime("%H:%M:%S")})


@app.route("/api/change_password", methods=["POST"])
@login_required
def api_change_password():
    if not check_csrf():
        return jsonify({"ok": False, "msg": "Token CSRF tidak valid."}), 400
    lama = request.form.get("lama", "")
    baru = request.form.get("baru", "")
    konf = request.form.get("konfirmasi", "")
    users = load_users()
    me = next((u for u in users if u["username"] == session.get("user")), None)
    if me is None:
        return jsonify({"ok": False, "msg": "Pengguna tidak ditemukan."})
    if not check_password_hash(me["password_hash"], lama):
        return jsonify({"ok": False, "msg": "Kata sandi lama salah."})
    if len(baru) < 6:
        return jsonify({"ok": False,
                        "msg": "Kata sandi baru minimal 6 karakter."})
    if baru != konf:
        return jsonify({"ok": False, "msg": "Konfirmasi kata sandi tidak sama."})
    if baru == lama:
        return jsonify({"ok": False,
                        "msg": "Kata sandi baru harus berbeda dari yang lama."})
    me["password_hash"] = generate_password_hash(baru)
    me["diubah"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_users(users)
    _log(f"Kata sandi diubah untuk '{me['username']}'")
    return jsonify({"ok": True, "msg": "Kata sandi berhasil diganti."})


def _infer_scenario(alerts):
    recent = [a for a in alerts if a.get("kind") == "ALERT"]
    if not recent:
        return None
    hits = {}
    for a in recent:
        hits.setdefault(a["metric"], set()).add(a["device"])
    for metric, devs in hits.items():
        if len(devs) >= 2:
            return "S4 (serangan multi-perangkat)"
    return recent[-1].get("hint")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Dashboard web MINT")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()
    _log("MINT dashboard v9.2.5 dimulai (login: admin / mintadmin)")
    print(f"MINT dashboard v9.2.5 -> http://localhost:{args.port}  (Ctrl+C untuk berhenti)")
    print("Analyzer terintegrasi AKTIF — metrik tshark + MQTT digabung "
          "(serangan web pasti terlihat di grafik/anomali).")
    print("Halaman: / Beranda | /nodes Node | /pps Grafik PPS | /anomali Anomali"
          " | /serang Serangan | /sesi Sesi Rekam | /server | /log Log |"
          " /pengaturan | /bantuan")
    print("Kelola akun: python dashboard/add_user.py | ganti sandi: menu Pengaturan")
    app.run(host=args.host, port=args.port, debug=False)
