#!/usr/bin/env python3
"""MINT - Analyzer real-time: window 1 detik -> threshold -> state.json + alerts.jsonl.

v9.1: penulisan state.json TAHAN KUNCI (fix PermissionError [WinError 5] di
      Windows saat dashboard/antivirus membuka berkas yang sama) — analyzer
      tidak lagi mati gara-gara tabrakan baca-tulis; retry + fallback + lewati.

Tiga mode operasi:
  1. LIVE   : tangkap traffic via tshark dari interface jaringan
              python analyzer/live_analyzer.py --iface 1 --thresholds thresholds.json
  2. PCAP   : proses berkas .pcap lalu berhenti (evaluasi cepat pasca-sesi)
              python analyzer/live_analyzer.py --pcap captures/uji.pcap
  3. REPLAY : putar ulang CSV metrik (demo tanpa perangkat / tanpa tshark)
              python analyzer/live_analyzer.py --replay data/demo_serangan.csv --speed 10

Keluaran (di folder run/):
  state.json   : kondisi terkini per perangkat -> dibaca dashboard Flask :5000
  alerts.jsonl : riwayat event ALERT/RECOVERY (satu JSON per baris)

Opsi: --influx menulis metrik ke InfluxDB (bucket traffic) bila modul tersedia.
"""
import argparse
import csv
import json
import os
import signal
import sys
import time

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detection import ThresholdEngine          # noqa: E402
from notifier import send_telegram, telegram_enabled  # noqa: E402
import tshark_io                               # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN_DIR = os.environ.get("MINT_RUN_DIR", os.path.join(ROOT, "run"))


# ---------------------------------------------------------------------- InfluxDB
class InfluxWriter:
    """Penulis ke InfluxDB 2.x (bucket traffic) — v9.2.6 ditulis ulang.

    Perbaikan dibanding v9.2.5 (penyebab grafik Grafana "ngestak"/putus-putus
    dan tidak sama dengan halaman web):
      * NON-BLOCKING: titik dimasukkan ke antrean, thread latar mengirim
        batch tiap ~1 detik. Dulu tiap titik ditulis sinkron di thread
        deteksi: InfluxDB lambat/mati = analyzer & dashboard ikut macet.
      * SATU TITIK PER PERANGKAT PER DETIK (zero-fill) — termasuk detik saat
        node diam (pps=0) dan node terdaftar yang belum pernah kirim. Dulu
        titik hanya ada saat node mengirim, jadi node 10-detik-an hanya
        punya 1 titik tiap 10 detik dan garis Grafana patah-patah.
      * TAG KONSISTEN: hanya `device` (IP) dan `node` (nama). Tag `mac`
        dihapus — nilainya bergantian "-" (jalur MQTT) / MAC asli (jalur
        tshark) sehingga satu node terpecah jadi dua seri di Grafana.
      * METRIK SAMA DENGAN HALAMAN WEB: pps_15s / bps_15s / avg_pkt_size_15s
        (+ _2m), plus threshold (thr_*), baseline median (base_*), rasio
        terhadap threshold (ratio_*) dan status alert (0/1) per node —
        Grafana dan /pps menampilkan angka yang SAMA, bisa dibandingkan.
      * pengamatan serangan: measurement `attack` (scenario, active) tiap
        detik; alert: measurement `alerts` dengan field TETAP
        (value, threshold, ratio) dan tag kind — hitungan stat tidak lagi
        kegandaan 3x.
    """

    def __init__(self):
        self.ok = False
        self._q = None
        self._warn_ts = 0.0
        self._reg_cache = (0.0, {})
        try:
            import queue
            import threading
            from influxdb_client import InfluxDBClient, Point, WritePrecision
            from influxdb_client.client.write_api import SYNCHRONOUS
            url = os.environ.get("MINT_INFLUX_URL", "http://localhost:8086")
            token = os.environ.get("MINT_INFLUX_TOKEN", "mint-super-secret-token-change-me")
            org = os.environ.get("MINT_INFLUX_ORG", "mint")
            self.bucket = os.environ.get("MINT_INFLUX_BUCKET", "traffic")
            self.Point, self.WritePrecision = Point, WritePrecision
            self.api = InfluxDBClient(url=url, token=token, org=org,
                                      timeout=5000) \
                .write_api(write_options=SYNCHRONOUS)
            self._q = queue.Queue(maxsize=20000)
            self.ok = True
            threading.Thread(target=self._worker, daemon=True).start()
            print(f"[influx] aktif -> {url} bucket={self.bucket}")
        except Exception as e:
            print(f"[influx] NONAKTIF ({e.__class__.__name__}: {e})")

    # ----------------------------------------------------------- internal
    def _warn(self, msg):
        now = time.time()
        if now - self._warn_ts >= 30:
            self._warn_ts = now
            print(f"[influx] {msg}")

    def _worker(self):
        import queue
        while True:
            batch = []
            try:
                batch.append(self._q.get(timeout=1.0))
                while len(batch) < 2000:
                    batch.append(self._q.get_nowait())
            except queue.Empty:
                pass
            if not batch:
                continue
            try:
                self.api.write(bucket=self.bucket, record=batch)
            except Exception as e:
                self._warn(f"gagal menulis {len(batch)} titik "
                           f"({e.__class__.__name__}: {e}) — dicoba lagi nanti")
                time.sleep(2)

    def _put(self, point):
        try:
            self._q.put_nowait(point)
        except Exception:
            self._warn("antrean penuh — titik dibuang (InfluxDB lambat/mati)")

    def _registry(self):
        """devices.json (di-cache, dibaca ulang bila berubah)."""
        path = os.path.join(ROOT, "devices.json")
        try:
            mt = os.path.getmtime(path)
            if mt != self._reg_cache[0]:
                with open(path, encoding="utf-8") as f:
                    nodes = json.load(f).get("nodes", [])
                self._reg_cache = (mt, {n["ip"]: n for n in nodes if n.get("ip")})
        except Exception:
            pass
        return self._reg_cache[1]

    def node_label(self, device):
        n = self._registry().get(device)
        if n:
            return f"{n.get('name', device)} {n.get('sensor', '')}".strip()
        return str(device)

    # ----------------------------------------------------------- API
    def write_second(self, ts, devices, engine, attack=None):
        """Tulis satu detik penuh: SEMUA node (aktif, diam, terdaftar)."""
        if not self.ok:
            return
        ts_ns = int(ts) * 1_000_000_000
        reg = self._registry()
        seen = dict(devices)
        for ip in reg:                         # node terdaftar yang belum terlihat
            seen.setdefault(ip, None)
        for ip, d in seen.items():
            d = d or {}
            p = (self.Point("traffic_metrics")
                 .tag("device", ip).tag("node", self.node_label(ip))
                 .field("pps", int(d.get("pps", 0)))
                 .field("bps", int(d.get("bps", 0)))
                 .field("avg_pkt_size", float(d.get("avg_pkt_size") or 0))
                 .field("topics", int(d.get("topics", 0)))
                 .field("pps_15s", float(d.get("pps_15s", 0)))
                 .field("bps_15s", float(d.get("bps_15s", 0)))
                 .field("avg_pkt_size_15s", float(d.get("avg_pkt_size_15s", 0)))
                 .field("pps_2m", float(d.get("pps_2m", 0)))
                 .field("bps_2m", float(d.get("bps_2m", 0)))
                 .field("alert", 1 if d.get("status") == "ALERT" else 0)
                 .field("total_publish", int(d.get("total_publish", 0))))
            for metric in ("pps", "bps", "avg_pkt_size"):
                thr = engine.threshold_for(ip, metric) if engine else None
                if thr:
                    live = float(d.get(metric + "_15s", 0))
                    p = (p.field("thr_" + metric, float(thr))
                         .field("ratio_" + metric, round(live / float(thr), 4)))
                base = ((engine.thresholds.get("devices", {}).get(ip, {})
                         .get(metric, {})) if engine else {}).get("median")
                if base is not None:
                    p = p.field("base_" + metric, float(base))
            self._put(p.time(ts_ns, self.WritePrecision.NS))
        a = attack or {}
        self._put(self.Point("attack")
                  .tag("scenario", a.get("kode") or "none")
                  .field("active", 1 if a.get("kode") else 0)
                  .time(ts_ns, self.WritePrecision.NS))

    def write_window(self, row):
        """Kompatibilitas: satu baris window mentah (dipakai jalur lama)."""
        if not self.ok:
            return
        dev = row["device"]
        self._put(self.Point("traffic_metrics")
                  .tag("device", dev).tag("node", self.node_label(dev))
                  .field("pps", int(row["n_publish"]))
                  .field("bps", int(row["bytes"]))
                  .field("avg_pkt_size", float(row.get("avg_pkt_size") or 0))
                  .field("topics", int(row.get("topics") or 0))
                  .time(int(row["ts"]) * 1_000_000_000, self.WritePrecision.NS))

    def write_alert(self, ev):
        if not self.ok:
            return
        self._put(self.Point("alerts")
                  .tag("device", ev["device"])
                  .tag("node", self.node_label(ev["device"]))
                  .tag("metric", ev["metric"]).tag("type", ev["type"])
                  .tag("kind", ev["kind"])
                  .field("value", float(ev["value"]))
                  .field("threshold", float(ev["threshold"] or 0))
                  .field("ratio", float(ev["ratio"]))
                  .time(int(ev["ts"]) * 1_000_000_000, self.WritePrecision.NS))


# ---------------------------------------------------------------------- keluaran
class Output:
    """Tulis state.json (atomik, tahan kunci) dan alerts.jsonl (append).

    Fix v9.1: di Windows, os.replace() gagal dengan PermissionError
    [WinError 5] bila berkas tujuan sedang dibuka proses lain — misalnya
    dashboard yang membaca state.json tiap detik, antivirus, atau sinkronisasi
    OneDrive. Penulisan kini memakai retry singkat, fallback tulis langsung,
    dan bila tetap terkunci penulisan detik itu dilewati (tidak crash).
    """

    def __init__(self, run_dir, engine, source):
        os.makedirs(run_dir, exist_ok=True)
        self.run_dir = run_dir
        self.engine = engine
        self.source = source
        self.state_path = os.path.join(run_dir, "state.json")
        self.alerts_path = os.path.join(run_dir, "alerts.jsonl")
        self.last_window = {}
        self.first_seen = {}     # ip -> ts pertama terlihat (sejak analyzer start)
        self.totals = {}         # ip -> total PUBLISH kumulatif
        self.hist = {}           # ip -> [(ts, n_publish, bytes)] jendela 2 mnt terakhir
        self._warn_ts = 0.0      # throttle peringatan berkas terkunci (v9.1)

    def _warn_locked(self, path, err):
        """Peringatan berkas terkunci — maksimal satu baris / 30 detik."""
        now = time.time()
        if now - self._warn_ts >= 30:
            self._warn_ts = now
            print(f"[keluaran] PERINGATAN: {path} sedang dikunci proses lain "
                  f"({err.__class__.__name__}: {err}) — penulisan dilewati, "
                  f"akan dicoba lagi detik berikutnya")

    def _write_json_safe(self, path, obj):
        """Tulis JSON atomik sekaligus TAHAN KUNCI (fix v9.1 WinError 5).

        Urutan penyelamatan:
          1. tulis ke berkas sementara lalu os.replace() — coba hingga 6x
             (jeda 50 ms) menunggu pembaca lain menutup berkas;
          2. fallback: tulis langsung ke berkas tujuan (pembaca dashboard
             menoleransi JSON setengah jadi — dianggap basi, dicoba lagi);
          3. bila tetap gagal: lewati penulisan ini, jangan matikan analyzer.
        """
        payload = json.dumps(obj, ensure_ascii=False)
        tmp = path + ".tmp"
        last_err = None
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(payload)
        except OSError as e:
            last_err = e
        if last_err is None:
            for _ in range(6):
                try:
                    os.replace(tmp, path)
                    return True
                except PermissionError as e:      # WinError 5: dibuka proses lain
                    last_err = e
                    time.sleep(0.05)
                except OSError as e:
                    last_err = e
                    break
            try:
                os.remove(tmp)                    # bersihkan sisa berkas sementara
            except OSError:
                pass
        for _ in range(3):                       # fallback: tulis langsung
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(payload)
                return True
            except OSError as e:
                last_err = e
                time.sleep(0.05)
        self._warn_locked(path, last_err)
        return False

    # ------------------------------------------------- metrik bergulir 2 menit
    def _rolling(self, ts):
        """Rata-rata pps/bps/avg_pkt_size per perangkat: jendela 2 menit DAN 15 detik.

        Nilai sesaat (window 1 detik) bernilai 0 pada detik saat node tidak
        menerbitkan apa pun -- normal untuk node yang mengirim tiap beberapa
        detik. Dashboard memakai dua jendela:
          * _2m  : kartu KPI (stabil, mirip rata-rata bergerak panjang)
          * _15s : GRAFIK + kartu node -- responsif: lonjakan S1/S3/S4
                   terlihat dalam 1-2 detik.
        v9.2.6: pembagi = min(lebar jendela, umur perangkat sejak pertama
        terlihat). Dulu pembagi dihitung dari sampel PERTAMA di dalam
        jendela, sehingga satu pesan tunggal setelah jeda panjang tampil
        sebagai pps=1.0 (lonjakan palsu) lalu meluruh -- grafik bergerigi
        dan tidak sama antara halaman web dan Grafana.
        """
        out = {}
        for ip, h in self.hist.items():
            h = [x for x in h if x[0] > ts - 120]
            self.hist[ip] = h
            if not h:
                continue
            age = max(1.0, ts - self.first_seen.get(ip, h[0][0]) + 1)
            h15 = [x for x in h if x[0] > ts - 15]
            span15 = min(15.0, age)
            n15 = sum(x[1] for x in h15)
            b15 = sum(x[2] for x in h15)
            r15 = {"pps_15s": round(n15 / span15, 2),
                   "bps_15s": int(b15 / span15),
                   "avg_pkt_size_15s": round(b15 / n15, 1) if n15 else 0}
            span = min(120.0, age)
            n = sum(x[1] for x in h)
            b = sum(x[2] for x in h)
            out[ip] = {**r15,
                       "pps_2m": round(n / span, 2),
                       "bps_2m": int(b / span),
                       "avg_pkt_size_2m": round(b / n, 1) if n else 0}
        return out

    def write_state(self, ts, rows):
        for r in rows:
            h = self.hist.setdefault(r["device"], [])
            h.append((r["ts"], r["n_publish"], r["bytes"]))
            self.first_seen.setdefault(r["device"], r["ts"])
        roll = self._rolling(ts)
        devices = {}
        for r in rows:
            status, alerts = self.engine.device_status(r["device"])
            self.first_seen.setdefault(r["device"], r["ts"])
            self.totals[r["device"]] = self.totals.get(r["device"], 0) + r["n_publish"]
            devices[r["device"]] = {
                "mac": r["mac"], "topic_last": r.get("topic_last", "-"),
                "pps": r["n_publish"], "bps": r["bytes"],
                "avg_pkt_size": r.get("avg_pkt_size") or 0,
                "topics": r.get("topics") or 0,
                "status": status, "alerts": alerts, "last_seen": r["ts"],
                "first_seen": self.first_seen[r["device"]],
                "total_publish": self.totals[r["device"]],
                **roll.get(r["device"], {"pps_2m": 0, "bps_2m": 0,
                                         "avg_pkt_size_2m": 0,
                                         "pps_15s": 0, "bps_15s": 0,
                                         "avg_pkt_size_15s": 0}),
            }
            self.last_window[r["device"]] = devices[r["device"]]
        # perangkat yang tidak mengirim di window ini tetap tampil (data terakhir)
        for ip, prev in self.last_window.items():
            if ip not in devices:
                prev = dict(prev)
                prev["pps"], prev["bps"], prev["avg_pkt_size"] = 0, 0, 0
                prev["topics"] = 0
                # v9.2.6: status node diam dihitung ulang (dulu membeku di
                # nilai terakhir -> ALERT "menempel" walau sudah pulih)
                prev["status"], prev["alerts"] = self.engine.device_status(ip)
                prev.update(roll.get(ip, {"pps_2m": 0, "bps_2m": 0,
                                          "avg_pkt_size_2m": 0,
                                          "pps_15s": 0, "bps_15s": 0,
                                          "avg_pkt_size_15s": 0}))
                devices[ip] = prev
        state = {
            "updated": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
            "updated_ts": int(ts), "source": self.source,
            # kesegaran jam dinding: dipakai dashboard menilai analyzer aktif/
            # tidak — terpisah dari ts data (mode replay memakai waktu maya)
            "wall_ts": time.time(),
            "global": {
                "pps": sum(d["pps"] for d in devices.values()),
                "bps": sum(d["bps"] for d in devices.values()),
                "pps_2m": round(sum(d.get("pps_2m", 0)
                                    for d in devices.values()), 2),
                "bps_2m": sum(d.get("bps_2m", 0) for d in devices.values()),
                "pps_15s": round(sum(d.get("pps_15s", 0)
                                     for d in devices.values()), 2),
                "bps_15s": sum(d.get("bps_15s", 0) for d in devices.values()),
                "devices": len(devices),
            },
            "devices": devices,
            "engine": self.engine.snapshot(),
        }
        self._write_json_safe(self.state_path, state)   # v9.1: tahan kunci
        return devices

    def append_alerts(self, events):
        if not events:
            return
        try:
            with open(self.alerts_path, "a", encoding="utf-8") as f:
                for ev in events:
                    f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        except OSError as e:
            self._warn_locked(self.alerts_path, e)

    # kolom dataset window anomali (dipakai dashboard: halaman Anomali & Dataset)
    # v8.2: kolom "serangan" berisi kode uji serangan web (S1-S4) yang sedang
    # berjalan saat window itu tercatat — kosong utk analyzer mandiri/trafik nyata
    ANOM_COLS = ["ts", "waktu", "device", "mac", "n_publish", "bytes",
                 "avg_pkt_size", "topics", "topic_last", "metrik_lebihi",
                 "serangan"]

    def _migrate_anom_csv(self, path):
        """Samakan header lama (tanpa kolom 'serangan') dengan skema v8.2."""
        try:
            with open(path, newline="") as f:
                first = f.readline()
            if "serangan" in first:
                return
            with open(path, newline="") as f:
                rows = list(csv.reader(f))
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(self.ANOM_COLS)
                for r in rows[1:]:
                    w.writerow(r + [""] * (len(self.ANOM_COLS) - len(r)))
        except OSError:
            pass

    def log_anomaly_windows(self, engine, rows, serangan=None):
        """Catat SETIAP window yang melampaui threshold ke anomaly_windows.csv.

        Berbeda dari alerts.jsonl (satu event per episode), berkas ini menyimpan
        semua window 1-detik yang nilainya > threshold — siap diunduh sebagai
        dataset anomali dari menu 'Anomali & Dataset' di dashboard.
        Parameter serangan (v8.2): kode skenario uji web yang sedang berjalan
        (mis. "S1") saat window ini tercatat; None/"" = trafik tanpa uji aktif.
        """
        try:
            path = os.path.join(self.run_dir, "anomaly_windows.csv")
            baru = not os.path.exists(path)
            if not baru:
                self._migrate_anom_csv(path)
            with open(path, "a", newline="") as f:
                w = csv.writer(f)
                if baru:
                    w.writerow(self.ANOM_COLS)
                for r in rows:
                    if r.get("n_publish", 0) <= 0:
                        continue
                    exceeded = []
                    for metric, col in (("pps", "n_publish"), ("bps", "bytes"),
                                        ("avg_pkt_size", "avg_pkt_size")):
                        thr = engine.threshold_for(r["device"], metric)
                        val = r.get(col) or 0
                        if thr and val > thr:
                            exceeded.append(
                                f"{metric}={val:g} > thr {thr:g} ({val/thr:.1f}x)")
                    if exceeded:
                        w.writerow([
                            r["ts"],
                            time.strftime("%Y-%m-%d %H:%M:%S",
                                          time.localtime(r["ts"])),
                            r["device"], r["mac"], r["n_publish"], r["bytes"],
                            round(r.get("avg_pkt_size") or 0, 1),
                            r.get("topics") or 0, r.get("topic_last", "-"),
                            "; ".join(exceeded), serangan or ""])
        except OSError as e:
            print(f"[anomali] gagal mencatat window: {e}")

    @staticmethod
    def print_window(ts, rows, events, verbose=True):
        """Cetak ringkasan window ke konsol + kirim Telegram.

        Sejak v8.1 notifikasi Telegram DIGABUNG: seluruh event satu window
        untuk perangkat yang sama (mis. PPS dan BPS) dikirim sebagai SATU
        pesan, bukan satu pesan per metrik.
        """
        stamp = time.strftime("%H:%M:%S", time.localtime(ts))
        if verbose:
            for r in rows:
                print(f"[{stamp}] {r['device']:<16} pps={r['n_publish']:<4} "
                      f"bps={r['bytes']:<7} avg={r.get('avg_pkt_size', 0):<8} "
                      f"topik={r.get('topic_last', '-')}")
        for ev in events:
            if ev["kind"] == "ALERT":
                print(f"[{stamp}] *** ALERT {ev['type']} pada {ev['device']} "
                      f"({ev['metric']}={ev['value']} > thr={ev['threshold']}, "
                      f"{ev['ratio']}x) {ev.get('hint', '')}")
            else:
                print(f"[{stamp}] pulih: {ev['device']} {ev['metric']} kembali normal")
        # ---- Telegram: gabungkan event per perangkat -> satu pesan ----
        per_dev = {}
        for ev in events:
            if ev["kind"] == "ALERT" and not ev.get("notify", True):
                continue                # masa cooldown: tercatat, tidak dikirim
            d = per_dev.setdefault(ev["device"], {"mac": ev.get("mac", "-"),
                                                  "time": ev["time"],
                                                  "alerts": [], "rec": []})
            (d["alerts"] if ev["kind"] == "ALERT" else d["rec"]).append(ev)
        for dev, d in per_dev.items():
            if d["alerts"]:
                baris = ["MINT - ALERT TERDETEKSI",
                         f"Perangkat : {dev} ({d['mac']})"]
                for ev in d["alerts"]:
                    baris.append(f"- {ev['type']}: {ev['metric']} = {ev['value']:g}"
                                 f" > threshold {ev['threshold']:g} ({ev['ratio']}x)")
                hints = {ev.get("hint") for ev in d["alerts"] if ev.get("hint")}
                if hints:
                    baris.append("Indikasi : " + "; ".join(sorted(hints)))
                baris.append(f"Waktu : {d['time']}")
                send_telegram("\n".join(baris))
            if d["rec"]:
                metrik = ", ".join(sorted({ev["metric"] for ev in d["rec"]}))
                send_telegram(f"MINT - PULIH\nPerangkat : {dev} ({d['mac']})\n"
                              f"Metrik {metrik} kembali normal\nWaktu : {d['time']}")


# ---------------------------------------------------------------------- proses
def handle_rows(rows, engine, out, influx, notify=True, ts=None):
    ts = ts if ts is not None else (rows[0]["ts"] if rows else None)
    if ts is None:
        return
    events = []
    for r in rows:
        events += engine.update_window(r["ts"], r["device"], r["mac"], r)
    events += engine.tick(ts)               # v9.2.6: recovery node yang diam
    devices = out.write_state(ts, rows)
    out.append_alerts(events)
    out.log_anomaly_windows(engine, rows)
    out.print_window(ts, rows, events)
    if influx:
        influx.write_second(ts, devices, engine)
        for ev in events:
            influx.write_alert(ev)


def run_live(args, engine, out, influx):
    proc = tshark_io.open_live(args.iface)
    print(f"[live] tshark berjalan di interface {args.iface}. Ctrl+C untuk berhenti.")
    agg = tshark_io.WindowAggregator()
    try:
        for line in proc.stdout:
            pkt = tshark_io.parse_line(line)
            if not pkt:
                continue
            sec = int(pkt["ts"])
            if agg.cur_sec is not None and sec != agg.cur_sec:
                rows = agg.close()
                handle_rows(rows, engine, out, influx)
                agg.cur_sec = sec
            agg.add(pkt)
    except KeyboardInterrupt:
        pass
    finally:
        rows = agg.close()
        if rows:
            handle_rows(rows, engine, out, influx)
        proc.terminate()
        print("\n[live] dihentikan.")


def run_pcap(args, engine, out, influx):
    agg = tshark_io.WindowAggregator()
    n = 0
    for pkt in tshark_io.iter_pcapan(args.pcap):
        sec = int(pkt["ts"])
        if agg.cur_sec is not None and sec != agg.cur_sec:
            rows = agg.close()
            handle_rows(rows, engine, out, influx)
            n += len(rows)
            agg.cur_sec = sec
        agg.add(pkt)
    rows = agg.close()
    if rows:
        handle_rows(rows, engine, out, influx)
        n += len(rows)
    print(f"\n[pcap] selesai: {n} baris window dievaluasi.")


def run_replay(args, engine, out, influx):
    with open(args.replay, newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print("\n[replay] CSV kosong.")
        return
    # v8.2: geser seluruh waktu maya CSV ke JAM SERVER SAAT INI. Pola interval
    # antar-baris tetap sama, tetapi waktu yang tampil di dashboard/anomali
    # realtime (sebelumnya tercatat sebagai tanggal lampau ketika data demo
    # dibuat, sehingga menu Anomali tampak "tidak realtime").
    offset = time.time() - float(rows[0]["ts"] or 0)
    print(f"[replay] {len(rows)} baris; waktu maya digeser +{offset/3600:.1f} jam "
          f"agar cocok dengan jam server ({time.strftime('%H:%M:%S')})")
    for r in rows:
        r = {k: (v if k in ("device", "mac", "topic_last", "label") else float(v))
             for k, v in r.items()}
        r["ts"] = int(r["ts"] + offset)
        r["topics"] = int(r.get("topics") or 0)
        r["retrans"] = int(r.get("retrans") or 0)
        handle_rows([r], engine, out, influx)
        time.sleep(1.0 / max(args.speed, 0.1))
    print("\n[replay] selesai.")


def main():
    ap = argparse.ArgumentParser(description="Analyzer real-time MINT")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--iface", help="nomor/nama interface tshark (lihat: tshark -D)")
    g.add_argument("--pcap", help="proses berkas pcap lalu berhenti")
    g.add_argument("--replay", help="putar ulang CSV metrik (mode demo)")
    ap.add_argument("--thresholds", default=os.path.join(ROOT, "thresholds.json"))
    ap.add_argument("--speed", type=float, default=1.0,
                    help="kecepatan replay (10 = 10x lebih cepat)")
    ap.add_argument("--influx", action="store_true", help="tulis metrik ke InfluxDB")
    args = ap.parse_args()

    thresholds = {}
    if os.path.exists(args.thresholds):
        with open(args.thresholds) as f:
            thresholds = json.load(f)
        n = len(thresholds.get("devices", {}))
        print(f"[thr] memuat {args.thresholds}: {n} perangkat terkalibrasi")
    else:
        print(f"[thr] PERINGATAN: {args.thresholds} tidak ditemukan — "
              f"fallback global (sangat disarankan jalankan threshold_baseline.py)")

    engine = ThresholdEngine(thresholds, thresholds.get("params"))
    source = ("live:" + str(args.iface)) if args.iface else (
        "pcap:" + args.pcap if args.pcap else "replay:" + args.replay)
    out = Output(RUN_DIR, engine, source)
    influx = InfluxWriter() if args.influx else None
    if telegram_enabled():
        print("[telegram] notifikasi aktif")
    print("[MINT] analyzer v9.1 — penulisan state.json tahan kunci (fix WinError 5)")

    signal.signal(signal.SIGINT, signal.default_int_handler)
    if args.iface:
        run_live(args, engine, out, influx)
    elif args.pcap:
        run_pcap(args, engine, out, influx)
    else:
        run_replay(args, engine, out, influx)


if __name__ == "__main__":
    main()
