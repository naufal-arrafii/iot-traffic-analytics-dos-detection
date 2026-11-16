#!/usr/bin/env python3
"""MINT - Mesin deteksi anomali berbasis threshold (Spesifikasi Teknis Bab 5).

Aturan deteksi:
  * threshold per perangkat per metrik : median + k * 1.4826 * MAD (dari baseline)
  * 2-of-3      : >= confirm dari lookback window terakhir di atas threshold -> ALERT
  * override Nx : satu window >= N x threshold -> ALERT langsung (tanpa menunggu 2-of-3)
  * recovery    : status ALERT kembali OK setelah recovery_s detik tanpa window tinggi
  * cooldown    : notifikasi duplikat ALERT per (perangkat, metrik) ditekan cooldown_s detik

Metrik yang dievaluasi (hanya pada window yang memiliki PUBLISH):
  pps          -> jumlah PUBLISH per detik   (skenario S1/S2/S4)
  bps          -> total byte PUBLISH per detik
  avg_pkt_size -> rata-rata byte per PUBLISH (skenario S3, payload abnormal)
"""
import json
import time
from collections import deque

# Parameter default; dapat ditimpa oleh thresholds.json hasil threshold_baseline.py
DEFAULT_PARAMS = {
    "k": 3.0,
    "cooldown_s": 30.0,
    "recovery_s": 60.0,
    "metrics": {
        "pps":          {"lookback": 3, "confirm": 2, "override": 5.0},
        "bps":          {"lookback": 3, "confirm": 2, "override": 5.0},
        # Ukuran payload = sinyal bersih -> 1 window cukup, override lebih rendah
        "avg_pkt_size": {"lookback": 1, "confirm": 1, "override": 3.0},
    },
}

METRIC_TYPE = {
    "pps": "PUBLISH-FLOOD",
    "bps": "TRAFFIC-SPIKE",
    "avg_pkt_size": "OVERSIZED-PAYLOAD",
}


def _hint(metric, ratio):
    """Perkiraan skenario untuk ditampilkan di dashboard (indikatif, bukan diagnosis)."""
    if metric == "avg_pkt_size":
        return "indikasi S3 (payload abnormal)"
    if metric == "bps":
        return "indikasi S1/S3 (volume traffic)"
    if ratio >= 5:
        return "indikasi S1-L3/S2 (flooding ekstrem)"
    return "indikasi S1/S4 (flooding)"


class _MetricState:
    """State satu (perangkat, metrik): ring buffer + status + cooldown."""

    def __init__(self, params):
        p = params
        self.lookback = p["lookback"]
        self.confirm = p["confirm"]
        self.override = p["override"]
        self.ring = deque(maxlen=self.lookback)
        self.status = "OK"
        self.last_high_ts = None
        self.last_alert_notified = None
        self.alert_since = None

    def update(self, ts, value, threshold):
        """Kembalikan event dict bila terjadi ALERT/RECOVERY, selain itu None."""
        if threshold is None or threshold <= 0:
            return None
        high = value > threshold
        ratio = value / threshold
        ev = None
        self.ring.append(high)

        triggered = False
        if ratio >= self.override:                       # override: langsung ALERT
            triggered = True
        elif sum(self.ring) >= self.confirm:             # aturan 2-of-3
            triggered = True

        if triggered:
            self.last_high_ts = ts
            if self.status != "ALERT":                   # transisi OK -> ALERT
                self.status = "ALERT"
                self.alert_since = ts
                ev = ("ALERT", ratio)
            # bila sudah ALERT: tidak ada event baru (cukup satu event per episode)
        elif high:
            self.last_high_ts = ts
        # bila tidak tinggi dan sedang ALERT: recovery dicek oleh update_window()
        return ev

    def maybe_recover(self, ts, recovery_s):
        """ALERT -> OK bila sudah recovery_s detik tanpa window tinggi."""
        if (self.status == "ALERT" and self.last_high_ts is not None
                and (ts - self.last_high_ts) >= recovery_s):
            self.status = "OK"
            self.alert_since = None
            self.ring.clear()
            return True
        return False


class ThresholdEngine:
    """Evaluasi window per detik terhadap threshold; memancarkan event ALERT/RECOVERY."""

    def __init__(self, thresholds=None, params=None):
        self.thresholds = thresholds or {"global": {}}
        self.params = json.loads(json.dumps(DEFAULT_PARAMS))  # deep copy
        if params:
            self.params.update(params)
        self._states = {}       # (device, metric) -> _MetricState
        self._macs = {}
        self.events = []        # riwayat event di memori (dashboard memakai alerts.jsonl)

    # ------------------------------------------------------------------ util
    def _state(self, device, metric):
        key = (device, metric)
        if key not in self._states:
            self._states[key] = _MetricState(self.params["metrics"][metric])
        return self._states[key]

    def threshold_for(self, device, metric):
        dev = self.thresholds.get("devices", {}).get(device, {})
        if metric in dev:
            return dev[metric]["threshold"]
        return self.thresholds.get("global", {}).get(metric)

    def reload_thresholds(self, thresholds):
        """Ganti threshold secara LIVE dari halaman Pengaturan (v9.2.5).

        Status ALERT/ring buffer per (perangkat, metrik) DIKLIK: episode yang
        sedang berjalan tidak di-reset, sehingga perubahan nilai threshold
        langsung berlaku pada window berikutnya tanpa kehilangan riwayat
        deteksi. Penukaran referensi dict bersifat atomik terhadap thread
        dispatcher yang sedang mengevaluasi window.
        """
        self.thresholds = thresholds or {"global": {}}

    # ------------------------------------------------------------------ utama
    def update_window(self, ts, device, mac, row):
        """row = dict n_publish/bytes/avg_pkt_size. Kembalikan list event."""
        self._macs[device] = mac or self._macs.get(device, "-")
        events = []
        # 1) tutup episode lama yang sudah melewati masa recovery (penting bila
        #    perangkat sempat diam lama lalu menyerang lagi -> alert baru tetap muncul)
        for metric in self.params["metrics"]:
            st = self._states.get((device, metric))
            if st and st.maybe_recover(ts, self.params["recovery_s"]):
                events.append(self._event(ts, device, metric, "RECOVERY", 0, None, 1.0))
        # 2) window tanpa PUBLISH: tidak ada evaluasi threshold
        if row.get("n_publish", 0) <= 0:
            return events

        values = {
            "pps": row["n_publish"],
            "bps": row["bytes"],
            "avg_pkt_size": row.get("avg_pkt_size") or 0,
        }
        for metric, value in values.items():
            thr = self.threshold_for(device, metric)
            st = self._state(device, metric)
            res = st.update(ts, value, thr)
            if res:  # ("ALERT", ratio)
                kind, ratio = res
                cooldown_ok = (st.last_alert_notified is None
                               or (ts - st.last_alert_notified) >= self.params["cooldown_s"])
                if kind == "ALERT" and cooldown_ok:
                    st.last_alert_notified = ts
                ev = self._event(ts, device, metric, kind, value, thr, ratio)
                # v9.2.6: cooldown dulu hanya dihitung tapi tidak dipakai —
                # kini event dalam masa cooldown ditandai notify=False
                # (tetap tercatat, tapi tidak dikirim ke Telegram).
                ev["notify"] = bool(cooldown_ok)
                events.append(ev)
            elif st.status == "ALERT":
                if st.maybe_recover(ts, self.params["recovery_s"]):
                    events.append(self._event(ts, device, metric, "RECOVERY", value, thr,
                                              value / thr if thr else 1.0))
        return events

    def tick(self, ts):
        """Cek RECOVERY semua (perangkat, metrik) — dipanggil tiap detik.

        v9.2.6: sebelumnya recovery hanya dicek ketika perangkat itu sendiri
        mengirim window baru. Node yang berhenti mengirim (mati / diputus
        setelah diserang) tertahan di status ALERT selamanya.
        """
        events = []
        for (device, metric), st in list(self._states.items()):
            if st.maybe_recover(ts, self.params["recovery_s"]):
                events.append(self._event(ts, device, metric, "RECOVERY",
                                          0, None, 1.0))
        return events

    def _event(self, ts, device, metric, kind, value, thr, ratio):
        ev = {
            "ts": int(ts),
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
            "device": device,
            "mac": self._macs.get(device, "-"),
            "metric": metric,
            "type": METRIC_TYPE.get(metric, metric.upper()),
            "kind": kind,                       # ALERT | RECOVERY
            "value": round(float(value), 1),
            "threshold": round(float(thr), 1) if thr else None,
            "ratio": round(float(ratio), 2),
            "notify": True,
        }
        if kind == "ALERT":
            ev["hint"] = _hint(metric, ratio)
        self.events.append(ev)
        return ev

    # ------------------------------------------------------------------ status
    def device_status(self, device):
        alerts = [m for (d, m), s in self._states.items()
                  if d == device and s.status == "ALERT"]
        return "ALERT" if alerts else "OK", alerts

    def snapshot(self):
        """Ringkasan status seluruh perangkat untuk state.json."""
        out = {}
        for (device, metric), st in self._states.items():
            d = out.setdefault(device, {"alerts": [], "metrics": {}})
            d["metrics"][metric] = {
                "status": st.status,
                "threshold": self.threshold_for(device, metric),
                "alert_since": st.alert_since,
            }
            if st.status == "ALERT":
                d["alerts"].append(metric)
        return out
