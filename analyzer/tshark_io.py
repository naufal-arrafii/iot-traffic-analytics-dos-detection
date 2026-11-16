#!/usr/bin/env python3
"""MINT - Jembatan ke tshark: membangun perintah, parsing output, agregasi window 1 detik.

Format field yang dipakai (output tshark -T fields, pemisah TAB):
  frame.time_epoch | frame.len | ip.src | eth.src | mqtt.msgtype | mqtt.topic | tcp.analysis.retransmission

Catatan mqtt.msgtype bernomor: 1=CONNECT, 3=PUBLISH, 12=PINGREQ, dst.
Beberapa versi tshark menuliskan teks; parser menerima keduanya.

tshark dicari otomatis: PATH dulu, lalu lokasi instalasi umum Windows/macOS/Linux
(installer Wireshark di Windows TIDAK menambahkan PATH secara default, jadi
fallback lokasi ini menyelamatkan sebagian besar kasus "tshark tidak ditemukan").
"""
import os
import shutil
import subprocess

FIELDS = ["frame.time_epoch", "frame.len", "ip.src", "eth.src",
          "mqtt.msgtype", "mqtt.topic", "tcp.analysis.retransmission"]

# Lokasi instalasi Wireshark yang umum (dipakai bila PATH tidak memuat tshark)
TSHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "/usr/bin/tshark",
    "/usr/local/bin/tshark",
    "/opt/homebrew/bin/tshark",
]

_tshark_cache = None


def resolve_tshark():
    """Cari tshark: PATH dulu, lalu lokasi instalasi umum. None bila tidak ada."""
    global _tshark_cache
    if _tshark_cache is not None:
        return _tshark_cache
    found = shutil.which("tshark")
    if not found:
        for cand in TSHARK_CANDIDATES:
            if os.path.isfile(cand):
                found = cand
                break
    _tshark_cache = found
    return found


def _tshark_or_raise():
    exe = resolve_tshark()
    if not exe:
        raise FileNotFoundError(
            "tshark tidak ditemukan.\n"
            "  1. Instal Wireshark dari wireshark.org (ikutkan Npcap).\n"
            "  2. Bila sudah terinstal, tambahkan folder Wireshark ke PATH, mis.:\n"
            "       set \"PATH=%PATH%;C:\\Program Files\\Wireshark\"\n"
            "     lalu buka terminal BARU.\n"
            "  (Analyzer juga otomatis memeriksa lokasi umum instalasi Wireshark.)"
        )
    return exe


def build_cmd(iface=None, pcap=None, extra=None):
    """Bangun perintah tshark untuk mode live (iface) atau offline (pcap)."""
    cmd = [_tshark_or_raise()]
    if pcap:
        cmd += ["-r", pcap, "-n"]
    else:
        cmd += ["-i", str(iface), "-f", "port 1883"]
    cmd += ["-T", "fields"] + sum([["-e", f] for f in FIELDS], [])
    cmd += ["-E", "separator=/t", "-E", "occurrence=f"]
    if extra:
        cmd += extra
    return cmd


def _msgtype(val):
    """Normalisasi mqtt.msgtype -> nomor int, atau None bila bukan MQTT."""
    v = (val or "").strip()
    if not v:
        return None
    try:
        return int(v)
    except ValueError:
        v = v.upper()
        if "PUBLISH" in v:
            return 3
        if "CONNECT" in v:
            return 1
    return None


def parse_line(line):
    """Parse satu baris output tshark -> dict paket, atau None bila bukan TCP/MQTT."""
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 6 or not parts[0].strip():
        return None
    try:
        ts = float(parts[0])
        frame_len = int(parts[1] or 0)
    except ValueError:
        return None
    return {
        "ts": ts,
        "frame_len": frame_len,
        "ip": parts[2].strip(),
        "mac": parts[3].strip(),
        "msgtype": _msgtype(parts[4]),
        "topic": parts[5].strip(),
        "retrans": bool(parts[6].strip()) if len(parts) > 6 else False,
    }


class WindowAggregator:
    """Kumpulkan paket per detik; tiap detik menghasilkan baris metrik per perangkat."""

    def __init__(self):
        self.cur_sec = None
        self.buf = {}  # ip -> statistik window berjalan

    def add(self, pkt):
        if not pkt["ip"] or pkt["msgtype"] is None:
            return
        sec = int(pkt["ts"])
        if self.cur_sec is None:
            self.cur_sec = sec
        d = self.buf.setdefault(pkt["ip"], {
            "mac": pkt["mac"] or "-", "n_publish": 0, "n_connect": 0,
            "bytes": 0, "topics": set(), "retrans": 0, "topic_last": "-",
        })
        if pkt["mac"]:
            d["mac"] = pkt["mac"]
        if pkt["msgtype"] == 3:      # PUBLISH
            d["n_publish"] += 1
            d["bytes"] += pkt["frame_len"]
            if pkt["topic"]:
                d["topics"].add(pkt["topic"])
                d["topic_last"] = pkt["topic"]
            if pkt["retrans"]:
                d["retrans"] += 1
        elif pkt["msgtype"] == 1:    # CONNECT
            d["n_connect"] += 1

    def close(self):
        """Tutup window berjalan -> list baris metrik (satu per perangkat)."""
        rows = []
        for ip, d in self.buf.items():
            n = d["n_publish"]
            rows.append({
                "ts": self.cur_sec, "device": ip, "mac": d["mac"],
                "n_publish": n, "n_connect": d["n_connect"], "bytes": d["bytes"],
                "avg_pkt_size": round(d["bytes"] / n, 1) if n else 0.0,
                "topics": len(d["topics"]), "retrans": d["retrans"],
                "topic_last": d["topic_last"],
            })
        self.buf = {}
        return rows


def open_live(iface):
    """Buka proses tshark live; kembalikan objek Popen (stdout = teks)."""
    return subprocess.Popen(build_cmd(iface=iface), stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)


def iter_pcapan(pcap):
    """Jalankan tshark offline atas berkas .pcap; yield paket hasil parse."""
    proc = subprocess.Popen(build_cmd(pcap=pcap), stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)
    for line in proc.stdout:
        pkt = parse_line(line)
        if pkt:
            yield pkt
    proc.wait()
