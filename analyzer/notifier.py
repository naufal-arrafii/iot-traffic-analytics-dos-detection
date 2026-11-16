#!/usr/bin/env python3
"""MINT - Notifikasi Telegram (opsional, hanya memakai stdlib).

Aktifkan dengan variabel lingkungan sebelum menjalankan live_analyzer.py:
  set TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
  set TELEGRAM_CHAT_ID=987654321

Bila variabel tidak diisi, notifikasi dilewati secara diam-diam.
"""
import os
import queue
import ssl
import threading
import urllib.parse
import urllib.request

# Konteks SSL tanpa verifikasi – diperlukan bila jaringan memakai proxy
# dengan sertifikat self-signed (umum di kampus/kantor).
_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


def telegram_enabled():
    return bool(os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"))


_q = queue.Queue(maxsize=50)
_worker_started = False
_worker_lock = threading.Lock()


def _kirim(text):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return False
    url = (f"https://api.telegram.org/bot{token}/sendMessage"
           f"?chat_id={chat_id}&text={urllib.parse.quote(text[:4000])}")
    try:
        with urllib.request.urlopen(url, timeout=5, context=_ssl_ctx) as r:
            return r.status == 200
    except Exception as e:  # jangan sampai notifikasi mematikan analyzer
        print(f"[notifier] Telegram gagal: {e}")
        return False


def _worker():
    while True:
        _kirim(_q.get())


def send_telegram(text, wait=False):
    """Kirim pesan Telegram.

    v9.2.6: secara default NON-BLOCKING (antrean + thread latar). Dulu
    pengiriman sinkron (timeout 5 dtk) di thread deteksi: saat internet
    putus/lambat, tiap alert membekukan analyzer ~5 dtk sehingga grafik &
    status dashboard 'ngestak' persis ketika serangan terjadi.
    wait=True (tombol Tes di Pengaturan) = sinkron, mengembalikan hasil.
    """
    global _worker_started
    if not telegram_enabled():
        return False
    if wait:
        return _kirim(text)
    with _worker_lock:
        if not _worker_started:
            threading.Thread(target=_worker, daemon=True).start()
            _worker_started = True
    try:
        _q.put_nowait(text)
        return True
    except queue.Full:
        return False
