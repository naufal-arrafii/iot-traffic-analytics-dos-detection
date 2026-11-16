#!/usr/bin/env python3
"""MINT - Tambah/ubah pengguna dashboard.

Pengguna disimpan di dashboard/users.json (password dalam bentuk hash).

Pemakaian:
  python dashboard\\add_user.py budi mint456            # tambah operator baru
  python dashboard\\add_user.py budi mint456 --admin    # tambah sebagai admin
  python dashboard\\add_user.py budi --delete           # hapus pengguna
"""
import argparse
import json
import os

from werkzeug.security import generate_password_hash

USERS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")


def load():
    if os.path.exists(USERS_PATH):
        with open(USERS_PATH) as f:
            return json.load(f)
    return {"users": []}


def save(data):
    with open(USERS_PATH, "w") as f:
        json.dump(data, f, indent=2)


def main():
    ap = argparse.ArgumentParser(description="Manajemen pengguna dashboard MINT")
    ap.add_argument("username")
    ap.add_argument("password", nargs="?", help="kosongkan dengan --delete")
    ap.add_argument("--admin", action="store_true", help="jadikan admin")
    ap.add_argument("--delete", action="store_true", help="hapus pengguna")
    args = ap.parse_args()

    data = load()
    users = data["users"]
    existing = next((u for u in users if u["username"] == args.username), None)

    if args.delete:
        if not existing:
            print(f"Pengguna '{args.username}' tidak ditemukan.")
            return
        if args.username == "admin":
            print("Tidak boleh menghapus 'admin'.")
            return
        data["users"] = [u for u in users if u["username"] != args.username]
        save(data)
        print(f"Pengguna '{args.username}' dihapus.")
        return

    if not args.password:
        ap.error("password wajib diisi (atau pakai --delete)")

    entry = {
        "username": args.username,
        "password_hash": generate_password_hash(args.password),
        "role": "admin" if args.admin else "operator",
    }
    if existing:
        existing.update(entry)
        print(f"Pengguna '{args.username}' diperbarui (role: {entry['role']}).")
    else:
        users.append(entry)
        print(f"Pengguna '{args.username}' ditambahkan (role: {entry['role']}).")
    save(data)


if __name__ == "__main__":
    main()
