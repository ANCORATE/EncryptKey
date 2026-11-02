# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

import base64
import getpass
import json
import os
import sys

from base import CHUNK  # noqa: F401
from crypto import derive_master_key
from encrypt import encrypt_meta
from decrypt import decrypt_meta


def _load_vault(path: str):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    salt = base64.b64decode(data["salt"])
    blob = base64.b64decode(data["blob"])
    return salt, blob


def _save_vault(path: str, salt: bytes, blob: bytes):
    data = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "blob": base64.b64encode(blob).decode("ascii"),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def cmd_init(path: str):
    if os.path.exists(path):
        print("Vault already exists:", path)
        return 1
    pw1 = getpass.getpass("Master password: ")
    pw2 = getpass.getpass("Repeat password: ")
    if pw1 != pw2 or not pw1:
        print("Passwords do not match or are empty.")
        return 1
    salt = os.urandom(16)
    master = derive_master_key(pw1, salt)
    meta = {"version": 1, "entries": []}
    blob = encrypt_meta(meta, master)
    _save_vault(path, salt, blob)
    print("Vault created:", path)
    return 0


def _unlock(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    salt, blob = _load_vault(path)
    pw = getpass.getpass("Master password: ")
    master = derive_master_key(pw, salt)
    meta = decrypt_meta(blob, master)
    return salt, master, meta


def cmd_list(path: str):
    try:
        _, _, meta = _unlock(path)
    except Exception as e:
        print("Unlock failed:", e)
        return 1
    for entry in meta.get("entries", []):
        print(entry.get("name"))
    return 0


def cmd_get(path: str, name: str):
    try:
        _, _, meta = _unlock(path)
    except Exception as e:
        print("Unlock failed:", e)
        return 1
    for entry in meta.get("entries", []):
        if entry.get("name") == name:
            print(entry.get("secret"))
            return 0
    print("Entry not found:", name)
    return 1


def cmd_add(path: str, name: str):
    try:
        salt, master, meta = _unlock(path)
    except Exception as e:
        print("Unlock failed:", e)
        return 1
    if any(e.get("name") == name for e in meta.get("entries", [])):
        print("Entry already exists:", name)
        return 1
    secret = getpass.getpass("Secret: ")
    meta.setdefault("entries", []).append({"name": name, "secret": secret})
    blob = encrypt_meta(meta, master)
    _save_vault(path, salt, blob)
    print("Added:", name)
    return 0


def cmd_remove(path: str, name: str):
    try:
        salt, master, meta = _unlock(path)
    except Exception as e:
        print("Unlock failed:", e)
        return 1
    before = len(meta.get("entries", []))
    meta["entries"] = [e for e in meta.get("entries", []) if e.get("name") != name]
    if len(meta["entries"]) == before:
        print("Entry not found:", name)
        return 1
    blob = encrypt_meta(meta, master)
    _save_vault(path, salt, blob)
    print("Removed:", name)
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("Usage: keymanager.py <init|list|get|add|remove> <vault> [name]")
        return 2
    cmd = argv[0]
    if cmd == "init" and len(argv) == 2:
        return cmd_init(argv[1])
    if cmd == "list" and len(argv) == 2:
        return cmd_list(argv[1])
    if cmd == "get" and len(argv) == 3:
        return cmd_get(argv[1], argv[2])
    if cmd == "add" and len(argv) == 3:
        return cmd_add(argv[1], argv[2])
    if cmd == "remove" and len(argv) == 3:
        return cmd_remove(argv[1], argv[2])
    print("Invalid command or arguments.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())