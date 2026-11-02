# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

import hashlib
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROJECT_PEPPER = b"ANCORATE_734912285612843967510042198831607952451"
HKDF_INFO = b"ANCORATE-MASTER-26"
HKDF_LENGTH = 32

ARGON2_TIME = 3
ARGON2_MEM_KIB = 131072
ARGON2_PAR = 4
ARGON2_OUT = 32


def derive_argon2(password_bytes: bytes, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEM_KIB,
        parallelism=ARGON2_PAR,
        hash_len=ARGON2_OUT,
        type=Type.ID,
    )


def derive_master_key(password: str, salt: bytes, device_bound: bool = False, device_key: bytes | None = None) -> bytes:
    if not isinstance(password, str):
        raise TypeError("password muss str sein.")
    if not isinstance(salt, bytes) or len(salt) != 16:
        raise ValueError("salt muss 16 Bytes lang sein.")

    pwd_bytes = password.encode("utf-8") + PROJECT_PEPPER
    pwd_key = derive_argon2(pwd_bytes, salt)

    device_hash = hashlib.sha256(device_key).digest() if (device_bound and device_key) else b""
    ikm = pwd_key + device_hash

    master = HKDF(
        algorithm=hashes.SHA256(), length=HKDF_LENGTH, salt=salt, info=HKDF_INFO
    ).derive(ikm)
    return master