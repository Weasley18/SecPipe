import hashlib

from argon2 import PasswordHasher


def hash_password(password):
    # ruleid: secnotes-weak-password-hash
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(stored, password):
    # ruleid: secnotes-weak-password-hash
    return stored == hashlib.sha1(password.encode()).hexdigest()


def file_checksum(data):
    # ok: secnotes-weak-password-hash
    return hashlib.sha256(data).hexdigest()


def hash_password_argon2(password):
    # ok: secnotes-weak-password-hash
    return PasswordHasher().hash(password)
