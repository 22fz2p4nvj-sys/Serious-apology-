"""Encrypted vault for family documents.

Threat: scans of Aadhaar/PAN/passport cards, bank statements, insurance
papers and medical reports sit unprotected on laptops, phones, pen drives
and cloud folders. If the device is lost or hacked, all of it leaks.

Security ideas you will learn here:
  * Encryption - scrambling data so only someone with the key can read it.
  * Key derivation (scrypt) - turning a human passphrase into a strong key,
    and doing it SLOWLY on purpose so guessing passphrases is expensive.
  * Salt - random bytes mixed into the key so two families using the same
    passphrase still get different keys.
  * Authenticated encryption (Fernet) - any tampering with the encrypted
    file is detected instead of silently producing garbage.

File format: MAGIC (4 bytes) + SALT (16 bytes) + Fernet token.
"""

import base64
import os
import unicodedata

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"FSV1"
SALT_SIZE = 16
EXTENSION = ".fsv"


class VaultError(Exception):
    """Raised for a wrong passphrase, a damaged file, or a non-vault file."""


def derive_key(passphrase, salt):
    """Stretch a passphrase into a 32-byte key.

    n=2**15 makes each attempt take noticeable time and ~32 MB of memory,
    which barely affects you but slows down an attacker trying billions.
    """
    # Accented letters like "é" can be typed as one or two characters
    # depending on the device; normalising makes both give the same key.
    passphrase = unicodedata.normalize("NFC", passphrase)
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    # "surrogatepass" keeps odd bytes from a misconfigured terminal from crashing us.
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8", "surrogatepass")))


def encrypt_bytes(data, passphrase):
    salt = os.urandom(SALT_SIZE)  # fresh random salt for every file
    token = Fernet(derive_key(passphrase, salt)).encrypt(data)
    return MAGIC + salt + token


def decrypt_bytes(blob, passphrase):
    if not blob.startswith(MAGIC) or len(blob) <= len(MAGIC) + SALT_SIZE:
        raise VaultError("This is not a Family Shield vault file.")
    salt = blob[len(MAGIC):len(MAGIC) + SALT_SIZE]
    token = blob[len(MAGIC) + SALT_SIZE:]
    try:
        return Fernet(derive_key(passphrase, salt)).decrypt(token)
    except InvalidToken:
        raise VaultError("Wrong passphrase, or the file was damaged/tampered with.") from None


def _write_new_file(path, data):
    """Write a file, refusing to overwrite something that already exists."""
    # Mode "x" checks and creates in one step, so nothing can sneak in between.
    try:
        with open(path, "xb") as handle:
            handle.write(data)
    except FileExistsError:
        raise VaultError(f"{path} already exists - move or rename it first.") from None


def encrypt_file(path, passphrase):
    """Create PATH.fsv next to the original. Returns the new file's path."""
    with open(path, "rb") as handle:
        data = handle.read()
    out_path = path + EXTENSION
    _write_new_file(out_path, encrypt_bytes(data, passphrase))
    return out_path


def decrypt_file(path, passphrase):
    """Restore the original from a .fsv file. Returns the restored path."""
    if not path.endswith(EXTENSION):
        raise VaultError(f"Expected a file ending in {EXTENSION}.")
    with open(path, "rb") as handle:
        blob = handle.read()
    data = decrypt_bytes(blob, passphrase)
    out_path = path[:-len(EXTENSION)]
    _write_new_file(out_path, data)
    return out_path
