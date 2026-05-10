import hashlib
import os


def get_file_hash(path):
    sha256_hash = hashlib.sha256()

    with open(path, "rb") as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.digest()


def get_file_size(path):
    return os.path.getsize(path)


def get_file_name(path):
    return os.path.basename(path)


def build_decrypted_path(encrypted_path):
    base_path = encrypted_path.replace(".enc", "")
    name, ext = os.path.splitext(base_path)
    return f"{name}_decrypted{ext}"