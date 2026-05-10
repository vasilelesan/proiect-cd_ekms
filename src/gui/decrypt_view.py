import os
import subprocess
import tempfile

import customtkinter as ctk
from tkinter import messagebox

import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from db import db_manager as db
from services.crypto_config import OPENSSL_EXE
from services.file_service import get_file_hash, build_decrypted_path
from services.performance_service import PerformanceTracker

def handle_decryption(app):
    selected_option = app.dec_file_menu.get()

    if selected_option == "Nu exista fisiere criptate":
        messagebox.showwarning(
            "Eroare",
            "Nu ai fisiere criptate in DB de decriptat!"
        )
        return
    input_bytes = os.path.getsize(in_path)

    file_id = app.enc_file_dict[selected_option]
    meta = db.get_file_metadata(file_id)

    if not meta:
        messagebox.showerror(
            "Eroare",
            "Nu s-au putut extrage metadatele din baza de date."
        )
        return

    alg_name = meta["alg_name"]
    key_hex = meta["private_key"].hex()
    in_path = meta["file_path"]
    is_rsa = "rsa" in alg_name.lower()

    out_path = build_decrypted_path(in_path)

    if not os.path.exists(in_path):
        messagebox.showerror(
            "Eroare",
            f"Fisierul fizic nu mai exista la calea:\n{in_path}"
        )
        return

    selected_fw = app.fw_menu.get()

    tracker = PerformanceTracker()
    tracker.start()

    if selected_fw == "OpenSSL":
        if is_rsa:
            priv_key_bytes = bytes.fromhex(key_hex)

            with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as temp_priv:
                temp_priv.write(priv_key_bytes)
                temp_priv_path = temp_priv.name

            command = [
                OPENSSL_EXE,
                "pkeyutl",
                "-decrypt",
                "-inkey",
                temp_priv_path,
                "-in",
                in_path,
                "-out",
                out_path
            ]

            result = subprocess.run(command, capture_output=True, text=True)
            os.remove(temp_priv_path)

        else:
            iv_hex = meta["init_vector"].hex() if meta["init_vector"] else ""

            command = [
                OPENSSL_EXE,
                "enc",
                "-d",
                f"-{alg_name}",
                "-K",
                key_hex,
                "-iv",
                iv_hex,
                "-in",
                in_path,
                "-out",
                out_path,
                "-nosalt"
            ]

            result = subprocess.run(command, capture_output=True, text=True)

        success = result.returncode == 0
        error_msg = result.stderr if not success else ""

    elif selected_fw == "Python Cryptography":
        if is_rsa:
            messagebox.showwarning(
                "Info",
                "Pentru acest test foloseste OpenSSL pt RSA."
            )
            return

        try:
            iv_hex = meta["init_vector"].hex()
            key_b = bytes.fromhex(key_hex)
            iv_b = bytes.fromhex(iv_hex)

            with open(in_path, "rb") as file:
                ciphertext = file.read()

            cipher = Cipher(
                algorithms.AES(key_b),
                modes.CBC(iv_b),
                backend=default_backend()
            )

            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_data) + unpadder.finalize()

            with open(out_path, "wb") as file:
                file.write(plaintext)

            success = True
            error_msg = ""

        except Exception as error:
            success = False
            error_msg = str(error)

    exec_ms, mem_kb = tracker.stop()

    if success:
        output_bytes = os.path.getsize(out_path)
        db.update_decrypted_file_size(file_id, output_bytes)
        new_hash = get_file_hash(out_path)
        orig_hash = meta["original_hash"]

        integrity_msg = (
            "INTEGRITATE CONFIRMATA!"
            if new_hash == orig_hash
            else "AVERTISMENT: Hash-ul NU se potriveste!"
        )

        fw_version = (
            cryptography.__version__
            if selected_fw == "Python Cryptography"
            else "3.0.x"
        )

        fwid = db.register_framework(selected_fw, fw_version)

        db.log_test_performance({
    "f_id": file_id,
    "a_id": meta["id_algorithm"],
    "fw_id": fwid,
    "op": f"Decriptare {selected_fw}",
    "time": exec_ms,
    "mem": mem_kb,
    "input_bytes": input_bytes,
    "output_bytes": output_bytes
})

        messagebox.showinfo(
            "Succes",
            f"Fisier decriptat cu {selected_fw}!\n\n"
            f"{integrity_msg}\n"
            f"Timp: {exec_ms:.2f}ms\n"
            f"Memorie: {mem_kb:.2f}KB"
        )

        app.render_dashboard()

    else:
        messagebox.showerror(f"Eroare {selected_fw}", error_msg)


def render_decrypt_form(app):
    app.clear_main_view()

    ctk.CTkLabel(
        app.main_view,
        text="Decriptare Fisiere",
        font=("Arial", 22, "bold")
    ).pack(pady=20)

    ctk.CTkLabel(
        app.main_view,
        text="1. Alege un fisier din baza de date:"
    ).pack(pady=(20, 5))

    enc_files = db.get_encrypted_files()
    app.enc_file_dict = {}

    for file in enc_files:
        display_name = f"ID: {file['id']} - {file['file_name']}"
        app.enc_file_dict[display_name] = file["id"]

    file_list = (
        list(app.enc_file_dict.keys())
        if app.enc_file_dict
        else ["Nu exista fisiere criptate"]
    )

    app.dec_file_menu = ctk.CTkOptionMenu(
        app.main_view,
        values=file_list,
        width=300
    )
    app.dec_file_menu.pack(pady=10)

    ctk.CTkLabel(
        app.main_view,
        text="2. Alege Framework-ul pt decriptare:"
    ).pack(pady=(20, 5))

    app.fw_menu = ctk.CTkOptionMenu(
        app.main_view,
        values=["OpenSSL", "Python Cryptography"]
    )
    app.fw_menu.pack(pady=10)

    app.btn_run_dec = ctk.CTkButton(
        app.main_view,
        text="DECRIPTARE",
        fg_color="#1f8d53",
        height=50,
        font=("Arial", 16, "bold"),
        command=lambda: handle_decryption(app)
    )
    app.btn_run_dec.pack(pady=50)