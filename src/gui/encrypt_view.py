import os
import subprocess
import tempfile

import customtkinter as ctk
from tkinter import filedialog, messagebox

import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from db import db_manager as db
from services.crypto_config import OPENSSL_EXE
from services.file_service import get_file_hash
from services.performance_service import PerformanceTracker

def handle_encryption(app):
    if not app.selected_file_path:
        messagebox.showwarning("Eroare", "Te rog selectează un fișier!")
        return

    input_bytes = os.path.getsize(app.selected_file_path)

    algo_name = app.algo_menu.get()
    mode = app.key_source_var.get()
    is_rsa = "rsa" in algo_name

    if is_rsa and os.path.getsize(app.selected_file_path) > 240:
        messagebox.showwarning(
            "Eroare RSA",
            "Pentru RSA pur, fisierul trebuie sa fie < 240 bytes. Alege un fisier .txt mic!"
        )
        return

    pub_key_bytes = None

    if mode == "auto":
        if is_rsa:
            priv_res = subprocess.run(
                [OPENSSL_EXE, "genrsa", "2048"],
                capture_output=True,
                text=True
            )
            priv_pem = priv_res.stdout.encode("utf-8")

            pub_res = subprocess.run(
                [OPENSSL_EXE, "rsa", "-pubout"],
                input=priv_res.stdout,
                capture_output=True,
                text=True
            )
            pub_key_bytes = pub_res.stdout.encode("utf-8")

            key_hex = priv_pem.hex()
        else:
            key_bytes = 32 if "256" in algo_name else 16
            key_hex = os.urandom(key_bytes).hex()

    elif mode == "db":
        selected_key_option = app.db_key_menu.get()

        if selected_key_option == "Fara chei in DB":
            messagebox.showwarning("Eroare", "Nu exista chei in baza de date!")
            return

        key_hex, pub_hex = app.key_dict[selected_key_option]

        if is_rsa:
            if not pub_hex:
                messagebox.showwarning("Eroare", "Cheia aleasa nu este o pereche RSA!")
                return

            pub_key_bytes = bytes.fromhex(pub_hex)

    elif mode == "manual":
        if is_rsa:
            messagebox.showwarning(
                "Info",
                "Introducerea manuala pt RSA nu este suportata momentan. Foloseste modul Auto."
            )
            return

        key_hex = app.key_entry.get().strip()

        if not key_hex:
            messagebox.showwarning("Eroare", "Te rog introdu o cheie!")
            return

    out_path = app.selected_file_path + ".enc"
    orig_hash = get_file_hash(app.selected_file_path)

    selected_fw = app.fw_menu.get()
    fw_db_name = "Python Cryptography" if selected_fw == "Py. Crypt." else selected_fw

    tracker = PerformanceTracker()
    tracker.start()

    if selected_fw == "OpenSSL":
        if is_rsa:
            iv_hex = ""
            key_bit_len = 2048

            with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as temp_pub:
                temp_pub.write(pub_key_bytes)
                temp_pub_path = temp_pub.name

            command = [
                OPENSSL_EXE,
                "pkeyutl",
                "-encrypt",
                "-pubin",
                "-inkey",
                temp_pub_path,
                "-in",
                app.selected_file_path,
                "-out",
                out_path
            ]

            result = subprocess.run(command, capture_output=True, text=True)
            os.remove(temp_pub_path)

        else:
            iv_hex = os.urandom(16).hex()
            key_bit_len = 256 if "256" in algo_name else 128

            command = [
                OPENSSL_EXE,
                "enc",
                f"-{algo_name}",
                "-K",
                key_hex,
                "-iv",
                iv_hex,
                "-in",
                app.selected_file_path,
                "-out",
                out_path,
                "-nosalt"
            ]

            result = subprocess.run(command, capture_output=True, text=True)

        success = result.returncode == 0
        error_msg = result.stderr if not success else ""
        fw_version = "3.0.x"

    elif selected_fw == "Py. Crypt.":
        if is_rsa:
            messagebox.showwarning(
                "Info",
                "Pentru acest test, noul framework suporta doar AES. Foloseste OpenSSL pt RSA."
            )
            return

        iv_hex = os.urandom(16).hex()
        key_bit_len = 256 if "256" in algo_name else 128

        try:
            with open(app.selected_file_path, "rb") as file:
                plaintext = file.read()

            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()

            key_b = bytes.fromhex(key_hex)
            iv_b = bytes.fromhex(iv_hex)

            cipher = Cipher(
                algorithms.AES(key_b),
                modes.CBC(iv_b),
                backend=default_backend()
            )

            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            with open(out_path, "wb") as file:
                file.write(ciphertext)

            success = True
            error_msg = ""

        except Exception as error:
            success = False
            error_msg = str(error)

        fw_version = cryptography.__version__

    exec_ms, mem_kb = tracker.stop()

    if success:
        output_bytes = os.path.getsize(out_path)
        enc_hash = get_file_hash(out_path)

        aid = db.add_algorithm(
            algo_name,
            "Asymmetric" if is_rsa else "Symmetric",
            key_bit_len,
            128 if not is_rsa else 0
        )

        fwid = db.register_framework(fw_db_name, fw_version)

        file_data = {
    "user_id": 1,
    "algo_id": aid,
    "framework_id": fwid,
    "public_key_bytes": pub_key_bytes,
    "private_key_bytes": bytes.fromhex(key_hex),
    "name": os.path.basename(out_path),
    "type": "enc",
    "size": output_bytes,
    "original_dimension": input_bytes,
    "encrypted_dimension": output_bytes,
    "decrypted_dimension": None,
    "path": out_path,
    "orig_hash": orig_hash,
    "enc_hash": enc_hash,
    "payload": b"",
    "iv": bytes.fromhex(iv_hex) if iv_hex else b""
    }

        fid = db.register_encrypted_file(file_data)

        db.log_test_performance({
    "f_id": fid,
    "a_id": aid,
    "fw_id": fwid,
    "op": f"Criptare {selected_fw}",
    "time": exec_ms,
    "mem": mem_kb,
    "input_bytes": input_bytes,
    "output_bytes": output_bytes
})

        messagebox.showinfo(
            "Succes",
            f"Fisier criptat cu {selected_fw}!\n"
            f"Timp: {exec_ms:.2f}ms\n"
            f"Memorie: {mem_kb:.2f}KB"
        )

        app.render_dashboard()

    else:
        messagebox.showerror(f"Eroare {selected_fw}", error_msg)

def render_encrypt_form(app):
    app.clear_main_view()

    ctk.CTkLabel(
        app.main_view,
        text="Configurare Criptare",
        font=("Arial", 22, "bold")
    ).pack(pady=20)

    app.btn_select = ctk.CTkButton(
        app.main_view,
        text="1. Selectează Fișier",
        command=lambda: handle_file_select(app)
    )
    app.btn_select.pack(pady=10)

    app.lbl_file = ctk.CTkLabel(
        app.main_view,
        text="Niciun fișier ales",
        text_color="gray"
    )
    app.lbl_file.pack()

    ctk.CTkLabel(
        app.main_view,
        text="2. Alege Algoritm:"
    ).pack(pady=(20, 5))

    app.algo_menu = ctk.CTkOptionMenu(
        app.main_view,
        values=["aes-256-cbc", "aes-128-cbc", "rsa-2048"]
    )
    app.algo_menu.pack()

    ctk.CTkLabel(
        app.main_view,
        text="3. Sursa cheiei de criptare:"
    ).pack(pady=(20, 5))

    app.key_source_var = ctk.StringVar(value="auto")

    radio_frame = ctk.CTkFrame(app.main_view, fg_color="transparent")
    radio_frame.pack(pady=5)

    app.rb_auto = ctk.CTkRadioButton(
        radio_frame,
        text="Generare automata",
        variable=app.key_source_var,
        value="auto",
        command=lambda: update_key_ui(app)
    )
    app.rb_auto.grid(row=0, column=0, padx=10)

    app.rb_db = ctk.CTkRadioButton(
        radio_frame,
        text="Din baza de date",
        variable=app.key_source_var,
        value="db",
        command=lambda: update_key_ui(app)
    )
    app.rb_db.grid(row=0, column=1, padx=10)

    app.rb_manual = ctk.CTkRadioButton(
        radio_frame,
        text="Introducere manuala",
        variable=app.key_source_var,
        value="manual",
        command=lambda: update_key_ui(app)
    )
    app.rb_manual.grid(row=0, column=2, padx=10)

    keys = db.get_all_keys()
    app.key_dict = {}

    for key in keys:
        priv_hex = key["private_key"].hex()
        pub_blob = key["public_key"]
        pub_hex = pub_blob.hex() if pub_blob else None

        display_name = f"ID: {key['id']} ({priv_hex[:8]}...)"
        app.key_dict[display_name] = (priv_hex, pub_hex)

    db_keys_list = list(app.key_dict.keys()) if app.key_dict else ["Fara chei in DB"]

    app.db_key_menu = ctk.CTkOptionMenu(
        app.main_view,
        values=db_keys_list
    )
    app.db_key_menu.pack(pady=10)

    app.key_entry = ctk.CTkEntry(
        app.main_view,
        width=300,
        placeholder_text="ex: 603deb1015ca..."
    )
    app.key_entry.pack(pady=5)

    update_key_ui(app)

    ctk.CTkLabel(
        app.main_view,
        text="4. Alege Framework-ul:"
    ).pack(pady=(20, 5))

    app.fw_menu = ctk.CTkOptionMenu(
        app.main_view,
        values=["OpenSSL", "Py. Crypt."]
    )
    app.fw_menu.pack(pady=10)

    app.btn_run = ctk.CTkButton(
        app.main_view,
        text="CRIPTARE",
        fg_color="#1f538d",
        height=50,
        font=("Arial", 16, "bold"),
        command=lambda: handle_encryption(app)
    )
    app.btn_run.pack(pady=50)


def update_key_ui(app):
    mode = app.key_source_var.get()

    if mode == "auto":
        app.db_key_menu.configure(state="disabled")
        app.key_entry.configure(state="disabled")
        app.key_entry.delete(0, "end")

    elif mode == "db":
        if app.key_dict:
            app.db_key_menu.configure(state="normal")

        app.key_entry.configure(state="disabled")
        app.key_entry.delete(0, "end")

    elif mode == "manual":
        app.db_key_menu.configure(state="disabled")
        app.key_entry.configure(state="normal")


def handle_file_select(app):
    app.selected_file_path = filedialog.askopenfilename()

    if app.selected_file_path:
        app.lbl_file.configure(
            text=os.path.basename(app.selected_file_path),
            text_color="#1fbd1f"
        )