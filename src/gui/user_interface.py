import sys
from wsgiref import headers
import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import time
import psutil
import subprocess
import hashlib
import tempfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import cryptography

# Import logica de DB
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from db import db_manager as db 

# CONFIGURARE CALE OPENSSL 
OPENSSL_EXE = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"

class CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("EKMS - Manager Criptare Locală")
        self.geometry("1100x600")
        ctk.set_appearance_mode("dark")
        
        # layout principal
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # sidebar
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo = ctk.CTkLabel(self.sidebar, text="EKMS PANEL", font=("Roboto", 24, "bold"))
        self.logo.pack(pady=30)

        self.btn_dash = ctk.CTkButton(self.sidebar, text="Fișiere & Performanță", command=self.render_dashboard)
        self.btn_dash.pack(pady=10, padx=20)

        self.btn_encrypt = ctk.CTkButton(self.sidebar, text="Criptare Nouă", command=self.render_encrypt_form)
        self.btn_encrypt.pack(pady=10, padx=20)

        self.btn_decrypt = ctk.CTkButton(self.sidebar, text="Decriptare", command=self.render_decrypt_form)
        self.btn_decrypt.pack(pady=10, padx=20)

        # containerul principal pentru continut
        self.main_view = ctk.CTkScrollableFrame(self, corner_radius=15, fg_color="transparent")
        self.main_view.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

        # Variabile de stare
        self.selected_file_path = ""
        
        # initializez DB si incarc prima pagina
        db.init_db()
        self.render_dashboard()

    # --- hash compute ---
    def get_file_hash(self, path):
        sha256_hash = hashlib.sha256()
        with open(path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.digest()

    # --- PAGINA: DASHBOARD  ---
    def render_dashboard(self):
        for widget in self.main_view.winfo_children():
            widget.destroy()

        ctk.CTkLabel(self.main_view, text="Analiză Performanță Criptare", font=("Arial", 22, "bold")).pack(pady=15)
        col_widths = [150, 150, 150, 150, 150, 150, 150]
        # cap de tabel (header)
        header_frame = ctk.CTkFrame(self.main_view, fg_color="gray20")
        header_frame.pack(fill="x", pady=5, padx=10)
    
        headers = ["Fișier", "Algoritm", "Framework", "Operatie", "Cheie (Hex)", "Timp (ms)", "Memorie (KB)"]
        for i, h in enumerate(headers):
            ctk.CTkLabel(header_frame, text=h, font=("Arial", 12, "bold"), width=150).grid(row=0, column=i, padx=5, pady=5)

        # preiau datele din DB printr-un JOIN intre Performance, File, Algorithm si Framework
        # Va trebui să adaugi o funcție în db_manager numită get_all_performance_logs()
        logs = db.get_performance_report() 

        for log in logs:
            row = ctk.CTkFrame(self.main_view)
            row.pack(fill="x", pady=2, padx=10)
        
            raw_op = log['operation_type']
            display_op = "Criptare" if "Criptare" in raw_op else "Decriptare"

            # color based on operation
            color = "#1fbd1f" if "Criptare" in log['operation_type'] else "#e67e22"

            full_key_hex = log['private_key'].hex()
            key_snippet = f"{full_key_hex[:8]}..."
        
            # place elements matching header widths and paddings exactly
            ctk.CTkLabel(row, text=log['file_name'], width=col_widths[0]).grid(row=0, column=0, padx=5, pady=5)
            ctk.CTkLabel(row, text=log['alg_name'], width=col_widths[1]).grid(row=0, column=1, padx=5, pady=5)
            ctk.CTkLabel(row, text=log['fw_name'], width=col_widths[2]).grid(row=0, column=2, padx=5, pady=5)
            ctk.CTkLabel(row, text=display_op, width=col_widths[3], text_color=color).grid(row=0, column=3, padx=5, pady=5)
            
            # clickable button for full key
            btn_key = ctk.CTkButton(row, text=key_snippet, width=col_widths[4], fg_color="transparent", border_width=1, text_color="white", hover_color="gray30", command=lambda k=full_key_hex: messagebox.showinfo("Cheie Completa", k))
            btn_key.grid(row=0, column=4, padx=5, pady=5)
            
            ctk.CTkLabel(row, text=f"{log['time']:.2f}", width=col_widths[5]).grid(row=0, column=5, padx=5, pady=5)
            ctk.CTkLabel(row, text=f"{log['mem']:.0f}", width=col_widths[6]).grid(row=0, column=6, padx=5, pady=5)

    # --- MOD DE SELECTARE A CHEII DE CRIPTARE ---
    def update_key_ui(self):
        # get selected mode
        mode = self.key_source_var.get()
        
        if mode == "auto":
            # generarea automata a cheii - dezactivez celelalte moduri
            self.db_key_menu.configure(state="disabled")
            self.key_entry.configure(state="disabled")
            self.key_entry.delete(0, 'end')
        elif mode == "db":
            # selectare cheie din db -> dezactivez inputul userului
            if self.key_dict:
                self.db_key_menu.configure(state="normal")
            self.key_entry.configure(state="disabled")
            self.key_entry.delete(0, 'end')
        elif mode == "manual":
            # introducere manuala a cheii utilizatorului
            self.db_key_menu.configure(state="disabled")
            self.key_entry.configure(state="normal")

    # --- PAGINA: FORMULAR CRIPTARE ---
    def render_encrypt_form(self):
        for widget in self.main_view.winfo_children():
            widget.destroy()

        ctk.CTkLabel(self.main_view, text="Configurare Criptare", font=("Arial", 22, "bold")).pack(pady=20)

        # selectie fisier
        self.btn_select = ctk.CTkButton(self.main_view, text="1. Selectează Fișier", command=self.handle_file_select)
        self.btn_select.pack(pady=10)
        self.lbl_file = ctk.CTkLabel(self.main_view, text="Niciun fișier ales", text_color="gray")
        self.lbl_file.pack()

        # selectie algoritm
        ctk.CTkLabel(self.main_view, text="2. Alege Algoritm:").pack(pady=(20, 5))
        self.algo_menu = ctk.CTkOptionMenu(self.main_view, values=["aes-256-cbc", "aes-128-cbc", "rsa-2048"])
        self.algo_menu.pack()

        # selectare cheie deja existenta in db
        ctk.CTkLabel(self.main_view, text="3. Sursa cheiei de criptare:").pack(pady=(20, 5))
        
        # tracking variable for radio buttons
        self.key_source_var = ctk.StringVar(value="auto")

        # frame to align radio buttons horizontally
        radio_frame = ctk.CTkFrame(self.main_view, fg_color="transparent")
        radio_frame.pack(pady=5)

        self.rb_auto = ctk.CTkRadioButton(radio_frame, text="Generare automata", variable=self.key_source_var, value="auto", command=self.update_key_ui)
        self.rb_auto.grid(row=0, column=0, padx=10)

        self.rb_db = ctk.CTkRadioButton(radio_frame, text="Din baza de date", variable=self.key_source_var, value="db", command=self.update_key_ui)
        self.rb_db.grid(row=0, column=1, padx=10)

        self.rb_manual = ctk.CTkRadioButton(radio_frame, text="Introducere manuala", variable=self.key_source_var, value="manual", command=self.update_key_ui)
        self.rb_manual.grid(row=0, column=2, padx=10)

        # db key dropdown
        keys = db.get_all_keys()
        self.key_dict = {}
        for k in keys:
            priv_hex = k['private_key'].hex()
            pub_blob = k['public_key']
            pub_hex = pub_blob.hex() if pub_blob else None
            
            display_name = f"ID: {k['id']} ({priv_hex[:8]}...)"
            self.key_dict[display_name] = (priv_hex, pub_hex)

        db_keys_list = list(self.key_dict.keys()) if self.key_dict else ["Fara chei in DB"]
        self.db_key_menu = ctk.CTkOptionMenu(self.main_view, values=db_keys_list)
        self.db_key_menu.pack(pady=10)

        # manual key entry
        self.key_entry = ctk.CTkEntry(self.main_view, width=300, placeholder_text="ex: 603deb1015ca...")
        self.key_entry.pack(pady=5)

        # set initial ui state
        self.update_key_ui()

        # selectie framework
        ctk.CTkLabel(self.main_view, text="4. Alege Framework-ul:").pack(pady=(20, 5))
        self.fw_menu = ctk.CTkOptionMenu(self.main_view, values=["OpenSSL", "Python Cryptography"])
        self.fw_menu.pack(pady=10)

        # buton de executie
        self.btn_run = ctk.CTkButton(self.main_view, text="CRIPTARE", fg_color="#1f538d", height=50, font=("Arial", 16, "bold"), command=self.handle_encryption)
        self.btn_run.pack(pady=50)

    def handle_file_select(self):
        self.selected_file_path = filedialog.askopenfilename()
        if self.selected_file_path:
            self.lbl_file.configure(text=os.path.basename(self.selected_file_path), text_color="#1fbd1f")

    def handle_delete(self, fid):
        if db.delete_file_and_key(fid):
            self.render_dashboard()

    # --- LOGICA DE CRIPTARE + SUBPROCESS + PERFORMANTA ---
    def handle_encryption(self):
        if not self.selected_file_path:
            messagebox.showwarning("Eroare", "Te rog selectează un fișier!")
            return

        # 1. initializare date
        # preluare algoritm
        algo_name = self.algo_menu.get()   
        mode = self.key_source_var.get()
        is_rsa = "rsa" in algo_name

        if is_rsa and os.path.getsize(self.selected_file_path) > 240:
            messagebox.showwarning("Eroare RSA", "Pentru RSA pur, fisierul trebuie sa fie < 240 bytes. Alege un fisier .txt mic!")
            return

        pub_key_bytes = None

        if mode == "auto":
            if is_rsa:
                # generate rsa private key
                priv_res = subprocess.run([OPENSSL_EXE, 'genrsa', '2048'], capture_output=True, text=True)
                priv_pem = priv_res.stdout.encode('utf-8')
                
                # extract public key
                pub_res = subprocess.run([OPENSSL_EXE, 'rsa', '-pubout'], input=priv_res.stdout, capture_output=True, text=True)
                pub_key_bytes = pub_res.stdout.encode('utf-8')
                
                key_hex = priv_pem.hex()
            else:
                key_bytes = 32 if "256" in algo_name else 16
                key_hex = os.urandom(key_bytes).hex()
            
        elif mode == "db":
            selected_key_option = self.db_key_menu.get()
            if selected_key_option == "Fara chei in DB":
                messagebox.showwarning("Eroare", "Nu exista chei in baza de date!")
                return
            
            key_hex, pub_hex = self.key_dict[selected_key_option]
            
            if is_rsa:
                if not pub_hex:
                    messagebox.showwarning("Eroare", "Cheia aleasa nu este o pereche RSA!")
                    return
                pub_key_bytes = bytes.fromhex(pub_hex)
            
        elif mode == "manual":
            if is_rsa:
                messagebox.showwarning("Info", "Introducerea manuala pt RSA nu este suportata momentan. Foloseste modul Auto.")
                return
            key_hex = self.key_entry.get().strip()
            if not key_hex:
                messagebox.showwarning("Eroare", "Te rog introdu o cheie!")
                return

        out_path = self.selected_file_path + ".enc"
        orig_hash = self.get_file_hash(self.selected_file_path)

        # performance tracking
        # preluare framework din UI
        selected_fw = self.fw_menu.get()

        # performance tracking
        start_t = time.perf_counter()
        mem_start = psutil.Process().memory_info().rss
        
        # executie in functie de framework si algoritm
        if selected_fw == "OpenSSL":
            if is_rsa:
                iv_hex = ""
                key_bit_len = 2048
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as temp_pub:
                    temp_pub.write(pub_key_bytes)
                    temp_pub_path = temp_pub.name
                    
                command = [
                    OPENSSL_EXE, "pkeyutl", "-encrypt", "-pubin", 
                    "-inkey", temp_pub_path, 
                    "-in", self.selected_file_path, 
                    "-out", out_path
                ]
                result = subprocess.run(command, capture_output=True, text=True)
                os.remove(temp_pub_path)
            else:
                iv_hex = os.urandom(16).hex()
                key_bit_len = 256 if "256" in algo_name else 128
                command = [
                    OPENSSL_EXE, "enc", f"-{algo_name}", "-K", key_hex, "-iv", iv_hex,
                    "-in", self.selected_file_path, "-out", out_path, "-nosalt"
                ]
                result = subprocess.run(command, capture_output=True, text=True)
            
            success = result.returncode == 0
            error_msg = result.stderr if not success else ""
            fw_version = "3.0.x"

        elif selected_fw == "Python Cryptography":
            if is_rsa:
                messagebox.showwarning("Info", "Pentru acest test, noul framework suporta doar AES. Foloseste OpenSSL pt RSA.")
                return
                
            iv_hex = os.urandom(16).hex()
            key_bit_len = 256 if "256" in algo_name else 128
            
            try:
                # citire fisier
                with open(self.selected_file_path, "rb") as f:
                    plaintext = f.read()
                
                # adaugare padding pkcs7 (necesar pt cbc)
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(plaintext) + padder.finalize()
                
                # criptare
                key_b = bytes.fromhex(key_hex)
                iv_b = bytes.fromhex(iv_hex)
                cipher = Cipher(algorithms.AES(key_b), modes.CBC(iv_b), backend=default_backend())
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                
                # scriere fisier
                with open(out_path, "wb") as f:
                    f.write(ciphertext)
                
                success = True
                error_msg = ""
            except Exception as e:
                success = False
                error_msg = str(e)
                
            fw_version = cryptography.__version__

        end_t = time.perf_counter()
        mem_end = psutil.Process().memory_info().rss

        if success:
            exec_ms = (end_t - start_t) * 1000
            mem_kb = abs(mem_end - mem_start) / 1024
            enc_hash = self.get_file_hash(out_path)

            aid = db.add_algorithm(algo_name, "Asymmetric" if is_rsa else "Symmetric", key_bit_len, 128 if not is_rsa else 0)
            fwid = db.register_framework(selected_fw, fw_version)

            file_data = {
                'user_id': 1, 'algo_id': aid, 'framework_id': fwid,
                'public_key_bytes': pub_key_bytes, 'private_key_bytes': bytes.fromhex(key_hex),
                'name': os.path.basename(out_path), 'type': 'enc',
                'size': os.path.getsize(out_path), 'path': out_path,
                'orig_hash': orig_hash, 'enc_hash': enc_hash,
                'payload': b'', 'iv': bytes.fromhex(iv_hex) if iv_hex else b''
            }
            
            fid = db.register_encrypted_file(file_data)
            
            db.log_test_performance({
                'f_id': fid, 'a_id': aid, 'fw_id': fwid,
                'op': f'Criptare', 'time': exec_ms, 'mem': mem_kb
            })

            messagebox.showinfo("Succes", f"Fisier criptat cu {selected_fw}!\nTimp: {exec_ms:.2f}ms\nMemorie: {mem_kb:.2f}KB")
            self.render_dashboard()
        else:
            messagebox.showerror(f"Eroare {selected_fw}", error_msg)

    # --- PAGINA: FORMULAR DECRIPTARE ---
    def render_decrypt_form(self):
        for widget in self.main_view.winfo_children():
            widget.destroy()

        ctk.CTkLabel(self.main_view, text="Decriptare Fisiere", font=("Arial", 22, "bold")).pack(pady=20)

        ctk.CTkLabel(self.main_view, text="1. Alege un fisier din baza de date:").pack(pady=(20, 5))

        # incarcam doar fisierele criptate
        enc_files = db.get_encrypted_files()
        self.enc_file_dict = {}
        for f in enc_files:
            display_name = f"ID: {f['id']} - {f['file_name']}"
            self.enc_file_dict[display_name] = f['id']

        file_list = list(self.enc_file_dict.keys()) if self.enc_file_dict else ["Nu exista fisiere criptate"]
        self.dec_file_menu = ctk.CTkOptionMenu(self.main_view, values=file_list, width=300)
        self.dec_file_menu.pack(pady=10)

        ctk.CTkLabel(self.main_view, text="2. Alege Framework-ul pt decriptare:").pack(pady=(20, 5))
        self.fw_menu = ctk.CTkOptionMenu(self.main_view, values=["OpenSSL", "Python Cryptography"])
        self.fw_menu.pack(pady=10)

        # buton de decriptare
        self.btn_run_dec = ctk.CTkButton(self.main_view, text="DECRIPTARE", fg_color="#1f8d53", height=50, font=("Arial", 16, "bold"), command=self.handle_decryption)
        self.btn_run_dec.pack(pady=50)

    # --- LOGICA DE DECRIPTARE ---
    def handle_decryption(self):
        selected_option = self.dec_file_menu.get()
        if selected_option == "Nu exista fisiere criptate":
            messagebox.showwarning("Eroare", "Nu ai fisiere criptate in DB de decriptat!")
            return

        # 1. preiau id-ul fisierului si extrag metadatele
        file_id = self.enc_file_dict[selected_option]
        meta = db.get_file_metadata(file_id)

        if not meta:
            messagebox.showerror("Eroare", "Nu s-au putut extrage metadatele din baza de date.")
            return

        # 2. pregatire variabile
        alg_name = meta['alg_name']
        key_hex = meta['private_key'].hex()
        in_path = meta['file_path']
        is_rsa = "rsa" in alg_name.lower()
        
        # formatez fisierul de iesire
        base_path = in_path.replace(".enc", "")
        name, ext = os.path.splitext(base_path)
        out_path = f"{name}_decrypted{ext}"

        if not os.path.exists(in_path):
            messagebox.showerror("Eroare", f"Fisierul fizic nu mai exista la calea:\n{in_path}")
            return

        selected_fw = self.fw_menu.get()
        
        # 3. masurare performanta (start)
        start_t = time.perf_counter()
        mem_start = psutil.Process().memory_info().rss
        
        if selected_fw == "OpenSSL":
            if is_rsa:
                priv_key_bytes = bytes.fromhex(key_hex)
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as temp_priv:
                    temp_priv.write(priv_key_bytes)
                    temp_priv_path = temp_priv.name
                    
                command = [
                    OPENSSL_EXE, "pkeyutl", "-decrypt", "-inkey", temp_priv_path,
                    "-in", in_path, "-out", out_path
                ]
                result = subprocess.run(command, capture_output=True, text=True)
                os.remove(temp_priv_path)
            else:
                iv_hex = meta['init_vector'].hex() if meta['init_vector'] else ""
                command = [
                    OPENSSL_EXE, "enc", "-d", f"-{alg_name}", "-K", key_hex, "-iv", iv_hex,
                    "-in", in_path, "-out", out_path, "-nosalt"
                ]
                result = subprocess.run(command, capture_output=True, text=True)
            
            success = result.returncode == 0
            error_msg = result.stderr if not success else ""
            
        elif selected_fw == "Python Cryptography":
            if is_rsa:
                messagebox.showwarning("Info", "Pentru acest test foloseste OpenSSL pt RSA.")
                return
                
            try:
                iv_hex = meta['init_vector'].hex()
                key_b = bytes.fromhex(key_hex)
                iv_b = bytes.fromhex(iv_hex)
                
                with open(in_path, "rb") as f:
                    ciphertext = f.read()
                    
                cipher = Cipher(algorithms.AES(key_b), modes.CBC(iv_b), backend=default_backend())
                decryptor = cipher.decryptor()
                padded_data = decryptor.update(ciphertext) + decryptor.finalize()
                
                unpadder = padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(padded_data) + unpadder.finalize()
                
                with open(out_path, "wb") as f:
                    f.write(plaintext)
                    
                success = True
                error_msg = ""
            except Exception as e:
                success = False
                error_msg = str(e)

        end_t = time.perf_counter()
        mem_end = psutil.Process().memory_info().rss

        if success:
            exec_ms = (end_t - start_t) * 1000
            mem_kb = abs(mem_end - mem_start) / 1024

            new_hash = self.get_file_hash(out_path)
            orig_hash = meta['original_hash']
            integrity_msg = "INTEGRITATE CONFIRMATA!" if new_hash == orig_hash else "AVERTISMENT: Hash-ul NU se potriveste!"

            # extragem fwid pentru noul fw (il inregistram daca nu exista)
            fw_version = cryptography.__version__ if selected_fw == "Python Cryptography" else "3.0.x"
            fwid = db.register_framework(selected_fw, fw_version)

            db.log_test_performance({
                'f_id': file_id, 'a_id': meta['id_algorithm'], 'fw_id': fwid,
                'op': f'Decriptare', 'time': exec_ms, 'mem': mem_kb
            })

            messagebox.showinfo("Succes", f"Fisier decriptat cu {selected_fw}!\n\n{integrity_msg}\nTimp: {exec_ms:.2f}ms\nMemorie: {mem_kb:.2f}KB")
            self.render_dashboard()
        else:
            messagebox.showerror(f"Eroare {selected_fw}", error_msg)

if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()