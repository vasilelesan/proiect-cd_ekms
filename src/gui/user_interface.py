import sys
from wsgiref import headers
import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import time
import psutil
import subprocess
import hashlib

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

        self.btn_encrypt = ctk.CTkButton(self.sidebar, text="Criptare Nouă (OpenSSL)", command=self.render_encrypt_form)
        self.btn_encrypt.pack(pady=10, padx=20)

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
    
        # cap de tabel (header)
        header_frame = ctk.CTkFrame(self.main_view, fg_color="gray20")
        header_frame.pack(fill="x", pady=5, padx=10)
    
        headers = ["Fișier", "Algoritm", "Framework", "Timp (ms)", "Memorie (KB)"]
        for i, h in enumerate(headers):
            ctk.CTkLabel(header_frame, text=h, font=("Arial", 12, "bold"), width=150).grid(row=0, column=i, padx=5, pady=5)

        # preiau datele din DB printr-un JOIN intre Performance, File, Algorithm si Framework
        # Va trebui să adaugi o funcție în db_manager numită get_all_performance_logs()
        logs = db.get_performance_report() 

        for log in logs:
            row = ctk.CTkFrame(self.main_view)
            row.pack(fill="x", pady=2, padx=10)
        
            # culori diferite pentru frameworkuri diferite
            color = "#1f538d" if log['fw_name'] == "OpenSSL" else "#1f8d53"
        
            ctk.CTkLabel(row, text=log['file_name'], width=150).grid(row=0, column=0)
            ctk.CTkLabel(row, text=log['alg_name'], width=150).grid(row=0, column=1)
            ctk.CTkLabel(row, text=log['fw_name'], width=150, text_color=color).grid(row=0, column=2)
            ctk.CTkLabel(row, text=f"{log['time']:.2f}", width=150).grid(row=0, column=3)
            ctk.CTkLabel(row, text=f"{log['mem']:.0f}", width=150).grid(row=0, column=4)

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

        ctk.CTkLabel(self.main_view, text="Configurare Criptare OpenSSL", font=("Arial", 22, "bold")).pack(pady=20)

        # selectie fisier
        self.btn_select = ctk.CTkButton(self.main_view, text="1. Selectează Fișier", command=self.handle_file_select)
        self.btn_select.pack(pady=10)
        self.lbl_file = ctk.CTkLabel(self.main_view, text="Niciun fișier ales", text_color="gray")
        self.lbl_file.pack()

        # selectie algoritm
        ctk.CTkLabel(self.main_view, text="2. Alege Algoritm:").pack(pady=(20, 5))
        self.algo_menu = ctk.CTkOptionMenu(self.main_view, values=["aes-256-cbc", "aes-128-cbc"])
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
            key_hex = k['private_key'].hex()
            display_name = f"ID: {k['id']} ({key_hex[:8]}...)"
            self.key_dict[display_name] = key_hex

        db_keys_list = list(self.key_dict.keys()) if self.key_dict else ["Fara chei in DB"]
        self.db_key_menu = ctk.CTkOptionMenu(self.main_view, values=db_keys_list)
        self.db_key_menu.pack(pady=10)

        # manual key entry
        self.key_entry = ctk.CTkEntry(self.main_view, width=300, placeholder_text="ex: 603deb1015ca...")
        self.key_entry.pack(pady=5)

        # set initial ui state
        self.update_key_ui()

        # buton de executie
        self.btn_run = ctk.CTkButton(self.main_view, text="EXECUTE OPENSSL", fg_color="#1f538d", height=50, font=("Arial", 16, "bold"), command=self.handle_encryption)
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

        # preluare cheie/generare cheie
        # selected_key_option = self.db_key_menu.get()
        # if selected_key_option != "Cheie Noua (Generare)":
        #     key_hex = self.key_dict[selected_key_option]
        # else:
        #     user_key = self.key_entry.get().strip()
        #     if not user_key:
        #         key_bytes = 32 if "256" in algo_name else 16
        #         user_key = os.urandom(key_bytes).hex()
        #     key_hex = user_key
        if mode == "auto":
            # generate random key
            key_bytes = 32 if "256" in algo_name else 16
            key_hex = os.urandom(key_bytes).hex()
            
        elif mode == "db":
            # extract key from db dropdown
            selected_key_option = self.db_key_menu.get()
            if selected_key_option == "Fara chei in DB":
                messagebox.showwarning("Eroare", "Nu exista chei in baza de date!")
                return
            key_hex = self.key_dict[selected_key_option]
            
        elif mode == "manual":
            # read user input
            key_hex = self.key_entry.get().strip()
            if not key_hex:
                messagebox.showwarning("Eroare", "Te rog introdu o cheie!")
                return
            # optional: check key length based on algorithm here

        # generare vector de initializare
        iv_hex = os.urandom(16).hex()
        out_path = self.selected_file_path + ".enc"
        
        # pregatesc IDs 
        # Pentru test folosim IDs create de tine anterior
        key_bit_len = 256 if "256" in algo_name else 128
        aid = db.add_algorithm(algo_name, "Symmetric", key_bit_len, 128)
        fwid = db.register_framework("OpenSSL", "3.0.x")

        # 2. calcul hash original
        orig_hash = self.get_file_hash(self.selected_file_path)

        # 3. comanda OpenSSL
        command = [
            OPENSSL_EXE, "enc", f"-{algo_name}", "-K", key_hex, "-iv", iv_hex,
            "-in", self.selected_file_path, "-out", out_path, "-nosalt"
        ]

        # 4.masurare performanta
        start_t = time.perf_counter()
        mem_start = psutil.Process().memory_info().rss
        
        result = subprocess.run(command, capture_output=True, text=True)
        
        end_t = time.perf_counter()
        mem_end = psutil.Process().memory_info().rss

        if result.returncode == 0:
            exec_ms = (end_t - start_t) * 1000
            mem_kb = abs(mem_end - mem_start) / 1024

            # 5. calcul hash criptat
            enc_hash = self.get_file_hash(out_path)

            # 6. salvare in DB prin fucntie
            file_data = {
                'user_id': 1,
                'algo_id': aid,
                'framework_id': fwid,
                'public_key_bytes': None,
                'private_key_bytes': bytes.fromhex(key_hex),
                'name': os.path.basename(out_path),
                'type': 'enc',
                'size': os.path.getsize(out_path),
                'path': out_path,
                'orig_hash': orig_hash,
                'enc_hash': enc_hash,
                'payload': b'',
                'iv': bytes.fromhex(iv_hex)
            }
            
            fid = db.register_encrypted_file(file_data)
            
            # log performanta
            db.log_test_performance({
                'f_id': fid, 'a_id': aid, 'fw_id': fwid,
                'op': 'Criptare OpenSSL', 'time': exec_ms, 'mem': mem_kb
            })

            messagebox.showinfo("Succes", f"Fișier criptat!\nTimp: {exec_ms:.2f}ms\nMemorie: {mem_kb:.2f}KB")
            self.render_dashboard()
        else:
            messagebox.showerror("Eroare OpenSSL", result.stderr)

if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()