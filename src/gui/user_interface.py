import sys
import os
import customtkinter as ctk

current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(current_dir)
sys.path.append(src_dir)

from db import db_manager as db

from gui.dashboard_view import render_dashboard
from gui.encrypt_view import render_encrypt_form
from gui.decrypt_view import render_decrypt_form

class CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("EKMS - Manager Criptare Locală")
        self.geometry("1300x700")
        ctk.set_appearance_mode("dark")

        self.selected_file_path = ""

        db.init_db()

        self.setup_layout()
        self.render_dashboard()

    def setup_layout(self):
        # layout principal
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # sidebar
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        self.logo = ctk.CTkLabel(
            self.sidebar,
            text="EKMS PANEL",
            font=("Roboto", 24, "bold")
        )
        self.logo.pack(pady=30)

        self.btn_dash = ctk.CTkButton(
            self.sidebar,
            text="Fișiere & Performanță",
            command=self.render_dashboard
        )
        self.btn_dash.pack(pady=10, padx=20)

        self.btn_encrypt = ctk.CTkButton(
            self.sidebar,
            text="Criptare Nouă",
            command=self.render_encrypt_form
        )
        self.btn_encrypt.pack(pady=10, padx=20)

        self.btn_decrypt = ctk.CTkButton(
            self.sidebar,
            text="Decriptare",
            command=self.render_decrypt_form
        )
        self.btn_decrypt.pack(pady=10, padx=20)

        self.main_view = ctk.CTkScrollableFrame(
            self,
            corner_radius=15,
            fg_color="transparent"
        )
        self.main_view.grid(
            row=0,
            column=1,
            padx=20,
            pady=20,
            sticky="nsew"
        )

    def clear_main_view(self):
        for widget in self.main_view.winfo_children():
            widget.destroy()

    # metode wrapper: ele doar trimit obiectul app către fișierele UI
    def render_dashboard(self):
        render_dashboard(self)

    def render_encrypt_form(self):
        render_encrypt_form(self)

    def render_decrypt_form(self):
        render_decrypt_form(self)


if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()