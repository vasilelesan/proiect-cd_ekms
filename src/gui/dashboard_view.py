import customtkinter as ctk
from tkinter import messagebox

from db import db_manager as db


def render_dashboard(app):
    app.clear_main_view()

    ctk.CTkLabel(
        app.main_view,
        text="Analiză Performanță Criptare",
        font=("Arial", 22, "bold")
    ).pack(pady=15)

    col_widths = [150, 120, 140, 150, 100, 100, 90, 90, 90, 90, 90]

    header_frame = ctk.CTkFrame(app.main_view, fg_color="gray20")
    header_frame.pack(fill="x", pady=5, padx=10)

    headers = [
    "Fișier",
    "Algoritm",
    "Framework",
    "Operație",
    "Input",
    "Output",
    "Timp",
    "ms/KB",
    "Memorie",
    "KB/KB",
    "Acțiuni"
]

    for index, header in enumerate(headers):
        ctk.CTkLabel(
            header_frame,
            text=header,
            font=("Arial", 12, "bold"),
            width=col_widths[index]
        ).grid(row=0, column=index, padx=3, pady=5)

    logs = db.get_performance_report()

    if not logs:
        ctk.CTkLabel(
            app.main_view,
            text="Nu există încă date de performanță.",
            text_color="gray"
        ).pack(pady=20)
        return

    for log in logs:
        row = ctk.CTkFrame(app.main_view)
        row.pack(fill="x", pady=2, padx=10)

        color = "#1fbd1f" if "Criptare" in log["operation_type"] else "#e67e22"

        input_bytes = log["input_bytes"] or 0
        output_bytes = log["output_bytes"] or 0
        time_per_byte = log["time_per_byte"]
        memory_per_byte = log["memory_per_byte"]

        values = [
    log["file_name"],
    log["alg_name"],
    log["fw_name"],
    log["operation_type"],
    format_size(input_bytes),
    format_size(output_bytes),
    f"{log['time']:.2f} ms",
    format_time_per_kb(time_per_byte),
    f"{log['mem']:.2f} KB",
    format_memory_per_kb(memory_per_byte)
]

        for index, value in enumerate(values):
            text_color = color if index == 3 else "white"

            ctk.CTkLabel(
                row,
                text=value,
                width=col_widths[index],
                text_color=text_color
            ).grid(row=0, column=index, padx=3, pady=5)

        ctk.CTkButton(
            row,
            text="Șterge",
            width=col_widths[10],
            fg_color="#a83232",
            hover_color="#7a2424",
            command=lambda fid=log["file_id"]: handle_delete(app, fid)
        ).grid(row=0, column=10, padx=3, pady=5)


def handle_delete(app, fid):
    confirm = messagebox.askyesno(
        "Confirmare ștergere",
        "Sigur vrei să ștergi fișierul și cheia asociată din baza de date?"
    )

    if not confirm:
        return

    if db.delete_file_and_key(fid):
        messagebox.showinfo("Succes", "Fișierul a fost șters din baza de date.")
        app.render_dashboard()
    else:
        messagebox.showerror("Eroare", "Nu s-a putut șterge fișierul.")


def format_size(bytes_value):
    if bytes_value is None:
        return "-"

    kb = float(bytes_value) / 1024
    return f"{kb:.2f} KB"


def format_time_per_kb(time_per_byte):
    if time_per_byte is None:
        return "-"

    return f"{time_per_byte * 1024:.4f}"


def format_memory_per_kb(memory_per_byte):
    if memory_per_byte is None:
        return "-"

    return f"{memory_per_byte * 1024:.4f}"