import customtkinter as ctk
from tkinter import messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from db import db_manager as db

def format_operation_name(name):
    return name.replace("Python Cryptography", "Py. Crypt.")

def format_framework_name(name):
    if name == "Python Cryptography":
        return "Py. Crypt."
    return name

def render_dashboard(app):
    app.clear_main_view()

    ctk.CTkLabel(
        app.main_view,
        text="Analiza Performanta Criptare",
        font=("Arial", 22, "bold")
    ).pack(pady=15)

    top_actions_frame = ctk.CTkFrame(app.main_view, fg_color="transparent")
    top_actions_frame.pack(fill="x", padx=10, pady=(0, 10))

    ctk.CTkButton(
        top_actions_frame,
        text="Curăță chei abandonate",
        fg_color="#7a4f9a",
        hover_color="#5f3d78",
        command=lambda: handle_delete_abandoned_keys(app)
    ).pack(side="right", padx=5)

    logs = db.get_performance_report()

    if not logs:
        ctk.CTkLabel(
            app.main_view,
            text="Nu exista inca date de performanta.",
            text_color="gray"
        ).pack(pady=20)
        return

    # frame cu scroll orizontal pentru tabel
    table_scroll = ctk.CTkScrollableFrame(
        app.main_view,
        orientation="horizontal",
        height=520
    )
    table_scroll.pack(fill="both", expand=True, padx=10, pady=10)

    table_frame = ctk.CTkFrame(table_scroll, fg_color="transparent")
    table_frame.pack(fill="both", expand=True)

    col_widths = [150, 120, 140, 150, 100, 100, 90, 90, 90, 90, 150]

    headers = [
        "Fisier",
        "Algoritm",
        "Framework",
        "Operatie",
        "Input",
        "Output",
        "Timp",
        "ms/KB",
        "Memorie",
        "Mem/KB",
        "Actiuni"
    ]

    header_frame = ctk.CTkFrame(table_frame, fg_color="gray20")
    header_frame.pack(fill="x", pady=5, padx=5)

    for index, header in enumerate(headers):
        ctk.CTkLabel(
            header_frame,
            text=header,
            font=("Arial", 12, "bold"),
            width=col_widths[index]
        ).grid(row=0, column=index, padx=3, pady=5)

    for log in logs:
        row = ctk.CTkFrame(table_frame)
        row.pack(fill="x", pady=2, padx=5)

        color = "#1fbd1f" if "Criptare" in log["operation_type"] else "#e67e22"

        input_bytes = log["input_bytes"] or 0
        output_bytes = log["output_bytes"] or 0
        time_per_byte = log["time_per_byte"]
        memory_per_byte = log["memory_per_byte"]

        private_key = log["private_key"]

        if private_key:
            full_key_hex = private_key.hex()
        else:
            full_key_hex = "Nu exista cheie salvata pentru acest fisier."

        values = [
            log["file_name"],
            log["alg_name"],
            format_framework_name(log["fw_name"]),
            format_operation_name(log["operation_type"]),
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

        actions_frame = ctk.CTkFrame(row, fg_color="transparent", width=col_widths[10])
        actions_frame.grid(row=0, column=10, padx=3, pady=5)

        ctk.CTkButton(
            actions_frame,
            text="Cheie",
            width=65,
            fg_color="gray25",
            hover_color="gray35",
            command=lambda key=full_key_hex: messagebox.showinfo(
                "Cheie de criptare",
                key
            )
        ).grid(row=0, column=0, padx=2)

        ctk.CTkButton(
            actions_frame,
            text="Șterge",
            width=65,
            fg_color="#a83232",
            hover_color="#7a2424",
            command=lambda fid=log["file_id"]: handle_delete(app, fid)
        ).grid(row=0, column=1, padx=2)

    render_performance_charts(app, logs)

def handle_delete(app, fid):
    confirm = messagebox.askyesno(
        "Confirmare stergere",
        "Sigur vrei sa stergi fisierul din baza de date?\n\n"
        "Cheia de criptare NU va fi stearsa."
    )

    if not confirm:
        return

    if db.delete_file_only(fid):
        messagebox.showinfo(
            "Succes",
            "Fisierul a fost sters din baza de date. Cheia a fost pastrata."
        )
        app.render_dashboard()
    else:
        messagebox.showerror("Eroare", "Nu s-a putut sterge fisierul.")


def handle_delete_abandoned_keys(app):
    abandoned_keys = db.get_abandoned_keys()

    if not abandoned_keys:
        messagebox.showinfo(
            "Chei abandonate",
            "Nu există chei abandonate în baza de date."
        )
        return

    keys_text = "Chei abandonate găsite:\n\n"

    for key in abandoned_keys:
        private_key = key["private_key"]

        if private_key:
            key_hex = private_key.hex()
            key_preview = f"{key_hex[:32]}..."
        else:
            key_preview = "Fără cheie privată"

        alg_name = key["alg_name"] if key["alg_name"] else "Algoritm necunoscut"
        creation_date = key["creation_date"] if key["creation_date"] else "-"

        keys_text += (
            f"ID cheie: {key['id']}\n"
            f"Algoritm: {alg_name}\n"
            f"Creată la: {creation_date}\n"
            f"Cheie: {key_preview}\n"
            f"{'-' * 40}\n"
        )

    confirm = messagebox.askyesno(
        "Chei abandonate",
        keys_text + "\nVrei să ștergi aceste chei?"
    )

    if not confirm:
        return

    deleted_count = db.delete_abandoned_keys()

    if deleted_count == -1:
        messagebox.showerror(
            "Eroare",
            "A apărut o eroare la ștergerea cheilor abandonate."
        )
    else:
        messagebox.showinfo(
            "Succes",
            f"Au fost șterse {deleted_count} chei abandonate."
        )

    app.render_dashboard()


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

    return f"{memory_per_byte * 1024:.4f} KB"


def is_aes_log(log):
    return "aes" in log["alg_name"].lower()


def is_rsa_log(log):
    return "rsa" in log["alg_name"].lower()


def get_framework_short_name(log):
    fw_name = log["fw_name"]

    if fw_name == "Python Cryptography":
        return "Py. Crypt."

    return fw_name


def get_operation_short_name(log):
    operation = log["operation_type"]

    operation = operation.replace("Python Cryptography", "Py. Crypt.")
    operation = operation.replace("Criptare", "Cript.")
    operation = operation.replace("Decriptare", "Decript.")

    return operation


def build_chart_label(log):
    framework = get_framework_short_name(log)
    operation = get_operation_short_name(log)

    return f"{framework}\n{operation}"


def render_performance_charts(app, logs):
    if not logs:
        return

    chart_frame = ctk.CTkFrame(app.main_view)
    chart_frame.pack(fill="both", expand=True, padx=10, pady=20)

    ctk.CTkLabel(
        chart_frame,
        text="Grafice performanță",
        font=("Arial", 20, "bold")
    ).pack(pady=10)

    aes_logs = [log for log in logs if is_aes_log(log)]
    rsa_logs = [log for log in logs if is_rsa_log(log)]

    if aes_logs:
        ctk.CTkLabel(
            chart_frame,
            text="AES - comparație între framework-uri",
            font=("Arial", 17, "bold")
        ).pack(pady=(15, 5))

        render_algorithm_charts(chart_frame, aes_logs, "AES")

    if rsa_logs:
        ctk.CTkLabel(
            chart_frame,
            text="RSA - comparație între framework-uri",
            font=("Arial", 17, "bold")
        ).pack(pady=(20, 5))

        render_algorithm_charts(chart_frame, rsa_logs, "RSA")


def render_algorithm_charts(parent, logs, algorithm_name):
    # Luăm ultimele 10 operații pentru algoritmul respectiv,
    # ca să nu se aglomereze graficul.
    logs = logs[:10]

    labels = []
    total_times = []
    time_per_kb_values = []

    for log in logs:
        labels.append(build_chart_label(log))
        total_times.append(log["time"] or 0)

        if log["time_per_byte"] is not None:
            time_per_kb_values.append(log["time_per_byte"] * 1024)
        else:
            time_per_kb_values.append(0)

    create_bar_chart(
        parent,
        f"{algorithm_name} - timp total de execuție",
        labels,
        total_times,
        "Timp (ms)"
    )

    create_bar_chart(
        parent,
        f"{algorithm_name} - timp raportat la dimensiunea fișierului",
        labels,
        time_per_kb_values,
        "Timp (ms/KB)"
    )


def create_bar_chart(parent, title, labels, values, y_label):
    chart_container = ctk.CTkFrame(parent)
    chart_container.pack(fill="both", expand=True, padx=10, pady=15)

    fig, ax = plt.subplots(figsize=(10, 4))

    ax.bar(labels, values)
    ax.set_title(title)
    ax.set_ylabel(y_label)
    ax.tick_params(axis="x", labelrotation=35)

    fig.tight_layout()

    canvas = FigureCanvasTkAgg(fig, master=chart_container)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)

    plt.close(fig)