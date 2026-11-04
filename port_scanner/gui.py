"""Interfaz de escritorio del escáner de puertos (CustomTkinter)."""

from __future__ import annotations

import csv
import json
import queue
import threading
import time
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from .scanner import (
    PORT_PRESETS, PortResult, PortScanner, needs_authorization_warning,
    parse_ports, resolve_target,
)

ACCENT = "#1f6aa5"
DANGER = "#c0392b"
RISK_RED = "#ff6b6b"
TABLE_BG = "#242424"
TABLE_HEADER = "#1a1a1a"
DISABLED = "#3a3a3a"


class StatCard(ctk.CTkFrame):
    """Tarjeta pequeña con un dato del escaneo."""

    def __init__(self, master, title: str):
        super().__init__(master, corner_radius=10)
        ctk.CTkLabel(self, text=title, text_color="gray70",
                     font=ctk.CTkFont(size=12)).pack(anchor="w", padx=14, pady=(10, 0))
        self.value = ctk.CTkLabel(self, text="-", font=ctk.CTkFont(size=20, weight="bold"))
        self.value.pack(anchor="w", padx=14, pady=(0, 10))

    def set(self, text: str) -> None:
        self.value.configure(text=text)


class PortScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Port Scanner")
        self.geometry("1100x680")
        self.minsize(950, 600)

        self.events: queue.Queue = queue.Queue()
        self.scanner: PortScanner | None = None
        self.results: list[PortResult] = []
        self.target_name = ""
        self.target_ip = ""
        self.start_time = 0.0
        self.total_ports = 0

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()
        self._style_table()
        self.after(50, self._process_events)

    # ------------------------------------------------------------------ UI --

    def _build_sidebar(self) -> None:
        side = ctk.CTkFrame(self, width=280, corner_radius=0)
        side.grid(row=0, column=0, sticky="nsw")
        side.grid_propagate(False)

        ctk.CTkLabel(side, text="Port Scanner",
                     font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=20, pady=(24, 0))
        ctk.CTkLabel(side, text="Escáner de puertos TCP", text_color="gray70").pack(anchor="w", padx=20)

        self._section(side, "Objetivo")
        self.target_entry = ctk.CTkEntry(side, placeholder_text="scanme.nmap.org o 192.168.1.1")
        self.target_entry.pack(fill="x", padx=20)
        self.target_entry.bind("<Return>", lambda _e: self.start_scan())

        self._section(side, "Puertos")
        self.preset = ctk.CTkSegmentedButton(
            side, values=["Comunes", "1-1024", "Todos", "Otros"], command=self._on_preset)
        self.preset.pack(fill="x", padx=20)
        self.preset.set("Comunes")
        self.custom_ports = ctk.CTkEntry(side, placeholder_text="Ej: 22,80,443,8000-8100")
        # Solo se muestra cuando se elige "Otros" (ver _on_preset).

        self._section(side, "Hilos")
        self.threads_label = ctk.CTkLabel(side, text="100 hilos en paralelo", text_color="gray70")
        self.threads_label.pack(anchor="w", padx=20)
        self.threads = ctk.CTkSlider(side, from_=10, to=500, number_of_steps=49,
                                     command=lambda v: self.threads_label.configure(
                                         text=f"{int(v)} hilos en paralelo"))
        self.threads.set(100)
        self.threads.pack(fill="x", padx=20)

        self._section(side, "Tiempo de espera")
        self.timeout_label = ctk.CTkLabel(side, text="1.0 s por puerto", text_color="gray70")
        self.timeout_label.pack(anchor="w", padx=20)
        self.timeout = ctk.CTkSlider(side, from_=0.2, to=3.0, number_of_steps=28,
                                     command=lambda v: self.timeout_label.configure(
                                         text=f"{v:.1f} s por puerto"))
        self.timeout.set(1.0)
        self.timeout.pack(fill="x", padx=20)

        self.banner_check = ctk.CTkCheckBox(side, text="Detectar versión del servicio (banner)")
        self.banner_check.select()
        self.banner_check.pack(anchor="w", padx=20, pady=(16, 0))

        self.scan_button = ctk.CTkButton(side, text="Escanear", height=40,
                                         font=ctk.CTkFont(size=15, weight="bold"),
                                         command=self.start_scan)
        self.scan_button.pack(fill="x", padx=20, pady=(24, 8))
        self.stop_button = ctk.CTkButton(side, text="Detener", height=36, fg_color=DISABLED,
                                         hover_color="#962d22", state="disabled",
                                         command=self.stop_scan)
        self.stop_button.pack(fill="x", padx=20)

        ctk.CTkLabel(side, text="Úsalo solo en equipos propios o con\nautorización del propietario.",
                     text_color="gray55", font=ctk.CTkFont(size=11),
                     justify="left").pack(side="bottom", anchor="w", padx=20, pady=16)

    def _section(self, parent, text: str) -> None:
        ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=13, weight="bold")).pack(
            anchor="w", padx=20, pady=(18, 4))

    def _build_main(self) -> None:
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)

        cards = ctk.CTkFrame(main, fg_color="transparent")
        cards.grid(row=0, column=0, sticky="ew")
        self.card_host = StatCard(cards, "Objetivo")
        self.card_open = StatCard(cards, "Puertos abiertos")
        self.card_scanned = StatCard(cards, "Puertos escaneados")
        self.card_time = StatCard(cards, "Tiempo")
        for i, card in enumerate((self.card_host, self.card_open, self.card_scanned, self.card_time)):
            cards.grid_columnconfigure(i, weight=1, uniform="cards")
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 8, 0))

        progress_row = ctk.CTkFrame(main, fg_color="transparent")
        progress_row.grid(row=1, column=0, sticky="ew", pady=(16, 8))
        progress_row.grid_columnconfigure(0, weight=1)
        self.progress = ctk.CTkProgressBar(progress_row, height=10, fg_color=DISABLED,
                                           progress_color=DISABLED)
        self.progress.set(0)
        self.progress.grid(row=0, column=0, sticky="ew")
        self.status = ctk.CTkLabel(progress_row, text="Listo para escanear", text_color="gray70")
        self.status.grid(row=1, column=0, sticky="w", pady=(4, 0))

        table_frame = ctk.CTkFrame(main, corner_radius=10)
        table_frame.grid(row=2, column=0, sticky="nsew")
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        columns = ("port", "service", "banner", "risk")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings")
        for col, title, width, stretch in (
            ("port", "Puerto", 80, False),
            ("service", "Servicio", 120, False),
            ("banner", "Versión / banner", 260, True),
            ("risk", "Observaciones", 300, True),
        ):
            self.table.heading(col, text=title, anchor="w")
            self.table.column(col, width=width, minwidth=60, stretch=stretch, anchor="w")
        self.table.tag_configure("risk", foreground=RISK_RED)
        self.table.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)

        scroll = ctk.CTkScrollbar(table_frame, command=self.table.yview)
        scroll.grid(row=0, column=1, sticky="ns", pady=8)
        self.table.configure(yscrollcommand=scroll.set)

        bottom = ctk.CTkFrame(main, fg_color="transparent")
        bottom.grid(row=3, column=0, sticky="ew", pady=(12, 0))
        self.legend = ctk.CTkLabel(bottom, text="En rojo: servicios que suelen suponer un riesgo si están expuestos",
                                   text_color="gray60", font=ctk.CTkFont(size=11))
        self.legend.pack(side="left")
        self.export_button = ctk.CTkButton(bottom, text="Exportar resultados", width=170,
                                           state="disabled", fg_color=DISABLED,
                                           command=self.export_results)
        self.export_button.pack(side="right")

    def _style_table(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        # Quita el borde blanco que el tema "clam" dibuja alrededor de la tabla.
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        style.configure("Treeview", background=TABLE_BG, fieldbackground=TABLE_BG,
                        foreground="white", rowheight=30, borderwidth=0, font=("Segoe UI", 11),
                        bordercolor=TABLE_BG, lightcolor=TABLE_BG, darkcolor=TABLE_BG)
        style.configure("Treeview.Heading", background=TABLE_HEADER, foreground="white",
                        relief="flat", font=("Segoe UI", 11, "bold"), padding=6)
        style.map("Treeview", background=[("selected", ACCENT)])
        style.map("Treeview.Heading", background=[("active", TABLE_HEADER)])

    def _on_preset(self, value: str) -> None:
        if value == "Otros":
            self.custom_ports.pack(fill="x", padx=20, pady=(8, 0), after=self.preset)
            self.custom_ports.focus()
        else:
            self.custom_ports.pack_forget()

    # ------------------------------------------------------------ escaneo --

    def _selected_ports(self) -> list[int]:
        preset = self.preset.get()
        if preset == "Otros":
            return parse_ports(self.custom_ports.get())
        return PORT_PRESETS[preset]

    def start_scan(self) -> None:
        if self.scanner is not None:
            return
        target = self.target_entry.get().strip()
        try:
            ports = self._selected_ports()
            ip = resolve_target(target)
        except ValueError as exc:
            messagebox.showerror("Revisa los datos", str(exc))
            return

        if needs_authorization_warning(target, ip):
            if not messagebox.askyesno(
                "Confirmar autorización",
                f"{target} ({ip}) es una dirección pública.\n\n"
                "Escanear equipos sin permiso puede ser ilegal. "
                "¿Tienes autorización para escanear este objetivo?",
                icon="warning",
            ):
                return

        self.results.clear()
        self.table.delete(*self.table.get_children())
        self.target_name, self.target_ip = target, ip
        self.total_ports = len(ports)
        self.start_time = time.perf_counter()

        self.card_host.set(ip)
        self.card_open.set("0")
        self.card_scanned.set(f"0 / {len(ports)}")
        self.card_time.set("0.0 s")
        self.progress.set(0)
        self.progress.configure(progress_color=ACCENT)
        self.status.configure(text=f"Escaneando {target} ({ip})...")
        self._set_running(True)

        self.scanner = PortScanner(threads=int(self.threads.get()),
                                   timeout=float(self.timeout.get()),
                                   banners=bool(self.banner_check.get()))
        threading.Thread(target=self._run_scan, args=(self.scanner, ip, ports, target),
                         daemon=True).start()

    def _run_scan(self, scanner: PortScanner, ip: str, ports: list[int], host: str) -> None:
        """Se ejecuta en un hilo aparte para que la ventana no se congele.

        Tkinter no se puede tocar desde otros hilos, así que los resultados se
        mandan por una cola y la ventana los recoge en _process_events.
        """
        try:
            scanner.scan(ip, ports, host,
                         on_open=lambda r: self.events.put(("open", r)),
                         on_progress=lambda done, total: self.events.put(("progress", done)))
            self.events.put(("done", scanner.stopped))
        except Exception as exc:  # noqa: BLE001 - se muestra al usuario
            self.events.put(("error", str(exc)))

    def stop_scan(self) -> None:
        if self.scanner:
            self.scanner.stop()
            self.status.configure(text="Deteniendo...")
            self.stop_button.configure(state="disabled", fg_color=DISABLED)

    def _process_events(self) -> None:
        last_progress = None
        try:
            while True:
                kind, data = self.events.get_nowait()
                if kind == "open":
                    self._add_result(data)
                elif kind == "progress":
                    last_progress = data
                elif kind == "done":
                    self._finish(stopped=data)
                elif kind == "error":
                    self._finish(stopped=True)
                    messagebox.showerror("Error", data)
        except queue.Empty:
            pass

        if last_progress is not None and self.total_ports:
            self.progress.set(last_progress / self.total_ports)
            self.card_scanned.set(f"{last_progress} / {self.total_ports}")
        if self.scanner is not None:
            self.card_time.set(f"{time.perf_counter() - self.start_time:.1f} s")
        self.after(50, self._process_events)

    def _add_result(self, result: PortResult) -> None:
        self.results.append(result)
        self.results.sort(key=lambda r: r.port)
        index = self.results.index(result)
        self.table.insert("", index, values=(result.port, result.service,
                                             result.banner or "-", result.risk or "-"),
                          tags=("risk",) if result.risk else ())
        self.card_open.set(str(len(self.results)))

    def _finish(self, stopped: bool) -> None:
        elapsed = time.perf_counter() - self.start_time
        self.scanner = None
        self._set_running(False)
        self.card_time.set(f"{elapsed:.1f} s")
        state = "Escaneo detenido" if stopped else "Escaneo completado"
        n = len(self.results)
        found = "1 puerto abierto" if n == 1 else f"{n} puertos abiertos"
        self.status.configure(text=f"{state}: {found} en {self.target_name} ({elapsed:.1f} s)")
        if not stopped:
            self.progress.set(1)

    def _set_running(self, running: bool) -> None:
        self.scan_button.configure(state="disabled" if running else "normal",
                                   text="Escaneando..." if running else "Escanear")
        self.stop_button.configure(state="normal" if running else "disabled",
                                   fg_color=DANGER if running else DISABLED)
        can_export = not running and bool(self.results)
        self.export_button.configure(state="normal" if can_export else "disabled",
                                     fg_color=ACCENT if can_export else DISABLED)

    # ---------------------------------------------------------- exportar --

    def export_results(self) -> None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M")
        path = filedialog.asksaveasfilename(
            title="Exportar resultados",
            initialfile=f"escaneo-{self.target_name}-{stamp}",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")],
        )
        if not path:
            return
        rows = [{"puerto": r.port, "servicio": r.service, "banner": r.banner, "riesgo": r.risk}
                for r in self.results]
        if path.lower().endswith(".json"):
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"objetivo": self.target_name, "ip": self.target_ip,
                           "fecha": datetime.now().isoformat(timespec="seconds"),
                           "puertos_abiertos": rows}, f, ensure_ascii=False, indent=2)
        else:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=["puerto", "servicio", "banner", "riesgo"])
                writer.writeheader()
                writer.writerows(rows)
        self.status.configure(text=f"Resultados guardados en {path}")


def main() -> None:
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    PortScannerApp().mainloop()
