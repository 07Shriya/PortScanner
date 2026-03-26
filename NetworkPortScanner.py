import socket
import threading
import time
import queue
import sys
import ipaddress
import csv
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

# ---------------------------
# Service Map (extended)
# ---------------------------
COMMON_PORTS = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
    110: 'POP3', 119: 'NNTP', 123: 'NTP', 135: 'MS-RPC', 137: 'NetBIOS',
    138: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP-Trap',
    179: 'BGP', 194: 'IRC', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
    465: 'SMTPS', 514: 'Syslog', 515: 'LPD', 587: 'SMTP-Sub', 631: 'IPP',
    636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS',
    1194: 'OpenVPN', 1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP',
    2049: 'NFS', 2181: 'Zookeeper', 2375: 'Docker', 2376: 'Docker-TLS',
    3000: 'Dev-HTTP', 3306: 'MySQL', 3389: 'RDP', 4444: 'Metasploit',
    5000: 'Flask/UPnP', 5432: 'PostgreSQL', 5900: 'VNC', 5984: 'CouchDB',
    6379: 'Redis', 6443: 'K8s-API', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    8888: 'Jupyter', 9000: 'PHP-FPM', 9092: 'Kafka', 9200: 'Elasticsearch',
    27017: 'MongoDB', 27018: 'MongoDB', 50070: 'Hadoop'
}

PRESET_RANGES = {
    "Well-Known (1–1023)": (1, 1023),
    "Common (1–1024)": (1, 1024),
    "Extended (1–5000)": (1, 5000),
    "Registered (1024–49151)": (1024, 49151),
    "Top 100 Services": None,  # handled specially
    "Custom": None,
}

TOP_100_PORTS = sorted([
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 138,
    139, 143, 161, 162, 179, 194, 389, 443, 445, 465, 514, 515, 587,
    631, 636, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049, 2181, 2375,
    2376, 3000, 3306, 3389, 4444, 5000, 5432, 5900, 5984, 6379, 6443,
    8080, 8443, 8888, 9000, 9092, 9200, 27017, 27018, 50070
])

# ---------------------------
# Banner Grab
# ---------------------------
def grab_banner(ip, port, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # Try to receive banner
        try:
            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = s.recv(256).decode('utf-8', errors='replace').strip()
        except Exception:
            banner = ""
        s.close()
        return banner[:120] if banner else ""
    except Exception:
        return ""

# ---------------------------
# Scanner Worker
# ---------------------------
class PortScanner:
    def __init__(self, target, ports, timeout=0.5, max_workers=500, grab_banners=False):
        self.target = target
        self.ports = ports  # list of ints
        self.timeout = timeout
        self.max_workers = max_workers
        self.grab_banners = grab_banners
        self._stop_event = threading.Event()

        self.total_ports = len(ports)
        self.scanned_count = 0
        self.open_ports = []  # list[(port, service, banner)]
        self._lock = threading.Lock()
        self.result_queue = queue.Queue()
        self.resolved_ip = None

    def stop(self):
        self._stop_event.set()

    def _scan_port(self, port):
        if self._stop_event.is_set():
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.resolved_ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                banner = ""
                if self.grab_banners:
                    banner = grab_banner(self.resolved_ip, port, timeout=1.5)
                with self._lock:
                    self.open_ports.append((port, service, banner))
                self.result_queue.put(('open', port, service, banner))
            s.close()
        except Exception:
            pass
        finally:
            with self._lock:
                self.scanned_count += 1
            self.result_queue.put(('progress', self.scanned_count, self.total_ports))

    def resolve_target(self):
        self.resolved_ip = socket.gethostbyname(self.target)
        return self.resolved_ip

    def run(self):
        sem = threading.Semaphore(self.max_workers)
        threads = []
        for port in self.ports:
            if self._stop_event.is_set():
                break
            sem.acquire()
            t = threading.Thread(target=self._worker_wrapper, args=(sem, port), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        self.result_queue.put(('done', None, None, None))

    def _worker_wrapper(self, sem, port):
        try:
            self._scan_port(port)
        finally:
            sem.release()

# ---------------------------
# Color Palette / Theme
# ---------------------------
BG         = "#0d1117"
BG2        = "#161b22"
BG3        = "#21262d"
ACCENT     = "#00ff88"
ACCENT2    = "#00ccff"
WARN       = "#ff6b35"
TEXT       = "#e6edf3"
TEXT_DIM   = "#8b949e"
BORDER     = "#30363d"
GREEN_OPEN = "#39d353"
RED_CLOSE  = "#f85149"

FONT_MONO  = ("Consolas", 10)
FONT_MONO_SM = ("Consolas", 9)
FONT_HEAD  = ("Consolas", 11, "bold")
FONT_TITLE = ("Consolas", 13, "bold")

# ---------------------------
# Tkinter GUI
# ---------------------------
class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NETSCAN // Port Intelligence Tool")
        self.geometry("860x660")
        self.minsize(780, 560)
        self.configure(bg=BG)

        self.scanner_thread = None
        self.scanner = None
        self.start_time = None
        self.poll_after_ms = 40
        self._elapsed_after = None
        self._scan_log = []  # history entries

        self._apply_theme()
        self._build_ui()

    def _apply_theme(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".",
            background=BG, foreground=TEXT,
            font=FONT_MONO, bordercolor=BORDER,
            troughcolor=BG2, fieldbackground=BG3,
            selectbackground=ACCENT, selectforeground=BG
        )
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT, font=FONT_MONO)
        style.configure("Dim.TLabel", background=BG, foreground=TEXT_DIM, font=FONT_MONO_SM)
        style.configure("Title.TLabel", background=BG, foreground=ACCENT, font=FONT_TITLE)
        style.configure("Accent.TLabel", background=BG, foreground=ACCENT2, font=FONT_MONO)

        style.configure("TEntry",
            fieldbackground=BG3, foreground=TEXT,
            insertcolor=ACCENT, relief="flat",
            bordercolor=BORDER, font=FONT_MONO
        )
        style.map("TEntry",
            bordercolor=[("focus", ACCENT)],
            fieldbackground=[("focus", BG2)]
        )

        style.configure("TButton",
            background=BG3, foreground=TEXT,
            relief="flat", bordercolor=BORDER,
            padding=(10, 5), font=FONT_MONO
        )
        style.map("TButton",
            background=[("active", BG2), ("disabled", BG)],
            foreground=[("disabled", TEXT_DIM)]
        )
        style.configure("Scan.TButton",
            background=ACCENT, foreground=BG,
            font=FONT_HEAD
        )
        style.map("Scan.TButton",
            background=[("active", "#00cc70"), ("disabled", BG3)],
            foreground=[("disabled", TEXT_DIM)]
        )
        style.configure("Stop.TButton",
            background=WARN, foreground=BG,
            font=FONT_HEAD
        )
        style.map("Stop.TButton",
            background=[("active", "#e55a2a"), ("disabled", BG3)],
            foreground=[("disabled", TEXT_DIM)]
        )

        style.configure("TLabelframe",
            background=BG, foreground=ACCENT2,
            bordercolor=BORDER, relief="flat",
            font=FONT_HEAD
        )
        style.configure("TLabelframe.Label",
            background=BG, foreground=ACCENT2,
            font=FONT_HEAD
        )

        style.configure("Horizontal.TProgressbar",
            troughcolor=BG3, background=ACCENT,
            bordercolor=BG3, thickness=6
        )

        style.configure("TCombobox",
            fieldbackground=BG3, background=BG3,
            foreground=TEXT, selectbackground=BG3,
            selectforeground=ACCENT, arrowcolor=TEXT,
            bordercolor=BORDER
        )
        style.map("TCombobox",
            fieldbackground=[("readonly", BG3)],
            bordercolor=[("focus", ACCENT)]
        )

        style.configure("TCheckbutton",
            background=BG, foreground=TEXT,
            font=FONT_MONO
        )
        style.map("TCheckbutton",
            background=[("active", BG)],
            foreground=[("active", ACCENT)]
        )

        style.configure("TNotebook",
            background=BG, bordercolor=BORDER
        )
        style.configure("TNotebook.Tab",
            background=BG3, foreground=TEXT_DIM,
            font=FONT_MONO, padding=(12, 5)
        )
        style.map("TNotebook.Tab",
            background=[("selected", BG2)],
            foreground=[("selected", ACCENT)]
        )

    def _build_ui(self):
        # === HEADER ===
        hdr = tk.Frame(self, bg=BG, pady=0)
        hdr.pack(fill="x", padx=14, pady=(14, 0))

        tk.Label(hdr, text="◈ NETSCAN", font=("Consolas", 18, "bold"),
                 bg=BG, fg=ACCENT).pack(side="left")
        tk.Label(hdr, text=" // Port Intelligence Tool",
                 font=("Consolas", 11), bg=BG, fg=TEXT_DIM).pack(side="left", pady=(4,0))

        self.lbl_time = tk.Label(hdr, text="", font=FONT_MONO_SM, bg=BG, fg=TEXT_DIM)
        self.lbl_time.pack(side="right")
        self._tick_clock()

        # Separator line
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=14, pady=(8, 0))

        # === NOTEBOOK (Scan / History) ===
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=14, pady=10)

        self.tab_scan = ttk.Frame(self.notebook)
        self.tab_history = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_scan, text=" SCAN ")
        self.notebook.add(self.tab_history, text=" HISTORY ")

        self._build_scan_tab(self.tab_scan)
        self._build_history_tab(self.tab_history)

    def _build_scan_tab(self, parent):
        # --- CONFIG SECTION ---
        cfg = tk.Frame(parent, bg=BG2, pady=10, padx=12,
                       highlightbackground=BORDER, highlightthickness=1)
        cfg.pack(fill="x", pady=(0, 10))

        # Row 0: Target
        tk.Label(cfg, text="TARGET", font=FONT_MONO_SM, bg=BG2, fg=TEXT_DIM).grid(
            row=0, column=0, sticky="w", padx=(0, 6), pady=(0,4))
        tk.Label(cfg, text="PRESET", font=FONT_MONO_SM, bg=BG2, fg=TEXT_DIM).grid(
            row=0, column=2, sticky="w", padx=(16, 6), pady=(0,4))
        tk.Label(cfg, text="PORT RANGE", font=FONT_MONO_SM, bg=BG2, fg=TEXT_DIM).grid(
            row=0, column=4, sticky="w", padx=(16, 6), pady=(0,4))

        self.ent_target = self._dark_entry(cfg, width=28)
        self.ent_target.grid(row=1, column=0, columnspan=2, sticky="ew", padx=(0,0))

        self.var_preset = tk.StringVar(value="Common (1–1024)")
        self.cmb_preset = ttk.Combobox(cfg, textvariable=self.var_preset,
                                        values=list(PRESET_RANGES.keys()),
                                        state="readonly", width=20)
        self.cmb_preset.grid(row=1, column=2, columnspan=2, sticky="ew", padx=(16, 0))
        self.cmb_preset.bind("<<ComboboxSelected>>", self._on_preset_change)

        port_frame = tk.Frame(cfg, bg=BG2)
        port_frame.grid(row=1, column=4, columnspan=4, sticky="ew", padx=(16, 0))

        self.ent_start = self._dark_entry(port_frame, width=8)
        self.ent_start.insert(0, "1")
        self.ent_start.pack(side="left")
        tk.Label(port_frame, text=" → ", bg=BG2, fg=TEXT_DIM, font=FONT_MONO).pack(side="left")
        self.ent_end = self._dark_entry(port_frame, width=8)
        self.ent_end.insert(0, "1024")
        self.ent_end.pack(side="left")

        # Row 2: Options
        opt_frame = tk.Frame(cfg, bg=BG2)
        opt_frame.grid(row=2, column=0, columnspan=8, sticky="w", pady=(12, 4))

        self.var_banner = tk.BooleanVar(value=False)
        self._dark_check(opt_frame, "Grab banners", self.var_banner).pack(side="left", padx=(0, 20))

        tk.Label(opt_frame, text="Timeout (s):", bg=BG2, fg=TEXT_DIM, font=FONT_MONO_SM).pack(side="left")
        self.ent_timeout = self._dark_entry(opt_frame, width=5)
        self.ent_timeout.insert(0, "0.5")
        self.ent_timeout.pack(side="left", padx=(4, 20))

        tk.Label(opt_frame, text="Threads:", bg=BG2, fg=TEXT_DIM, font=FONT_MONO_SM).pack(side="left")
        self.ent_threads = self._dark_entry(opt_frame, width=6)
        self.ent_threads.insert(0, "500")
        self.ent_threads.pack(side="left", padx=(4, 0))

        cfg.grid_columnconfigure(1, weight=1)
        cfg.grid_columnconfigure(3, weight=1)

        # --- BUTTONS ---
        btn_bar = tk.Frame(parent, bg=BG)
        btn_bar.pack(fill="x", pady=(0, 8))

        self.btn_start = ttk.Button(btn_bar, text="▶  START SCAN",
                                     command=self.start_scan, style="Scan.TButton")
        self.btn_start.pack(side="left", padx=(0, 8))

        self.btn_stop = ttk.Button(btn_bar, text="■  STOP",
                                    command=self.stop_scan, style="Stop.TButton",
                                    state="disabled")
        self.btn_stop.pack(side="left", padx=(0, 8))

        self.btn_clear = ttk.Button(btn_bar, text="⌫  CLEAR", command=self.clear_results)
        self.btn_clear.pack(side="left", padx=(0, 8))

        self.btn_save = ttk.Button(btn_bar, text="↓  EXPORT", command=self.save_results,
                                    state="disabled")
        self.btn_save.pack(side="right")

        # --- STATUS BAR ---
        stat_bar = tk.Frame(parent, bg=BG3,
                             highlightbackground=BORDER, highlightthickness=1)
        stat_bar.pack(fill="x", pady=(0, 6))

        self.lbl_status = tk.Label(stat_bar, text="IDLE", font=FONT_MONO,
                                    bg=BG3, fg=ACCENT, width=30, anchor="w")
        self.lbl_status.pack(side="left", padx=10, pady=5)

        self.lbl_stats = tk.Label(stat_bar, text="", font=FONT_MONO_SM,
                                   bg=BG3, fg=TEXT_DIM)
        self.lbl_stats.pack(side="left", padx=4)

        self.lbl_elapsed = tk.Label(stat_bar, text="00:00.000",
                                     font=("Consolas", 10, "bold"), bg=BG3, fg=ACCENT2)
        self.lbl_elapsed.pack(side="right", padx=10, pady=5)

        self.progress = ttk.Progressbar(parent, orient="horizontal",
                                          mode="determinate",
                                          style="Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(0, 6))

        # --- RESULTS PANE ---
        pane = tk.Frame(parent, bg=BG)
        pane.pack(fill="both", expand=True)

        # Column headers
        hdr_bar = tk.Frame(pane, bg=BG3, pady=3,
                            highlightbackground=BORDER, highlightthickness=1)
        hdr_bar.pack(fill="x")
        for col, w in [("PORT", 8), ("SERVICE", 16), ("STATUS", 10), ("BANNER / NOTE", 50)]:
            tk.Label(hdr_bar, text=col, font=FONT_MONO_SM, bg=BG3,
                     fg=TEXT_DIM, width=w, anchor="w").pack(side="left", padx=6)

        # Text widget with scrollbars
        txt_frame = tk.Frame(pane, bg=BG)
        txt_frame.pack(fill="both", expand=True)

        self.txt_results = tk.Text(
            txt_frame,
            bg=BG, fg=TEXT,
            font=FONT_MONO_SM,
            insertbackground=ACCENT,
            selectbackground=BG3,
            selectforeground=ACCENT,
            relief="flat",
            wrap="none",
            padx=6, pady=4,
            state="disabled",
            cursor="arrow"
        )
        self.txt_results.pack(fill="both", expand=True, side="left")

        yscroll = tk.Scrollbar(txt_frame, orient="vertical",
                               command=self.txt_results.yview,
                               bg=BG2, troughcolor=BG, width=10)
        yscroll.pack(side="right", fill="y")
        self.txt_results.configure(yscrollcommand=yscroll.set)

        xscroll = tk.Scrollbar(pane, orient="horizontal",
                               command=self.txt_results.xview,
                               bg=BG2, troughcolor=BG, width=8)
        xscroll.pack(fill="x")
        self.txt_results.configure(xscrollcommand=xscroll.set)

        # Text tags for coloring
        self.txt_results.tag_configure("open",   foreground=GREEN_OPEN)
        self.txt_results.tag_configure("info",   foreground=ACCENT2)
        self.txt_results.tag_configure("warn",   foreground=WARN)
        self.txt_results.tag_configure("dim",    foreground=TEXT_DIM)
        self.txt_results.tag_configure("head",   foreground=ACCENT, font=FONT_HEAD)
        self.txt_results.tag_configure("banner", foreground="#c9d1d9")

    def _build_history_tab(self, parent):
        tk.Label(parent, text="Scan History", font=FONT_HEAD,
                 bg=BG, fg=ACCENT2).pack(anchor="w", padx=10, pady=(10, 4))

        self.hist_text = tk.Text(parent, bg=BG2, fg=TEXT,
                                  font=FONT_MONO_SM, relief="flat",
                                  state="disabled", wrap="none",
                                  padx=8, pady=6)
        self.hist_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.hist_text.tag_configure("head",   foreground=ACCENT)
        self.hist_text.tag_configure("open",   foreground=GREEN_OPEN)
        self.hist_text.tag_configure("dim",    foreground=TEXT_DIM)
        self.hist_text.tag_configure("info",   foreground=ACCENT2)

    # ---------------------------
    # Helpers
    # ---------------------------
    def _dark_entry(self, parent, width=20):
        e = tk.Entry(parent, width=width,
                     bg=BG3, fg=TEXT,
                     insertbackground=ACCENT,
                     relief="flat",
                     highlightbackground=BORDER,
                     highlightthickness=1,
                     font=FONT_MONO)
        e.bind("<FocusIn>",  lambda ev, w=e: w.config(highlightbackground=ACCENT))
        e.bind("<FocusOut>", lambda ev, w=e: w.config(highlightbackground=BORDER))
        return e

    def _dark_check(self, parent, text, var):
        return ttk.Checkbutton(parent, text=text, variable=var, style="TCheckbutton")

    def _tick_clock(self):
        self.lbl_time.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _print_scan_header(self, target, resolved_ip, port_display, grab_banners):
        self.append_text(self._sep(), "dim")
        self.append_text(f"  TARGET   {target}", "head")
        self.append_text(f"  ({resolved_ip})\n", "info")
        self.append_text(f"  PORTS    {port_display}\n", "head")
        self.append_text(f"  STARTED  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", "dim")
        if grab_banners:
            self.append_text(f"  BANNERS  enabled\n", "dim")
        self.append_text(self._sep(), "dim")
        self.append_text("\n", "dim")

    def _sep(self):
        """Return a full-width separator string that fills the text widget."""
        try:
            self.txt_results.update_idletasks()
            widget_width_px = self.txt_results.winfo_width() - 12  # minus padx*2
            # measure width of one char in pixels
            char_w = self.txt_results.tk.call(
                "font", "measure", str(self.txt_results.cget("font")), "="
            )
            cols = max(20, int(widget_width_px / char_w))
        except Exception:
            cols = 80
        return "=" * cols + "\n"

    def append_text(self, text, tag=""):
        self.txt_results.configure(state="normal")
        if tag:
            self.txt_results.insert(tk.END, text, tag)
        else:
            self.txt_results.insert(tk.END, text)
        self.txt_results.see(tk.END)
        self.txt_results.configure(state="disabled")

    def _hist_append(self, text, tag=""):
        self.hist_text.configure(state="normal")
        if tag:
            self.hist_text.insert(tk.END, text, tag)
        else:
            self.hist_text.insert(tk.END, text)
        self.hist_text.see(tk.END)
        self.hist_text.configure(state="disabled")

    def _on_preset_change(self, event=None):
        preset = self.var_preset.get()
        if preset == "Custom" or preset == "Top 100 Services":
            return
        r = PRESET_RANGES.get(preset)
        if r:
            self.ent_start.delete(0, tk.END)
            self.ent_end.delete(0, tk.END)
            self.ent_start.insert(0, str(r[0]))
            self.ent_end.insert(0, str(r[1]))

    # ---------------------------
    # Scan Controls
    # ---------------------------
    def start_scan(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            messagebox.showinfo("Scanner", "A scan is already running.")
            return

        target = self.ent_target.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a target IP or hostname.")
            return

        # Validate target
        resolved_ip = None
        try:
            resolved_ip = socket.gethostbyname(target)
        except socket.gaierror:
            messagebox.showerror("Resolution Error",
                f"Cannot resolve '{target}'.\nCheck the hostname or IP.")
            return

        # Parse ports
        preset = self.var_preset.get()
        if preset == "Top 100 Services":
            ports = TOP_100_PORTS
        else:
            try:
                start_port = int(self.ent_start.get().strip())
                end_port   = int(self.ent_end.get().strip())
            except ValueError:
                messagebox.showerror("Input Error", "Port range must be integers.")
                return
            if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port):
                messagebox.showerror("Input Error",
                    "Port range: 0–65535, start ≤ end.")
                return
            ports = list(range(start_port, end_port + 1))

        # Parse timeout & threads
        try:
            timeout = float(self.ent_timeout.get().strip())
            if timeout <= 0: raise ValueError
        except ValueError:
            messagebox.showerror("Input Error", "Timeout must be a positive number (e.g. 0.5).")
            return

        try:
            max_threads = int(self.ent_threads.get().strip())
            if not (1 <= max_threads <= 2000): raise ValueError
        except ValueError:
            messagebox.showerror("Input Error", "Threads: 1–2000.")
            return

        grab_banners = self.var_banner.get()

        self.scanner = PortScanner(target, ports, timeout=timeout,
                                    max_workers=max_threads,
                                    grab_banners=grab_banners)
        self.scanner.resolved_ip = resolved_ip

        # Reset UI
        self.txt_results.configure(state="normal")
        self.txt_results.delete("1.0", tk.END)
        self.txt_results.configure(state="disabled")

        port_display = (f"{ports[0]}–{ports[-1]}"
                        if preset != "Top 100 Services"
                        else f"Top {len(ports)} ports")

        self.after(50, lambda: self._print_scan_header(target, resolved_ip, port_display, grab_banners))

        self.progress.configure(maximum=max(len(ports), 1), value=0)
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_save.configure(state="disabled")
        self.lbl_status.configure(text="SCANNING", fg=ACCENT)

        self.start_time = time.time()
        self._start_elapsed()

        self.scanner_thread = threading.Thread(target=self.scanner.run, daemon=True)
        self.scanner_thread.start()
        self.after(self.poll_after_ms, self.poll_results)

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            self.lbl_status.configure(text="STOPPING…", fg=WARN)

    def clear_results(self):
        self.txt_results.configure(state="normal")
        self.txt_results.delete("1.0", tk.END)
        self.txt_results.configure(state="disabled")
        self.progress.configure(value=0)
        self.lbl_status.configure(text="IDLE", fg=ACCENT)
        self.lbl_elapsed.configure(text="00:00.000")
        self.lbl_stats.configure(text="")
        self.btn_save.configure(state="disabled")

    def save_results(self):
        if not self.scanner or not self.scanner.open_ports:
            messagebox.showinfo("Export", "No open ports to export.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Export Results",
            defaultextension=".txt",
            initialfile=f"scan_{self.scanner.target}_{int(time.time())}",
            filetypes=[
                ("Text File", "*.txt"),
                ("CSV File",  "*.csv"),
                ("JSON File", "*.json"),
                ("All Files", "*.*")
            ]
        )
        if not file_path:
            return

        sorted_ports = sorted(self.scanner.open_ports, key=lambda x: x[0])

        try:
            if file_path.endswith(".csv"):
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["Port", "Service", "Banner"])
                    for port, svc, banner in sorted_ports:
                        w.writerow([port, svc, banner])

            elif file_path.endswith(".json"):
                data = {
                    "target": self.scanner.target,
                    "resolved_ip": self.scanner.resolved_ip,
                    "scan_time": datetime.now().isoformat(),
                    "open_ports": [
                        {"port": p, "service": s, "banner": b}
                        for p, s, b in sorted_ports
                    ]
                }
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)

            else:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(f"NETSCAN // Scan Report\n")
                    f.write(f"Target  : {self.scanner.target} ({self.scanner.resolved_ip})\n")
                    f.write(f"Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"{'='*50}\n\n")
                    for port, svc, banner in sorted_ports:
                        line = f"  Port {port:<6} {svc:<18} OPEN"
                        if banner:
                            line += f"\n  Banner: {banner}"
                        f.write(line + "\n")
                    f.write(f"\n{len(sorted_ports)} open port(s) found.\n")

            messagebox.showinfo("Exported", f"Results saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    # ---------------------------
    # Elapsed Timer
    # ---------------------------
    def _start_elapsed(self):
        if self._elapsed_after:
            self.after_cancel(self._elapsed_after)
        self._update_elapsed()

    def _update_elapsed(self):
        if self.start_time:
            elapsed = time.time() - self.start_time
            mins = int(elapsed // 60)
            secs = elapsed % 60
            self.lbl_elapsed.configure(text=f"{mins:02d}:{secs:06.3f}")
            self._elapsed_after = self.after(50, self._update_elapsed)

    # ---------------------------
    # Result Polling
    # ---------------------------
    def poll_results(self):
        if not self.scanner:
            return
        try:
            while True:
                msg = self.scanner.result_queue.get_nowait()
                msg_type = msg[0]

                if msg_type == 'open':
                    _, port, service, banner = msg
                    line = f"  {port:<7} {service:<18} OPEN"
                    self.append_text(line, "open")
                    if banner:
                        self.append_text(f"\n  {'':>25}↳ {banner}", "banner")
                    self.append_text("\n")

                elif msg_type == 'progress':
                    _, scanned, total = msg
                    self.progress.configure(value=scanned)
                    open_so_far = len(self.scanner.open_ports)
                    pct = (scanned / total * 100) if total else 0
                    self.lbl_status.configure(
                        text=f"SCANNING  {scanned}/{total}  ({pct:.0f}%)",
                        fg=ACCENT
                    )
                    self.lbl_stats.configure(
                        text=f"│  {open_so_far} open",
                        fg=GREEN_OPEN if open_so_far else TEXT_DIM
                    )

                elif msg_type == 'done':
                    self._scan_complete()
                    return

        except queue.Empty:
            pass

        if self.scanner_thread and self.scanner_thread.is_alive():
            self.after(self.poll_after_ms, self.poll_results)
        else:
            self._scan_complete()

    def _scan_complete(self):
        if self.start_time:
            elapsed = time.time() - self.start_time
        else:
            elapsed = 0
        self.start_time = None

        total_open = len(self.scanner.open_ports) if self.scanner else 0
        was_stopped = self.scanner and self.scanner._stop_event.is_set()

        status_text = "STOPPED" if was_stopped else "COMPLETE"
        self.lbl_status.configure(text=status_text,
                                   fg=WARN if was_stopped else GREEN_OPEN)
        self.lbl_stats.configure(
            text=f"│  {total_open} open port(s)",
            fg=GREEN_OPEN if total_open else TEXT_DIM
        )

        mins = int(elapsed // 60)
        secs = elapsed % 60

        self.append_text(f"\n", "dim")
        self.append_text(self._sep(), "dim")
        self.append_text(f"  {'STOPPED' if was_stopped else 'SCAN COMPLETE'}\n", "warn" if was_stopped else "open")
        self.append_text(f"  Open ports : {total_open}\n", "info")
        self.append_text(f"  Duration   : {mins:02d}:{secs:06.3f}\n", "dim")
        self.append_text(self._sep(), "dim")

        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.btn_save.configure(state="normal" if total_open else "disabled")

        # Log to history
        if self.scanner:
            self._add_to_history(elapsed, was_stopped)

    def _add_to_history(self, elapsed, was_stopped):
        ts = datetime.now().strftime("%H:%M:%S")
        target = self.scanner.target
        ip = self.scanner.resolved_ip or ""
        total = len(self.scanner.ports)
        opens = len(self.scanner.open_ports)
        status = "STOPPED" if was_stopped else "OK"
        mins = int(elapsed // 60)
        secs = elapsed % 60

        self._hist_append(f"\n[{ts}]  ", "dim")
        self._hist_append(f"{target}", "head")
        self._hist_append(f"  ({ip})\n", "dim")
        self._hist_append(f"  {total} ports scanned  │  ", "dim")
        self._hist_append(f"{opens} open", "open")
        self._hist_append(f"  │  {mins:02d}:{secs:06.3f}  │  {status}\n", "dim")

        if opens:
            for port, svc, _ in sorted(self.scanner.open_ports, key=lambda x: x[0]):
                self._hist_append(f"    :{port}  {svc}\n", "info")

        self._hist_append(f"  {'─'*60}\n", "dim")

# ---------------------------
# Entry Point
# ---------------------------
def main():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-10), 7)
        except Exception:
            pass

    app = ScannerGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
