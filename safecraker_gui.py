
#!/usr/bin/env python3
"""
SafeCraker GUI (Blue Team Edition) - Python 3.9+

Requires: Tkinter (usually included with Python on Linux).
"""

import json
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path


class SafeCrakerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SafeCraker (Blue Team Edition) - SSH Exposure Scanner")
        self.geometry("980x600")

        self.proc = None
        self.reader_thread = None
        self.q = queue.Queue()
        self.running = False

        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Target (-H):").grid(row=0, column=0, sticky="w")
        self.target_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(top, textvariable=self.target_var, width=35).grid(row=0, column=1, padx=6)

        ttk.Label(top, text="Targets file:").grid(row=0, column=2, sticky="w")
        self.targets_file_var = tk.StringVar(value="")
        ttk.Entry(top, textvariable=self.targets_file_var, width=35).grid(row=0, column=3, padx=6)
        ttk.Button(top, text="Browse", command=self._browse_targets).grid(row=0, column=4, padx=6)

        ttk.Label(top, text="Ports (-p):").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.ports_var = tk.StringVar(value="22")
        ttk.Entry(top, textvariable=self.ports_var, width=35).grid(row=1, column=1, padx=6, pady=(8, 0))

        ttk.Label(top, text="Threads (-T):").grid(row=1, column=2, sticky="w", pady=(8, 0))
        self.threads_var = tk.StringVar(value="64")
        ttk.Entry(top, textvariable=self.threads_var, width=10).grid(row=1, column=3, sticky="w", padx=6, pady=(8, 0))

        ttk.Label(top, text="Timeout:").grid(row=1, column=3, sticky="e", padx=(0, 60), pady=(8, 0))
        self.timeout_var = tk.StringVar(value="3.0")
        ttk.Entry(top, textvariable=self.timeout_var, width=10).grid(row=1, column=4, sticky="w", padx=6, pady=(8, 0))

        self.open_only_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Open only", variable=self.open_only_var).grid(row=2, column=0, sticky="w", pady=(10, 0))

        ttk.Label(top, text="Report output (JSON):").grid(row=2, column=1, sticky="w", pady=(10, 0))
        self.out_var = tk.StringVar(value=str(Path.cwd() / "report.json"))
        ttk.Entry(top, textvariable=self.out_var, width=55).grid(row=2, column=2, columnspan=2, sticky="w", pady=(10, 0))
        ttk.Button(top, text="Save As", command=self._browse_output).grid(row=2, column=4, padx=6, pady=(10, 0))

        btns = ttk.Frame(self, padding=(10, 0, 10, 10))
        btns.pack(fill="x")

        self.start_btn = ttk.Button(btns, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side="left")

        self.stop_btn = ttk.Button(btns, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=8)

        self.clear_btn = ttk.Button(btns, text="Clear Output", command=self.clear_output)
        self.clear_btn.pack(side="left", padx=8)

        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(btns, textvariable=self.status_var).pack(side="right")

        mid = ttk.Frame(self, padding=10)
        mid.pack(fill="both", expand=True)

        self.text = tk.Text(mid, wrap="none")
        self.text.pack(fill="both", expand=True)

        self.after(100, self._drain_queue)

    def _browse_targets(self):
        path = filedialog.askopenfilename(title="Select targets file", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.targets_file_var.set(path)

    def _browse_output(self):
        path = filedialog.asksaveasfilename(title="Save report as", defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            self.out_var.set(path)

    def clear_output(self):
        self.text.delete("1.0", "end")

    def start_scan(self):
        if self.running:
            return

        script = Path(__file__).with_name("SafeCraker-1.py")
        if not script.exists():
            messagebox.showerror("Missing file", "SafeCraker-1.py must be in the same folder as safecraker_gui.py")
            return

        cmd = [sys.executable, str(script)]

        target = self.target_var.get().strip()
        targets_file = self.targets_file_var.get().strip()
        ports = self.ports_var.get().strip()
        threads = self.threads_var.get().strip()
        timeout = self.timeout_var.get().strip()
        out = self.out_var.get().strip()

        if target:
            cmd += ["-H", target]
        if targets_file:
            cmd += ["--targets-file", targets_file]
        if ports:
            cmd += ["-p", ports]
        if threads:
            cmd += ["-T", threads]
        if timeout:
            cmd += ["--timeout", timeout]
        if self.open_only_var.get():
            cmd += ["--open-only"]
        if out:
            cmd += ["-o", out]

        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        except Exception as e:
            messagebox.showerror("Failed to start", str(e))
            return

        self.running = True
        self.status_var.set("Running...")
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

        self.reader_thread = threading.Thread(target=self._reader, daemon=True)
        self.reader_thread.start()

    def stop_scan(self):
        if self.proc and self.running:
            try:
                self.proc.terminate()
            except Exception:
                pass

    def _reader(self):
        try:
            for line in self.proc.stdout:
                self.q.put(line)
        finally:
            self.q.put("__SAFECRAKER_DONE__")

    def _drain_queue(self):
        try:
            while True:
                item = self.q.get_nowait()
                if item == "__SAFECRAKER_DONE__":
                    self._on_done()
                    break
                self.text.insert("end", item)
                self.text.see("end")
        except queue.Empty:
            pass

        self.after(100, self._drain_queue)

    def _on_done(self):
        self.running = False
        self.status_var.set("Idle")
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.proc = None


if __name__ == "__main__":
    app = SafeCrakerGUI()
    app.mainloop()
