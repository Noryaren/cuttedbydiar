"""Tkinter Desktop GUI for cuttedbydiar (Cross-platform: Windows & Linux).

Features:
  - Scan button (ARP scan + gateway detection)
  - Device table: IP, MAC, Hostname, Whitelist status, Block status
  - Whitelist toggle / Add / Remove
  - Block / Unblock controls
  - Live log panel
"""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .network import BlockEngine, get_gateway, scan_devices
from .utils import require_admin
from .whitelist import Whitelist


class CuttedByDiarApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("cuttedbydiar - LAN Device Controller")
        self.root.geometry("900x600")
        self.root.minsize(750, 500)

        self.whitelist = Whitelist()
        self.devices: list = []
        self.engine: BlockEngine | None = None
        self.is_blocking = False

        self._build_ui()
        self.log("Ready. Click 'Scan Network' to begin.")

    def _build_ui(self):
        # Top Frame - Controls
        top_frame = ttk.LabelFrame(self.root, text=" Control Panel ", padding=10)
        top_frame.pack(fill=tk.X, padx=10, pady=10)

        self.btn_scan = ttk.Button(top_frame, text="🔍 Scan Network", command=self.on_scan)
        self.btn_scan.pack(side=tk.LEFT, padx=5)

        self.btn_block = ttk.Button(top_frame, text="🚫 Block Selected", command=self.on_block_selected, state=tk.DISABLED)
        self.btn_block.pack(side=tk.LEFT, padx=5)

        self.btn_unblock = ttk.Button(top_frame, text="🟢 Unblock All", command=self.on_unblock_all, state=tk.DISABLED)
        self.btn_unblock.pack(side=tk.LEFT, padx=5)

        self.lbl_gw = ttk.Label(top_frame, text="Gateway: Not scanned", font=("Arial", 9, "italic"))
        self.lbl_gw.pack(side=tk.RIGHT, padx=5)

        # Middle Frame - Device Table
        table_frame = ttk.LabelFrame(self.root, text=" Discovered Devices ", padding=10)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = ("ip", "mac", "hostname", "whitelist", "status")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="extended")

        self.tree.heading("ip", text="IP Address")
        self.tree.heading("mac", text="MAC Address")
        self.tree.heading("hostname", text="Hostname")
        self.tree.heading("whitelist", text="Whitelist")
        self.tree.heading("status", text="Status")

        self.tree.column("ip", width=130, anchor=tk.W)
        self.tree.column("mac", width=150, anchor=tk.W)
        self.tree.column("hostname", width=220, anchor=tk.W)
        self.tree.column("whitelist", width=90, anchor=tk.CENTER)
        self.tree.column("status", width=110, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", self.on_toggle_whitelist_click)

        # Bottom Frame - Log Panel
        log_frame = ttk.LabelFrame(self.root, text=" Activity Log ", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=10)

        self.log_text = tk.Text(log_frame, height=7, wrap=tk.WORD, bg="#1e1e1e", fg="#dcdcdc", font=("Consolas", 9))
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def log(self, msg: str):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def on_scan(self):
        self.btn_scan.config(state=tk.DISABLED)
        self.log("Checking administrator privileges...")

        try:
            require_admin()
        except PermissionError as exc:
            messagebox.showerror("Permission Error", str(exc))
            self.log(f"Error: {exc}")
            self.btn_scan.config(state=tk.NORMAL)
            return

        if self.engine:
            self.engine.stop()
            self.engine = None

        self.log("Scanning local network for devices...")

        def worker():
            try:
                from .network import _local_iface
                iface, own_mac = _local_iface()
                gw_ip, gw_mac = get_gateway(iface)
                devices = scan_devices(iface)
            except Exception as exc:
                self.root.after(0, lambda: messagebox.showerror("Scan Failed", str(exc)))
                self.root.after(0, lambda: self.log(f"Scan failed: {exc}"))
                self.root.after(0, lambda: self.btn_scan.config(state=tk.NORMAL))
                return

            def update_ui():
                self.tree.delete(*self.tree.get_children())
                self.devices = devices
                for dev in devices:
                    wl = self.whitelist.is_whitelisted(dev.mac)
                    wl_str = "Yes ⭐" if wl else "No"
                    status = "Whitelisted" if wl else "Online"
                    self.tree.insert("", tk.END, values=(dev.ip, dev.mac, dev.hostname, wl_str, status))

                self.lbl_gw.config(text=f"Gateway: {gw_ip} ({gw_mac})")
                self.log(f"Scan complete. Found {len(devices)} device(s). Gateway: {gw_ip}")
                self.btn_scan.config(state=tk.NORMAL)
                self.btn_block.config(state=tk.NORMAL)
                self.btn_unblock.config(state=tk.NORMAL)

                # Initialize engine
                self.engine = BlockEngine(
                    gateway_ip=gw_ip,
                    gateway_mac=gw_mac,
                    iface_name=iface,
                    whitelist=self.whitelist,
                    on_event=lambda msg: self.root.after(0, lambda: self.log(msg)),
                )

            self.root.after(0, update_ui)

        threading.Thread(target=worker, daemon=True).start()

    def on_toggle_whitelist_click(self, event):
        item_id = self.tree.identify_row(event.y)
        if not item_id:
            return
        item = self.tree.item(item_id)
        values = item["values"]
        if not values:
            return

        ip, mac, hostname, wl_str, status = values
        current_wl = self.whitelist.is_whitelisted(mac)

        if current_wl:
            self.whitelist.remove(mac)
            new_wl_str = "No"
            new_status = "Online"
            self.log(f"Removed {mac} ({ip}) from whitelist.")
        else:
            self.whitelist.add(mac)
            new_wl_str = "Yes ⭐"
            new_status = "Whitelisted"
            self.log(f"Added {mac} ({ip}) to whitelist.")

        self.tree.item(item_id, values=(ip, mac, hostname, new_wl_str, new_status))

    def on_block_selected(self):
        if not self.engine:
            messagebox.showwarning("Warning", "Please scan the network first.")
            return

        selected_items = self.tree.selection()
        if not selected_items:
            # Block all non-whitelisted if none selected
            selected_items = self.tree.get_children()

        count = 0
        for item_id in selected_items:
            values = self.tree.item(item_id)["values"]
            ip, mac, hostname, wl_str, status = values
            if self.whitelist.is_whitelisted(mac):
                self.log(f"Skipping {ip} ({mac}) — Protected by Whitelist.")
                continue

            self.engine.block(ip, mac)
            self.tree.item(item_id, values=(ip, mac, hostname, wl_str, "Blocked 🚫"))
            count += 1

        self.log(f"Started blocking {count} device(s).")
        self.is_blocking = True

    def on_unblock_all(self):
        if self.engine:
            self.engine.unblock_all()
        for item_id in self.tree.get_children():
            values = self.tree.item(item_id)["values"]
            ip, mac, hostname, wl_str, _ = values
            status = "Whitelisted" if "Yes" in wl_str else "Online"
            self.tree.item(item_id, values=(ip, mac, hostname, wl_str, status))
        self.log("All devices unblocked.")
        self.is_blocking = False


def main():
    root = tk.Tk()
    app = CuttedByDiarApp(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.engine and app.engine.stop(), root.destroy()))
    root.mainloop()


if __name__ == "__main__":
    main()
