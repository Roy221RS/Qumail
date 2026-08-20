import os
import threading
import queue
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import customtkinter as ctk

from config import Config
from emailEngine import send_email, fetch_inbox, EmailMessage, EmailAttachment
from kmAdapter import MockKMAdapter

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

SECURITY_LEVELS = {
    "Level 1: Standard (No Quantum)": 1,
    "Level 2: Quantum-Aided AES (Placeholder)": 2,
    "Level 3: Quantum Secure OTP (Placeholder)": 3,
}


class QuMailApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("QuMail - Quantum Secure Client")
        self.geometry("1100x680")

        self.config_mgr = Config()
        self.km_adapter = MockKMAdapter()

        # Queues for background-thread -> main-thread communication.
        # One per operation type keeps polling logic simple.
        self.send_queue: "queue.Queue" = queue.Queue()
        self.fetch_queue: "queue.Queue" = queue.Queue()

        self.attachment_paths: list[str] = []

        self._build_layout()
        self._show_view("inbox")

        # Kick off polling loops - these run forever, checking queues every
        # 100ms. Harmless / near-zero cost when queues are empty.
        self.after(100, self._poll_send_queue)
        self.after(100, self._poll_fetch_queue)

    # ------------------------------------------------------------------ #
    # Layout scaffolding
    # ------------------------------------------------------------------ #
    def _build_layout(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()

        # Container that holds all views stacked on top of each other;
        # we raise the one we want with tkraise() instead of destroying
        # and rebuilding widgets on every nav click.
        self.content_container = ctk.CTkFrame(self, fg_color="transparent")
        self.content_container.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.content_container.grid_rowconfigure(0, weight=1)
        self.content_container.grid_columnconfigure(0, weight=1)

        self.views: dict[str, ctk.CTkFrame] = {}
        for name, builder in (
            ("compose", self._build_compose_view),
            ("inbox", self._build_inbox_view),
            ("settings", self._build_settings_view),
        ):
            frame = builder(self.content_container)
            frame.grid(row=0, column=0, sticky="nsew")
            self.views[name] = frame

    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsw")
        sidebar.grid_propagate(False)

        ctk.CTkLabel(
            sidebar, text="QuMail", font=ctk.CTkFont(size=22, weight="bold")
        ).pack(pady=(24, 0), padx=20, anchor="w")
        ctk.CTkLabel(
            sidebar, text="Quantum Secure Client", font=ctk.CTkFont(size=12),
            text_color="gray60",
        ).pack(pady=(0, 24), padx=20, anchor="w")

        for label, view in (("Compose", "compose"), ("Inbox", "inbox"), ("Settings", "settings")):
            ctk.CTkButton(
                sidebar, text=label, anchor="w",
                command=lambda v=view: self._show_view(v),
            ).pack(fill="x", padx=16, pady=6)

        # --- QKD Key Bank Status - now wired to real km_adapter.py data ---
        key_bank_frame = ctk.CTkFrame(sidebar)
        key_bank_frame.pack(side="bottom", fill="x", padx=16, pady=20)

        ctk.CTkLabel(
            key_bank_frame, text="Local Key Manager", font=ctk.CTkFont(size=12, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 2))
        self.key_bank_status_label = ctk.CTkLabel(
            key_bank_frame, text="Status: Ready", text_color="gray60", font=ctk.CTkFont(size=11)
        )
        self.key_bank_status_label.pack(anchor="w", padx=10)

        self.key_bank_progress = ctk.CTkProgressBar(key_bank_frame)
        self.key_bank_progress.pack(fill="x", padx=10, pady=(8, 2))

        self.key_bank_count_label = ctk.CTkLabel(
            key_bank_frame, text="", font=ctk.CTkFont(size=11), text_color="gray60",
        )
        self.key_bank_count_label.pack(anchor="w", padx=10, pady=(0, 10))

        self._refresh_key_bank_widget()  # populate with real numbers immediately

    def _refresh_key_bank_widget(self):
        """Pull real numbers from km_adapter and update the sidebar widget.
        Call this after any operation that consumes a key (currently none
        do yet, since crypto Phase 2 hasn't landed - but Settings/Send will
        call this once L2/L3 actually fetch keys)."""
        status = self.km_adapter.get_status()
        total = status["total_keys"]
        available = status["available_keys"]

        self.key_bank_progress.set(available / total if total else 0)
        self.key_bank_count_label.configure(text=f"{available} / {total} Keys Available")

        if available == 0:
            self.key_bank_status_label.configure(text="Status: Exhausted", text_color="red")
        elif available < total * 0.2:
            self.key_bank_status_label.configure(text="Status: Low", text_color="orange")
        else:
            self.key_bank_status_label.configure(text="Status: Ready", text_color="gray60")

    def _show_view(self, name: str):
        self.views[name].tkraise()
        if name == "inbox" and not getattr(self, "_inbox_loaded_once", False):
            # auto-load inbox first time the view is shown
            self._inbox_loaded_once = True
            self._refresh_inbox()

    # ------------------------------------------------------------------ #
    # Compose view
    # ------------------------------------------------------------------ #
    def _build_compose_view(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(frame, text="Compose", font=ctk.CTkFont(size=18, weight="bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 12)
        )

        self.to_entry = ctk.CTkEntry(frame, placeholder_text="To")
        self.to_entry.grid(row=1, column=0, sticky="ew", pady=4)

        self.subject_entry = ctk.CTkEntry(frame, placeholder_text="Subject")
        self.subject_entry.grid(row=2, column=0, sticky="ew", pady=4)

        self.body_text = ctk.CTkTextbox(frame, height=260)
        self.body_text.grid(row=3, column=0, sticky="nsew", pady=4)
        frame.grid_rowconfigure(3, weight=1)

        # --- Attachments ---
        attach_row = ctk.CTkFrame(frame, fg_color="transparent")
        attach_row.grid(row=4, column=0, sticky="ew", pady=(8, 4))
        ctk.CTkButton(attach_row, text="+ Attach File", width=120, command=self._browse_attachment).pack(side="left")
        self.attachment_label = ctk.CTkLabel(attach_row, text="No files attached", text_color="gray60")
        self.attachment_label.pack(side="left", padx=12)

        # --- Security level selector ---
        ctk.CTkLabel(frame, text="Security Level", font=ctk.CTkFont(size=13, weight="bold")).grid(
            row=5, column=0, sticky="w", pady=(12, 4)
        )
        self.security_var = tk.StringVar(value="Level 1: Standard (No Quantum)")
        sec_frame = ctk.CTkFrame(frame, fg_color="transparent")
        sec_frame.grid(row=6, column=0, sticky="w")
        for label in SECURITY_LEVELS:
            ctk.CTkRadioButton(
                sec_frame, text=label, variable=self.security_var, value=label
            ).pack(anchor="w", pady=2)
        # NOTE: Level 2/3 are selectable in the UI but CryptoAdapter raises
        # NotImplementedError for them until Phase 2 - _send_clicked()
        # catches that and shows a clear error toast rather than crashing.

        # --- Send button + status ---
        send_row = ctk.CTkFrame(frame, fg_color="transparent")
        send_row.grid(row=7, column=0, sticky="ew", pady=(16, 0))
        self.send_button = ctk.CTkButton(send_row, text="Send Mail", command=self._send_clicked)
        self.send_button.pack(side="left")
        self.send_status_label = ctk.CTkLabel(send_row, text="", text_color="gray60")
        self.send_status_label.pack(side="left", padx=12)

        return frame

    def _browse_attachment(self):
        paths = filedialog.askopenfilenames(title="Select file(s) to attach")
        if paths:
            self.attachment_paths = list(paths)
            names = ", ".join(os.path.basename(p) for p in self.attachment_paths)
            self.attachment_label.configure(text=names)

    def _send_clicked(self):
        to_address = self.to_entry.get().strip()
        subject = self.subject_entry.get().strip()
        body = self.body_text.get("1.0", "end").strip()

        if not to_address:
            messagebox.showwarning("Missing recipient", "Please enter a recipient address.")
            return
        if not self.config_mgr.is_configured():
            messagebox.showwarning(
                "Not configured", "Please fill in your email settings in Settings first."
            )
            return

        level = SECURITY_LEVELS[self.security_var.get()]

        self.send_button.configure(state="disabled")
        self.send_status_label.configure(text="Sending...", text_color="gray60")

        # Background thread: I/O only, no widget access.
        thread = threading.Thread(
            target=self._send_worker,
            args=(to_address, subject, body, list(self.attachment_paths), level),
            daemon=True,
        )
        thread.start()

    def _send_worker(self, to_address, subject, body, attachment_paths, level):
        """Runs on a background thread. Never touch widgets here."""
        try:
            send_email(
                self.config_mgr.data,
                to_address=to_address,
                subject=subject,
                body=body,
                attachment_paths=attachment_paths,
                security_level=level,
                km_adapter=self.km_adapter,
            )
            self.send_queue.put(("ok", None))
        except Exception as e:  # noqa: BLE001 - surface any failure to the UI
            self.send_queue.put(("error", str(e)))

    def _poll_send_queue(self):
        """Runs on the main thread via .after() - safe to touch widgets here."""
        try:
            status, payload = self.send_queue.get_nowait()
        except queue.Empty:
            pass
        else:
            self.send_button.configure(state="normal")
            if status == "ok":
                self.send_status_label.configure(text="Sent successfully", text_color="green")
                self.to_entry.delete(0, "end")
                self.subject_entry.delete(0, "end")
                self.body_text.delete("1.0", "end")
                self.attachment_paths = []
                self.attachment_label.configure(text="No files attached")
                self._refresh_key_bank_widget()  # L2/L3 sends consume a key
            else:
                self.send_status_label.configure(text="Send failed", text_color="red")
                messagebox.showerror("Send failed", payload)
        finally:
            self.after(100, self._poll_send_queue)

    # ------------------------------------------------------------------ #
    # Inbox view
    # ------------------------------------------------------------------ #
    def _build_inbox_view(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)

        header_row = ctk.CTkFrame(frame, fg_color="transparent")
        header_row.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ctk.CTkLabel(header_row, text="Inbox", font=ctk.CTkFont(size=18, weight="bold")).pack(side="left")
        self.refresh_button = ctk.CTkButton(
            header_row, text="Refresh Inbox", width=130, command=self._refresh_inbox
        )
        self.refresh_button.pack(side="right")
        self.inbox_status_label = ctk.CTkLabel(header_row, text="", text_color="gray60")
        self.inbox_status_label.pack(side="right", padx=12)

        # --- Treeview table (themed to roughly match dark mode) ---
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Treeview", background="#2b2b2b", foreground="white",
            fieldbackground="#2b2b2b", rowheight=26, borderwidth=0,
        )
        style.configure("Treeview.Heading", background="#1f1f1f", foreground="white")
        style.map("Treeview", background=[("selected", "#1f6aa5")])

        columns = ("level", "sender", "subject", "date")
        self.inbox_tree = ttk.Treeview(frame, columns=columns, show="headings", height=12)
        self.inbox_tree.heading("level", text="Status")
        self.inbox_tree.heading("sender", text="Sender")
        self.inbox_tree.heading("subject", text="Subject")
        self.inbox_tree.heading("date", text="Date")
        self.inbox_tree.column("level", width=90, anchor="center")
        self.inbox_tree.column("sender", width=200)
        self.inbox_tree.column("subject", width=320)
        self.inbox_tree.column("date", width=180)
        self.inbox_tree.grid(row=1, column=0, sticky="ew")
        self.inbox_tree.bind("<<TreeviewSelect>>", self._on_inbox_select)

        # keep parsed EmailMessage objects indexed by Treeview item id
        self._inbox_items: dict[str, EmailMessage] = {}

        # --- Attachments strip (Save button per attachment, populated on select) ---
        self.attachments_frame = ctk.CTkFrame(frame, fg_color="transparent")
        self.attachments_frame.grid(row=2, column=0, sticky="ew", pady=(12, 0))

        # --- Reading pane ---
        self.reading_pane = ctk.CTkTextbox(frame)
        self.reading_pane.grid(row=3, column=0, sticky="nsew", pady=(8, 0))
        self.reading_pane.configure(state="disabled")
        frame.grid_rowconfigure(3, weight=1)

        return frame

    def _refresh_inbox(self):
        self.refresh_button.configure(state="disabled")
        self.inbox_status_label.configure(text="Loading...", text_color="gray60")

        if not self.config_mgr.is_configured():
            self.refresh_button.configure(state="normal")
            self.inbox_status_label.configure(text="Not configured", text_color="red")
            return

        thread = threading.Thread(target=self._fetch_worker, daemon=True)
        thread.start()

    def _fetch_worker(self):
        """Runs on a background thread. Never touch widgets here."""
        try:
            messages = fetch_inbox(
                self.config_mgr.data, max_emails=15, km_adapter=self.km_adapter
            )
            self.fetch_queue.put(("ok", messages))
        except Exception as e:  # noqa: BLE001
            self.fetch_queue.put(("error", str(e)))

    def _poll_fetch_queue(self):
        """Runs on the main thread via .after() - safe to touch widgets here."""
        try:
            status, payload = self.fetch_queue.get_nowait()
        except queue.Empty:
            pass
        else:
            self.refresh_button.configure(state="normal")
            if status == "ok":
                self._populate_inbox(payload)
                self.inbox_status_label.configure(
                    text=f"{len(payload)} messages", text_color="gray60"
                )
                self._refresh_key_bank_widget()  # decrypting L2/L3 mail also consumes a key
            else:
                self.inbox_status_label.configure(text="Failed to load", text_color="red")
                messagebox.showerror("Inbox fetch failed", payload)
        finally:
            self.after(100, self._poll_fetch_queue)

    def _populate_inbox(self, messages: list[EmailMessage]):
        self.inbox_tree.delete(*self.inbox_tree.get_children())
        self._inbox_items.clear()

        for msg in messages:
            tag = "Standard" if msg.security_level == 1 else f"L{msg.security_level}"
            item_id = self.inbox_tree.insert(
                "", "end", values=(tag, msg.sender, msg.subject, msg.date)
            )
            self._inbox_items[item_id] = msg

    def _on_inbox_select(self, _event):
        selection = self.inbox_tree.selection()
        if not selection:
            return
        msg = self._inbox_items.get(selection[0])
        if not msg:
            return

        # --- rebuild attachments strip for this email ---
        for child in self.attachments_frame.winfo_children():
            child.destroy()

        if msg.attachments:
            ctk.CTkLabel(
                self.attachments_frame, text="Attachments:", text_color="gray60"
            ).pack(side="left", padx=(0, 8))
            for att in msg.attachments:
                self._add_attachment_chip(att)

        # --- reading pane: header + body only, no attachment names inline ---
        self.reading_pane.configure(state="normal")
        self.reading_pane.delete("1.0", "end")
        header = f"From: {msg.sender}\nSubject: {msg.subject}\nDate: {msg.date}\n"
        header += "\n" + "-" * 60 + "\n\n"
        self.reading_pane.insert("1.0", header + msg.body)
        self.reading_pane.configure(state="disabled")

    def _add_attachment_chip(self, att: EmailAttachment):
        """One small pill per attachment: filename + Save button."""
        chip = ctk.CTkFrame(self.attachments_frame, fg_color="#2b2b2b")
        chip.pack(side="left", padx=4)
        ctk.CTkLabel(chip, text=att.filename, font=ctk.CTkFont(size=12)).pack(
            side="left", padx=(10, 6), pady=4
        )
        ctk.CTkButton(
            chip, text="Save", width=54, height=24,
            command=lambda a=att: self._save_attachment(a),
        ).pack(side="left", padx=(0, 6), pady=4)

    def _save_attachment(self, att: EmailAttachment):
        if not att.data:
            messagebox.showwarning(
                "Empty attachment", f"'{att.filename}' has no data to save."
            )
            return
        dest = filedialog.asksaveasfilename(
            initialfile=att.filename,
            title="Save attachment as",
        )
        if not dest:
            return
        try:
            with open(dest, "wb") as f:
                f.write(att.data)
        except OSError as e:
            messagebox.showerror("Save failed", str(e))
        else:
            messagebox.showinfo("Saved", f"Saved to {dest}")

    # ------------------------------------------------------------------ #
    # Settings view
    # ------------------------------------------------------------------ #
    def _build_settings_view(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(frame, text="Settings", font=ctk.CTkFont(size=18, weight="bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 16)
        )

        fields = [
            ("user_name", "Your Name"),
            ("email_address", "Email Address"),
            ("smtp_host", "SMTP Host"),
            ("smtp_port", "SMTP Port"),
            ("imap_host", "IMAP Host"),
            ("imap_port", "IMAP Port"),
            ("app_password", "App Password"),
        ]
        self.settings_entries: dict[str, ctk.CTkEntry] = {}

        row = 1
        for key, label in fields:
            ctk.CTkLabel(frame, text=label).grid(row=row, column=0, sticky="w", pady=(10, 2))
            row += 1
            show = "*" if key == "app_password" else ""
            entry = ctk.CTkEntry(frame, show=show)
            entry.grid(row=row, column=0, sticky="ew")
            entry.insert(0, str(self.config_mgr.get(key, "")))
            self.settings_entries[key] = entry
            row += 1

        ctk.CTkButton(frame, text="Save Settings", command=self._save_settings).grid(
            row=row, column=0, sticky="w", pady=20
        )
        row += 1
        self.settings_status_label = ctk.CTkLabel(frame, text="", text_color="gray60")
        self.settings_status_label.grid(row=row, column=0, sticky="w")

        return frame

    def _save_settings(self):
        for key, entry in self.settings_entries.items():
            value = entry.get().strip()
            if key in ("smtp_port", "imap_port"):
                try:
                    value = int(value)
                except ValueError:
                    self.settings_status_label.configure(
                        text=f"{key} must be a number", text_color="red"
                    )
                    return
            self.config_mgr.set(key, value)

        self.config_mgr.save()
        self.settings_status_label.configure(text="Saved", text_color="green")