import json
import os

configPath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

DEFAULT_CONFIG = {
    "user_name": "",
    "email_address": "",
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 465,
    "imap_host": "imap.gmail.com",
    "imap_port": 993,
    "app_password": "",
}

class Config:
    """Load config from disk. If the file doesn't exist yet, fall back
        to defaults (first-run scenario) — caller should then prompt the
        user via the Settings view and call save()."""

    def __init__(self, path: str = configPath):
        self.path = path
        self.data = dict(DEFAULT_CONFIG)
        self.load()

    def load(self) -> dict:
        """Load config from disk. If the file doesn't exist yet, fall back
        to defaults (first-run scenario) — caller should then prompt the
        user via the Settings view and call save()."""
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    on_disk = json.load(f)
                # merge with defaults so new keys added later don't break
                # configs saved by an older version of the app
                self.data = {**DEFAULT_CONFIG, **on_disk}
            except (json.JSONDecodeError, OSError):
                # corrupted config file - don't crash, just fall back
                self.data = dict(DEFAULT_CONFIG)
        return self.data

    def save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)

    def is_configured(self) -> bool:
        """True once the minimum fields needed to send/receive are set."""
        required = ("email_address", "smtp_host", "imap_host", "app_password")
        return all(self.data.get(k) for k in required)

    # convenience accessors -------------------------------------------------
    def get(self, key: str, default=None):
        return self.data.get(key, default)
 
    def set(self, key: str, value) -> None:
        self.data[key] = value
 
    def update(self, **kwargs) -> None:
        self.data.update(kwargs)
