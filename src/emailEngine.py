"""
email_engine.py

Core protocol engine for QuMail:
- send_email(): builds a MIME message and sends over SMTP+SSL
- fetch_inbox(): pulls recent messages over IMAP+SSL, parses headers/body

Both functions are synchronous / blocking on purpose — the GUI layer is
responsible for running these on a background thread (see gui_app.py) and
must NEVER touch CTk widgets directly from that thread. Push results into
a queue.Queue and poll it from the main thread via .after().

Security metadata:
QuMail attaches two custom headers so the receiver knows how a message was
protected and which quantum key to re-fetch from its own local KM:
    X-QuMail-Level   -> "1" | "2" | "3"
    X-QuMail-KeyID   -> key identifier string, or "" for Level 1

In Phase 1, CryptoAdapter is a passthrough (Level 1 only), so these headers
are always ("1", "") - but fetch_inbox parses them now so the Inbox UI's
status-tag column is driven by real header data from day one, instead of
being hardcoded and needing rework in Phase 2.
"""

import smtplib
import imaplib
import email
import os
from dataclasses import dataclass, field
from email.message import EmailMessage as MimeEmailMessage
from email.header import decode_header
from typing import Optional, List, Dict, Any

from crypto_adapter import CryptoAdapter

HEADER_LEVEL = "X-QuMail-Level"
HEADER_KEYID = "X-QuMail-KeyID"


@dataclass
class EmailMessage:
    """Structured representation of a fetched email, for GUI consumption."""
    uid: str
    sender: str
    subject: str
    date: str
    body: str
    security_level: int = 1
    key_id: Optional[str] = None
    attachments: List[str] = field(default_factory=list)  # filenames only, Phase 1


def _decode_mime_words(s: str) -> str:
    """Decode possibly-encoded email header (e.g. '=?UTF-8?B?...?=') into a
    plain string."""
    if not s:
        return ""
    parts = decode_header(s)
    decoded = ""
    for text, enc in parts:
        if isinstance(text, bytes):
            decoded += text.decode(enc or "utf-8", errors="replace")
        else:
            decoded += text
    return decoded


def send_email(
    config: Dict[str, Any],
    to_address: str,
    subject: str,
    body: str,
    attachment_paths: Optional[List[str]] = None,
    security_level: int = 1,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Send an email over SMTP+SSL.

    config: dict from Config.data (needs email_address, smtp_host, smtp_port,
            app_password, user_name)
    security_level: 1, 2, or 3 - passed to CryptoAdapter to process the body
            (and in future, attachments) before sending
    metadata: optional dict passed through to CryptoAdapter.encrypt_payload,
            e.g. {"key_material": ..., "key_id": ...} once Phase 2 lands

    Raises smtplib/OSError exceptions on failure - caller (GUI thread
    wrapper) is responsible for catching these and surfacing a toast/error,
    never let this crash the background thread silently.
    """
    attachment_paths = attachment_paths or []
    metadata = metadata or {}

    adapter = CryptoAdapter()
    processed_body_bytes, crypto_meta = adapter.encrypt_payload(
        body.encode("utf-8"),
        level=security_level,
        key_material=metadata.get("key_material"),
        key_id=metadata.get("key_id"),
    )

    msg = MimeEmailMessage()
    msg["From"] = f"{config.get('user_name', '')} <{config['email_address']}>".strip()
    msg["To"] = to_address
    msg["Subject"] = subject
    msg[HEADER_LEVEL] = str(crypto_meta.get("level", security_level))
    msg[HEADER_KEYID] = crypto_meta.get("key_id") or ""

    # Phase 1: level 1 is a passthrough, so this is just the plaintext body.
    # Phase 2: processed_body_bytes may be ciphertext - set_content still
    # works since we treat it as a byte payload either way, but real Phase 2
    # code should base64 or otherwise encode non-UTF8-safe bytes before
    # calling set_content with a text subtype.
    try:
        msg.set_content(processed_body_bytes.decode("utf-8"))
    except UnicodeDecodeError:
        # ciphertext isn't valid utf-8 text - Phase 2 concern, base64-encode
        import base64
        msg.set_content(base64.b64encode(processed_body_bytes).decode("ascii"))
        msg.replace_header("Content-Transfer-Encoding", "base64")

    for path in attachment_paths:
        if not os.path.isfile(path):
            continue
        filename = os.path.basename(path)
        with open(path, "rb") as f:
            data = f.read()
        # Phase 1: attachments are NOT run through the crypto adapter yet.
        # Phase 2 TODO: encrypt attachment bytes the same way as the body
        # before attaching, and record that in crypto_meta / headers.
        msg.add_attachment(
            data,
            maintype="application",
            subtype="octet-stream",
            filename=filename,
        )

    with smtplib.SMTP_SSL(config["smtp_host"], int(config["smtp_port"])) as server:
        server.login(config["email_address"], config["app_password"])
        server.send_message(msg)


def fetch_inbox(config: Dict[str, Any], max_emails: int = 15) -> List[EmailMessage]:
    """
    Fetch the most recent `max_emails` messages from the inbox via IMAP+SSL.

    Returns a list of EmailMessage, most recent first.
    Raises imaplib.IMAP4.error / OSError on connection/auth failure.
    """
    results: List[EmailMessage] = []

    with imaplib.IMAP4_SSL(config["imap_host"], int(config["imap_port"])) as imap:
        imap.login(config["email_address"], config["app_password"])
        imap.select("INBOX")

        status, data = imap.search(None, "ALL")
        if status != "OK":
            return results

        uids = data[0].split()
        uids = uids[-max_emails:]  # most recent N
        uids.reverse()  # newest first

        for uid in uids:
            status, msg_data = imap.fetch(uid, "(RFC822)")
            if status != "OK" or not msg_data or msg_data[0] is None:
                continue

            raw_email = msg_data[0][1]
            parsed = email.message_from_bytes(raw_email)

            sender = _decode_mime_words(parsed.get("From", ""))
            subject = _decode_mime_words(parsed.get("Subject", ""))
            date = parsed.get("Date", "")

            level_hdr = parsed.get(HEADER_LEVEL, "1")
            try:
                security_level = int(level_hdr)
            except (TypeError, ValueError):
                security_level = 1
            key_id = parsed.get(HEADER_KEYID) or None

            body = ""
            attachments = []

            if parsed.is_multipart():
                for part in parsed.walk():
                    content_disposition = str(part.get("Content-Disposition", ""))
                    content_type = part.get_content_type()

                    if "attachment" in content_disposition:
                        filename = part.get_filename()
                        if filename:
                            attachments.append(_decode_mime_words(filename))
                    elif content_type == "text/plain" and not body:
                        try:
                            body = part.get_payload(decode=True).decode(
                                part.get_content_charset() or "utf-8",
                                errors="replace",
                            )
                        except Exception:
                            body = "[Could not decode message body]"
            else:
                try:
                    payload = parsed.get_payload(decode=True)
                    body = payload.decode(
                        parsed.get_content_charset() or "utf-8", errors="replace"
                    ) if payload else ""
                except Exception:
                    body = "[Could not decode message body]"

            # Phase 1: body is never actually decrypted (level 1 only exists).
            # Phase 2 TODO: if security_level > 1, call
            # CryptoAdapter.decrypt_payload(body_bytes, {"level":..., "key_id":...})
            # after fetching key_id's key material from KMAdapter.

            results.append(
                EmailMessage(
                    uid=uid.decode() if isinstance(uid, bytes) else str(uid),
                    sender=sender,
                    subject=subject,
                    date=date,
                    body=body,
                    security_level=security_level,
                    key_id=key_id,
                    attachments=attachments,
                )
            )

    return results
