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
import re
import html as html_module
from dataclasses import dataclass, field
from email.message import EmailMessage as MimeEmailMessage
from email.header import decode_header
from typing import Optional, List, Dict, Any

from cryptoAdapter import CryptoAdapter

HEADER_LEVEL = "X-QuMail-Level"
HEADER_KEYID = "X-QuMail-KeyID"


@dataclass
class EmailAttachment:
    """A single attachment's filename and raw bytes, extracted during
    fetch_inbox() so it can be saved to disk without re-fetching the
    whole email from the server."""
    filename: str
    data: bytes


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
    attachments: List[EmailAttachment] = field(default_factory=list)


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


_TAG_RE = re.compile(r"<[^>]+>")
_STYLE_SCRIPT_RE = re.compile(r"<(style|script)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_MULTI_BLANK_RE = re.compile(r"\n{3,}")
# Matches both closing block tags (</p>, </div>...) AND self-closing/void
# tags like <br>, <br/>, <br /> which never have a closing counterpart.
_BLOCK_BREAK_RE = re.compile(
    r"</(p|div|tr|table|li|h[1-6])\s*>|<br\s*/?>", re.IGNORECASE
)


def _html_to_text(html_body: str) -> str:
    """
    Very lightweight HTML -> plain text conversion for display in the
    reading pane. This is NOT a full HTML renderer (Phase 1 doesn't need
    one) - it just strips tags so the user sees readable text instead of
    raw markup, which is what was happening for HTML-only emails before
    this fix.

    Good enough for: newsletters, automated mail, HTML-composed messages.
    Not attempting: images, tables, links-as-clickable, styling.
    """
    if not html_body:
        return ""

    text = _STYLE_SCRIPT_RE.sub("", html_body)  # drop <style>/<script> contents entirely
    text = _BLOCK_BREAK_RE.sub("\n", text)      # turn block-level closes + <br> into line breaks
    text = _TAG_RE.sub("", text)                # strip all remaining tags
    text = html_module.unescape(text)           # decode entities like &amp; &nbsp;
    text = text.replace("\xa0", " ")            # normalize non-breaking spaces to regular ones
    text = _MULTI_BLANK_RE.sub("\n\n", text)    # collapse excess blank lines
    return text.strip()


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
            html_fallback = ""  # used only if no text/plain part exists
            attachments = []

            if parsed.is_multipart():
                for part in parsed.walk():
                    content_disposition = str(part.get("Content-Disposition", ""))
                    content_type = part.get_content_type()

                    if "attachment" in content_disposition:
                        filename = part.get_filename()
                        if filename:
                            try:
                                data = part.get_payload(decode=True) or b""
                            except Exception:
                                data = b""
                            attachments.append(
                                EmailAttachment(
                                    filename=_decode_mime_words(filename), data=data
                                )
                            )
                    elif content_type == "text/plain" and not body:
                        try:
                            body = part.get_payload(decode=True).decode(
                                part.get_content_charset() or "utf-8",
                                errors="replace",
                            )
                        except Exception:
                            body = "[Could not decode message body]"
                    elif content_type == "text/html" and not html_fallback:
                        # Many emails (esp. multipart/alternative) only ship
                        # an HTML version. Keep it as a fallback in case no
                        # text/plain part turns up anywhere in the tree.
                        try:
                            html_fallback = part.get_payload(decode=True).decode(
                                part.get_content_charset() or "utf-8",
                                errors="replace",
                            )
                        except Exception:
                            pass

                if not body and html_fallback:
                    body = _html_to_text(html_fallback)
            else:
                content_type = parsed.get_content_type()
                try:
                    payload = parsed.get_payload(decode=True)
                    raw = payload.decode(
                        parsed.get_content_charset() or "utf-8", errors="replace"
                    ) if payload else ""
                except Exception:
                    raw = ""
                    body = "[Could not decode message body]"
                else:
                    # This is the actual bug fix: single-part HTML emails
                    # were being dumped as raw markup before. Now we check
                    # content_type before deciding whether to convert.
                    body = _html_to_text(raw) if content_type == "text/html" else raw

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