import smtplib
import imaplib
import email
import os
import re
import base64
import html as html_module
from dataclasses import dataclass, field
from email.message import EmailMessage as MimeEmailMessage
from email.header import decode_header
from typing import Optional, List, Dict, Any

from cryptoAdapter import CryptoAdapter
from kmAdapter import KMAdapter

HEADER_LEVEL = "X-QuMail-Level"
HEADER_KEYID = "X-QuMail-KeyID"
HEADER_NONCE = "X-QuMail-Nonce"


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
    km_adapter: Optional[KMAdapter] = None,
) -> None:
    """
    Send an email over SMTP+SSL.

    config: dict from Config.data (needs email_address, smtp_host, smtp_port,
            app_password, user_name)
    security_level: 1, 2, or 3 - passed to CryptoAdapter to process the body
            before sending
    metadata: optional override, e.g. {"key_material": ..., "key_id": ...}
            to force a specific key instead of allocating a fresh one -
            mainly useful for tests. Normal usage leaves this None and lets
            km_adapter allocate a fresh key automatically.
    km_adapter: REQUIRED if security_level > 1. Used to allocate a fresh
            quantum key to encrypt this message with.

    Raises ValueError if security_level > 1 and no km_adapter was given.
    Raises smtplib/OSError exceptions on failure - caller (GUI thread
    wrapper) is responsible for catching these and surfacing a toast/error,
    never let this crash the background thread silently.
    """
    attachment_paths = attachment_paths or []
    metadata = metadata or {}

    key_material = metadata.get("key_material")
    key_id = metadata.get("key_id")

    if security_level > 1 and key_material is None:
        if km_adapter is None:
            raise ValueError(
                f"security_level={security_level} requires a km_adapter to fetch a key."
            )
        # Sender side: allocate a fresh, previously-unused key.
        key_material, key_id = km_adapter.get_key()

    adapter = CryptoAdapter()
    processed_body_bytes, crypto_meta = adapter.encrypt_payload(
        body.encode("utf-8"),
        level=security_level,
        key_material=key_material,
        key_id=key_id,
    )

    msg = MimeEmailMessage()
    msg["From"] = f"{config.get('user_name', '')} <{config['email_address']}>".strip()
    msg["To"] = to_address
    msg["Subject"] = subject
    msg[HEADER_LEVEL] = str(crypto_meta.get("level", security_level))
    msg[HEADER_KEYID] = crypto_meta.get("key_id") or ""
    if crypto_meta.get("nonce"):
        msg[HEADER_NONCE] = crypto_meta["nonce"]

    if security_level == 1:
        # Plaintext body - human readable, no special encoding needed.
        msg.set_content(processed_body_bytes.decode("utf-8"))
    else:
        # Ciphertext is arbitrary bytes, not valid text - base64-encode it
        # explicitly (not left to chance/exceptions) so fetch_inbox can
        # reliably get the raw bytes back via get_payload(decode=True).
        msg.set_content(base64.b64encode(processed_body_bytes).decode("ascii"))
        msg.replace_header("Content-Transfer-Encoding", "base64")

    for path in attachment_paths:
        if not os.path.isfile(path):
            continue
        filename = os.path.basename(path)
        with open(path, "rb") as f:
            data = f.read()
        # Phase 2 TODO: attachments are NOT run through the crypto adapter
        # yet - only the body is encrypted so far. Encrypting attachment
        # bytes the same way is the next piece of work, not yet done here.
        msg.add_attachment(
            data,
            maintype="application",
            subtype="octet-stream",
            filename=filename,
        )

    with smtplib.SMTP_SSL(config["smtp_host"], int(config["smtp_port"])) as server:
        server.login(config["email_address"], config["app_password"])
        server.send_message(msg)


def fetch_inbox(
    config: Dict[str, Any],
    max_emails: int = 15,
    km_adapter: Optional[KMAdapter] = None,
) -> List[EmailMessage]:
    """
    Fetch the most recent `max_emails` messages from the inbox via IMAP+SSL.

    km_adapter: needed to decrypt any Level 2+ message found in the inbox.
            If None, encrypted messages are still listed (sender/subject/
            date all work) but the body shows a placeholder instead of
            attempting decryption.

    Returns a list of EmailMessage, most recent first.
    Raises imaplib.IMAP4.error / OSError on connection/auth failure.
    """
    results: List[EmailMessage] = []
    crypto = CryptoAdapter()

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
            nonce_b64 = parsed.get(HEADER_NONCE) or None

            attachments = []

            # First pass: collect attachments, and grab the RAW bytes of the
            # main body part - deliberately NOT charset-decoded yet. For an
            # encrypted message these raw bytes (after get_payload(decode=True)
            # strips the base64 Content-Transfer-Encoding) are the actual
            # ciphertext; for a plaintext message they're just the plain
            # text/html bytes, decoded further below.
            body_raw_bytes = b""
            body_is_html = False
            body_charset = "utf-8"
            html_fallback_bytes = b""
            html_charset = "utf-8"
            found_plain = False

            if parsed.is_multipart():
                for part in parsed.walk():
                    content_disposition = str(part.get("Content-Disposition", ""))
                    content_type = part.get_content_type()

                    if "attachment" in content_disposition:
                        filename = part.get_filename()
                        if filename:
                            try:
                                att_data = part.get_payload(decode=True) or b""
                            except Exception:
                                att_data = b""
                            attachments.append(
                                EmailAttachment(
                                    filename=_decode_mime_words(filename), data=att_data
                                )
                            )
                    elif content_type == "text/plain" and not found_plain:
                        try:
                            body_raw_bytes = part.get_payload(decode=True) or b""
                            body_charset = part.get_content_charset() or "utf-8"
                            found_plain = True
                        except Exception:
                            body_raw_bytes = b""
                    elif content_type == "text/html" and not html_fallback_bytes:
                        try:
                            html_fallback_bytes = part.get_payload(decode=True) or b""
                            html_charset = part.get_content_charset() or "utf-8"
                        except Exception:
                            pass

                if not found_plain and html_fallback_bytes:
                    body_raw_bytes = html_fallback_bytes
                    body_charset = html_charset
                    body_is_html = True
            else:
                content_type = parsed.get_content_type()
                try:
                    body_raw_bytes = parsed.get_payload(decode=True) or b""
                except Exception:
                    body_raw_bytes = b""
                body_charset = parsed.get_content_charset() or "utf-8"
                body_is_html = content_type == "text/html"

            # Second pass: turn body_raw_bytes into the final display string.
            # This is the branch point between "just show me the text" (L1)
            # and "decrypt this first" (L2/L3).
            if security_level == 1:
                try:
                    raw_text = body_raw_bytes.decode(body_charset, errors="replace")
                except Exception:
                    raw_text = ""
                body = _html_to_text(raw_text) if body_is_html else raw_text

            else:
                if km_adapter is None:
                    body = (
                        f"[Encrypted message - Level {security_level} - "
                        "no key manager available to decrypt]"
                    )
                elif not key_id:
                    body = "[Encrypted message - missing key ID header, cannot decrypt]"
                else:
                    try:
                        key_bytes, _ = km_adapter.get_key(key_id=key_id)
                        plaintext_bytes = crypto.decrypt_payload(
                            body_raw_bytes,
                            {"level": security_level, "key_id": key_id, "nonce": nonce_b64},
                            key_material=key_bytes,
                        )
                        body = plaintext_bytes.decode("utf-8", errors="replace")
                    except KeyError:
                        body = "[Could not decrypt: key not found in local key bank]"
                    except ValueError as e:
                        body = f"[Could not decrypt message: {e}]"
                    except NotImplementedError:
                        body = f"[Level {security_level} decryption not implemented yet]"

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