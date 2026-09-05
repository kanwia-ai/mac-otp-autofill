#!/usr/bin/env python3
"""
otp_watcher.py — watch the macOS Messages database for incoming one-time
passcodes and hand them to:

  1. the clipboard (+ a Notification Center banner), and
  2. a loopback-only HTTP endpoint that the companion Chrome extension
     claims from when it sees a one-time-code field on the page.

Nothing ever leaves the machine. The server binds 127.0.0.1, requires a
bearer token, and only ever emits the digits of a code plus a sender label —
never message text.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

VERSION = "1.0.0"

CHAT_DB = Path.home() / "Library" / "Messages" / "chat.db"
CONFIG_PATH = Path.home() / ".config" / "otp-autofill" / "config.json"
LOG_PATH = Path.home() / "Library" / "Logs" / "otp-autofill.log"
LOG_MAX_BYTES = 512 * 1024

# Apple's Core Data epoch: 2001-01-01T00:00:00Z
APPLE_EPOCH_OFFSET = 978307200


def apple_date_to_unix(raw) -> float | None:
    """Convert chat.db's message.date to a unix timestamp.

    Modern macOS stores nanoseconds since the Core Data epoch; databases
    migrated from very old versions can still hold plain seconds.
    """
    if not raw:
        return None
    if raw > 10**15:
        raw = raw / 1e9
    return raw + APPLE_EPOCH_OFFSET

DEFAULT_CONFIG = {
    "port": 8787,
    "token": "",
    "ttl_seconds": 300,
    "poll_seconds": 1.5,
    "clipboard": True,
    "notify": True,
    "strict_domain_binding": False,
}


# --------------------------------------------------------------------------
# logging
# --------------------------------------------------------------------------

_log_lock = threading.Lock()


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {msg}"
    with _log_lock:
        try:
            LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            if LOG_PATH.exists() and LOG_PATH.stat().st_size > LOG_MAX_BYTES:
                # keep the tail, drop the head
                tail = LOG_PATH.read_bytes()[-LOG_MAX_BYTES // 2 :]
                LOG_PATH.write_bytes(tail)
            with LOG_PATH.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass
    print(line, flush=True)


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_PATH.read_text()))
        except (OSError, json.JSONDecodeError) as exc:
            log(f"config: could not read {CONFIG_PATH} ({exc}); using defaults")
    if not cfg.get("token"):
        log("config: no token set — refusing to start. Run setup.sh first.")
        sys.exit(2)
    return cfg


# --------------------------------------------------------------------------
# code extraction
# --------------------------------------------------------------------------

# Does this message look like it is about a passcode at all? If not, we never
# pull digits out of it — that alone kills most false positives.
OTP_CONTEXT = re.compile(
    r"(one[\s\-]?time|verification|verify|security\s+code|access\s+code|"
    r"login\s+code|log[\s\-]?in\s+code|sign[\s\-]?in\s+code|confirmation\s+code|"
    r"auth(?:entication)?\s+code|passcode|\bOTP\b|\bPIN\b|\b2FA\b|\bcode\b)",
    re.I,
)

# Origin-bound one-time code (the WebOTP / "@example.com #123456" convention).
# Marketing posts look identical ("@somevenue.example #photobooth"), so the code
# must contain a digit and the message must still read as a passcode message.
ORIGIN_BOUND = re.compile(r"@([\w.-]+\.[A-Za-z]{2,})\s+#([A-Za-z0-9]{4,10})\b")

# Messages that talk about "passcode" but never carry a 2FA code.
NOT_OTP = re.compile(
    r"(zoom\.us/|join zoom meeting|meeting id\b|teams\.microsoft\.com|meet\.google\.com|"
    r"webex\.com|dial[\s\-]?in\b|conference (?:id|line)\b|personal meeting room)",
    re.I,
)

# Ordered best-guess patterns. First hit that survives _plausible() wins.
PATTERNS: list[re.Pattern] = [
    # "your code is: 123456", "Code 386002.", "OTP - 4821"
    re.compile(
        r"\b(?:code|otp|pin|passcode|password|token)\b[^A-Za-z0-9\n]{0,15}(\d{4,8})\b",
        re.I,
    ),
    # Google-style "G-123456"
    re.compile(r"\b[A-Z]-(\d{4,8})\b"),
    # "018340 is your Fabrikam verification code." / "Use 7227 as Litware security code"
    re.compile(r"\b(\d{4,8})\b\s+(?:is|as)\s+(?:your|the|a|an)?[\w\s]{0,25}?\bcode\b", re.I),
    # "The OTP to view your trip is 588817"
    re.compile(r"\b(?:is|:)\s*(\d{4,8})\b", re.I),
    # "557954 Use this code to access your account" — code leads the message
    re.compile(r"^\s*(?:<#>)?\s*(\d{4,8})\b"),
    # Alphanumeric codes, e.g. "Your code is A7B9C2". Deliberately strict: a
    # loose version matched marketing copy ("...148UQ..."), so the keyword must
    # be joined to the token by is/:/= and the token must mix letters + digits.
    re.compile(r"\b(?:code|otp|passcode)\b\s*(?:is|:|=)\s*([A-Z0-9]{4,8})\b"),
]

CURRENCY_PREFIX = re.compile(r"[$£€¥]\s*$")
UNIT_SUFFIX = re.compile(r"^\s*(%|minutes?\b|mins?\b|hours?\b|hrs?\b|seconds?\b|secs?\b|days?\b)")


def _plausible(token: str, text: str, span: tuple[int, int]) -> bool:
    """Reject digit runs that are clearly not passcodes."""
    if not re.search(r"\d", token):
        return False
    before = text[max(0, span[0] - 3) : span[0]]
    after = text[span[1] : span[1] + 12]
    if CURRENCY_PREFIX.search(before):
        return False
    if UNIT_SUFFIX.match(after):
        return False
    # a bare 4-digit year is far more often a date than a passcode
    if re.fullmatch(r"(19|20)\d{2}", token):
        return False
    return True


def extract_code(text: str) -> tuple[str | None, str | None]:
    """Return (code, bound_host). bound_host is set only for @domain #code SMS."""
    if not text:
        return None, None
    if not OTP_CONTEXT.search(text) or NOT_OTP.search(text):
        return None, None

    bound = ORIGIN_BOUND.search(text)
    if bound and re.search(r"\d", bound.group(2)):
        return bound.group(2), bound.group(1).lower()

    for pattern in PATTERNS:
        for m in pattern.finditer(text):
            token = m.group(1)
            if _plausible(token, text, m.span(1)):
                return token, None
    return None, None


# --------------------------------------------------------------------------
# sender labelling
# --------------------------------------------------------------------------

# These stay case-SENSITIVE on the capture group — brands are capitalised and
# the surrounding filler words are not. (Applying re.I to the whole pattern made
# `[A-Z]` match lowercase, which produced labels like "Fabrikam verification".)
# \w is Unicode-aware in Python 3, so accented brands ("Café Systems") stay intact.
# The lowercase-connector branch is what lets "Bank of Fabrikam" survive as one
# label instead of truncating to "Bank".
_WORD = r"[A-Z][\w&.\-]{1,20}"
_BRAND = rf"({_WORD}(?:\s+(?:of|and|the|de)\s+{_WORD}|\s+{_WORD}){{0,2}})"
_QUALIFIER = (
    r"(?:(?i:verification|security|login|log[\s\-]?in|sign[\s\-]?in|access|confirmation|"
    r"authorization|authentication|withdrawal|payment|password\s+reset|one[\s\-]?time)\s+)?"
)

BRAND_HINTS: list[re.Pattern] = [
    # "Your Contoso verification code is ...", "Your Fabrikam withdrawal code ..."
    re.compile(rf"(?i:\b(?:your|from)\s+){_BRAND}\s+{_QUALIFIER}(?i:code|passcode|otp)\b"),
    # "Your authorization code for Northwind is ...", "code for Café Systems"
    re.compile(rf"(?i:\b(?:code|passcode|otp)\s+(?:for|from)\s+){_BRAND}\b"),
    # "Litware code: 179811", "Contoso Verification Code: ..."
    re.compile(rf"^\s*(?:<#>)?\s*{_BRAND}\s*[:,]?\s*{_QUALIFIER}(?i:code|passcode|otp)\b"),
    # "From: Contoso ..." — the header word would otherwise become the label.
    re.compile(rf"^\s*(?:<#>)?\s*(?i:from)\s*:\s*{_BRAND}"),
    # "Bank of Fabrikam: DO NOT share...", "Litware: If anyone asks..."
    # Leading brand followed by a colon, with no "code" nearby to anchor on.
    re.compile(rf"^\s*(?:<#>)?\s*{_BRAND}\s*:"),
    # "Trey Research will NEVER call or text you for this code."
    re.compile(rf"^\s*(?:<#>)?\s*{_BRAND}\s+(?i:will|has|is|sent|never)\b"),
]

_LABEL_STOPWORDS = {
    "the", "a", "an", "this", "that", "do", "not", "never", "your", "use", "from",
    "to", "re", "fwd", "hi", "hey", "alert", "notice", "reminder", "important",
    "urgent", "new", "attention", "warning", "please", "dear", "if", "for",
}

# "Contoso Verification Code:" parses as brand "Contoso Verification" — the greedy
# capture swallows the qualifier, so trim it back off the tail.
_QUALIFIER_TAIL = re.compile(
    r"\s+(?i:verification|verify|security|login|log[\s\-]?in|sign[\s\-]?in|access|"
    r"confirmation|authorization|authentication|one[\s\-]?time|passcode|code|otp|"
    r"account|support|team|notification|alerts?)$"
)


def guess_sender_label(text: str, handle: str | None) -> str:
    """A human label for the notification/toast — brand name if we can find one."""
    for pattern in BRAND_HINTS:
        m = pattern.search(text or "")
        if not m:
            continue
        label = m.group(1).strip(" .,:")
        # SMS shouts ("Contoso NEVER share...") read as capitalised brand words, so
        # drop ALL-CAPS trailing words. The first word is never trimmed, which
        # keeps genuinely capitalised brands like USAA and IRS intact.
        words = label.split()
        while len(words) > 1 and words[-1].isupper() and len(words[-1]) >= 2:
            words.pop()
        label = " ".join(words)
        while True:
            trimmed = _QUALIFIER_TAIL.sub("", label)
            if trimmed == label:
                break
            label = trimmed
        if label and label.split()[0].lower() not in _LABEL_STOPWORDS:
            return label
    if handle:
        # e.g. "united_airlines_xxx@rbm.goog" -> "united airlines"
        if "@" in handle and handle.endswith(".goog"):
            return handle.split("@")[0].split("_agent")[0].replace("_", " ").title()
        return handle
    return "Messages"


# --------------------------------------------------------------------------
# code store
# --------------------------------------------------------------------------


@dataclass
class Code:
    code: str
    sender: str
    handle: str
    received_at: float
    bound_host: str | None = None
    consumed_by: str | None = None
    consumed_at: float | None = None


@dataclass
class Store:
    ttl: float
    lock: threading.Lock = field(default_factory=threading.Lock)
    items: list[Code] = field(default_factory=list)

    def add(self, code: Code) -> bool:
        """Add unless we saw the same code from the same handle in the last 60s."""
        with self.lock:
            now = code.received_at
            for existing in self.items:
                if (
                    existing.code == code.code
                    and existing.handle == code.handle
                    and now - existing.received_at < 60
                ):
                    return False
            self.items.append(code)
            self.items = [c for c in self.items if now - c.received_at < 3600][-25:]
            return True

    def claim(self, host: str) -> Code | None:
        """Hand out the newest unconsumed, unexpired code and burn it."""
        now = time.time()
        with self.lock:
            for c in sorted(self.items, key=lambda c: c.received_at, reverse=True):
                if c.consumed_by is not None:
                    continue
                if now - c.received_at > self.ttl:
                    continue
                if c.bound_host and not _host_matches(host, c.bound_host):
                    continue
                c.consumed_by = host or "unknown"
                c.consumed_at = now
                return c
        return None

    def pending(self) -> int:
        now = time.time()
        with self.lock:
            return sum(
                1 for c in self.items if c.consumed_by is None and now - c.received_at <= self.ttl
            )


def _host_matches(host: str, bound: str) -> bool:
    host = (host or "").lower().lstrip(".")
    bound = bound.lower().lstrip(".")
    return host == bound or host.endswith("." + bound)


# --------------------------------------------------------------------------
# side effects: clipboard + notification
# --------------------------------------------------------------------------


def copy_to_clipboard(value: str) -> None:
    try:
        subprocess.run(["/usr/bin/pbcopy"], input=value.encode(), check=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        log(f"clipboard: failed ({exc})")


def _osa_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def notify(title: str, body: str) -> None:
    script = f'display notification "{_osa_quote(body)}" with title "{_osa_quote(title)}"'
    try:
        subprocess.run(["/usr/bin/osascript", "-e", script], check=False, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        log(f"notify: failed ({exc})")


# --------------------------------------------------------------------------
# Messages database
# --------------------------------------------------------------------------


def open_db() -> sqlite3.Connection:
    """
    Open chat.db read-only at the *connection* level (PRAGMA query_only) rather
    than with mode=ro. A true read-only open cannot initialise the -shm file of
    a WAL database, so it intermittently fails to see the newest messages;
    query_only gives us WAL visibility while still making writes impossible.
    """
    conn = sqlite3.connect(str(CHAT_DB), timeout=5.0)
    conn.execute("PRAGMA query_only = ON;")
    conn.execute("PRAGMA busy_timeout = 3000;")
    return conn


def decode_attributed_body(blob: bytes | None) -> str | None:
    """Pull the plain string out of an NSAttributedString typedstream blob."""
    if not blob:
        return None
    try:
        chunk = blob.split(b"NSString")[1][5:]
        if chunk[0] == 0x81:
            length = int.from_bytes(chunk[1:3], "little")
            chunk = chunk[3:]
        else:
            length = chunk[0]
            chunk = chunk[1:]
        return chunk[:length].decode("utf-8", errors="replace")
    except (IndexError, UnicodeDecodeError):
        return None


# `participants` is the one structural signal worth having. Group threads never
# carry 2FA codes but routinely carry things that parse exactly like them —
# door codes, wifi passwords, lockbox PINs.
#
# A "have you ever replied to this sender" signal was tried here and removed: on
# real history it discarded genuine codes from two banks, a telecom and a large
# retailer,
# because two-way SMS with a service shortcode is completely normal. Group
# membership caught every true false positive on its own.
NEW_MESSAGES_SQL = """
SELECT m.ROWID, m.text, m.attributedBody, h.id, m.date,
       (SELECT COUNT(*) FROM chat_handle_join chj WHERE chj.chat_id = cmj.chat_id)
         AS participants
FROM message m
LEFT JOIN handle h ON m.handle_id = h.ROWID
LEFT JOIN chat_message_join cmj ON cmj.message_id = m.ROWID
WHERE m.ROWID > ? AND m.is_from_me = 0
ORDER BY m.ROWID ASC
LIMIT 200
"""


def sender_is_service(participants: int | None) -> bool:
    """False for group threads, where code-shaped text is usually a door code."""
    return (participants or 0) <= 1


DB_RETRY_SECONDS = 15


def watch(store: Store, cfg: dict, state: "State") -> None:
    """
    Runs forever. A missing Full Disk Access grant is a normal startup state
    (the user has not visited System Settings yet), not a crash — so we hold and
    retry rather than exiting, which would leave launchd restarting us every few
    seconds and the /health endpoint permanently down.
    """
    poll = float(cfg["poll_seconds"])
    conn: sqlite3.Connection | None = None
    last_rowid = 0
    warned = False

    while True:
        if conn is None:
            try:
                conn = open_db()
                last_rowid = conn.execute(
                    "SELECT COALESCE(MAX(ROWID), 0) FROM message"
                ).fetchone()[0]
            except sqlite3.Error as exc:
                state.db_ok = False
                if not warned:
                    log(
                        f"cannot read chat.db ({exc}). Grant Full Disk Access to "
                        f"'OTP Autofill.app', then this will pick up on its own. "
                        f"Retrying every {DB_RETRY_SECONDS}s."
                    )
                    warned = True
                time.sleep(DB_RETRY_SECONDS)
                continue
            state.db_ok = True
            warned = False
            log(f"watching chat.db from ROWID {last_rowid}")

        time.sleep(poll)
        try:
            rows = conn.execute(NEW_MESSAGES_SQL, (last_rowid,)).fetchall()
        except sqlite3.Error as exc:
            log(f"db: {exc} — reopening")
            try:
                conn.close()
            except sqlite3.Error:
                pass
            conn = None
            state.db_ok = False
            continue

        for rowid, text, attributed, handle, date_raw, participants in rows:
            last_rowid = max(last_rowid, rowid)
            body = text or decode_attributed_body(attributed)
            if not body:
                continue
            code, bound_host = extract_code(body)
            if not code:
                continue
            if not sender_is_service(participants):
                log(f"ignored code-like text in a group thread ({handle})")
                continue

            sender = guess_sender_label(body, handle)

            # A row can surface in chat.db long after the message was sent —
            # iCloud backfill and delayed SMS forwarding both replay old
            # messages (seen live: a code re-appeared 16 minutes later and
            # beat the fresh code to the claim). Stamp the code with when it
            # was SENT, and drop it outright once that is past the TTL so a
            # replay can never win a claim, overwrite the clipboard, or fire
            # a notification.
            now = time.time()
            sent_at = apple_date_to_unix(date_raw)
            received_at = min(sent_at, now) if sent_at else now
            if now - received_at > store.ttl:
                log(
                    f"ignored stale code from {sender} "
                    f"(sent {round(now - received_at)}s ago)"
                )
                continue

            entry = Code(
                code=code,
                sender=sender,
                handle=handle or "",
                received_at=received_at,
                bound_host=bound_host,
            )
            if not store.add(entry):
                continue

            bound_note = f" [bound to {bound_host}]" if bound_host else ""
            log(f"code {code} from {sender}{bound_note}")

            if cfg.get("clipboard", True):
                copy_to_clipboard(code)
            if cfg.get("notify", True):
                notify(f"Code from {sender}", f"{code} — copied to clipboard")


# --------------------------------------------------------------------------
# loopback HTTP endpoint
# --------------------------------------------------------------------------


@dataclass
class State:
    """Shared health flags between the watcher thread and the HTTP thread."""

    db_ok: bool = False
    # When the extension last asked for a code. Lets --check tell "the extension
    # is not installed/enabled" apart from "no code has arrived yet".
    last_claim_attempt: float | None = None


class Handler(BaseHTTPRequestHandler):
    server_version = f"otp-autofill/{VERSION}"
    store: Store
    token: str
    state: "State"

    def log_message(self, fmt, *args):  # silence stderr access logs
        pass

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        origin = self.headers.get("Origin", "")
        if origin.startswith("chrome-extension://"):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Headers", "Authorization")
            self.send_header("Access-Control-Allow-Private-Network", "true")
        self.end_headers()
        self.wfile.write(body)

    def _authorised(self) -> bool:
        auth = self.headers.get("Authorization", "")
        expected = f"Bearer {self.token}"
        # constant-time-ish compare
        if len(auth) != len(expected):
            return False
        return sum(a != b for a, b in zip(auth, expected)) == 0

    def do_OPTIONS(self):  # noqa: N802
        self._send(204, {})

    def do_GET(self):  # noqa: N802
        route = urlparse(self.path)
        params = parse_qs(route.query)

        if route.path == "/health":
            last = self.state.last_claim_attempt
            self._send(
                200,
                {
                    "ok": True,
                    "version": VERSION,
                    "db_access": self.state.db_ok,
                    "pending": self.store.pending(),
                    "seconds_since_extension_poll": (
                        None if last is None else round(time.time() - last, 1)
                    ),
                },
            )
            return

        if not self._authorised():
            self._send(401, {"error": "unauthorised"})
            return

        if route.path == "/claim":
            self.state.last_claim_attempt = time.time()
            host = (params.get("site", [""])[0] or "")[:255]
            code = self.store.claim(host)
            if code is None:
                self._send(200, {})
                return
            log(f"claimed {code.code} ({code.sender}) -> {host or 'unknown site'}")
            self._send(
                200,
                {
                    "code": code.code,
                    "sender": code.sender,
                    "age": round(time.time() - code.received_at, 1),
                },
            )
            return

        self._send(404, {"error": "not found"})


def serve(store: Store, cfg: dict, state: "State") -> None:
    Handler.store = store
    Handler.token = cfg["token"]
    Handler.state = state
    httpd = ThreadingHTTPServer(("127.0.0.1", int(cfg["port"])), Handler)
    httpd.daemon_threads = True
    log(f"listening on 127.0.0.1:{cfg['port']}")
    httpd.serve_forever()


# --------------------------------------------------------------------------
# entrypoints
# --------------------------------------------------------------------------


def check() -> int:
    print(f"otp-autofill {VERSION}")
    print(f"  config       {CONFIG_PATH} {'✓' if CONFIG_PATH.exists() else '✗ missing'}")

    # This shell may well have Full Disk Access when the daemon does not, so
    # report the two separately — the daemon's is the one that matters.
    try:
        conn = open_db()
        total = conn.execute("SELECT COUNT(*) FROM message").fetchone()[0]
        print(f"  this shell   ✓ can read chat.db ({total:,} messages)")
    except sqlite3.Error as exc:
        print(f"  this shell   ✗ cannot read chat.db ({exc})")

    try:
        cfg = dict(DEFAULT_CONFIG)
        cfg.update(json.loads(CONFIG_PATH.read_text()))
    except (OSError, json.JSONDecodeError):
        print("  daemon       ✗ no config — run setup.sh")
        return 1

    import urllib.error
    import urllib.request

    url = f"http://127.0.0.1:{cfg['port']}/health"
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            health = json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        print(f"  daemon       ✗ not responding on 127.0.0.1:{cfg['port']} ({exc})")
        print()
        print("  Start it with:")
        print(f"    launchctl kickstart -k gui/{os.getuid()}/com.kyra.otp-autofill")
        return 1

    print(f"  daemon       ✓ running (v{health.get('version')})")
    if not health.get("db_access"):
        print("  daemon db    ✗ cannot read Messages")
        print()
        print("  Grant Full Disk Access to the daemon:")
        print("    System Settings → Privacy & Security → Full Disk Access → +")
        print(f"    {Path.home()}/Applications/OTP Autofill.app")
        print("  then:")
        print(f"    launchctl kickstart -k gui/{os.getuid()}/com.kyra.otp-autofill")
        return 1

    print(f"  daemon db    ✓ reading Messages ({health.get('pending', 0)} code(s) waiting)")

    since = health.get("seconds_since_extension_poll")
    if since is None:
        print("  extension    — has not asked for a code yet")
        print("               (it only polls when a passcode field is on the")
        print("                focused tab, so this is normal until then)")
    else:
        print(f"  extension    ✓ last asked {since}s ago")
    return 0


def selftest() -> int:
    # Every case below mirrors the wording of a real SMS the extractor was tuned
    # against, with fictional brand names substituted. The parsing shape is what
    # matters — keep the structure if you edit these.
    samples = [
        ("Use 731011 as your Northwind verification code.", "731011"),          # code before "as your"
        ("018340 is your Fabrikam verification code.", "018340"),               # leading code, "is your"
        ("The OTP to view your trip is 588817", "588817"),                      # trailing "is"
        ("Your Contoso verification code is 232015. This code will expire", "232015"),
        ("Your Umbra code is: 753446.\nClose this message and enter the", "753446"),
        ("Your Blue Yonder verification code is: 364384. This code", "364384"), # two-word brand
        ("Your Trey Research verification code is 155448", "155448"),
        ("<#>Bank of Fabrikam: DO NOT share this code. Code 386002. We", "386002"),  # <#> prefix, "of" connector
        ("G-482915 is your Contoso verification code.", "482915"),              # G-nnnnnn form
        ("Your code is 920431\n\n@example.com #920431", "920431"),              # origin-bound
        ("Use 7227 as Litware account security code", "7227"),                  # 4-digit, no "your"
        ("557954 Use this code to access your account for Adventure Works", "557954"),
        ("Your order of $124.99 shipped, arriving 2026", None),                 # currency + year
        ("Hey are you free at 7? call me on 5551234567", None),                 # phone number
        ("Your code expires in 10 minutes", None),                              # duration
        # regressions found against real message history
        ("Share and tag us! #somevenue.example @somevenue.example #photobooth", None),
        ("Join Zoom Meeting https://zoom.us/j/123\nMeeting ID: 958 6132\nPasscode: 297368", None),
        (
            "Loyalty qualifying points (LQP) must be earned. Fare code 148UQ applies to "
            "Contoso Rewards members.",
            None,
        ),
    ]
    label_samples = [
        ("Your Fabrikam verification code is: 665418.", "Fabrikam"),
        ("Your Contoso verification code is 707297.", "Contoso"),
        ("Litware code: 179811. Valid for 3 minutes.", "Litware"),
        ("Your authorization code for Northwind is 369489", "Northwind"),
        ("926146 is your verification code for Café Systems", "Café Systems"),  # non-ASCII brand
        ("<#>Bank of Fabrikam: DO NOT share this code. Code 386002.", "Bank of Fabrikam"),
        ("Trey Research will NEVER call or text you for this code.", "Trey Research"),
    ]
    failures = 0
    for text, expected in samples:
        got, bound = extract_code(text)
        ok = got == expected
        failures += not ok
        mark = "✓" if ok else "✗"
        detail = f" (bound {bound})" if bound else ""
        print(f"  {mark} {got!r:>10}{detail}  <- {text[:58]!r}")

    print()
    for text, expected in label_samples:
        got = guess_sender_label(text, None)
        ok = got == expected
        failures += not ok
        print(f"  {'✓' if ok else '✗'} label {got!r:>14}  (want {expected!r})")

    total = len(samples) + len(label_samples)
    print(f"\n{total - failures}/{total} passed")
    return 1 if failures else 0


def main() -> int:
    if "--check" in sys.argv:
        return check()
    if "--selftest" in sys.argv:
        return selftest()

    cfg = load_config()
    store = Store(ttl=float(cfg["ttl_seconds"]))
    state = State()

    threading.Thread(target=serve, args=(store, cfg, state), daemon=True).start()

    try:
        watch(store, cfg, state)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
