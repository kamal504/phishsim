"""
Generic Syslog Listener Adapter
================================
Listens on a UDP/TCP port for syslog messages from ANY email gateway
that supports syslog output (Barracuda, Cisco Secure Email, Sophos,
Fortinet, Trend Micro, and many others).

Parses CEF (Common Event Format) and LEEF (Log Event Extended Format)
and plain JSON syslog lines.

CEF example (from Barracuda):
  CEF:0|Barracuda|EmailSecurity|1.0|phishing|Phishing detected|8|
  dst=john@company.com spt=25 act=blocked reason=phishing

LEEF example (from IBM QRadar/gateways):
  LEEF:1.0|Sophos|Email|1.0|phishing|usrName=john@company.com threatName=Phishing

The listener stores events in-memory between poll() calls.
The gateway sync scheduler calls pull() to drain the buffer.
"""

import json
import logging
import re
import socketserver
import threading
from datetime import datetime
from typing import Optional

from .base import BaseGatewayAdapter, GatewayEvent

log = logging.getLogger(__name__)

# In-memory event buffer (thread-safe via lock)
_buffer: list[dict] = []
_buffer_lock = threading.Lock()
_server_thread: Optional[threading.Thread] = None
_server: Optional[socketserver.UDPServer] = None

# Patterns for email extraction
_EMAIL_RE = re.compile(r"[\w.%+\-]+@[\w.\-]+\.[a-z]{2,}", re.IGNORECASE)


class _SyslogHandler(socketserver.BaseRequestHandler):
    def handle(self):
        raw = self.request[0].decode(errors="replace").strip()
        parsed = _parse_syslog_line(raw)
        if parsed:
            with _buffer_lock:
                _buffer.append(parsed)


def _parse_syslog_line(line: str) -> Optional[dict]:
    """Parse a syslog line into a dict with email and event_type."""
    line_lower = line.lower()

    # Determine event type from message content
    event_type = None
    if "phish" in line_lower:
        event_type = "phish"
    elif "malware" in line_lower or "virus" in line_lower:
        event_type = "malware"
    elif "bec" in line_lower or "impersonat" in line_lower or "business email" in line_lower:
        event_type = "bec"
    elif "click" in line_lower and ("malicious" in line_lower or "url" in line_lower):
        event_type = "real_click"
    else:
        return None

    # Extract recipient email
    # CEF: dst=user@domain or duser=user@domain
    email = None
    for field in ("dst=", "duser=", "recipient=", "rcpt=", "to=", "usrName="):
        idx = line.find(field)
        if idx >= 0:
            rest = line[idx + len(field):].split()[0].strip(";,\"'<>")
            if "@" in rest:
                email = rest.lower()
                break

    if not email:
        # Fallback: find any email in the line
        match = _EMAIL_RE.search(line)
        if match:
            email = match.group(0).lower()

    if not email:
        return None

    return {
        "email":      email,
        "event_type": event_type,
        "raw":        line,
        "occurred_at": datetime.utcnow().isoformat(),
    }


def start_listener(port: int = 5140):
    """Start the UDP syslog listener in a background thread."""
    global _server_thread, _server
    if _server_thread and _server_thread.is_alive():
        return  # Already running
    try:
        _server = socketserver.UDPServer(("0.0.0.0", port), _SyslogHandler)
        _server_thread = threading.Thread(target=_server.serve_forever, daemon=True)
        _server_thread.start()
        log.info(f"Syslog listener started on UDP port {port}")
    except Exception as e:
        log.error(f"Syslog listener failed to start: {e}")


def stop_listener():
    global _server
    if _server:
        _server.shutdown()
        log.info("Syslog listener stopped")


class SyslogAdapter(BaseGatewayAdapter):
    name = "syslog"

    def test_connection(self) -> tuple[bool, str]:
        """For syslog we just verify the port is bindable."""
        import socket
        port = self.config.syslog_port or 5140
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", port))
            sock.close()
            return True, f"Syslog port {port}/UDP is available."
        except OSError:
            # Port already in use — likely our own listener is running
            if _server_thread and _server_thread.is_alive():
                return True, f"Syslog listener already running on port {port}/UDP."
            return False, f"Port {port}/UDP is in use by another process."

    def pull(self, since: Optional[datetime] = None) -> list[GatewayEvent]:
        """Drain the in-memory buffer and convert to GatewayEvents."""
        global _buffer
        with _buffer_lock:
            batch  = _buffer[:]
            _buffer = []

        events = []
        for record in batch:
            try:
                occurred_at = datetime.fromisoformat(record["occurred_at"])
            except Exception:
                occurred_at = datetime.utcnow()

            if since and occurred_at < since:
                continue

            events.append(GatewayEvent(
                email=record["email"],
                event_type=record["event_type"],
                gateway=self.name,
                occurred_at=occurred_at,
                raw={"line": record["raw"]},
            ))

        log.info(f"Syslog adapter drained {len(events)} events from buffer")
        return events
