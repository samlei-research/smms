
#!/usr/bin/env python3
"""
Compute Sync - tiny scheduler for a shared compute box.
 
Zero dependencies (Python >= 3.8). State lives in one JSON file.
 
Access model (no logins):
  * Reachability  = ZeroTier membership. Bind to the ZeroTier IP:
        python3 server.py --host <your-zerotier-ip> --port 8080
  * Ownership     = the client's IP. Only the IP that created a booking /
                    session can delete it. The typed name is display-only.
  * Admin         = requests coming from the host machine itself (loopback or
                    the host's own ZeroTier/LAN IP), plus any --admin IPs.
                    Admins can delete anything.
"""
import argparse
import ipaddress
import json
import os
import re
import threading
import time
from datetime import date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
 
SLOT_HOURS = 6
SLOTS_PER_DAY = 24 // SLOT_HOURS
HERE = Path(__file__).resolve().parent
EXTRA_ADMINS = set()  # filled from --admin
 
 
class ApiError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code, self.msg = code, msg
 
 
def clean(text, limit):
    return re.sub(r"\s+", " ", str(text or "")).strip()[:limit]
 
 
def require_note(note: str):
    if len(note) < 3:
        raise ApiError(400, "Planned usage is required (at least 3 characters).")
 
 
def slot_start(d: date, idx: int) -> datetime:
    return datetime(d.year, d.month, d.day) + timedelta(hours=idx * SLOT_HOURS)
 
 
def current_key() -> str:
    n = datetime.now()
    return f"{n.date().isoformat()}:{n.hour // SLOT_HOURS}"
 
 
def norm_ip(addr: str):
    ip = ipaddress.ip_address(addr.split("%")[0])
    return ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped else ip
 
 
def public(entry, ip):
    """Strip internals (IPs, flags) and tell the requester whether it is theirs."""
    if entry is None:
        return None
    out = {k: v for k, v in entry.items() if k not in ("ip", "auto", "auto_key")}
    out["mine"] = entry.get("ip") == ip
    return out
 
 
def deny_unless_owner(entry, ip, admin):
    if admin or entry.get("ip") == ip:
        return
    raise ApiError(403, f"Only {entry['name']} (the creator) or the host can remove this.")
 
 
class Store:
    """JSON-file persistence; one lock guards every read-modify-write."""
 
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.data = {"bookings": {}, "live": None}
        if path.exists():
            self.data.update(json.loads(path.read_text()))
 
    def _save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1))
        os.replace(tmp, self.path)  # atomic on POSIX: no half-written file on crash
 
    # ---- reads -----------------------------------------------------------
    def state(self, ref: date, ip: str, admin: bool):
        with self.lock:
            ws = ref - timedelta(days=ref.weekday())  # Monday
            we = ws + timedelta(days=6)
            now = datetime.now()
            key = current_key()
            week = {
                k: public(v, ip)
                for k, v in self.data["bookings"].items()
                if ws.isoformat() <= k[:10] <= we.isoformat()
            }
            return {
                "admin": admin,
                "now_ts": time.time(),
                "utc_offset": int(now.astimezone().utcoffset().total_seconds()),
                "tz": time.tzname[time.daylight and time.localtime().tm_isdst > 0],
                "slot_hours": SLOT_HOURS,
                "week_start": ws.isoformat(),
                "iso_week": ws.isocalendar()[1],
                "days": [(ws + timedelta(days=i)).isoformat() for i in range(7)],
                "today": now.date().isoformat(),
                "current_key": key,
                "current_booking": public(self.data["bookings"].get(key), ip),
                "bookings": week,
                "live": public(self.data["live"], ip),
            }
 
    # ---- writes ----------------------------------------------------------
    def book(self, d: date, idx: int, name: str, note: str, ip: str):
        require_note(note)
        with self.lock:
            if slot_start(d, idx) + timedelta(hours=SLOT_HOURS) <= datetime.now():
                raise ApiError(400, "That slot is already over.")
            key = f"{d.isoformat()}:{idx}"
            taken = self.data["bookings"].get(key)
            if taken:
                raise ApiError(409, f"Already booked by {taken['name']}.")
            self.data["bookings"][key] = {"name": name, "note": note, "created": time.time(), "ip": ip}
            self._save()
 
    def release(self, d: date, idx: int, ip: str, admin: bool):
        with self.lock:
            key = f"{d.isoformat()}:{idx}"
            bk = self.data["bookings"].get(key)
            if bk:
                deny_unless_owner(bk, ip, admin)
                del self.data["bookings"][key]
                self._save()
 
    def live_start(self, name: str, note: str, ip: str):
        """Start a session, aligned with the current 6h slot:
        - slot free               -> auto-book it for the caller (note required)
        - slot is the caller's own -> reuse its note (or require one if it has none)
        - slot is someone else's  -> session runs anyway, their booking is untouched
        """
        with self.lock:
            cur = self.data["live"]
            if cur and cur.get("ip") != ip:
                raise ApiError(409, f"{cur['name']} is already using it.")
            if cur:
                return  # already running for this client
            key = current_key()
            bk = self.data["bookings"].get(key)
            if bk and bk.get("ip") == ip and not note:
                note = bk.get("note", "")
            require_note(note)
            auto = bk is None
            if auto:
                self.data["bookings"][key] = {"name": name, "note": note, "created": time.time(), "ip": ip, "auto": True}
            self.data["live"] = {"name": name, "since": time.time(), "note": note, "ip": ip,
                                 "auto_key": key if auto else None}
            self._save()
 
    def live_stop(self, ip: str, admin: bool):
        """End the session. A slot that this session auto-booked is freed again
        if it is still the current slot, so stopping early doesn't block others."""
        with self.lock:
            cur = self.data["live"]
            if not cur:
                return
            deny_unless_owner(cur, ip, admin)
            if cur.get("auto_key") == current_key():
                self.data["bookings"].pop(cur["auto_key"], None)
            self.data["live"] = None
            self._save()
 
 
class Handler(BaseHTTPRequestHandler):
    server_version = "ComputeSync/1.1"
    store: Store
 
    # -- identity --
    def _who(self):
        """(client ip, is_admin). Proxy headers are deliberately ignored."""
        peer = norm_ip(self.client_address[0])
        local = norm_ip(self.connection.getsockname()[0])
        admin = peer.is_loopback or peer == local or str(peer) in EXTRA_ADMINS
        return str(peer), admin
 
    # -- helpers --
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
 
    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 10_000:
            raise ApiError(413, "Body too large.")
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            raise ApiError(400, "Invalid JSON.")
 
    @staticmethod
    def _slot(body):
        try:
            d = date.fromisoformat(str(body.get("date")))
            idx = int(body.get("slot"))
        except (TypeError, ValueError):
            raise ApiError(400, "Bad date/slot.")
        if not 0 <= idx < SLOTS_PER_DAY:
            raise ApiError(400, "Bad slot.")
        return d, idx
 
    @staticmethod
    def _name(body):
        name = clean(body.get("name"), 32)
        if not name:
            raise ApiError(400, "Name required.")
        return name
 
    # -- routes --
    def do_GET(self):
        url = urlparse(self.path)
        try:
            if url.path == "/api/state":
                q = parse_qs(url.query)
                try:
                    ref = date.fromisoformat(q["week"][0]) if "week" in q else date.today()
                except ValueError:
                    raise ApiError(400, "Bad week.")
                ip, admin = self._who()
                return self._json(200, self.store.state(ref, ip, admin))
            if url.path in ("/", "/index.html"):
                body = (HERE / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
            self.send_error(404)
        except ApiError as e:
            self._json(e.code, {"error": e.msg})
 
    def do_POST(self):
        path = urlparse(self.path).path
        ip, admin = self._who()
        try:
            b = self._body()
            if path == "/api/book":
                d, idx = self._slot(b)
                self.store.book(d, idx, self._name(b), clean(b.get("note"), 80), ip)
            elif path == "/api/release":
                d, idx = self._slot(b)
                self.store.release(d, idx, ip, admin)
            elif path == "/api/live/start":
                self.store.live_start(self._name(b), clean(b.get("note"), 80), ip)
            elif path == "/api/live/stop":
                self.store.live_stop(ip, admin)
            else:
                return self.send_error(404)
            self._json(200, {"ok": True})
        except ApiError as e:
            self._json(e.code, {"error": e.msg})
 
 
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="0.0.0.0", help="bind address; use your ZeroTier IP to keep it off other interfaces")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--data", default=str(HERE / "schedule.json"), help="path of the JSON state file")
    ap.add_argument("--admin", action="append", default=[], metavar="IP",
                    help="additional admin client IP (repeatable); the host itself is always admin")
    args = ap.parse_args()
 
    EXTRA_ADMINS.update(str(norm_ip(a)) for a in args.admin)
    Handler.store = Store(Path(args.data))
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Compute Sync on http://{args.host}:{args.port}  (data: {args.data}, tz: {time.tzname[0]}, "
          f"extra admins: {sorted(EXTRA_ADMINS) or 'none'})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
 
 
if __name__ == "__main__":
    main()
 
