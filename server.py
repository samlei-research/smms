
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
 
#!/usr/bin/env python3
"""
SMMS - Single Machine Multiple Students: shared-compute scheduler with OS-level slot enforcement.

Zero dependencies (Python >= 3.10, tested on 3.13; Linux for enforcement). Run as root on the
compute machine, bound to its ZeroTier IP:

    sudo python3 server.py --host <zt-ip> --port 8080 --enforce \
        --gate /srv/compute/gate --device '/dev/nvidia*'

Model
  * Users     name <-> Linux account <-> ZeroTier IP(s), kept in users.json and managed
              from the admin page. Accounts are created by you beforehand (adduser);
              this tool never creates them.
  * Identity  = client IP -> user. Unregistered IPs are read-only viewers.
              (ZeroTier authenticates members; see SECURITY.md for the IP-spoofing caveat.)
  * Operations (book, start, stop) require a registered user; only the creator
    (or an admin) can delete a booking/session.
  * Admin     = whoever presents the admin token (a root-only file, created on first
              start). NOT "requests from localhost": local shell users must not be admin.
  * Enforcement: the user holding the *current 6h slot* is the only one granted
    access to the gate directories / device nodes (POSIX ACL entry). Everyone
    else keeps whatever read-only view you mounted (see setup_ubuntu.sh).
  * Default bind is 127.0.0.1; pass --host <zerotier-ip> to serve the network.
"""
import argparse
import glob
import grp
import hmac
import ipaddress
import json
import os
import pwd
import re
import secrets
import stat
import subprocess
import sys
import threading
import time
from datetime import date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SLOT_HOURS = 6
SLOTS_PER_DAY = 24 // SLOT_HOURS
HERE = Path(__file__).resolve().parent
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
ADMIN_TOKEN = b""          # set in main(); empty = admin disabled
ALLOWED_HOSTS = set()       # extra Host header names accepted besides IP literals / localhost


def log(msg):
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}", flush=True)


class ApiError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code, self.msg = code, msg


def clean(text, limit):
    return re.sub(r"\s+", " ", str(text or "")).strip()[:limit]


def require_note(note):
    if len(note) < 3:
        raise ApiError(400, "Planned usage is required (at least 3 characters).")


def slot_start(d, idx):
    return datetime(d.year, d.month, d.day) + timedelta(hours=idx * SLOT_HOURS)


def current_key():
    n = datetime.now()
    return f"{n.date().isoformat()}:{n.hour // SLOT_HOURS}"


def norm_ip(addr):
    ip = ipaddress.ip_address(addr.split("%")[0])
    return ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped else ip


def is_me(entry, me):
    return bool(me) and entry.get("name", "").lower() == me.lower()


def public(entry, me):
    """Whitelist what the browser may see (no internals) and flag ownership."""
    if entry is None:
        return None
    out = {k: v for k, v in entry.items() if k in ("name", "note", "created", "since")}
    out["mine"] = is_me(entry, me)
    return out


def deny_unless_owner(entry, me, admin):
    if admin or is_me(entry, me):
        return
    raise ApiError(403, f"Only {entry['name']} (the creator) or an admin can remove this.")


def atomic_write(path: Path, text: str):
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # names/IPs: not world-readable
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)  # atomic on POSIX: no half-written file on crash


def load_admin_token(path: Path) -> bytes:
    """Read the admin token, creating it (mode 0600) on first start. Rotate by deleting the file."""
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_urlsafe(32) + "\n")
        log(f"[admin] created admin token: {path}  (read it with: sudo cat {path})")
    if path.stat().st_mode & 0o077:
        os.chmod(path, 0o600)
        log(f"[admin] tightened permissions on {path} to 0600")
    token = path.read_text().strip().encode()
    if len(token) < 16:
        sys.exit(f"Admin token in {path} is too short (need >= 16 chars). Delete the file to regenerate.")
    return token


# ============================================================================
# User registry:  name <-> linux account <-> ZeroTier IPs
# ============================================================================
class Users:
    def __init__(self, path: Path):
        self.path, self.lock = path, threading.Lock()
        self._mtime, self._users = None, {}

    def _load(self):  # re-read if someone edited users.json by hand
        try:
            m = self.path.stat().st_mtime_ns
        except FileNotFoundError:
            self._users, self._mtime = {}, None
            return
        if m == self._mtime:
            return
        try:
            raw = json.loads(self.path.read_text()).get("users", {})
            users = {}
            for name, u in raw.items():
                users[name] = {"linux": str(u["linux"]), "ips": [str(norm_ip(i)) for i in u.get("ips", [])]}
            self._users, self._mtime = users, m
        except Exception as e:  # keep the last good registry on a bad edit
            log(f"[users] ignoring unreadable {self.path}: {e}")
            self._mtime = m

    def _save(self):
        atomic_write(self.path, json.dumps({"users": self._users}, indent=1))
        self._mtime = self.path.stat().st_mtime_ns

    def all(self):
        with self.lock:
            self._load()
            return {n: dict(u, ips=list(u["ips"])) for n, u in self._users.items()}

    def canonical(self, name):
        with self.lock:
            self._load()
            return next((n for n in self._users if n.lower() == (name or "").lower()), None)

    def by_ip(self, ip):
        with self.lock:
            self._load()
            return next((n for n, u in self._users.items() if ip in u["ips"]), None)

    def linux_of(self, name):
        with self.lock:
            self._load()
            n = next((n for n in self._users if n.lower() == (name or "").lower()), None)
            return self._users[n]["linux"] if n else None

    def upsert(self, name, linux, ips):
        name, linux = clean(name, 32), clean(linux, 32)
        if not NAME_RE.match(name):
            raise ApiError(400, "Name: letters, digits, . _ - only (max 32).")
        try:
            pw = pwd.getpwnam(linux)
        except KeyError:
            raise ApiError(400, f"Linux account '{linux}' does not exist. Create it first: sudo adduser {linux}")
        if pw.pw_uid == 0:
            raise ApiError(400, "Refusing to map a user to root.")
        try:
            ips = sorted({str(norm_ip(clean(i, 45))) for i in ips if clean(i, 45)})
        except ValueError:
            raise ApiError(400, "Invalid IP address.")
        if not ips:
            raise ApiError(400, "At least one ZeroTier IP is required.")
        with self.lock:
            self._load()
            key = next((n for n in self._users if n.lower() == name.lower()), name)
            for other, u in self._users.items():
                if other == key:
                    continue
                if set(ips) & set(u["ips"]):
                    raise ApiError(409, f"IP already assigned to {other}.")
                if u["linux"] == linux:
                    raise ApiError(409, f"Linux account '{linux}' already belongs to {other}.")
            self._users[key] = {"linux": linux, "ips": ips}
            self._save()
        return key

    def delete(self, name):
        with self.lock:
            self._load()
            key = next((n for n in self._users if n.lower() == (name or "").lower()), None)
            if not key:
                raise ApiError(404, "No such user.")
            del self._users[key]
            self._save()
        return key


# ============================================================================
# Schedule store
# ============================================================================
class Store:
    """JSON-file persistence; one lock guards every read-modify-write."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.data = {"bookings": {}, "live": None}
        if path.exists():
            self.data.update(json.loads(path.read_text()))

    def _save(self):
        atomic_write(self.path, json.dumps(self.data, indent=1))

    def _maintain(self):
        """A live session is valid only while its owner holds the current slot."""
        live = self.data["live"]
        if live:
            bk = self.data["bookings"].get(current_key())
            if not (bk and bk["name"].lower() == live["name"].lower()):
                self.data["live"] = None
                self._save()

    def maintain(self):
        with self.lock:
            self._maintain()

    def holder(self):
        """User name holding the current slot, or None."""
        with self.lock:
            bk = self.data["bookings"].get(current_key())
            return bk["name"] if bk else None

    # ---- reads -----------------------------------------------------------
    def state(self, ref, me):
        with self.lock:
            self._maintain()
            ws = ref - timedelta(days=ref.weekday())  # Monday
            we = ws + timedelta(days=6)
            now = datetime.now()
            key = current_key()
            week = {k: public(v, me) for k, v in self.data["bookings"].items()
                    if ws.isoformat() <= k[:10] <= we.isoformat()}
            return {
                "now_ts": time.time(),
                "utc_offset": int(now.astimezone().utcoffset().total_seconds()),
                "tz": time.tzname[time.daylight and time.localtime().tm_isdst > 0],
                "slot_hours": SLOT_HOURS,
                "week_start": ws.isoformat(),
                "iso_week": ws.isocalendar()[1],
                "days": [(ws + timedelta(days=i)).isoformat() for i in range(7)],
                "today": now.date().isoformat(),
                "current_key": key,
                "current_booking": public(self.data["bookings"].get(key), me),
                "bookings": week,
                "live": public(self.data["live"], me),
            }

    # ---- writes ----------------------------------------------------------
    def book(self, d, idx, user, note):
        require_note(note)
        with self.lock:
            if slot_start(d, idx) + timedelta(hours=SLOT_HOURS) <= datetime.now():
                raise ApiError(400, "That slot is already over.")
            key = f"{d.isoformat()}:{idx}"
            taken = self.data["bookings"].get(key)
            if taken:
                raise ApiError(409, f"Already booked by {taken['name']}.")
            self.data["bookings"][key] = {"name": user, "note": note, "created": time.time()}
            self._save()

    def release(self, d, idx, me, admin):
        with self.lock:
            key = f"{d.isoformat()}:{idx}"
            bk = self.data["bookings"].get(key)
            if bk:
                deny_unless_owner(bk, me, admin)
                del self.data["bookings"][key]
                self._maintain()
                self._save()

    def live_start(self, user, note):
        """Start a session. Only the holder of the current slot may; a free
        slot is auto-booked for the caller (note required)."""
        with self.lock:
            self._maintain()
            cur = self.data["live"]
            if cur and cur["name"].lower() != user.lower():
                raise ApiError(409, f"{cur['name']} is already using it.")
            if cur:
                return
            key = current_key()
            bk = self.data["bookings"].get(key)
            if bk and not is_me(bk, user):
                raise ApiError(403, f"This slot is reserved for {bk['name']}.")
            if bk and not note:
                note = bk.get("note", "")
            require_note(note)
            auto = bk is None
            if auto:
                self.data["bookings"][key] = {"name": user, "note": note, "created": time.time(), "auto": True}
            self.data["live"] = {"name": user, "since": time.time(), "note": note,
                                 "auto_key": key if auto else None}
            self._save()

    def live_stop(self, me, admin):
        """End the session; a slot it auto-booked is freed again if still current."""
        with self.lock:
            cur = self.data["live"]
            if not cur:
                return
            deny_unless_owner(cur, me, admin)
            if cur.get("auto_key") == current_key():
                self.data["bookings"].pop(cur["auto_key"], None)
            self.data["live"] = None
            self._save()

    def purge_user(self, name):
        """User removed from the registry: drop their unfinished bookings + session."""
        with self.lock:
            now = datetime.now()
            for key in list(self.data["bookings"]):
                bk = self.data["bookings"][key]
                d, idx = date.fromisoformat(key[:10]), int(key[11:])
                if bk["name"].lower() == name.lower() and slot_start(d, idx) + timedelta(hours=SLOT_HOURS) > now:
                    del self.data["bookings"][key]
            self._maintain()
            self._save()


# ============================================================================
# OS enforcement: only the slot holder's Linux account gets access
# ============================================================================
class Enforcer:
    """
    Grants the current slot holder (and nobody else) a POSIX ACL entry on:
      * gate directories  -> --x   (traverse into the writable bind-mount behind it)
      * device nodes      -> rw-   (e.g. /dev/nvidia*)
    Idempotent: only touches a path when its named-user ACL differs from the
    desired state, so it is cheap to run every few seconds.
    """

    def __init__(self, gates, devices, enabled, dry_run):
        self.gates, self.devices = gates, devices
        self.enabled, self.dry_run = enabled, dry_run
        self.lock = threading.Lock()
        self.warnings, self.holder_linux = [], None

    def _targets(self):
        t = [(g, "--x", False) for g in self.gates]
        for pat in self.devices:
            # skip directories (e.g. /dev/nvidia-caps): only real device nodes are gated
            t += [(p, "rw-", True) for p in sorted(glob.glob(pat)) if not os.path.isdir(p)]
        return t

    @staticmethod
    def _named_users(path):
        r = subprocess.run(["getfacl", "-cp", path], capture_output=True, text=True, timeout=15)
        if r.returncode:
            raise OSError(r.stderr.strip() or "getfacl failed")
        named = {}
        for line in r.stdout.splitlines():
            f = line.split("#")[0].strip().split(":")
            if len(f) == 3 and f[0] == "user" and f[1]:
                named[f[1]] = f[2]
        return named

    def _run(self, *cmd):
        if self.dry_run:
            log("[dry-run] " + " ".join(cmd))
            return
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if r.returncode:
            raise OSError(r.stderr.strip() or f"{cmd[0]} failed")

    def reconcile(self, linux_user, registered_linux=()):
        if not (self.enabled or self.dry_run):
            return
        with self.lock:
            warnings = []
            if linux_user:
                try:
                    pwd.getpwnam(linux_user)
                except KeyError:
                    warnings.append(f"Holder's Linux account '{linux_user}' does not exist; nobody gets access.")
                    linux_user = None
            for path, perm, is_dev in self._targets():
                try:
                    st = os.stat(path)
                    if is_dev and st.st_mode & 0o007:       # 0666 device nodes would defeat the gate
                        if self.dry_run:
                            log(f"[dry-run] chmod o-rwx {path}")
                        else:
                            os.chmod(path, stat.S_IMODE(st.st_mode) & ~0o007)
                    elif not is_dev and st.st_mode & 0o007:
                        warnings.append(f"{path} is accessible by 'other' - run: chmod 0700 {path}")
                    if is_dev:
                        try:
                            members = set(grp.getgrgid(st.st_gid).gr_mem)
                            members |= {u.pw_name for u in pwd.getpwall() if u.pw_gid == st.st_gid}
                            leak = sorted(members & set(registered_linux))
                            if leak:
                                warnings.append(f"{path}: group '{grp.getgrgid(st.st_gid).gr_name}' still grants "
                                                f"access to {', '.join(leak)} (remove them from that group)")
                        except KeyError:
                            pass
                    want = {linux_user: perm} if linux_user else {}
                    if self._named_users(path) != want:
                        self._run("setfacl", "-b", path)
                        if linux_user:
                            self._run("setfacl", "-m", f"u:{linux_user}:{perm}", path)
                        log(f"[acl] {path}: access -> {linux_user or 'nobody'}")
                except Exception as e:
                    warnings.append(f"{path}: {e}")
            for g in self.gates:
                if not os.path.isdir(g):
                    warnings.append(f"Gate directory {g} does not exist (run setup-ubuntu.sh).")
            if not self._targets():
                warnings.append("No --gate/--device configured: nothing is enforced.")
            self.warnings, self.holder_linux = warnings, linux_user

    def status(self, admin):
        s = {"enabled": self.enabled, "dry_run": self.dry_run,
             "targets": [p for p, _, _ in self._targets()]}
        if admin:
            s["warnings"] = list(self.warnings)
        return s


class Controller:
    """Glues schedule + users + enforcement together; called by the loop and after each write."""

    def __init__(self, store, users, enforcer):
        self.store, self.users, self.enforcer = store, users, enforcer
        self.lock = threading.Lock()

    def tick(self):
        with self.lock:
            self.store.maintain()
            holder = self.store.holder()
            self.enforcer.reconcile(self.users.linux_of(holder) if holder else None,
                                    [u["linux"] for u in self.users.all().values()])

    def loop(self, interval):
        while True:
            try:
                self.tick()
            except Exception as e:
                log(f"[tick] {e}")
            time.sleep(interval)


# ============================================================================
# HTTP
# ============================================================================
class Handler(BaseHTTPRequestHandler):
    server_version = "SMMS/2.1"
    ctl: Controller

    def _who(self):
        """(client ip, registered user name or None). Proxy headers are ignored on purpose."""
        ip = str(norm_ip(self.client_address[0]))
        return ip, self.ctl.users.by_ip(ip)

    def _is_admin(self):
        """Admin = valid 'Authorization: Bearer <token>'. Where the request comes from does not matter."""
        auth = self.headers.get("Authorization") or ""
        if not ADMIN_TOKEN or not auth.startswith("Bearer "):
            return False
        return hmac.compare_digest(auth[7:].strip().encode(), ADMIN_TOKEN)

    def _guard(self, post):
        """Browser-attack defences (CSRF, DNS rebinding, clickjacking come from headers below)."""
        host = (self.headers.get("Host") or "").strip()
        name = (urlparse("//" + host).hostname or "").lower()
        try:
            ipaddress.ip_address(name)
            ok = True
        except ValueError:
            ok = name == "localhost" or name in ALLOWED_HOSTS
        if not ok:   # DNS rebinding: a hostile site resolving to our IP sends its own Host name
            raise ApiError(421, "Unexpected Host header. Use the IP address (or add --allowed-host).")
        if post:
            if not (self.headers.get("Content-Type") or "").lower().startswith("application/json"):
                raise ApiError(415, "Content-Type must be application/json.")   # cross-site forms can't send this
            origin = self.headers.get("Origin")
            if origin and urlparse(origin).netloc.lower() != host.lower():
                raise ApiError(403, "Cross-origin request refused.")

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
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
            d, idx = date.fromisoformat(str(body.get("date"))), int(body.get("slot"))
        except (TypeError, ValueError):
            raise ApiError(400, "Bad date/slot.")
        if not 0 <= idx < SLOTS_PER_DAY:
            raise ApiError(400, "Bad slot.")
        return d, idx

    @staticmethod
    def _need_user(user, ip):
        if not user:
            raise ApiError(403, f"Your IP ({ip}) is not registered. Ask the admin to add you.")
        return user

    @staticmethod
    def _need_admin(admin):
        if not admin:
            raise ApiError(403, "Admin only (missing or wrong admin token).")

    def do_GET(self):
        url = urlparse(self.path)
        try:
            self._guard(post=False)
            ip, user = self._who()
            admin = self._is_admin()
            if url.path == "/api/state":
                q = parse_qs(url.query)
                try:
                    ref = date.fromisoformat(q["week"][0]) if "week" in q else date.today()
                except ValueError:
                    raise ApiError(400, "Bad week.")
                st = self.ctl.store.state(ref, user)
                st.update({"admin": admin, "me": {"name": user, "ip": ip},
                           "holder": (st["current_booking"] or {}).get("name"),
                           "enforce": self.ctl.enforcer.status(admin)})
                return self._json(200, st)
            if url.path == "/api/users":
                self._need_admin(admin)
                return self._json(200, {"users": [dict(name=n, **u) for n, u in sorted(self.ctl.users.all().items())]})
            if url.path in ("/", "/index.html"):
                body = (HERE / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy",
                                 "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                                 "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
                self.end_headers()
                return self.wfile.write(body)
            self.send_error(404)
        except ApiError as e:
            self._json(e.code, {"error": e.msg})

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            self._guard(post=True)
            ip, user = self._who()
            admin = self._is_admin()
            b = self._body()
            c = self.ctl
            if path == "/api/book":
                d, idx = self._slot(b)
                c.store.book(d, idx, self._need_user(user, ip), clean(b.get("note"), 80))
            elif path == "/api/release":
                d, idx = self._slot(b)
                c.store.release(d, idx, user, admin)
            elif path == "/api/live/start":
                c.store.live_start(self._need_user(user, ip), clean(b.get("note"), 80))
            elif path == "/api/live/stop":
                c.store.live_stop(user, admin)
            elif path == "/api/users":
                self._need_admin(admin)
                ips = b.get("ips") or []
                ips = re.split(r"[,\s]+", ips) if isinstance(ips, str) else ips
                log(f"[admin] upsert user {c.users.upsert(b.get('name'), b.get('linux'), ips)}")
            elif path == "/api/users/delete":
                self._need_admin(admin)
                name = c.users.delete(b.get("name"))
                c.store.purge_user(name)
                log(f"[admin] deleted user {name}")
            else:
                return self.send_error(404)
            c.tick()  # apply access changes immediately, not at the next poll
            self._json(200, {"ok": True})
        except ApiError as e:
            self._json(e.code, {"error": e.msg})

    def log_message(self, fmt, *args):
        pass  # keep the journal for our own [acl]/[admin] lines


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default: localhost only); use your ZeroTier IP to serve the network")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--data", default=str(HERE / "schedule.json"), help="schedule state file")
    ap.add_argument("--users", default=str(HERE / "users.json"), help="user registry file")
    ap.add_argument("--admin-token-file", default=str(HERE / "admin-token"), help="root-only file holding the admin token (created if missing)")
    ap.add_argument("--allowed-host", action="append", default=[], metavar="NAME", help="extra DNS name accepted in the Host header (IPs and localhost always are)")
    ap.add_argument("--enforce", action="store_true", help="apply ACLs for the slot holder (needs root)")
    ap.add_argument("--dry-run", action="store_true", help="print the enforcement commands instead of running them")
    ap.add_argument("--gate", action="append", default=[], metavar="DIR", help="gate directory (repeatable)")
    ap.add_argument("--device", action="append", default=[], metavar="GLOB", help="device node glob, e.g. '/dev/nvidia*'")
    ap.add_argument("--interval", type=float, default=5, help="seconds between enforcement checks")
    a = ap.parse_args()

    if a.enforce and os.geteuid() != 0:
        sys.exit("--enforce needs root (it changes ACLs). Run with sudo.")
    if (a.gate or a.device) and not (a.enforce or a.dry_run):
        log("WARNING: --gate/--device given but neither --enforce nor --dry-run: nothing will be enforced.")

    global ADMIN_TOKEN
    ADMIN_TOKEN = load_admin_token(Path(a.admin_token_file))
    ALLOWED_HOSTS.update(h.lower() for h in a.allowed_host)
    if a.host in ("0.0.0.0", "::", ""):
        log("WARNING: listening on ALL interfaces. SMMS speaks plain HTTP and runs as root; bind to the ZeroTier IP instead (--host <zt-ip>).")
    store, users = Store(Path(a.data)), Users(Path(a.users))
    enforcer = Enforcer([os.path.abspath(g) for g in a.gate], a.device, a.enforce, a.dry_run)
    Handler.ctl = Controller(store, users, enforcer)
    Handler.ctl.tick()
    threading.Thread(target=Handler.ctl.loop, args=(a.interval,), daemon=True).start()

    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    log(f"SMMS on http://{a.host}:{a.port}  tz={time.tzname[0]}  "
        f"enforce={'ON' if a.enforce else 'dry-run' if a.dry_run else 'off'}  "
        f"users={len(users.all())}  admin-token={a.admin_token_file}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()