#!/usr/bin/env bash
# Prepares an Ubuntu machine for SMMS's slot enforcement. Idempotent; run as root.
# Review it before running: it edits /etc/fstab, creates mounts and installs a root systemd service.
#
#   sudo ZT_IP=10.147.17.1 ./setup_ubuntu.sh
#
# Layout it creates (BASE defaults to /srv/compute):
#
#   $BASE/.store/data   the real shared data (root:compute, setgid). $BASE/.store is 0700 root,
#                       so nobody can reach the data except through the two views below.
#   $BASE/ro            bind mount of the data: read-only + noexec. Everybody can read, nobody
#                       can write or run anything from here.
#   $BASE/gate          0700 root directory. SMMS adds an ACL entry for the CURRENT SLOT
#                       HOLDER only (--x = may walk in, nothing else).
#   $BASE/gate/work     bind mount of the data, read-write + exec. Only reachable through the gate.
#
# Why a gate dir? A bind mount shares the data's inode, so its permissions can't differ per view.
# The per-user decision therefore has to live on a real parent directory: the gate.
#
# Env: BASE, GROUP (default compute), ZT_IP (install systemd unit bound to this IP),
#      GPU_GLOB (default '/dev/nvidia*'), FSTAB, SKIP_SERVICE=1, INSTALL_DIR (/opt/smms)
set -euo pipefail

BASE=${BASE:-/srv/compute}
GROUP=${GROUP:-compute}
FSTAB=${FSTAB:-/etc/fstab}
GPU_GLOB=${GPU_GLOB:-/dev/nvidia*}
INSTALL_DIR=${INSTALL_DIR:-/opt/smms}
STORE=$BASE/.store
DATA=$STORE/data
HERE=$(cd "$(dirname "$0")" && pwd)

[ "$(id -u)" = 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }

command -v setfacl >/dev/null || { apt-get update -qq && apt-get install -y -qq acl; }
getent group "$GROUP" >/dev/null || groupadd "$GROUP"

mkdir -p "$STORE" "$DATA" "$BASE/ro" "$BASE/gate"
chown root:root "$BASE" "$STORE" "$BASE/gate"
chmod 0755 "$BASE"
chmod 0700 "$STORE" "$BASE/gate"                       # gate: ACL-managed by SMMS
chown root:"$GROUP" "$DATA"; chmod 2775 "$DATA"        # setgid: new files inherit the group
# default ACL: new files stay group-writable whatever the user's umask is, so the next
# slot holder can modify what the previous one created
setfacl -m g:"$GROUP":rwx "$DATA"
setfacl -d -m g:"$GROUP":rwx "$DATA"
mkdir -p "$BASE/gate/work"

add_fstab() {
  grep -qsF "$1 $2 " "$FSTAB" || printf '%s %s none %s 0 0\n' "$1" "$2" "$3" >> "$FSTAB"
}
add_fstab "$DATA" "$BASE/ro"        "bind,ro,noexec,nosuid,nodev"
add_fstab "$DATA" "$BASE/gate/work" "bind,nosuid,nodev"
for m in "$BASE/ro" "$BASE/gate/work"; do
  mountpoint -q "$m" || mount -T "$FSTAB" "$m"
done
# util-linux < 2.27 ignores ro on the first bind; make sure it really is read-only
mount -o remount,bind,ro,noexec,nosuid,nodev "$BASE/ro"

echo "Mounts:"; for m in "$BASE/ro" "$BASE/gate/work"; do findmnt -n -o TARGET,OPTIONS "$m" | sed 's/^/  /'; done

if [ -n "${ZT_IP:-}" ] && [ "${SKIP_SERVICE:-0}" != 1 ]; then
  install -d -m 0755 "$INSTALL_DIR"
  install -m 0644 "$HERE/index.html" "$INSTALL_DIR/index.html"
  install -m 0755 "$HERE/server.py"  "$INSTALL_DIR/server.py"
  cat > /etc/systemd/system/smms.service <<EOF
[Unit]
Description=SMMS (slot scheduler + access gate)
After=network-online.target zerotier-one.service local-fs.target
Wants=network-online.target

[Service]
# Retry until the ZeroTier address exists (it can appear after boot).
ExecStart=/usr/bin/python3 $INSTALL_DIR/server.py --host $ZT_IP --port 8080 --enforce \\
  --gate $BASE/gate --device '$GPU_GLOB' \\
  --data $INSTALL_DIR/schedule.json --users $INSTALL_DIR/users.json \\
  --admin-token-file $INSTALL_DIR/admin-token
UMask=0077
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now smms.service
  echo "Service started: http://$ZT_IP:8080  (logs: journalctl -u smms -f)"
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$INSTALL_DIR/admin-token" ] && break; sleep 0.5; done
  echo "Admin token (root-only file): sudo cat $INSTALL_DIR/admin-token"
else
  echo "Skipped service install (set ZT_IP=<your zerotier ip> to install it)."
fi

cat <<EOF

Next, per person (accounts are created manually, the tool only maps to them):
  sudo adduser alice
  sudo adduser alice $GROUP
Then open the web UI, click "Admin", paste the admin token (sudo cat $INSTALL_DIR/admin-token),
click "Users" and add:  name, linux account, ZeroTier IP(s).
EOF