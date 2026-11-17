# Security policy

SMMS is a small tool that runs **as root** on a shared machine and changes file permissions (POSIX ACLs)
and device-node modes. Read this before deploying it, and review the code: it is short on purpose.

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's private reporting:
**Security tab -> "Report a vulnerability"** on this repository. Include the version/commit, what you did,
and what happened. I will acknowledge within a few days; this is a hobby/research project without a
guaranteed response time.

## Threat model

**Designed for:** a small group of people you know (a lab, a course) sharing one machine over a private
ZeroTier network, where the goal is to *prevent accidents and honest-mistake conflicts*, and to make
"only the booked person may modify/run things on the shared data" hold against ordinary users.

**Not designed for:** the open internet, hostile users with root, or defending against a determined
attacker who already controls a member's device or the ZeroTier network.

### What SMMS relies on

| Assumption | Consequence if it is false |
|---|---|
| **Client IP = identity.** Only registered ZeroTier IPs can act as a user. | A network member who can send packets *as another member's IP* can act as that member. ZeroTier authenticates members, but check your network's flow rules; if you cannot rule this out, treat SMMS as advisory. |
| **The admin token stays secret.** It lives in a root-only file (`0600`). | Whoever has the token is admin: they can manage users and remove any booking/session. Rotate by deleting the file and restarting. |
| **Traffic is on the private ZeroTier network.** SMMS speaks plain HTTP (ZeroTier encrypts the link). | Exposed on another interface, the admin token and session would cross the network unencrypted. Bind to the ZeroTier IP (`--host`), never `0.0.0.0` on an untrusted network. |
| **The Linux accounts are separate people.** | If two people share an account, they share the slot. |

### What is hardened

* **Admin is a token, not a location.** Requests from localhost or from the machine's own IP are *not* admin,
  so students with a shell on the machine cannot manage SMMS.
* **Bind defaults to `127.0.0.1`.** You must pass `--host <zerotier-ip>` to serve the network; `0.0.0.0` logs a warning.
* **Browser attacks:** POSTs require `Content-Type: application/json` and a same-origin `Origin` (cross-site
  CSRF is refused); the `Host` header must be an IP or an allowed name (DNS rebinding is refused); the page
  sends `X-Frame-Options: DENY` and a restrictive CSP.
* **Private data:** `users.json`, `schedule.json` and `admin-token` are written with mode `0600`.
  They are git-ignored; never commit them (they contain names and IPs).
* **No shell-injection surface:** external commands (`setfacl`, `getfacl`) are run without a shell, with
  arguments built only from Linux account names that must already exist on the machine.

## Known limitations

* No process killing at slot end: a running job keeps running after handover (see README).
* The gate covers the shared data tree and configured device nodes, not the whole OS.
* Members of a device node's owning group (e.g. `video`) keep access to it.
* No rate limiting or audit log beyond the service journal (`journalctl -u smms`).
* If the service is stopped, the last ACLs remain until it starts again.

## Deployment checklist

- [ ] `--host` is the ZeroTier IP (or `127.0.0.1` behind your own tunnel), not `0.0.0.0`.
- [ ] ZeroTier network is **private** (members approved by you) with flow rules you have reviewed.
- [ ] `/opt/smms/admin-token`, `users.json`, `schedule.json` are `0600` root (the server enforces this).
- [ ] Tried `--dry-run` first and checked the printed `setfacl` commands.
- [ ] You can still log in as root/sudo through a path that does not depend on SMMS (SMMS never touches your admin account's access).