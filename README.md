# edo

> _reanimation protocol · ctf infrastructure_

A standalone Linux CLI that bridges **WireGuard** and **Docker** so a single
operator can stand up isolated, per-challenge containers for Capture-The-Flag
events. Participants dial in over the VPN, each lands on their own VPN IP, and
each challenge runs on its own static IP on a dedicated Docker bridge. State
lives in SQLite, traffic is policed by `iptables` from a dedicated chain.

---

## What it gives you

- **Per-participant WireGuard peers** with auto-allocated IPs (`10.8.0.0/24`).
- **Per-challenge containers** with static IPs on `edo_br0` (`10.9.0.0/24`).
- **Client isolation** — participants cannot see each other on the VPN.
- **Egress containment** — challenge containers cannot reach the public internet.
- **Reverse-shell channel** — containers _can_ originate connections back to
  the VPN subnet, so participants catch callbacks from exploited services.
- **One source of truth** — SQLite at `/var/lib/edo/edo.db` tracks every
  peer and container so restarts don't lose state.

---

## Requirements

- Linux host (tested on Debian/Ubuntu-class distros; anything with `iptables`,
  `iproute2`, and a recent kernel will do).
- Root privileges. `edo` refuses to start without them.
- **System packages**
  ```
  wireguard-tools     # provides wg, wg-quick
  iptables
  iproute2            # provides ip
  docker-ce / docker.io + docker-compose-plugin
  ```
- **Python 3.10+** with the deps in `requirements.txt`:
  ```
  pip install -r requirements.txt
  ```

---

## Install

```bash
git clone https://github.com/Agentkiller9/edo.git /opt/edo
cd /opt/edo
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run via `sudo`:

```bash
sudo /opt/edo/.venv/bin/python /opt/edo/edo.py <command>
```

> ⚠ **Do not run `sudo python3 edo.py` from an activated venv.** `sudo`
> resets `PATH` and ignores venv activation — it resolves `python3` to the
> system interpreter, which does not see packages you `pip install`ed into
> the venv. You'll get `ModuleNotFoundError: No module named 'docker'` even
> though `pip install` succeeded. Always point `sudo` at the venv's
> interpreter explicitly: `sudo ./myvenv/bin/python edo.py`.

Optionally drop a wrapper into `/usr/local/bin/edo`:

```bash
sudo tee /usr/local/bin/edo >/dev/null <<'EOF'
#!/usr/bin/env bash
exec /opt/edo/.venv/bin/python /opt/edo/edo.py "$@"
EOF
sudo chmod +x /usr/local/bin/edo
```

---

## Quick start

```bash
# 1. Bring up the VPN + firewall + docker bridge
sudo edo init --endpoint vpn.your-ctf.example --port 51820

# 2. Bind a participant — produces /etc/wireguard/edo_clients/alice.conf
sudo edo add-peer alice --endpoint vpn.your-ctf.example

# 3. Summon a challenge from a directory containing a Dockerfile or compose file
sudo edo summon /opt/ctf-challenges/sql-injection --name sqli-01

# 4. See the live footprint
sudo edo status

# 5. Release a single vessel...
sudo edo release --container <id>

# ...or lift the entire seal
sudo edo teardown --yes
```

Hand `edo_clients/alice.conf` to the participant. They drop it into
`wg-quick` (or the WireGuard mobile/desktop app) and they're on.

---

## Interactive mode

Run `sudo edo` with no arguments for the menu:

```
  [1] Show status footprint
  [2] Summon a challenge (deploy)
  [3] Bind a new peer (add WireGuard client)
  [4] Release a vessel (teardown container)
  [5] Initialise / re-apply infrastructure
  [6] Lift the seal (teardown everything)
  [q] Quit
```

---

## Commands

| Command | Purpose |
| --- | --- |
| `edo init --endpoint HOST [--port N]` | Create the WireGuard server config, install iptables rules, create the Docker bridge, bring `wg0` up. Idempotent. |
| `edo add-peer USERNAME --endpoint HOST` | Allocate the next free VPN IP, generate keys, append the peer to the server config, apply it live, and write a client `.conf`. |
| `edo remove-peer USERNAME` | Inverse of `add-peer`. |
| `edo summon PATH [--name NAME]` | Detect a `Dockerfile` or `docker-compose.yml` in `PATH`, build, run, attach to `edo_br0` with a static IP, log to DB. |
| `edo release --container ID` | Stop + remove a single container. |
| `edo release --all` | Stop + remove every container `edo` knows about. |
| `edo status` | Print the bound peers and running containers as tables. |
| `edo teardown [--yes]` | Release every container, remove the bridge, lift the firewall, bring `wg0` down. |
| `edo menu` | Open the interactive menu (this is also the default with no command). |
| `edo doctor [--no-runtime]` | Diagnose the host: required binaries, kernel module, default route, docker daemon, port availability. Runs as non-root so you can spot the missing pieces *before* `sudo`. |

Global flags:

- `--db PATH` — override SQLite path (default `/var/lib/edo/edo.db`).
- `--verbose / -v` — enable DEBUG logging.

---

## Network topology

```
   participant ──wg──▶  wg0 (10.8.0.0/24)
                          │
                          │  edo iptables policy
                          ▼
                     edo_br0 (10.9.0.0/24)
                          │
                          ▼
                   challenge containers
```

edo installs rules in **two dedicated iptables chains**:

| Chain | Hooked into | Purpose |
| --- | --- | --- |
| `EDO_FORWARD` | `DOCKER-USER` (preferred), else `FORWARD` | The three forwarding guarantees below. Hooked into `DOCKER-USER` when Docker is installed so the rules survive `systemctl restart docker` — Docker preserves `DOCKER-USER`'s place at the top of `FORWARD`, which keeps our hook ahead of Docker's `DOCKER-FORWARD` chain (whose default behaviour will silently drop wg0→edo_br0 traffic). `edo doctor` flags this if the hook ever ends up in the wrong place. |
| `EDO_INPUT`   | `INPUT` | Accept the WireGuard handshake on `udp/51820`. Installed only when firewalld is *not* the active firewall — when firewalld is active, `edo init` runs `firewall-cmd --add-port=51820/udp --permanent` instead so a reload doesn't wipe it. |

Three forwarding guarantees, enforced in `EDO_FORWARD`:

1. **Client isolation.** Any packet whose source _and_ destination are inside
   `10.8.0.0/24` is `DROP`ped.
2. **Egress containment.** Packets sourced from `10.9.0.0/24` leaving via the
   host's default-route interface are `DROP`ped.
3. **Reverse-shell exception.** Packets from `10.9.0.0/24` to `10.8.0.0/24`
   are `ACCEPT`ed — evaluated _before_ the egress drop.

Docker's own `DOCKER` / `DOCKER-USER` chains are not modified. `edo teardown`
unhooks and deletes only its own chain.

---

## Layout on disk

| Path | What lives there |
| --- | --- |
| `/var/lib/edo/edo.db` | SQLite state (peers + containers). |
| `/etc/wireguard/wg0.conf` | Server config (regenerated on peer add/remove). |
| `/etc/wireguard/edo_clients/<user>.conf` | Generated client configs. |
| `EDO_FORWARD` (iptables) | All edo-installed firewall rules. |
| `edo_br0` (docker network) | Bridge for challenge containers. |

---

## Challenge directory layout

Two layouts are supported. `edo summon` detects which one by looking for files
in the directory you pass.

**Dockerfile** — single-container challenge:

```
sqli-01/
└── Dockerfile
```

**docker-compose** — multi-service challenge (web + db, etc.):

```
chain-01/
├── docker-compose.yml
├── web/
│   └── Dockerfile
└── db/
    └── init.sql
```

For compose deployments, each spawned container is attached to `edo_br0`
with a static IP from `10.9.0.0/24` _in addition to_ any networks compose
created. The IP `edo` assigns is what gets recorded in the DB and surfaced
to participants in `edo status`.

---

## Troubleshooting

**Always start with `edo doctor`.** It runs without root, checks every
prerequisite, and tells you the exact `apt` / `dnf` / `pacman` command
needed to fix anything missing. Critical issues block `init` / `add-peer` /
`summon` automatically — those commands run the same checks before they
touch anything.

```bash
./myvenv/bin/python edo.py doctor              # full diagnosis (no root)
sudo ./myvenv/bin/python edo.py doctor         # full diagnosis (root)
./myvenv/bin/python edo.py doctor --no-runtime # skip docker daemon/port checks
```

What it checks:

| | |
| --- | --- |
| root privileges | `os.geteuid() == 0` |
| binaries | `wg`, `wg-quick`, `iptables`, `ip`, `sysctl`, `docker` |
| python SDK | `import docker` |
| kernel | `wireguard` module loaded or loadable |
| sysctl | `net.ipv4.ip_forward` |
| routing | default IPv4 route present |
| docker | daemon reachable via `ping()` |
| docker | `10.9.0.0/24` not already owned by another bridge |
| wg0 | interface state |
| port | `51820/udp` available (host can bind) |
| firewall | `51820/udp` accepted by firewalld or `EDO_INPUT` |

Specific failure modes worth knowing:

- **`ModuleNotFoundError: No module named 'docker'` under sudo** — `sudo`
  resets PATH and ignores venv activation, so `sudo python3` runs the
  system interpreter, not your venv's. Run sudo against the venv's
  interpreter directly: `sudo ./myvenv/bin/python edo.py`.
- **`apply_firewall` complains about the public interface** — `edo` resolves
  the egress interface from `ip -4 route show default`. If your host has no
  default IPv4 route, set one before running `init`.
- **`wg-quick up wg0` says "already exists"** — harmless, `edo` treats it as
  a no-op.
- **Container can reach the internet** — sanity-check that `EDO_FORWARD` is
  still hooked: `iptables -L FORWARD --line-numbers | head`. The first jump
  should be to `EDO_FORWARD`. If Docker re-installed rules ahead of it,
  re-run `edo init`.
- **Peer can't reach a container** — confirm the peer's `AllowedIPs`
  includes `10.9.0.0/24`. The generated client config does this by default;
  hand-edited configs might not.

---

## Development

```bash
# Syntax-check everything without a Linux host:
python -c "import ast, pathlib; [ast.parse(p.read_text()) for p in pathlib.Path('.').rglob('*.py')]"
```

The code targets Python 3.10+; everything is typed and uses dataclasses for
structured returns. No `os.system` — all shell-out goes through
`subprocess.run` with `capture_output=True, check=True` and explicit
`CalledProcessError` handling.

---

## License

Not yet set. Treat as all rights reserved until a license file lands.
