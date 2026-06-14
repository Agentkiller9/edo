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
- **Per-challenge containers** with static IPs on `edo_br0` (`10.9.0.0/24`), created in Docker's **routed gateway mode** (Docker 24+) so containers keep their real IPs through the tunnel — `ping` works both ways and reverse shells see the actual VPN source IP.
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
| `edo add-peer USERNAME --public-key KEY` | Client-side-key mode: the participant generates their own keypair and gives you only the public key. The server stores `private_key=NULL` and the rendered config carries a placeholder they fill in locally. The private key never touches the server. |
| `edo add-peers --from teams.csv --endpoint HOST` | Bulk-import peers. CSV columns: `username` and optional `public_key` (header row optional). Username-only rows get server-generated keys; rows with a public key use client-side-key mode. One bad row never aborts the batch — a summary prints at the end. |
| `edo remove-peer USERNAME` | Inverse of `add-peer`. |
| `edo export USERNAME` | Print a peer's client config to stdout (pipe-friendly). |
| `edo export USERNAME -o PATH` | Write a copy of the config to PATH. |
| `edo export --all -o peers.tar.gz` | Bundle every peer's client config into a tarball. |
| `edo summon PATH [--name NAME]` | Detect a `Dockerfile` or `docker-compose.yml` in `PATH`, build, run, attach to `edo_br0` with a static IP, log to DB. |
| `edo release --container ID` | Stop + remove a single container. |
| `edo release --all` | Stop + remove every container `edo` knows about. |
| `edo status` | Print the bound peers and running containers as tables. The peer table shows live tunnel state pulled from `wg show wg0 dump` — an **Online** column (✓/✗), **Last HS** (handshake age), and **Transfer** (rx↓/tx↑) — so you can see at a glance who's actually connected during a CTF. Peers with no live record (wg0 down, or never connected) show `—`. |
| `edo teardown [--yes]` | Release every container, remove the bridge, lift the firewall, bring `wg0` down. State (server config, client configs, DB) is preserved so the next `init` restores everything. |
| `edo purge [--yes] [--wipe-state]` | Deep cleanup. Like `teardown`, but also: removes every container labelled `edo.managed=true`, disables `wg-quick@wg0.service`, strips any leftover `EDO_FORWARD`/`EDO_INPUT` chains. Add `--wipe-state` to also delete `/etc/wireguard/wg0.conf`, the client configs, and the SQLite DB. Use when the host is in an unknown state or you're migrating bridge modes. |
| `edo menu` | Open the interactive menu (this is also the default with no command). |
| `edo doctor [--no-runtime]` | Diagnose the host: required binaries, kernel module, default route, docker daemon, port availability. Runs as non-root so you can spot the missing pieces *before* `sudo`. |

Global flags:

- `--db PATH` — override SQLite path (default `/var/lib/edo/edo.db`).
- `--client-dir PATH` — where to write generated client `.conf` files. Defaults to `/etc/wireguard/edo_clients/`, or the value of `$EDO_CLIENT_CONFIG_DIR` if set. Used by `add-peer`, `remove-peer`, and `purge --wipe-state`. Useful when you want configs in `/home/operator/ctf-configs/` so `scp`/`rsync` to participants doesn't need `sudo`.
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

## Key handling: server-side vs client-side

By default (`edo add-peer alice`) edo generates the WireGuard keypair for
you and writes a ready-to-import client config. Convenient, but the
server then holds the participant's private key — in the SQLite DB and in
the on-disk client config.

For untrusted infra or a security-conscious CTF, prefer **client-side
keys**: the participant generates their own keypair and gives you only
the public half.

Participant runs locally:

```bash
wg genkey | tee privatekey | wg pubkey > publickey
cat publickey   # send this to the organizer
```

Organizer:

```bash
sudo python3 edo.py add-peer alice --public-key "$(cat publickey)"
```

The server stores `private_key=NULL`; the generated `alice.conf` has a
`PrivateKey = <PASTE_YOUR_PRIVATE_KEY_HERE>` placeholder. The participant
drops their private key into that one line and imports. The private key
never exists on the server.

Bulk version — a CSV with a `public_key` column uses client-side mode per
row automatically:

```csv
username,public_key
alice,bGmsK2...44chars...=
bob,Qf9aBc...44chars...=
```

```bash
sudo python3 edo.py add-peers --from teams.csv --endpoint vpn.example
```

The interactive `add-peer` flow also prompts for an optional public key,
so menu users get the same choice.

## Container security model

`edo` runs as host root (it has to — iptables, WireGuard, and the docker
socket all require it), but **container root is not host root**. Linux
namespaces (mount, pid, net, ipc) isolate each container's "uid 0" from
the host. Participants who pwn a service and get an in-container shell
have what amounts to a normal unprivileged process on the host, under
`dockerd`'s cgroup.

Default hardening every `summon` applies to a Dockerfile deployment:

| Setting | Why |
| --- | --- |
| `--security-opt no-new-privileges:true` | Blocks setuid-based privilege escalation from inside the container. |
| `--cap-drop NET_RAW` | Without `NET_RAW`, a compromised container can't sniff or spoof packets on `edo_br0`. Real lateral-movement protection between challenges. |
| Default Docker capability set (minus the above) | Doesn't break challenges that legitimately need `SETUID`, `CHOWN`, `KILL`, etc. |
| Default seccomp profile, no `--privileged`, no `docker.sock` mount, no host-path mounts, no shared namespaces | These are the *common* container-escape vectors. `edo` doesn't use any of them. |
| Restart policy `unless-stopped` | A crashed container comes back. Override with `--restart no` if you want pwned containers to stay dead so you can inspect them. |

Optional hardening flags on `edo summon`:

| Flag | What it does |
| --- | --- |
| `--memory 512m` | Hard memory cap. A team's fork bomb stays a team's problem. |
| `--cpus 1.0` | CPU cap. |
| `--pids-limit 100` | Max processes inside the container. The real fork-bomb defense. |
| `--read-only` | Rootfs is read-only; `/tmp` is a 64 MB tmpfs. Most CTF web challenges work unchanged. |
| `--cap-add CAP` / `--cap-drop CAP` | Repeatable. Tune capabilities per challenge. `NET_RAW` is always dropped regardless. |
| `--allow-setuid` | Disable `no-new-privileges`. Only use if a challenge intentionally relies on setuid bits. |
| `--restart {no\|on-failure\|unless-stopped\|always}` | Restart policy. |

Recommended baseline for a typical web challenge:

```bash
sudo python3 edo.py summon /path/to/challenge \
  --memory 512m --cpus 1 --pids-limit 100 --read-only
```

A "hardening" line shows after deploy so you see what's active:

```
[+] sqli-01  ->  abc123def456  @ 10.9.0.5
    hardening: no-new-privs cap-drop=NET_RAW read-only mem=512m cpus=1 pids=100 restart=unless-stopped
```

**Compose deployments don't get these flags** — `docker compose` owns the
service spec, so we'd have to merge into the YAML at runtime. `edo` emits
a warning if you pass hardening flags with a compose challenge, telling
you to declare the equivalent `security_opt:` / `cap_drop:` /
`mem_limit:` / `cpus:` keys in the compose file itself.

What edo *doesn't* protect against and probably never will:

- **Kernel CVEs.** Containers share the host kernel. Keep your host patched.
- **runc / containerd CVEs.** Keep Docker patched.
- **Intentionally vulnerable challenges that mount sensitive paths in their own Dockerfile.** Review challenge Dockerfiles before deploying — `edo` builds and runs whatever you point it at.

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
