<div align="center">

<pre>
   ▄████████ ████████▄   ▄██████▄
  ███    ███ ███   ▀███ ███    ███
  ███    █▀  ███    ███ ███    ███
 ▄███▄▄▄     ███    ███ ███    ███
▀▀███▀▀▀     ███    ███ ███    ███
  ███    █▄  ███    ███ ███    ███
  ███    ███ ███   ▄███ ███    ███
  ██████████ ████████▀   ▀██████▀
</pre>

### 𝐄𝐝𝐨 𝐓𝐞𝐧𝐬𝐞𝐢 · 反 ❲ reanimation protocol ❳ 魂

**Summon vulnerable containers. Bind participants over a VPN. Seal them off from each other.**
A single-operator CLI that fuses **WireGuard** + **Docker** into ready-to-fight CTF infrastructure.

<br>

![Python](https://img.shields.io/badge/python-3.10+-1f6feb?style=for-the-badge&logo=python&logoColor=white)
![Linux](https://img.shields.io/badge/linux-only-202020?style=for-the-badge&logo=linux&logoColor=white)
![WireGuard](https://img.shields.io/badge/WireGuard-88171A?style=for-the-badge&logo=wireguard&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)

</div>

---

## ⛩ The Jutsu

> Each participant lands on their own VPN IP. Each challenge is reanimated on its own static IP. The seal keeps them apart.

- 🩸 **Bind vessels** — per-participant WireGuard peers, IPs auto-allocated on `10.8.0.0/24`.
- 💀 **Reanimate challenges** — containers get static IPs on `10.9.0.0/24` in Docker **routed mode**, so pings work both ways and reverse shells see the real source IP.
- 🚧 **Client isolation** — participants can't touch each other across the VPN.
- ⛔ **Egress containment** — challenge containers can't reach the internet…
- 📡 **…except reverse shells** — containers *may* call back into the VPN, so players catch their shells.
- 📓 **One source of truth** — SQLite at `/var/lib/edo/edo.db` survives restarts.

---

## 🔮 The Ritual — quick start

```bash
# 0. Diagnose the host first (runs without root)
sudo edo doctor

# 1. Prepare the seal — VPN + firewall + docker bridge
sudo edo init --endpoint vpn.your-ctf.example

# 2. Bind a vessel — writes /etc/wireguard/edo_clients/alice.conf
sudo edo add-peer alice

# 3. Reanimate a challenge from its directory
sudo edo summon /opt/challenges/sqli --memory 512m --pids-limit 100 --read-only

# 4. Watch the battlefield
sudo edo status

# 5. Lift the seal when it's over
sudo edo teardown --yes
```

Hand `alice.conf` to the participant → they import it into the WireGuard app → they're in.

> 💡 No arguments? `sudo edo` opens an **interactive menu** with prompts for everything below.

---

## 📜 Commands

#### 🩸 Vessels — WireGuard peers
| Command | Does |
| --- | --- |
| `edo add-peer USER` | Bind a participant; edo generates the keypair + client config. |
| `edo add-peer USER --public-key KEY` | Client-side keys — server **never** sees the private key. |
| `edo add-peers --from teams.csv` | Bulk-bind a whole roster (`username[,public_key]` rows). |
| `edo remove-peer USER` | Unbind a participant. |
| `edo export USER` / `--all -o peers.tar.gz` | Re-print a config / bundle the whole roster. |

#### 💀 Reanimation — challenges
| Command | Does |
| --- | --- |
| `edo summon PATH [--name N]` | Build + run a `Dockerfile`/`compose` challenge on the bridge. |
| `edo release --container ID` | Release one container. |
| `edo release --all` | Release every reanimated challenge. |

#### 👁 Divination — read the battlefield
| Command | Does |
| --- | --- |
| `edo status` | Live table: peers (online ✓/✗, last handshake, transfer) + containers. |
| `edo doctor [--no-runtime]` | Pre-flight every prerequisite; prints exact fix commands. Non-root. |

#### ⛩ The Seal — lifecycle
| Command | Does |
| --- | --- |
| `edo init --endpoint HOST [--port N]` | Stand up VPN + firewall + bridge. Idempotent. |
| `edo teardown [--yes]` | Tear down infra, **keep** state for next `init`. |
| `edo purge [--yes] [--wipe-state]` | Deep clean every edo artifact; `--wipe-state` also deletes configs + DB. |

<details>
<summary><b>Global flags</b></summary>

<br>

- `--db PATH` — SQLite location (default `/var/lib/edo/edo.db`).
- `--client-dir PATH` — where client `.conf` files land (default `/etc/wireguard/edo_clients/`, or `$EDO_CLIENT_CONFIG_DIR`). Point it at a non-root dir so `scp` to players doesn't need `sudo`.
- `--verbose / -v` — DEBUG logging.

</details>

---

## 📦 Installation

<details>
<summary><b>System packages + Python deps + the one sudo gotcha</b></summary>

<br>

**Requirements:** a Linux host (root required) with these packages —

```bash
# Debian/Ubuntu
sudo apt install wireguard-tools iptables iproute2 docker.io docker-compose-plugin
# RHEL/Alma/Rocky
sudo dnf install wireguard-tools iptables iproute docker-ce docker-compose-plugin
```
Docker **24+** is needed for routed-bridge mode. `edo doctor` verifies all of this.

**Install:**

```bash
git clone https://github.com/Agentkiller9/edo.git /opt/edo
cd /opt/edo
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

**Run it** — point `sudo` at the venv's interpreter directly:

```bash
sudo /opt/edo/.venv/bin/python /opt/edo/edo.py <command>
```

> ⚠️ **The #1 footgun:** `sudo python3 edo.py` from an *activated* venv still
> fails with `ModuleNotFoundError: No module named 'docker'`. `sudo` resets
> `PATH` and ignores venv activation, so it runs the system Python. Always
> sudo the venv binary: `sudo .venv/bin/python edo.py`.

**Optional** — a global `edo` wrapper:

```bash
sudo tee /usr/local/bin/edo >/dev/null <<'EOF'
#!/usr/bin/env bash
exec /opt/edo/.venv/bin/python /opt/edo/edo.py "$@"
EOF
sudo chmod +x /usr/local/bin/edo
```

</details>

---

## 🕸 Network topology

<details>
<summary><b>The seal — subnets, chains & the three guarantees</b></summary>

<br>

```
   participant ──wg──▶  wg0  (10.8.0.0/24)
                          │
                          │   EDO_FORWARD  (iptables policy)
                          ▼
                       edo_br0  (10.9.0.0/24)
                          │
                          ▼
                    challenge containers
```

edo manages **two dedicated iptables chains** and never touches your other rules:

| Chain | Hooked into | Purpose |
| --- | --- | --- |
| `EDO_FORWARD` | `DOCKER-USER` (else `FORWARD`) | The three guarantees below. Lives in `DOCKER-USER` so it survives `systemctl restart docker` — otherwise Docker's `DOCKER-FORWARD` chain jumps ahead and silently drops wg0→edo_br0 traffic. `edo doctor` flags it if the hook drifts. |
| `EDO_INPUT` | `INPUT` | Opens `udp/51820` for the WG handshake. When firewalld is active, edo uses `firewall-cmd --add-port` instead so a reload can't wipe it. |

**Three guarantees enforced in `EDO_FORWARD`:**

1. **Client isolation** — src *and* dst inside `10.8.0.0/24` → `DROP`.
2. **Egress containment** — `10.9.0.0/24` out the public NIC → `DROP`.
3. **Reverse-shell channel** — `10.9.0.0/24` → `10.8.0.0/24` → `ACCEPT` (evaluated *before* the egress drop).

</details>

---

## 🔑 Key handling — server-side vs client-side

<details>
<summary><b>Keep participants' private keys off the server</b></summary>

<br>

**Default** (`edo add-peer alice`) — edo generates the keypair. Convenient, but the server holds the private key (DB + on-disk config).

**Client-side keys** (recommended for untrusted infra) — the participant keeps their private key. They run:

```bash
wg genkey | tee privatekey | wg pubkey   # send only the public key
```

You bind it:

```bash
sudo edo add-peer alice --public-key "<their-public-key>"
```

edo stores `private_key=NULL`; the generated config carries a
`PrivateKey = <PASTE_YOUR_PRIVATE_KEY_HERE>` placeholder they fill in locally. The private key never touches the server.

**Bulk** — a CSV with a `public_key` column uses client-side mode per row automatically:

```csv
username,public_key
alice,bGmsK2...=
bob,Qf9aBc...=
```
```bash
sudo edo add-peers --from teams.csv --endpoint vpn.example
```

</details>

---

## 🛡 Container security model

<details>
<summary><b>Container root ≠ host root — and how edo hardens it</b></summary>

<br>

edo runs as host root (iptables/WireGuard/docker need it), but a reanimated
container's `uid 0` is namespaced — a pwned challenge is just an unprivileged
process under `dockerd`, not root on your host.

**Applied by default to every Dockerfile `summon`:**

| Setting | Why |
| --- | --- |
| `no-new-privileges:true` | Blocks setuid escalation inside the container. |
| `cap-drop NET_RAW` | No sniffing/spoofing on the bridge — kills lateral movement. |
| no `--privileged`, no `docker.sock`, no host mounts, no shared namespaces | The common escape vectors — edo uses none of them. |
| default seccomp + capability set | Doesn't break legit challenges. |

**Opt-in hardening flags:**

| Flag | Effect |
| --- | --- |
| `--memory 512m` · `--cpus 1` · `--pids-limit 100` | Resource caps — contain fork bombs / OOM. |
| `--read-only` | Read-only rootfs + 64 MB tmpfs `/tmp`. |
| `--cap-add` / `--cap-drop` | Per-challenge capability tuning (`NET_RAW` always dropped). |
| `--allow-setuid` | Disable `no-new-privileges` (only if a challenge needs it). |
| `--restart {no\|on-failure\|unless-stopped\|always}` | Restart policy. |

Recommended baseline:

```bash
sudo edo summon /path/to/challenge --memory 512m --cpus 1 --pids-limit 100 --read-only
```

> ⚠️ **Compose challenges** ignore these flags — `docker compose` owns the spec.
> Declare `security_opt` / `cap_drop` / `mem_limit` / `cpus` in the YAML instead.
> Not covered, ever: **kernel / runc CVEs** (keep the host patched) and
> **malicious challenge Dockerfiles** (review them — edo runs what you point it at).

</details>

---

## 🩺 Troubleshooting

<details>
<summary><b>Start with <code>edo doctor</code> — then the usual suspects</b></summary>

<br>

`edo doctor` runs without root, checks every prerequisite, and prints the exact
`apt`/`dnf`/`pacman` fix. `init` / `add-peer` / `summon` run the same checks
before touching anything.

| Symptom | Fix |
| --- | --- |
| `ModuleNotFoundError: docker` under sudo | `sudo` ignores the venv — run `sudo .venv/bin/python edo.py`. |
| `apply_firewall` can't find the public interface | No default route — `ip -4 route show default` must return something. |
| `wg-quick up wg0` says *already exists* | Harmless — edo treats it as a no-op. |
| Container reaches the internet | `EDO_FORWARD` hook drifted below `DOCKER-FORWARD` — re-run `edo init`. |
| Peer can't reach a container | Client `AllowedIPs` must include `10.9.0.0/24` (the generated config does). |
| No handshake at all | Open `udp/51820` (provider firewall too), confirm `wg0` is up. |

</details>

---

## 🗂 Reference

<details>
<summary><b>On-disk layout & challenge directory formats</b></summary>

<br>

**Where state lives:**

| Path | Contents |
| --- | --- |
| `/var/lib/edo/edo.db` | SQLite — peers + containers. |
| `/etc/wireguard/wg0.conf` | Server config (regenerated on peer changes). |
| `/etc/wireguard/edo_clients/<user>.conf` | Generated client configs. |
| `EDO_FORWARD` / `EDO_INPUT` | iptables chains. |
| `edo_br0` | Docker bridge network. |

**Challenge layouts** (`edo summon` autodetects):

```
sqli/                 chain/
└── Dockerfile        ├── docker-compose.yml
                      ├── web/Dockerfile
                      └── db/init.sql
```

Single `Dockerfile` → build + run one container. `compose` file → `docker compose up`,
then each service is attached to `edo_br0` with a static IP recorded in the DB.

</details>

<details>
<summary><b>Development</b></summary>

<br>

```bash
# Syntax-check every module without a Linux host
python -c "import ast,pathlib;[ast.parse(p.read_text()) for p in pathlib.Path('.').rglob('*.py')]"
```

Python 3.10+, fully type-hinted, dataclasses for structured returns. No `os.system` —
every shell-out goes through `subprocess.run(..., capture_output=True, check=True)` with
explicit `CalledProcessError` handling.

</details>

---

<div align="center">
<sub>⚰️ <b>edo</b> · the dead fight on · all rights reserved until a license lands ⚰️</sub>
</div>
