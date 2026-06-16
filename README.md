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

**edo** — CTF infrastructure orchestrator

A single-operator CLI that ties WireGuard and Docker together so you can stand up
isolated, per-challenge containers for a Capture-the-Flag event and hand each
participant a VPN profile that only reaches what it should.

![Python](https://img.shields.io/badge/python-3.10+-1f6feb?style=flat-square&logo=python&logoColor=white)
![Linux](https://img.shields.io/badge/linux-only-202020?style=flat-square&logo=linux&logoColor=white)
![WireGuard](https://img.shields.io/badge/WireGuard-88171A?style=flat-square&logo=wireguard&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white)

</div>

---

## Overview

Running a CTF means juggling three things at once: a VPN so remote players can
reach the targets, a set of vulnerable containers each on a predictable address,
and a firewall policy that stops players from attacking each other or pivoting out
to the wider internet. edo handles all three from one command-line tool and keeps
the state in a single SQLite database so nothing is lost across restarts.

- **Per-participant VPN access.** Each WireGuard peer gets an address auto-allocated
  on `10.8.0.0/24`.
- **Per-challenge containers.** Each challenge runs on a static IP on `10.9.0.0/24`,
  on a Docker bridge created in routed mode (Docker 24+) so addresses survive the
  tunnel intact — pings work in both directions and reverse shells report the real
  source IP.
- **Client isolation.** Participants cannot reach one another across the VPN.
- **Egress containment.** Challenge containers cannot reach the public internet, with
  one deliberate exception: they may open connections back into the VPN subnet, so
  players can still catch reverse shells.
- **A single source of truth.** Peers and containers are tracked in SQLite at
  `/var/lib/edo/edo.db`.

> The name is a nod to *Edo Tensei*, the reanimation technique — the CLI summons
> "dead" challenges back to life and seals them off from one another. A few command
> names (`summon`, `teardown`) carry that flavour; everything else stays conventional.

---

## Quick start

```bash
# Check the host has everything it needs (this one runs without root)
sudo edo doctor

# Stand up the VPN, firewall, and Docker bridge
sudo edo init --endpoint vpn.your-ctf.example

# Add a participant — writes /etc/wireguard/edo_clients/alice.conf
sudo edo add-peer alice

# Deploy a challenge from its directory
sudo edo summon /opt/challenges/sqli --memory 512m --pids-limit 100 --read-only

# See who's connected and what's running
sudo edo status

# Tear everything down afterwards
sudo edo teardown --yes
```

Give `alice.conf` to the participant; they import it into the WireGuard client and
they're connected.

Running `sudo edo` with no arguments opens an interactive menu that prompts for
every option described below, so you don't have to memorise flags.

---

## Commands

**Participants (WireGuard peers)**

| Command | Description |
| --- | --- |
| `edo add-peer USER` | Add a participant. edo generates the keypair and writes the client config. |
| `edo add-peer USER --public-key KEY` | Client-supplied key: the server never sees the private key (see [Key handling](#key-handling)). |
| `edo add-peers --from teams.csv` | Bulk-import a roster. CSV columns: `username[,public_key]`. |
| `edo remove-peer USER` | Remove a participant. |
| `edo export USER` / `--all -o peers.tar.gz` | Reprint a single config, or bundle the whole roster. |

**Challenges (containers)**

| Command | Description |
| --- | --- |
| `edo summon PATH [--name N]` | Build and run a `Dockerfile` or Compose challenge on the bridge. If the name is already deployed, edo offers to replace it (or use `--replace` non-interactively). |
| `edo summon PATH --replace` | Remove the existing container and image for this name, then redeploy cleanly. |
| `edo release --container REF` | Release one container. `REF` can be the short id shown in `status`, a full id, or a challenge name (ambiguous names are rejected with the candidates listed). |
| `edo release --all` | Release every running challenge. |

**Status and diagnostics**

| Command | Description |
| --- | --- |
| `edo status` | Show connected peers (online status, last handshake, transfer) and running containers. Reconciles against Docker first and prunes records whose container no longer exists. |
| `edo doctor [--no-runtime]` | Check every prerequisite and print the exact fix for anything missing. Runs without root. |

**Lifecycle**

| Command | Description |
| --- | --- |
| `edo init --endpoint HOST [--port N]` | Bring up the VPN, firewall, and bridge. Safe to re-run. |
| `edo teardown [--yes]` | Tear down the infrastructure but keep state for the next `init`. |
| `edo purge [--yes] [--wipe-state]` | Remove every edo artifact. `--wipe-state` also deletes the configs and database. |

<details>
<summary>Global flags</summary>

<br>

- `--db PATH` — database location (default `/var/lib/edo/edo.db`).
- `--client-dir PATH` — where client configs are written (default
  `/etc/wireguard/edo_clients/`, or `$EDO_CLIENT_CONFIG_DIR`). Point this at a
  non-root directory so copying configs to participants doesn't need `sudo`.
- `--verbose` / `-v` — enable debug logging.

</details>

---

## Installation

<details>
<summary>System packages, Python dependencies, and the sudo caveat</summary>

<br>

edo requires a Linux host and root privileges. Install the system packages first:

```bash
# Debian / Ubuntu
sudo apt install wireguard-tools iptables iproute2 docker.io docker-compose-plugin

# RHEL / AlmaLinux / Rocky
sudo dnf install wireguard-tools iptables iproute docker-ce docker-compose-plugin
```

Docker 24 or newer is required for routed-bridge mode. `edo doctor` verifies all of
the above.

Then install edo itself:

```bash
git clone https://github.com/Agentkiller9/edo.git /opt/edo
cd /opt/edo
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Run it by pointing `sudo` at the virtual environment's interpreter:

```bash
sudo /opt/edo/.venv/bin/python /opt/edo/edo.py <command>
```

**A caveat worth knowing in advance:** running `sudo python3 edo.py` from an
activated virtualenv still fails with `ModuleNotFoundError: No module named 'docker'`.
`sudo` resets `PATH` and ignores the activation, so it runs the system Python instead
of the one in your venv. Always invoke the venv's interpreter directly, as shown
above.

If you'd rather type `edo`, drop in a small wrapper:

```bash
sudo tee /usr/local/bin/edo >/dev/null <<'EOF'
#!/usr/bin/env bash
exec /opt/edo/.venv/bin/python /opt/edo/edo.py "$@"
EOF
sudo chmod +x /usr/local/bin/edo
```

</details>

---

## Network topology

<details>
<summary>Subnets, iptables chains, and the three traffic guarantees</summary>

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

edo manages two dedicated iptables chains and leaves the rest of your ruleset alone:

| Chain | Hooked into | Purpose |
| --- | --- | --- |
| `EDO_FORWARD` | `DOCKER-USER` (or `FORWARD` if Docker isn't present) | Enforces the three guarantees below. It lives in `DOCKER-USER` so it survives `systemctl restart docker`; otherwise Docker's own `DOCKER-FORWARD` chain takes precedence and silently drops `wg0`→`edo_br0` traffic. `edo doctor` reports it if the hook ever drifts. |
| `EDO_INPUT` | `INPUT` | Opens `udp/51820` for the WireGuard handshake. When firewalld is active, edo uses `firewall-cmd --add-port` instead, so a reload can't wipe the rule. |

The three guarantees enforced in `EDO_FORWARD`:

1. **Client isolation** — traffic with both source and destination inside
   `10.8.0.0/24` is dropped.
2. **Egress containment** — traffic from `10.9.0.0/24` leaving via the public
   interface is dropped.
3. **Reverse-shell channel** — traffic from `10.9.0.0/24` to `10.8.0.0/24` is
   accepted, evaluated before the egress drop.

</details>

---

## Key handling

<details>
<summary>Server-side versus client-side private keys</summary>

<br>

By default, `edo add-peer alice` generates the keypair for the participant. It's the
convenient path, but it means the server holds the private key — both in the database
and in the client config on disk.

For untrusted infrastructure, prefer client-side keys. The participant generates
their own keypair and sends you only the public half:

```bash
wg genkey | tee privatekey | wg pubkey   # send the public key only
```

You register it:

```bash
sudo edo add-peer alice --public-key "<their-public-key>"
```

edo stores `private_key=NULL`, and the generated config contains a
`PrivateKey = <PASTE_YOUR_PRIVATE_KEY_HERE>` placeholder for them to fill in locally.
The private key never reaches the server.

For bulk imports, any CSV row that includes a public key uses client-side mode
automatically:

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

## Container security

<details>
<summary>What isolation edo provides, and what it deliberately doesn't</summary>

<br>

edo runs as root on the host because iptables, WireGuard, and Docker all require it.
That is not the same as giving containers root on the host: a reanimated challenge's
`uid 0` is namespaced, so a fully compromised challenge is still just an unprivileged
process under `dockerd`.

Applied by default to every Dockerfile deployment:

| Setting | Reason |
| --- | --- |
| `no-new-privileges:true` | Blocks setuid-based escalation inside the container. |
| `cap-drop NET_RAW` | Prevents packet sniffing and spoofing on the bridge, which is the main lateral-movement path between challenges. |
| No `--privileged`, no `docker.sock`, no host mounts, no shared namespaces | These are the common container-escape vectors; edo uses none of them. |
| Default seccomp and capability set | Keeps ordinary challenges working. |

Optional hardening flags:

| Flag | Effect |
| --- | --- |
| `--memory 512m`, `--cpus 1`, `--pids-limit 100` | Resource limits to contain fork bombs and out-of-memory situations. |
| `--read-only` | Read-only root filesystem with a 64 MB tmpfs at `/tmp`. |
| `--cap-add` / `--cap-drop` | Per-challenge capability tuning (`NET_RAW` is always dropped). |
| `--allow-setuid` | Disables `no-new-privileges`, for challenges that genuinely need it. |
| `--restart {no\|on-failure\|unless-stopped\|always}` | Restart policy. |

A reasonable baseline:

```bash
sudo edo summon /path/to/challenge --memory 512m --cpus 1 --pids-limit 100 --read-only
```

Two things to keep in mind. Compose challenges ignore these flags, because Docker
Compose owns the service specification — declare `security_opt`, `cap_drop`,
`mem_limit`, and `cpus` in the YAML instead. And edo does not protect against kernel
or runc vulnerabilities (keep the host patched) or against a malicious challenge
Dockerfile (review what you deploy — edo builds and runs whatever you point it at).

</details>

---

## Troubleshooting

<details>
<summary>Start with <code>edo doctor</code></summary>

<br>

`edo doctor` runs without root, checks every prerequisite, and prints the exact
`apt`/`dnf`/`pacman` command to fix anything missing. The `init`, `add-peer`, and
`summon` commands run the same checks before making changes.

| Symptom | Resolution |
| --- | --- |
| `ModuleNotFoundError: docker` under sudo | `sudo` ignores the venv; run `sudo .venv/bin/python edo.py`. |
| `apply_firewall` can't determine the public interface | No default route — `ip -4 route show default` must return one. |
| `wg-quick up wg0` reports "already exists" | Harmless; edo treats it as a no-op. |
| A `summon` build fails | The full `docker build` log streams above the error — read it for the real cause (an invalid apt package, a missing `COPY` source, and so on). Reproduce in isolation with `docker build -t test /path/to/challenge`. |
| A container can reach the internet | The `EDO_FORWARD` hook drifted below `DOCKER-FORWARD`; re-run `edo init`. |
| A peer can't reach a container | The client's `AllowedIPs` must include `10.9.0.0/24` (generated configs already do). |
| No handshake at all | Open `udp/51820`, including any provider-level firewall, and confirm `wg0` is up. |

</details>

---

## Reference

<details>
<summary>On-disk layout and challenge directory formats</summary>

<br>

Where state lives:

| Path | Contents |
| --- | --- |
| `/var/lib/edo/edo.db` | SQLite database — peers and containers. |
| `/etc/wireguard/wg0.conf` | Server config, regenerated when peers change. |
| `/etc/wireguard/edo_clients/<user>.conf` | Generated client configs. |
| `EDO_FORWARD` / `EDO_INPUT` | iptables chains. |
| `edo_br0` | Docker bridge network. |

Challenge layouts (`edo summon` detects which one applies):

```
sqli/                 chain/
└── Dockerfile        ├── docker-compose.yml
                      ├── web/Dockerfile
                      └── db/init.sql
```

A single `Dockerfile` builds and runs one container. A Compose file runs
`docker compose up`, after which each service is attached to `edo_br0` with a static
IP recorded in the database.

</details>

<details>
<summary>Development</summary>

<br>

```bash
# Syntax-check every module without a Linux host
python -c "import ast,pathlib;[ast.parse(p.read_text()) for p in pathlib.Path('.').rglob('*.py')]"
```

The codebase targets Python 3.10+, is fully type-hinted, and returns dataclasses
rather than raw strings. It avoids `os.system` entirely — every external command goes
through `subprocess.run(..., capture_output=True, check=True)` with explicit
`CalledProcessError` handling.

</details>

---

## License

Released under the [MIT License](LICENSE).

---

<div align="center">
<sub>𝐞𝐝𝐨 · 反 the dead fight on 魂 · CTF infrastructure orchestrator</sub>
</div>
