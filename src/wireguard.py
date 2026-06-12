"""WireGuard control plane for edo.

Generates server and client configurations, allocates non-colliding IPs by
querying the database, and applies changes to the live ``wg0`` interface
without requiring a full ``wg-quick`` cycle.
"""
from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from src.db_mgr import DatabaseManager, Peer
from src.network import (
    DOCKER_SUBNET,
    WG_INTERFACE,
    WG_SERVER_IP,
    WG_SUBNET,
    iter_subnet_hosts,
)

logger = logging.getLogger(__name__)

WG_CONFIG_DIR = Path("/etc/wireguard")
WG_SERVER_CONFIG = WG_CONFIG_DIR / f"{WG_INTERFACE}.conf"
WG_CLIENTS_DIR = WG_CONFIG_DIR / "edo_clients"
WG_LISTEN_PORT = 51820


@dataclass
class KeyPair:
    private_key: str
    public_key: str


@dataclass
class ServerConfig:
    private_key: str
    public_key: str
    endpoint: str
    listen_port: int
    config_path: Path = WG_SERVER_CONFIG


@dataclass
class ClientConfig:
    peer: Peer
    config_text: str
    config_path: Path


# ---- subprocess helper --------------------------------------------------
def _run(
    cmd: List[str], stdin: Optional[str] = None, check: bool = True
) -> subprocess.CompletedProcess:
    logger.debug("exec: %s", " ".join(cmd))
    return subprocess.run(
        cmd, input=stdin, capture_output=True, text=True, check=check
    )


# ---- key generation -----------------------------------------------------
def generate_keypair() -> KeyPair:
    """Shells out to ``wg genkey | wg pubkey``."""
    try:
        priv = _run(["wg", "genkey"]).stdout.strip()
        pub = _run(["wg", "pubkey"], stdin=priv).stdout.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"wg key generation failed: {(e.stderr or '').strip()}"
        ) from e
    return KeyPair(private_key=priv, public_key=pub)


def _derive_pubkey(private_key: str) -> str:
    try:
        return _run(["wg", "pubkey"], stdin=private_key).stdout.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"wg pubkey failed: {(e.stderr or '').strip()}"
        ) from e


# ---- IP allocation ------------------------------------------------------
def find_next_available_ip(db: DatabaseManager) -> str:
    """Return the next free address in the WireGuard subnet.

    Excludes the server's own address and anything currently held in DB.
    """
    blocked = list(db.get_used_peer_ips()) + [WG_SERVER_IP]
    return iter_subnet_hosts(WG_SUBNET, blocked)


# ---- server lifecycle ---------------------------------------------------
def init_server(endpoint: str, port: int = WG_LISTEN_PORT) -> ServerConfig:
    """Idempotently create the server config and return its keys."""
    WG_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if WG_SERVER_CONFIG.exists():
        logger.info("server config already present at %s", WG_SERVER_CONFIG)
        return _load_server_config(endpoint, port)

    kp = generate_keypair()
    contents = (
        "[Interface]\n"
        f"# edo: WireGuard server interface\n"
        f"Address = {WG_SERVER_IP}/{WG_SUBNET.prefixlen}\n"
        f"ListenPort = {port}\n"
        f"PrivateKey = {kp.private_key}\n"
        "SaveConfig = false\n"
    )
    WG_SERVER_CONFIG.write_text(contents)
    WG_SERVER_CONFIG.chmod(0o600)
    logger.info("server config written to %s", WG_SERVER_CONFIG)
    return ServerConfig(
        private_key=kp.private_key,
        public_key=kp.public_key,
        endpoint=endpoint,
        listen_port=port,
    )


def _load_server_config(endpoint: str, port: int) -> ServerConfig:
    text = WG_SERVER_CONFIG.read_text()
    priv = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("PrivateKey"):
            priv = stripped.split("=", 1)[1].strip()
            break
    if not priv:
        raise RuntimeError(
            f"could not parse PrivateKey from {WG_SERVER_CONFIG}"
        )
    return ServerConfig(
        private_key=priv,
        public_key=_derive_pubkey(priv),
        endpoint=endpoint,
        listen_port=port,
    )


# ---- peer lifecycle -----------------------------------------------------
def add_peer(
    db: DatabaseManager, username: str, server: ServerConfig
) -> ClientConfig:
    """Allocate, persist, write, and live-apply a new peer.

    Rolls back the DB record if any config/live-apply step raises.
    """
    if db.get_peer(username):
        raise ValueError(f"peer '{username}' already exists")

    kp = generate_keypair()
    ip = find_next_available_ip(db)
    peer = db.add_peer(
        username=username,
        ip_address=ip,
        public_key=kp.public_key,
        private_key=kp.private_key,
    )

    try:
        _append_peer_to_server_config(peer)
        _live_add_peer(peer)
        client_text = _render_client_config(peer, server)
        WG_CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
        out_path = WG_CLIENTS_DIR / f"{username}.conf"
        out_path.write_text(client_text)
        out_path.chmod(0o600)
    except Exception:
        logger.exception("peer creation failed for %s, rolling back DB", username)
        db.remove_peer(username)
        raise

    return ClientConfig(peer=peer, config_text=client_text, config_path=out_path)


def remove_peer(db: DatabaseManager, username: str) -> bool:
    """Remove a peer from DB, server config, live interface, and disk."""
    peer = db.get_peer(username)
    if not peer:
        return False

    # Live interface (best-effort; wg0 may be down).
    try:
        _run(["wg", "set", WG_INTERFACE, "peer", peer.public_key, "remove"])
    except subprocess.CalledProcessError as e:
        logger.warning(
            "live peer removal for %s failed: %s",
            username,
            (e.stderr or "").strip(),
        )

    _rewrite_server_config(db, exclude_username=username)
    db.remove_peer(username)

    client_conf = WG_CLIENTS_DIR / f"{username}.conf"
    if client_conf.exists():
        client_conf.unlink()
    return True


# ---- config rendering ---------------------------------------------------
def _append_peer_to_server_config(peer: Peer) -> None:
    block = (
        "\n[Peer]\n"
        f"# {peer.username}\n"
        f"PublicKey = {peer.public_key}\n"
        f"AllowedIPs = {peer.ip_address}/32\n"
    )
    with WG_SERVER_CONFIG.open("a") as f:
        f.write(block)


def _rewrite_server_config(
    db: DatabaseManager, exclude_username: str
) -> None:
    """Rebuild the server config from the [Interface] header + remaining DB peers."""
    text = WG_SERVER_CONFIG.read_text()
    header = text.split("[Peer]", 1)[0].rstrip() + "\n"
    parts = [header]
    for p in db.get_all_peers():
        if p.username == exclude_username:
            continue
        parts.append(
            "\n[Peer]\n"
            f"# {p.username}\n"
            f"PublicKey = {p.public_key}\n"
            f"AllowedIPs = {p.ip_address}/32\n"
        )
    WG_SERVER_CONFIG.write_text("".join(parts))


def _render_client_config(peer: Peer, server: ServerConfig) -> str:
    return (
        "[Interface]\n"
        f"# edo: client config for {peer.username}\n"
        f"PrivateKey = {peer.private_key}\n"
        f"Address = {peer.ip_address}/32\n"
        "DNS = 1.1.1.1\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {server.public_key}\n"
        f"Endpoint = {server.endpoint}:{server.listen_port}\n"
        f"AllowedIPs = {WG_SUBNET}, {DOCKER_SUBNET}\n"
        "PersistentKeepalive = 25\n"
    )


# ---- live interface control --------------------------------------------
def _live_add_peer(peer: Peer) -> None:
    """``wg set wg0 peer ...`` so the running interface picks up the new peer."""
    try:
        _run(
            [
                "wg",
                "set",
                WG_INTERFACE,
                "peer",
                peer.public_key,
                "allowed-ips",
                f"{peer.ip_address}/32",
            ]
        )
    except subprocess.CalledProcessError as e:
        # The interface may legitimately be down during first-time setup;
        # surface a warning rather than failing the whole operation.
        logger.warning(
            "could not apply peer to live %s (is it up?): %s",
            WG_INTERFACE,
            (e.stderr or "").strip(),
        )


def bring_up() -> None:
    """``wg-quick up wg0``. No-op if already up."""
    try:
        _run(["wg-quick", "up", WG_INTERFACE])
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").lower()
        if "already exists" in stderr or "rtnetlink" in stderr:
            logger.info("%s already up", WG_INTERFACE)
            return
        raise RuntimeError(
            f"wg-quick up {WG_INTERFACE} failed: {(e.stderr or '').strip()}"
        ) from e


def bring_down() -> None:
    """``wg-quick down wg0``. Logs and swallows if the interface is already down."""
    try:
        _run(["wg-quick", "down", WG_INTERFACE])
    except subprocess.CalledProcessError as e:
        logger.warning(
            "wg-quick down %s: %s", WG_INTERFACE, (e.stderr or "").strip()
        )


def reload_interface() -> None:
    """Heavy-hammer reload: cycle the interface to re-read the config file."""
    bring_down()
    bring_up()
