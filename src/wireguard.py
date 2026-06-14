"""WireGuard control plane for edo.

Generates server and client configurations, allocates non-colliding IPs by
querying the database, and applies changes to the live ``wg0`` interface
without requiring a full ``wg-quick`` cycle.
"""
from __future__ import annotations

import configparser
import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

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
# Default destination for generated client .conf files. Operators can
# override per-invocation with --client-dir or globally via the
# EDO_CLIENT_CONFIG_DIR environment variable; both are wired in cli.py.
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


@dataclass
class LivePeerStatus:
    """Snapshot of a peer's runtime state from ``wg show wg0 dump``.

    Used by ``edo status`` to surface whether each bound vessel is
    actually connected right now — the most common question an operator
    has during a live CTF.
    """

    public_key: str
    endpoint: Optional[str]
    latest_handshake: int  # unix timestamp; 0 means never
    rx_bytes: int
    tx_bytes: int

    @property
    def online(self) -> bool:
        """True if last handshake was within the WG keepalive window.

        WG re-handshakes every ~120 seconds by default. 180s gives a one-
        handshake grace period before we mark a peer offline.
        """
        if self.latest_handshake == 0:
            return False
        return (time.time() - self.latest_handshake) < 180


# ---- subprocess helper --------------------------------------------------
def _run(
    cmd: List[str], stdin: Optional[str] = None, check: bool = True
) -> subprocess.CompletedProcess:
    logger.debug("exec: %s", " ".join(cmd))
    try:
        return subprocess.run(
            cmd, input=stdin, capture_output=True, text=True, check=check
        )
    except FileNotFoundError as e:
        from src.preflight import install_hint

        raise RuntimeError(
            f"required binary not found: {cmd[0]}\n"
            f"  install: {install_hint(cmd[0])}"
        ) from e


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


# Placeholder written into a client config when the participant supplied
# only their public key. They replace this line with their own private key
# locally — the server never sees it.
CLIENT_KEY_PLACEHOLDER = "<PASTE_YOUR_PRIVATE_KEY_HERE>"


def is_valid_wg_key(key: str) -> bool:
    """Structural check for a WireGuard base64 key.

    WG keys are 32 raw bytes → 44 base64 chars ending in ``=``. This
    catches typos and truncation; it does not verify the key is on the
    curve (wg itself will reject a malformed key when we apply it).
    """
    import base64

    key = key.strip()
    if len(key) != 44 or not key.endswith("="):
        return False
    try:
        return len(base64.b64decode(key, validate=True)) == 32
    except (ValueError, Exception):
        return False


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


def _parse_interface_section() -> Dict[str, str]:
    """Read ``wg0.conf``'s ``[Interface]`` block into a dict.

    Uses :mod:`configparser` rather than line-by-line matching: handles
    comments (``#`` / ``;``), arbitrary whitespace around ``=``, and
    section detection, so a comment containing the word "PrivateKey"
    can't be mistaken for the actual key. WG keys are case-sensitive so
    we disable the default option-lowercasing behaviour.

    Raises ``RuntimeError`` if the config is missing or has no
    ``[Interface]`` section.
    """
    if not WG_SERVER_CONFIG.exists():
        raise RuntimeError(f"{WG_SERVER_CONFIG} does not exist")
    parser = configparser.ConfigParser(
        strict=False,                    # duplicate [Peer] sections are legal in WG
        allow_no_value=True,
        comment_prefixes=("#", ";"),
        inline_comment_prefixes=("#",),
        interpolation=None,
    )
    # Preserve case — wg's keys are PascalCase.
    parser.optionxform = str  # type: ignore[assignment]
    try:
        parser.read(WG_SERVER_CONFIG)
    except configparser.Error as e:
        raise RuntimeError(
            f"failed to parse {WG_SERVER_CONFIG}: {e}"
        ) from e
    if "Interface" not in parser:
        raise RuntimeError(
            f"no [Interface] section in {WG_SERVER_CONFIG}"
        )
    return {k: (v or "").strip() for k, v in parser["Interface"].items()}


def _load_server_config(endpoint: str, port: int) -> ServerConfig:
    iface = _parse_interface_section()
    priv = iface.get("PrivateKey", "")
    if not priv:
        raise RuntimeError(
            f"no PrivateKey in [Interface] of {WG_SERVER_CONFIG}"
        )
    return ServerConfig(
        private_key=priv,
        public_key=_derive_pubkey(priv),
        endpoint=endpoint,
        listen_port=port,
    )


def get_listen_port() -> int:
    """Return the port the server is *actually* configured on.

    Reads ``ListenPort`` out of ``wg0.conf``. Falls back to the default
    if the file is missing or malformed — used by teardown to close the
    right port even when ``--port`` was passed to a prior ``init``.
    """
    try:
        iface = _parse_interface_section()
    except RuntimeError:
        return WG_LISTEN_PORT
    raw = iface.get("ListenPort", "")
    try:
        return int(raw) if raw else WG_LISTEN_PORT
    except ValueError:
        logger.warning(
            "ListenPort=%r in %s is not an integer; using default %d",
            raw,
            WG_SERVER_CONFIG,
            WG_LISTEN_PORT,
        )
        return WG_LISTEN_PORT


def get_live_peer_status() -> Dict[str, LivePeerStatus]:
    """Snapshot of every peer attached to ``wg0`` right now.

    Returns a dict keyed by public key. Empty dict if ``wg0`` is down or
    the command fails — callers should treat absence as "offline" rather
    than failing.

    ``wg show wg0 dump`` format (tab-separated):
        line 0: <priv> <pub> <listen-port> <fwmark>          (interface)
        line 1+: <pub> <psk> <endpoint> <allowed-ips> <handshake> <rx> <tx> <keepalive>
    """
    try:
        proc = _run(["wg", "show", WG_INTERFACE, "dump"], check=False)
    except RuntimeError:
        return {}
    if proc.returncode != 0:
        return {}

    out: Dict[str, LivePeerStatus] = {}
    lines = proc.stdout.splitlines()
    # First line is the interface itself; skip.
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        public_key = parts[0]
        endpoint = parts[2] if parts[2] != "(none)" else None
        try:
            handshake = int(parts[4])
            rx = int(parts[5])
            tx = int(parts[6])
        except ValueError:
            continue
        out[public_key] = LivePeerStatus(
            public_key=public_key,
            endpoint=endpoint,
            latest_handshake=handshake,
            rx_bytes=rx,
            tx_bytes=tx,
        )
    return out


# ---- peer lifecycle -----------------------------------------------------
def add_peer(
    db: DatabaseManager,
    username: str,
    server: ServerConfig,
    clients_dir: Optional[Path] = None,
    public_key: Optional[str] = None,
) -> ClientConfig:
    """Allocate, persist, write, and live-apply a new peer.

    Two key-handling modes:

    * **Server-side keys** (``public_key=None``, default): edo generates the
      keypair and writes a ready-to-use client config containing the private
      key. Convenient, but the server holds the private key (in the DB and in
      the on-disk client config).

    * **Client-side keys** (``public_key`` supplied): the participant
      generated their own keypair and gave us only the public half. The
      server stores ``private_key=NULL`` and the rendered client config
      carries a placeholder the participant replaces locally. The private
      key never touches the server — the stronger model for untrusted infra.

    ``clients_dir`` controls where the generated ``<username>.conf`` is
    written. Defaults to :data:`WG_CLIENTS_DIR`. The directory is created
    (with 0700) if missing.

    Rolls back the DB record if any config/live-apply step raises.
    """
    if db.get_peer(username):
        raise ValueError(f"peer '{username}' already exists")

    if public_key is not None:
        public_key = public_key.strip()
        if not is_valid_wg_key(public_key):
            raise ValueError(
                f"'{public_key}' is not a valid WireGuard public key "
                "(expected 44 base64 chars ending in '=')"
            )
        stored_public, stored_private = public_key, None
    else:
        kp = generate_keypair()
        stored_public, stored_private = kp.public_key, kp.private_key

    ip = find_next_available_ip(db)
    peer = db.add_peer(
        username=username,
        ip_address=ip,
        public_key=stored_public,
        private_key=stored_private,
    )

    out_dir = Path(clients_dir) if clients_dir is not None else WG_CLIENTS_DIR
    try:
        _append_peer_to_server_config(peer)
        _live_add_peer(peer)
        client_text = _render_client_config(peer, server)
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            out_dir.chmod(0o700)
        except OSError:
            # Operator may have explicitly looser perms on a shared dir.
            pass
        out_path = out_dir / f"{username}.conf"
        out_path.write_text(client_text)
        out_path.chmod(0o600)
    except Exception:
        logger.exception("peer creation failed for %s, rolling back DB", username)
        db.remove_peer(username)
        raise

    return ClientConfig(peer=peer, config_text=client_text, config_path=out_path)


def remove_peer(
    db: DatabaseManager,
    username: str,
    clients_dir: Optional[Path] = None,
) -> bool:
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

    out_dir = Path(clients_dir) if clients_dir is not None else WG_CLIENTS_DIR
    client_conf = out_dir / f"{username}.conf"
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
    # In client-side-key mode peer.private_key is None; emit a placeholder
    # the participant fills in locally, plus a reminder comment.
    if peer.private_key:
        priv_line = f"PrivateKey = {peer.private_key}\n"
        note = ""
    else:
        priv_line = f"PrivateKey = {CLIENT_KEY_PLACEHOLDER}\n"
        note = (
            "# NOTE: replace the PrivateKey placeholder below with the private "
            "key you generated locally.\n"
        )
    return (
        "[Interface]\n"
        f"# edo: client config for {peer.username}\n"
        f"{note}"
        f"{priv_line}"
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
