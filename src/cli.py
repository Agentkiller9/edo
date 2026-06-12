"""edo terminal UI.

A thin layer over the orchestration modules: argparse-driven for scripted
use, plus an interactive menu for hands-on operation.

Visuals lean on rich when available and fall back to plain stdout otherwise.
The Edo Tensei flavour (summon / bind / release / seal) is cosmetic — flag
names stay conventional so muscle memory still works.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

try:  # rich is optional; fall back to plain stdout if unavailable.
    from rich.console import Console
    from rich.table import Table

    _RICH = True
except ImportError:  # pragma: no cover
    _RICH = False

from src import docker_mgr, network, wireguard
from src.db_mgr import DatabaseManager

logger = logging.getLogger(__name__)

BANNER = r"""
   ▄████████ ████████▄   ▄██████▄
  ███    ███ ███   ▀███ ███    ███
  ███    █▀  ███    ███ ███    ███
 ▄███▄▄▄     ███    ███ ███    ███
▀▀███▀▀▀     ███    ███ ███    ███
  ███    █▄  ███    ███ ███    ███
  ███    ███ ███   ▄███ ███    ███
  ██████████ ████████▀   ▀██████▀
       reanimation protocol · ctf infrastructure
   summon vessels · bind contracts · seal the flow
"""

_console: Optional["Console"] = Console() if _RICH else None


# ---- output helpers -----------------------------------------------------
def _print(message: str, style: Optional[str] = None) -> None:
    if _console:
        _console.print(message, style=style or "")
    else:
        print(message)


def _ask(prompt: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default else ""
    raw = input(f"{prompt}{suffix}: ").strip()
    return raw or (default or "")


def _confirm(prompt: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    raw = input(f"{prompt} [{suffix}]: ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


# ---- preflight ----------------------------------------------------------
def require_root() -> None:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None or geteuid() != 0:
        _print(
            "[!] edo requires root (sudo). iptables and WireGuard need it.",
            style="bold red",
        )
        sys.exit(1)


def show_banner() -> None:
    if _console:
        _console.print(BANNER, style="bold magenta")
    else:
        print(BANNER)


# ---- commands -----------------------------------------------------------
def cmd_init(args: argparse.Namespace, db: DatabaseManager) -> int:
    endpoint = getattr(args, "endpoint", None) or _ask(
        "Public endpoint clients will dial"
    )
    if not endpoint:
        _print("[!] endpoint required", style="bold red")
        return 2
    port = int(getattr(args, "port", None) or wireguard.WG_LISTEN_PORT)

    _print(f"[*] Initialising WireGuard server on {endpoint}:{port}")
    server = wireguard.init_server(endpoint=endpoint, port=port)

    _print("[*] Applying firewall sealing tags...")
    fw = network.apply_firewall()
    _print(
        f"[+] Firewall applied on {fw.public_interface} ({len(fw.rules)} rules).",
        style="green",
    )

    _print("[*] Ensuring docker bridge exists...")
    docker_mgr.ensure_network()

    _print(f"[*] Bringing {network.WG_INTERFACE} up...")
    wireguard.bring_up()

    _print(f"[+] Server public key: {server.public_key}", style="bold green")
    _print("[+] Reanimation seal complete.", style="green")
    return 0


def cmd_add_peer(args: argparse.Namespace, db: DatabaseManager) -> int:
    username = getattr(args, "username", None) or _ask("Username")
    if not username:
        _print("[!] username required", style="bold red")
        return 2

    endpoint = getattr(args, "endpoint", None) or _ask(
        "Public endpoint clients will dial"
    )
    if not endpoint:
        _print("[!] endpoint required", style="bold red")
        return 2

    port = int(getattr(args, "port", None) or wireguard.WG_LISTEN_PORT)
    server = wireguard.init_server(endpoint=endpoint, port=port)

    try:
        cc = wireguard.add_peer(db, username=username, server=server)
    except ValueError as e:
        _print(f"[!] {e}", style="bold red")
        return 2
    except RuntimeError as e:
        _print(f"[!] {e}", style="bold red")
        return 1

    _print(f"[+] Vessel '{username}' bound to the contract.", style="green")
    _print(f"    IP:     {cc.peer.ip_address}")
    _print(f"    Config: {cc.config_path}")
    return 0


def cmd_remove_peer(args: argparse.Namespace, db: DatabaseManager) -> int:
    username = getattr(args, "username", None) or _ask("Username")
    if not username:
        _print("[!] username required", style="bold red")
        return 2
    ok = wireguard.remove_peer(db, username)
    if ok:
        _print(f"[+] Released vessel '{username}'.", style="green")
        return 0
    _print(f"[!] No such peer: {username}", style="bold red")
    return 1


def cmd_summon(args: argparse.Namespace, db: DatabaseManager) -> int:
    raw = getattr(args, "path", None) or _ask(
        "Absolute path to challenge directory"
    )
    if not raw:
        _print("[!] path required", style="bold red")
        return 2

    path = Path(raw).expanduser().resolve()
    if not path.is_dir():
        _print(f"[!] {path} is not a directory", style="bold red")
        return 2
    if not path.is_absolute():
        _print(f"[!] {path} is not an absolute path", style="bold red")
        return 2

    layout = docker_mgr.detect_layout(path)
    if layout is None:
        _print(
            f"[!] No Dockerfile or docker-compose file in {path}",
            style="bold red",
        )
        return 2

    name = getattr(args, "name", None) or path.name
    _print(f"[*] Detected layout: {layout}. Summoning '{name}'...")

    if layout == "compose":
        result = docker_mgr.deploy_compose(db, challenge_name=name, path=path)
    else:
        result = docker_mgr.deploy_dockerfile(
            db, challenge_name=name, path=path
        )

    if not result.success:
        _print(f"[!] Summoning failed: {result.error}", style="bold red")
        return 1

    for c in result.containers:
        _print(
            f"[+] {c.challenge_name}  ->  {c.container_id[:12]}  @ {c.assigned_ip}",
            style="green",
        )
    return 0


def cmd_release(args: argparse.Namespace, db: DatabaseManager) -> int:
    if getattr(args, "all", False):
        n = docker_mgr.teardown_all(db)
        _print(f"[+] Released {n} vessel(s).", style="green")
        return 0

    cid = getattr(args, "container", None)
    if not cid:
        cid = _ask("Container ID to release")
    if not cid:
        _print("[!] container id required (or use --all)", style="bold red")
        return 2

    ok = docker_mgr.teardown_container(db, cid)
    if ok:
        _print(f"[+] Released {cid[:12]}.", style="green")
        return 0
    _print(f"[!] Release failed for {cid}", style="bold red")
    return 1


def cmd_status(args: argparse.Namespace, db: DatabaseManager) -> int:
    peers = db.get_all_peers()
    containers = db.get_active_containers()

    if _console:
        ptab = Table(
            title="Bound vessels (WireGuard peers)",
            show_lines=False,
            header_style="bold magenta",
        )
        for col in ("ID", "Username", "IP", "Public Key"):
            ptab.add_column(col)
        for p in peers:
            pk = p.public_key
            ptab.add_row(
                str(p.id),
                p.username,
                p.ip_address,
                (pk[:24] + "…") if len(pk) > 24 else pk,
            )
        _console.print(ptab)

        ctab = Table(
            title="Reanimated challenges (containers)",
            show_lines=False,
            header_style="bold magenta",
        )
        for col in ("ID", "Challenge", "Container", "IP", "Status"):
            ctab.add_column(col)
        for ct in containers:
            ctab.add_row(
                str(ct.id),
                ct.challenge_name,
                ct.container_id[:12],
                ct.assigned_ip,
                ct.status,
            )
        _console.print(ctab)
    else:
        print("Peers:")
        for p in peers:
            print(f"  {p.id}\t{p.username}\t{p.ip_address}")
        print("Containers:")
        for ct in containers:
            print(
                f"  {ct.id}\t{ct.challenge_name}\t{ct.container_id[:12]}\t"
                f"{ct.assigned_ip}\t{ct.status}"
            )
    return 0


def cmd_teardown(args: argparse.Namespace, db: DatabaseManager) -> int:
    if not getattr(args, "yes", False):
        if not _confirm(
            "Lift the seal and release ALL infrastructure?", default=False
        ):
            _print("[*] Aborted.", style="yellow")
            return 1

    _print("[*] Releasing all reanimated vessels...")
    docker_mgr.teardown_all(db)
    _print("[*] Removing docker bridge...")
    docker_mgr.remove_network()
    _print("[*] Lifting firewall rules...")
    network.remove_firewall()
    _print(f"[*] Bringing {network.WG_INTERFACE} down...")
    wireguard.bring_down()
    _print("[+] Sealing tag lifted. Reanimation released.", style="green")
    return 0


# ---- interactive menu ---------------------------------------------------
MenuHandler = Callable[[argparse.Namespace, DatabaseManager], int]


def interactive_menu(db: DatabaseManager, args: argparse.Namespace) -> int:
    show_banner()
    options: Dict[str, Tuple[str, Optional[MenuHandler]]] = {
        "1": ("Show status footprint", cmd_status),
        "2": ("Summon a challenge (deploy)", cmd_summon),
        "3": ("Bind a new peer (add WireGuard client)", cmd_add_peer),
        "4": ("Release a vessel (teardown container)", cmd_release),
        "5": ("Initialise / re-apply infrastructure", cmd_init),
        "6": ("Lift the seal (teardown everything)", cmd_teardown),
        "q": ("Quit", None),
    }

    while True:
        _print("")
        for key, (desc, _) in options.items():
            _print(f"  [{key}] {desc}")
        choice = _ask("Select", default="1").lower()
        if choice == "q":
            return 0
        if choice not in options:
            _print(f"[!] Unknown option: {choice}", style="bold red")
            continue
        _, handler = options[choice]
        if handler is None:
            return 0
        try:
            handler(args, db)
        except KeyboardInterrupt:
            _print("\n[!] Cancelled", style="yellow")
        except Exception as e:
            logger.exception("command failed")
            _print(f"[!] Error: {e}", style="bold red")


# ---- argument parser ----------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="edo",
        description="edo — CTF infrastructure orchestrator (WireGuard + Docker)",
    )
    p.add_argument(
        "--db",
        type=Path,
        default=None,
        help="Path to SQLite DB (default: /var/lib/edo/edo.db)",
    )
    p.add_argument("--verbose", "-v", action="store_true")
    sub = p.add_subparsers(dest="command")

    p_init = sub.add_parser("init", help="Initialise VPN + firewall")
    p_init.add_argument("--endpoint", help="Public endpoint for clients")
    p_init.add_argument("--port", type=int, default=wireguard.WG_LISTEN_PORT)

    p_add = sub.add_parser("add-peer", help="Bind a new participant")
    p_add.add_argument("username", nargs="?")
    p_add.add_argument("--endpoint", help="Public endpoint for clients")
    p_add.add_argument("--port", type=int, default=wireguard.WG_LISTEN_PORT)

    p_rem = sub.add_parser("remove-peer", help="Release a participant")
    p_rem.add_argument("username", nargs="?")

    p_sum = sub.add_parser(
        "summon", help="Deploy a challenge from a directory"
    )
    p_sum.add_argument("path", nargs="?")
    p_sum.add_argument("--name", help="Override challenge name")

    p_rel = sub.add_parser("release", help="Tear down a container")
    p_rel.add_argument("--container", help="Container ID")
    p_rel.add_argument("--all", action="store_true")

    sub.add_parser("status", help="Print live system footprint")

    p_td = sub.add_parser("teardown", help="Tear down ALL infrastructure")
    p_td.add_argument("--yes", "-y", action="store_true", help="Skip confirmation")

    sub.add_parser("menu", help="Open interactive menu (default)")

    return p


# ---- entrypoint ---------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    require_root()

    db_path = args.db or Path("/var/lib/edo/edo.db")
    db = DatabaseManager(db_path=db_path)

    dispatch: Dict[str, MenuHandler] = {
        "init": cmd_init,
        "add-peer": cmd_add_peer,
        "remove-peer": cmd_remove_peer,
        "summon": cmd_summon,
        "release": cmd_release,
        "status": cmd_status,
        "teardown": cmd_teardown,
    }

    if args.command in dispatch:
        try:
            return dispatch[args.command](args, db)
        except KeyboardInterrupt:
            _print("\n[!] Cancelled", style="yellow")
            return 130
        except Exception as e:
            logger.exception("command failed")
            _print(f"[!] Error: {e}", style="bold red")
            return 1

    if args.command in (None, "menu"):
        return interactive_menu(db, args)

    parser.print_help()
    return 2
