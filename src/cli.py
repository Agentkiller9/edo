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

from src import docker_mgr, network, preflight, wireguard
from src.db_mgr import DatabaseManager
from src.preflight import PreflightReport, Severity

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
            "[!] edo requires root (sudo). iptables and WireGuard need it.\n"
            "    Tip: if you installed in a venv, sudo your venv's interpreter:\n"
            "         sudo ./myvenv/bin/python edo.py",
            style="bold red",
        )
        sys.exit(1)


_SEVERITY_STYLE = {
    Severity.CRITICAL: ("bold red", "✗"),
    Severity.WARNING: ("yellow", "!"),
    Severity.INFO: ("dim", "·"),
}


def render_preflight(report: PreflightReport, title: str = "Preflight") -> None:
    if _console:
        table = Table(title=title, header_style="bold magenta", show_lines=False)
        for col in ("", "Check", "Detail", "Hint"):
            table.add_column(col)
        for c in report.checks:
            style, sym = _SEVERITY_STYLE[c.severity]
            mark = "[green]✓[/]" if c.ok else f"[{style}]{sym}[/]"
            table.add_row(mark, c.name, c.detail or "—", c.hint or "")
        _console.print(table)
    else:
        for c in report.checks:
            mark = "OK " if c.ok else "FAIL"
            print(f"  [{mark}] {c.name:30}  {c.detail}")
            if c.hint and not c.ok:
                print(f"           hint: {c.hint}")


def gate_with_preflight(command: str) -> bool:
    """Run targeted checks before a mutating command. Returns False to abort."""
    report = preflight.quick_checks_for(command)
    failures = report.critical_failures
    if failures:
        _print(f"[!] Preflight failed for `{command}`. Fix these first:", style="bold red")
        render_preflight(report, title=f"Preflight for {command}")
        return False
    return True


def show_banner() -> None:
    if _console:
        _console.print(BANNER, style="bold magenta")
    else:
        print(BANNER)


# ---- shared helpers -----------------------------------------------------
def resolve_client_dir(args: argparse.Namespace) -> Path:
    """Where do generated client configs land for this invocation?

    Precedence: ``--client-dir`` flag > ``EDO_CLIENT_CONFIG_DIR`` env >
    the wireguard module's default (``/etc/wireguard/edo_clients/``).
    """
    explicit = getattr(args, "client_dir", None)
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get("EDO_CLIENT_CONFIG_DIR")
    if env:
        return Path(env).expanduser()
    return wireguard.WG_CLIENTS_DIR


def resolve_endpoint(args: argparse.Namespace) -> Optional[str]:
    """Return ``--endpoint`` if given, otherwise prompt with the interface list.

    Shared by ``init`` and ``add-peer`` so both commands give the operator
    the same "here are your IPs, pick one" UX without leaving the menu.
    Returns ``None`` if the user gave nothing at all.
    """
    endpoint = getattr(args, "endpoint", None)
    if endpoint:
        return endpoint

    ifaces = network.list_interface_ips()
    default_ip: Optional[str] = None
    if ifaces:
        _print("\n[*] Detected interface IPs:")
        for iface in ifaces:
            tag = "  (default route)" if iface.is_default else ""
            _print(f"      {iface.name:14} {iface.ipv4}{tag}")
            if iface.is_default and not default_ip:
                default_ip = iface.ipv4
        _print("")
    return _ask(
        "Public endpoint clients will dial",
        default=default_ip,
    ) or None


# ---- commands -----------------------------------------------------------
def cmd_doctor(args: argparse.Namespace, db: DatabaseManager) -> int:
    """Diagnose the host: required binaries, kernel module, daemons, network."""
    include_runtime = not getattr(args, "no_runtime", False)
    report = preflight.run_all_checks(include_runtime=include_runtime)
    render_preflight(report, title="edo doctor")

    crit = len(report.critical_failures)
    warn = len(report.warnings)
    if crit:
        _print(
            f"\n[!] {crit} critical issue(s), {warn} warning(s). "
            "edo cannot run until criticals are resolved.",
            style="bold red",
        )
        return 1
    if warn:
        _print(
            f"\n[*] {warn} warning(s). edo will run but check the hints above.",
            style="yellow",
        )
        return 0
    _print("\n[+] All checks passed. Host is ready.", style="bold green")
    return 0


def cmd_init(args: argparse.Namespace, db: DatabaseManager) -> int:
    if not gate_with_preflight("init"):
        return 1

    endpoint = resolve_endpoint(args)
    if not endpoint:
        _print("[!] endpoint required", style="bold red")
        return 2
    port = int(getattr(args, "port", None) or wireguard.WG_LISTEN_PORT)

    _print(f"[*] Initialising WireGuard server on {endpoint}:{port}")
    server = wireguard.init_server(endpoint=endpoint, port=port)

    _print("[*] Applying firewall sealing tags...")
    fw = network.apply_firewall(wg_port=port)
    _print(
        f"[+] Firewall applied on {fw.public_interface} ({len(fw.rules)} rules).",
        style="green",
    )
    if network.firewalld_active():
        _print(f"    firewalld: opened {port}/udp (permanent)", style="dim")

    _print("[*] Ensuring docker bridge exists...")
    docker_mgr.ensure_network()

    _print(f"[*] Bringing {network.WG_INTERFACE} up...")
    wireguard.bring_up()

    _print(f"[+] Server public key: {server.public_key}", style="bold green")
    _print("[+] Reanimation seal complete.", style="green")
    return 0


def cmd_add_peer(args: argparse.Namespace, db: DatabaseManager) -> int:
    if not gate_with_preflight("add-peer"):
        return 1
    username = getattr(args, "username", None) or _ask("Username")
    if not username:
        _print("[!] username required", style="bold red")
        return 2

    endpoint = resolve_endpoint(args)
    if not endpoint:
        _print("[!] endpoint required", style="bold red")
        return 2

    port = int(getattr(args, "port", None) or wireguard.WG_LISTEN_PORT)
    server = wireguard.init_server(endpoint=endpoint, port=port)
    clients_dir = resolve_client_dir(args)

    try:
        cc = wireguard.add_peer(
            db, username=username, server=server, clients_dir=clients_dir
        )
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
    if not gate_with_preflight("remove-peer"):
        return 1
    username = getattr(args, "username", None) or _ask("Username")
    if not username:
        _print("[!] username required", style="bold red")
        return 2
    ok = wireguard.remove_peer(db, username, clients_dir=resolve_client_dir(args))
    if ok:
        _print(f"[+] Released vessel '{username}'.", style="green")
        return 0
    _print(f"[!] No such peer: {username}", style="bold red")
    return 1


def cmd_summon(args: argparse.Namespace, db: DatabaseManager) -> int:
    if not gate_with_preflight("summon"):
        return 1
    # Remember whether the path was supplied as a CLI arg — that's our
    # signal for "interactive mode" downstream (we don't pop a hardening
    # prompt when the operator already gave flags on the command line).
    interactive = getattr(args, "path", None) is None
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
    profile = _build_security_profile(args)
    if interactive and layout == "dockerfile":
        # Surface the hardening menu only for the Dockerfile path —
        # compose deployments ignore these flags anyway.
        profile = _maybe_prompt_security(profile)
    _print(f"[*] Detected layout: {layout}. Summoning '{name}'...")

    if layout == "compose":
        result = docker_mgr.deploy_compose(
            db, challenge_name=name, path=path, security=profile
        )
    else:
        result = docker_mgr.deploy_dockerfile(
            db, challenge_name=name, path=path, security=profile
        )

    if not result.success:
        _print(f"[!] Summoning failed: {result.error}", style="bold red")
        return 1

    for c in result.containers:
        _print(
            f"[+] {c.challenge_name}  ->  {c.container_id[:12]}  @ {c.assigned_ip}",
            style="green",
        )
    if result.security_summary:
        _print(f"    hardening: {result.security_summary}", style="dim")
    return 0


def _build_security_profile(args: argparse.Namespace) -> docker_mgr.SecurityProfile:
    """Translate ``summon`` CLI flags into a :class:`SecurityProfile`."""
    extra_drops = list(getattr(args, "cap_drop", None) or [])
    # NET_RAW is always dropped; if the operator passed it again, dedupe.
    cap_drop = ["NET_RAW"] + [c for c in extra_drops if c.upper() != "NET_RAW"]
    return docker_mgr.SecurityProfile(
        no_new_privileges=not getattr(args, "allow_setuid", False),
        cap_drop=cap_drop,
        cap_add=list(getattr(args, "cap_add", None) or []),
        read_only_rootfs=bool(getattr(args, "read_only", False)),
        memory=getattr(args, "memory", None),
        cpus=getattr(args, "cpus", None),
        pids_limit=getattr(args, "pids_limit", None),
        restart_policy=getattr(args, "restart", None) or "unless-stopped",
    )


def _maybe_prompt_security(
    default: docker_mgr.SecurityProfile,
) -> docker_mgr.SecurityProfile:
    """Interactive hardening prompt for the menu's summon flow.

    Shows the default profile and lets the operator either accept it
    (single keypress) or walk through resource-limit prompts. Capability
    add/drop and ``--allow-setuid`` are intentionally CLI-only — they're
    rare and easy to misuse without seeing the full context.
    """
    _print(f"\n[*] Default hardening: {default.summary()}", style="dim")
    if not _confirm(
        "Customise resource limits / read-only / restart policy?", default=False
    ):
        return default

    _print("\n  Press Enter to keep the default shown in [brackets].", style="dim")

    def _ask_int(label: str, current: Optional[int]) -> Optional[int]:
        raw = _ask(f"  {label}", default=str(current) if current is not None else "")
        return int(raw) if raw else None

    def _ask_float(label: str, current: Optional[float]) -> Optional[float]:
        raw = _ask(f"  {label}", default=str(current) if current is not None else "")
        return float(raw) if raw else None

    def _ask_str(label: str, current: Optional[str]) -> Optional[str]:
        raw = _ask(f"  {label}", default=current or "")
        return raw or None

    memory = _ask_str("Memory cap (e.g. 512m, 1g)", default.memory)
    try:
        cpus = _ask_float("CPU cap (e.g. 1.0, 0.5)", default.cpus)
        pids_limit = _ask_int("Max processes (pids-limit)", default.pids_limit)
    except ValueError as e:
        _print(f"[!] invalid number: {e} — keeping defaults", style="bold red")
        cpus = default.cpus
        pids_limit = default.pids_limit

    read_only = _confirm("Read-only rootfs (with tmpfs /tmp)?", default=default.read_only_rootfs)

    restart_choices = ("no", "on-failure", "unless-stopped", "always")
    restart = _ask(
        f"Restart policy {restart_choices}", default=default.restart_policy
    )
    if restart not in restart_choices:
        _print(
            f"[!] unknown restart policy '{restart}' — keeping {default.restart_policy}",
            style="yellow",
        )
        restart = default.restart_policy

    return docker_mgr.SecurityProfile(
        no_new_privileges=default.no_new_privileges,
        cap_drop=list(default.cap_drop),
        cap_add=list(default.cap_add),
        read_only_rootfs=read_only,
        memory=memory,
        cpus=cpus,
        pids_limit=pids_limit,
        restart_policy=restart,
    )


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


def cmd_purge(args: argparse.Namespace, db: Optional[DatabaseManager]) -> int:
    """Aggressively remove every artifact edo has ever installed on the host.

    Use this when the host is in an unknown state — leftover iptables
    chains, a stale docker bridge, half-running wg interface, orphan
    containers from a previous edo version. Every step is idempotent and
    error-tolerant; we keep going past individual failures and report the
    score at the end.

    By default the DB and on-disk client configs are preserved so peers
    can be restored on the next ``init``. Pass ``--wipe-state`` to nuke
    those too (irreversible).
    """
    if not getattr(args, "yes", False):
        _print(
            "[*] This will remove ALL edo artifacts on this host:",
            style="bold yellow",
        )
        _print("      - every container labelled edo.managed=true")
        _print("      - the edo_br0 docker network")
        _print("      - EDO_FORWARD + EDO_INPUT iptables chains")
        _print("      - firewalld 51820/udp (if active)")
        _print("      - the wg0 interface (wg-quick down + systemd disable)")
        if getattr(args, "wipe_state", False):
            _print(
                "      - /etc/wireguard/wg0.conf + edo_clients/ + the SQLite DB",
                style="bold red",
            )
        if not _confirm("Continue?", default=False):
            _print("[*] Aborted.", style="yellow")
            return 1

    steps: List[Tuple[str, bool, str]] = []

    def _step(name: str, fn: Callable[[], Optional[str]]) -> None:
        try:
            detail = fn() or ""
            steps.append((name, True, detail))
            _print(f"[+] {name}  {detail}", style="green")
        except Exception as e:
            steps.append((name, False, str(e)))
            _print(f"[!] {name}  failed: {e}", style="yellow")

    # 1. Containers labelled edo.managed=true (catches anything the DB
    #    doesn't know about — e.g. survived a DB wipe).
    def _kill_containers() -> str:
        try:
            import docker as _d

            client = _d.from_env()
            cs = client.containers.list(
                all=True, filters={"label": "edo.managed=true"}
            )
            for c in cs:
                try:
                    c.remove(force=True)
                except _d.errors.APIError as e:
                    logger.warning("could not remove %s: %s", c.short_id, e)
            # Also flush DB rows so `status` doesn't lie.
            if db is not None:
                for ct in db.get_active_containers():
                    db.remove_container(ct.container_id)
            return f"removed {len(cs)} container(s)"
        except ImportError:
            return "docker SDK not installed — skipped"

    _step("containers", _kill_containers)

    # 2. Docker network.
    _step(
        "docker network edo_br0",
        lambda: "removed" if docker_mgr.remove_network() else "not present",
    )

    # 3. Firewall: iptables chains + firewalld port.
    def _wipe_firewall() -> str:
        results = network.remove_firewall(wg_port=wireguard.WG_LISTEN_PORT)
        ok = sum(1 for r in results if r.success)
        return f"{ok}/{len(results)} rule ops succeeded"

    _step("firewall rules", _wipe_firewall)

    # 4. WireGuard interface + systemd unit.
    _step("wg0 down", lambda: (wireguard.bring_down(), "")[1] or "ok")
    _step(
        "wg-quick@wg0 disabled",
        lambda: _systemctl_disable("wg-quick@wg0") or "ok",
    )

    # 5. State files (only with --wipe-state).
    if getattr(args, "wipe_state", False):
        _step(
            "/etc/wireguard/wg0.conf",
            lambda: _unlink(wireguard.WG_SERVER_CONFIG) or "ok",
        )
        clients_dir = resolve_client_dir(args)
        _step(
            f"client configs ({clients_dir})",
            lambda: _rmtree(clients_dir) or "ok",
        )
        if db is not None:
            db_path = Path(getattr(args, "db", None) or "/var/lib/edo/edo.db")
            _step(f"sqlite DB {db_path}", lambda: _unlink(db_path) or "ok")

    failed = [name for name, ok, _ in steps if not ok]
    if failed:
        _print(
            f"\n[!] Purge finished with {len(failed)} failure(s): {', '.join(failed)}",
            style="bold yellow",
        )
        _print(
            "    Most failures are benign (e.g. 'already absent'); re-run with --verbose for tracebacks.",
            style="dim",
        )
        return 1
    _print("\n[+] Purge complete. Host is back to a clean slate.", style="bold green")
    return 0


def _systemctl_disable(unit: str) -> Optional[str]:
    """Best-effort `systemctl disable`. Returns a brief note on success."""
    import subprocess as _sp

    if not _sp.run(["systemctl", "list-unit-files", unit], capture_output=True).stdout.strip():
        return "unit not present"
    try:
        _sp.run(
            ["systemctl", "disable", "--now", unit],
            capture_output=True,
            text=True,
            check=True,
        )
    except _sp.CalledProcessError as e:
        # `disable` fails if the unit is masked or already disabled. We
        # treat the second case as success.
        stderr = (e.stderr or "").lower()
        if "not enabled" in stderr or "no such unit" in stderr:
            return "already disabled"
        raise
    return "disabled"


def _unlink(path: Path) -> Optional[str]:
    if not path.exists():
        return "not present"
    path.unlink()
    return "removed"


def _rmtree(path: Path) -> Optional[str]:
    import shutil as _sh

    if not path.exists():
        return "not present"
    _sh.rmtree(path)
    return "removed"


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
    network.remove_firewall(wg_port=wireguard.WG_LISTEN_PORT)
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
        "7": ("Diagnose host (edo doctor)", cmd_doctor),
        "8": ("Purge — deep cleanup of every edo artifact", cmd_purge),
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
            logger.debug("command failed", exc_info=True)
            _print(f"[!] {_format_exception(e)}", style="bold red")


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
    p.add_argument(
        "--client-dir",
        type=Path,
        default=None,
        help=(
            "Directory to write generated client .conf files into. "
            "Default: /etc/wireguard/edo_clients/ (or $EDO_CLIENT_CONFIG_DIR)"
        ),
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
    # ---- container hardening (Dockerfile path only; compose path warns) ----
    p_sum.add_argument(
        "--memory",
        help="Memory cap (e.g. 512m, 1g). Default: no limit.",
    )
    p_sum.add_argument(
        "--cpus",
        type=float,
        help="CPU cap (e.g. 0.5, 1, 2). Default: no limit.",
    )
    p_sum.add_argument(
        "--pids-limit",
        type=int,
        help="Max processes the container may spawn. Default: no limit.",
    )
    p_sum.add_argument(
        "--read-only",
        action="store_true",
        help="Mount the rootfs read-only with a tmpfs /tmp.",
    )
    p_sum.add_argument(
        "--cap-add",
        action="append",
        default=[],
        metavar="CAP",
        help="Add a Linux capability (repeatable). Example: --cap-add SYS_PTRACE",
    )
    p_sum.add_argument(
        "--cap-drop",
        action="append",
        default=[],
        metavar="CAP",
        help="Drop an additional capability (repeatable). NET_RAW is always dropped.",
    )
    p_sum.add_argument(
        "--allow-setuid",
        action="store_true",
        help="Disable no-new-privileges. Only do this if a challenge intentionally needs setuid.",
    )
    p_sum.add_argument(
        "--restart",
        choices=("no", "on-failure", "unless-stopped", "always"),
        default="unless-stopped",
        help="Container restart policy. Default: unless-stopped.",
    )

    p_rel = sub.add_parser("release", help="Tear down a container")
    p_rel.add_argument("--container", help="Container ID")
    p_rel.add_argument("--all", action="store_true")

    sub.add_parser("status", help="Print live system footprint")

    p_td = sub.add_parser("teardown", help="Tear down ALL infrastructure")
    p_td.add_argument("--yes", "-y", action="store_true", help="Skip confirmation")

    sub.add_parser("menu", help="Open interactive menu (default)")

    p_doc = sub.add_parser(
        "doctor",
        help="Diagnose the host — binaries, kernel module, daemons, network",
    )
    p_doc.add_argument(
        "--no-runtime",
        action="store_true",
        help="Skip checks that touch running services (docker daemon, port bind)",
    )

    p_purge = sub.add_parser(
        "purge",
        help="Deep cleanup of every artifact edo has installed on the host",
    )
    p_purge.add_argument(
        "--yes", "-y", action="store_true", help="Skip confirmation"
    )
    p_purge.add_argument(
        "--wipe-state",
        action="store_true",
        help="Also delete /etc/wireguard/wg0.conf, edo_clients/, and the SQLite DB",
    )

    return p


# ---- error translation --------------------------------------------------
def _format_exception(e: BaseException) -> str:
    """Map common exception shapes to actionable, single-paragraph messages."""
    import subprocess as _sp

    # Missing binary — most likely a known dependency.
    if isinstance(e, FileNotFoundError):
        missing = getattr(e, "filename", None) or "?"
        try:
            hint = preflight.install_hint(str(missing))
        except Exception:
            hint = "install the missing tool"
        return f"required binary not found: {missing}\n  install: {hint}"

    # Subprocess returned non-zero. Pull out the stderr so the user sees the
    # actual failure instead of the generic CalledProcessError repr.
    if isinstance(e, _sp.CalledProcessError):
        stderr = (e.stderr or "").strip()
        cmd = e.cmd[0] if isinstance(e.cmd, list) and e.cmd else str(e.cmd)
        stderr_low = stderr.lower()
        if "operation not permitted" in stderr_low or "permission denied" in stderr_low:
            return (
                f"`{cmd}` failed with a permission error.\n"
                f"  stderr: {stderr}\n"
                f"  hint:   run with sudo (point at your venv's python if you used one)"
            )
        if "rtnetlink answers: file exists" in stderr_low:
            return (
                f"`{cmd}` reported an interface/route already exists.\n"
                f"  stderr: {stderr}\n"
                f"  hint:   if this is leftover from a prior run, `edo teardown` first"
            )
        return f"`{cmd}` exited {e.returncode}: {stderr}"

    # Catch-all for the docker SDK if it's loaded.
    try:
        from docker.errors import DockerException

        if isinstance(e, DockerException):
            low = str(e).lower()
            if "permission denied" in low:
                hint = "run with sudo, or add user to docker group"
            elif "connection refused" in low or "no such file" in low:
                hint = "start the daemon: sudo systemctl start docker"
            else:
                hint = "run `edo doctor` for a full diagnosis"
            return f"docker error: {e}\n  hint: {hint}"
    except ImportError:
        pass

    return f"{type(e).__name__}: {e}"


# ---- entrypoint ---------------------------------------------------------
# Commands that don't need root or a DB connection. Doctor is the obvious
# one — its whole job is to *report* missing capabilities, so it can't itself
# require them.
_NO_ROOT_COMMANDS = {"doctor"}
_NO_DB_COMMANDS = {"doctor"}


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.command not in _NO_ROOT_COMMANDS:
        require_root()

    if args.command in _NO_DB_COMMANDS:
        db: Optional[DatabaseManager] = None
    else:
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
        "doctor": cmd_doctor,
        "purge": cmd_purge,
    }

    if args.command in dispatch:
        try:
            return dispatch[args.command](args, db)
        except KeyboardInterrupt:
            _print("\n[!] Cancelled", style="yellow")
            return 130
        except Exception as e:
            logger.debug("command failed", exc_info=True)
            _print(f"[!] {_format_exception(e)}", style="bold red")
            _print(
                "    run `edo doctor` to diagnose the host, or re-run with --verbose for a stack trace.",
                style="dim",
            )
            return 1

    if args.command in (None, "menu"):
        return interactive_menu(db, args)

    parser.print_help()
    return 2
