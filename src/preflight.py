"""Environment preflight checks for edo.

Every check is a small pure function that returns a :class:`Check`. They are
intentionally side-effect-free so we can run the full suite read-only as
``edo doctor`` *and* invoke individual checks at the top of mutating commands
(``init`` / ``add-peer`` / ``summon``) to fail fast with an actionable hint
instead of mid-way through with a stack trace.

A check carries a :class:`Severity`:

* ``CRITICAL`` — edo cannot do useful work; abort.
* ``WARNING``  — degraded mode (e.g. docker subnet conflict, port busy); the
                 user should look but we'll try anyway.
* ``INFO``     — pure observation, never blocks.

The helpers never raise. Failures collect into the report.
"""
from __future__ import annotations

import logging
import os
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


class Severity(Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


@dataclass
class Check:
    name: str
    ok: bool
    severity: Severity
    detail: str = ""
    hint: str = ""


@dataclass
class PreflightReport:
    checks: List[Check] = field(default_factory=list)

    @property
    def critical_failures(self) -> List[Check]:
        return [c for c in self.checks if not c.ok and c.severity == Severity.CRITICAL]

    @property
    def warnings(self) -> List[Check]:
        return [c for c in self.checks if not c.ok and c.severity == Severity.WARNING]

    @property
    def ok(self) -> bool:
        return not self.critical_failures


# ---- distro detection ---------------------------------------------------
_INSTALL_HINTS = {
    "wg": {
        "deb": "sudo apt install wireguard wireguard-tools",
        "rpm": "sudo dnf install wireguard-tools",
        "arch": "sudo pacman -S wireguard-tools",
    },
    "wg-quick": {
        "deb": "sudo apt install wireguard wireguard-tools",
        "rpm": "sudo dnf install wireguard-tools",
        "arch": "sudo pacman -S wireguard-tools",
    },
    "iptables": {
        "deb": "sudo apt install iptables",
        "rpm": "sudo dnf install iptables",
        "arch": "sudo pacman -S iptables",
    },
    "ip": {
        "deb": "sudo apt install iproute2",
        "rpm": "sudo dnf install iproute",
        "arch": "sudo pacman -S iproute2",
    },
    "sysctl": {
        "deb": "sudo apt install procps",
        "rpm": "sudo dnf install procps-ng",
        "arch": "sudo pacman -S procps-ng",
    },
    "docker": {
        "deb": "sudo apt install docker-ce docker-compose-plugin",
        "rpm": "sudo dnf install docker-ce docker-compose-plugin",
        "arch": "sudo pacman -S docker docker-compose",
    },
    "modprobe": {
        "deb": "sudo apt install kmod",
        "rpm": "sudo dnf install kmod",
        "arch": "sudo pacman -S kmod",
    },
}


def _detect_distro_family() -> str:
    if Path("/etc/arch-release").exists():
        return "arch"
    if Path("/etc/debian_version").exists():
        return "deb"
    if Path("/etc/redhat-release").exists() or Path("/etc/system-release").exists():
        return "rpm"
    osr = Path("/etc/os-release")
    if osr.exists():
        try:
            text = osr.read_text()
        except OSError:
            text = ""
        text_low = text.lower()
        if "id=arch" in text_low or "id_like=arch" in text_low:
            return "arch"
        if "debian" in text_low or "ubuntu" in text_low:
            return "deb"
        if "rhel" in text_low or "fedora" in text_low or "centos" in text_low or "almalinux" in text_low or "rocky" in text_low:
            return "rpm"
    return "deb"


def install_hint(binary: str) -> str:
    """Return the best-guess install command for ``binary`` on this host."""
    family = _detect_distro_family()
    return _INSTALL_HINTS.get(binary, {}).get(family) or f"install {binary} via your package manager"


# ---- individual checks --------------------------------------------------
def check_root() -> Check:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return Check(
            "root privileges",
            False,
            Severity.CRITICAL,
            detail="os.geteuid unavailable (non-POSIX host)",
            hint="edo is Linux-only",
        )
    is_root = geteuid() == 0
    return Check(
        "root privileges",
        is_root,
        Severity.CRITICAL,
        detail="" if is_root else f"running as uid {geteuid()}",
        hint="" if is_root else "re-run with sudo (point at your venv's python: sudo ./myvenv/bin/python edo.py)",
    )


def check_binary(name: str, severity: Severity = Severity.CRITICAL) -> Check:
    path = shutil.which(name)
    return Check(
        name=f"binary: {name}",
        ok=path is not None,
        severity=severity,
        detail=f"found at {path}" if path else "not on PATH",
        hint="" if path else install_hint(name),
    )


def check_python_pkg(name: str, severity: Severity = Severity.CRITICAL) -> Check:
    try:
        __import__(name)
        return Check(
            f"python pkg: {name}", True, severity, detail="importable"
        )
    except ImportError as e:
        hint = f"pip install {name}"
        # Detect the classic venv-sudo trap: an active venv exists in CWD
        # but sys.executable isn't pointing inside it.
        venv_path = _detect_active_venv()
        if venv_path:
            venv_py = venv_path / "bin" / "python"
            if venv_py.exists() and Path(sys.executable).resolve() != venv_py.resolve():
                hint = (
                    f"pip install {name} — and remember `sudo python3` ignores venvs; "
                    f"run sudo {venv_py} edo.py instead"
                )
        return Check(
            f"python pkg: {name}", False, severity, detail=str(e), hint=hint
        )


def _detect_active_venv() -> Optional[Path]:
    """Look for an obvious venv adjacent to the project — heuristic only."""
    cwd = Path.cwd()
    for candidate in (".venv", "venv", "myvenv", "env"):
        p = cwd / candidate
        if (p / "bin" / "python").exists() or (p / "Scripts" / "python.exe").exists():
            return p
    return None


def check_kernel_module(name: str) -> Check:
    """Best-effort check that a kernel module is available.

    A module shown by ``/proc/modules`` is loaded; ``modprobe -n -v`` confirms
    it could be loaded on demand. Failing both flags a possible kernel
    support gap.
    """
    proc_modules = Path("/proc/modules")
    if proc_modules.exists():
        try:
            for line in proc_modules.read_text().splitlines():
                if line.startswith(f"{name} "):
                    return Check(
                        f"kernel module: {name}",
                        True,
                        Severity.WARNING,
                        detail="loaded",
                    )
        except OSError:
            pass

    if shutil.which("modprobe"):
        try:
            proc = subprocess.run(
                ["modprobe", "-n", "-v", name],
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                return Check(
                    f"kernel module: {name}",
                    True,
                    Severity.INFO,
                    detail="loadable (lazy)",
                    hint=f"pre-load with: sudo modprobe {name}",
                )
        except OSError:
            pass

    return Check(
        f"kernel module: {name}",
        False,
        Severity.WARNING,
        detail="not loaded and modprobe could not stage it",
        hint=f"kernel may lack {name} support; check `uname -r` and your distro's kernel modules package",
    )


def check_ip_forward() -> Check:
    p = Path("/proc/sys/net/ipv4/ip_forward")
    try:
        val = p.read_text().strip()
    except OSError as e:
        return Check(
            "ip_forward enabled",
            False,
            Severity.WARNING,
            detail=str(e),
            hint="`edo init` will try to enable this with sysctl",
        )
    if val == "1":
        return Check("ip_forward enabled", True, Severity.INFO, detail="net.ipv4.ip_forward=1")
    return Check(
        "ip_forward enabled",
        False,
        Severity.WARNING,
        detail=f"net.ipv4.ip_forward={val}",
        hint="`edo init` enables this; for a persistent value add net.ipv4.ip_forward=1 to /etc/sysctl.conf",
    )


def check_default_route() -> Check:
    if not shutil.which("ip"):
        return Check(
            "default IPv4 route",
            False,
            Severity.CRITICAL,
            detail="ip command missing",
            hint=install_hint("ip"),
        )
    try:
        proc = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as e:
        return Check("default IPv4 route", False, Severity.CRITICAL, detail=str(e))
    tokens = proc.stdout.split()
    if "dev" in tokens:
        idx = tokens.index("dev")
        if idx + 1 < len(tokens):
            iface = tokens[idx + 1]
            return Check(
                "default IPv4 route", True, Severity.CRITICAL, detail=f"via {iface}"
            )
    return Check(
        "default IPv4 route",
        False,
        Severity.CRITICAL,
        detail="no default IPv4 route",
        hint="edo's egress firewall rule needs to know the public interface; check `ip -4 route show default`",
    )


def check_port_free(port: int = 51820, proto: str = "udp") -> Check:
    sock_type = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
    try:
        with socket.socket(socket.AF_INET, sock_type) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
    except OSError as e:
        return Check(
            f"port {port}/{proto} free",
            False,
            Severity.WARNING,
            detail=str(e),
            hint=f"if wg0 is already up from a previous edo run, this is fine; otherwise pick a different --port",
        )
    return Check(f"port {port}/{proto} free", True, Severity.INFO)


def check_docker_daemon() -> Check:
    try:
        import docker
        from docker.errors import DockerException
    except ImportError as e:
        return Check(
            "docker daemon reachable",
            False,
            Severity.CRITICAL,
            detail=f"docker python SDK missing: {e}",
            hint="pip install docker",
        )
    try:
        client = docker.from_env()
        client.ping()
        return Check("docker daemon reachable", True, Severity.CRITICAL, detail="ping ok")
    except DockerException as e:
        msg = str(e)
        hint = "is dockerd running? try: sudo systemctl start docker"
        msg_low = msg.lower()
        if "permission denied" in msg_low:
            hint = "permission denied on /var/run/docker.sock — run with sudo, or add your user to the docker group and re-login"
        elif "connection refused" in msg_low or "no such file" in msg_low or "cannot connect" in msg_low:
            hint = "docker daemon socket not reachable — sudo systemctl start docker (and sudo systemctl enable docker for boot)"
        return Check(
            "docker daemon reachable", False, Severity.CRITICAL, detail=msg, hint=hint
        )


def check_docker_subnet_clear() -> Check:
    """Make sure the docker bridge subnet isn't already owned by another network."""
    try:
        import docker
        from docker.errors import DockerException
        from src.network import DOCKER_BRIDGE, DOCKER_SUBNET
    except ImportError as e:
        return Check(
            "docker subnet clear",
            False,
            Severity.WARNING,
            detail=f"prerequisite missing: {e}",
        )
    try:
        client = docker.from_env()
        target = str(DOCKER_SUBNET)
        for net in client.networks.list():
            if net.name == DOCKER_BRIDGE:
                continue
            ipam = (net.attrs.get("IPAM") or {}).get("Config") or []
            for cfg in ipam:
                if cfg.get("Subnet") == target:
                    return Check(
                        "docker subnet clear",
                        False,
                        Severity.CRITICAL,
                        detail=f"{target} already used by docker network '{net.name}'",
                        hint=f"remove the conflicting network first: docker network rm {net.name}",
                    )
        return Check("docker subnet clear", True, Severity.INFO, detail=f"{target} available")
    except DockerException as e:
        return Check(
            "docker subnet clear",
            False,
            Severity.WARNING,
            detail=str(e),
            hint="docker daemon must be reachable first — see the previous check",
        )


def check_edo_chain_precedence() -> Check:
    """Verify ``EDO_FORWARD`` is hooked into the right place.

    On hosts with Docker installed, Docker re-inserts its own
    ``DOCKER-USER`` and ``DOCKER-FORWARD`` chains at the top of FORWARD on
    every restart. If ``EDO_FORWARD`` is hooked into FORWARD directly, it
    ends up *after* ``DOCKER-FORWARD`` and our rules never fire because
    Docker's chain drops wg0→edo_br0 traffic first. Detects that case and
    points at the fix.
    """
    if not shutil.which("iptables"):
        return Check(
            "EDO_FORWARD precedence",
            False,
            Severity.WARNING,
            detail="iptables binary missing",
            hint=install_hint("iptables"),
        )
    try:
        forward = subprocess.run(
            ["iptables", "-L", "FORWARD", "-n", "--line-numbers"],
            capture_output=True,
            text=True,
            check=False,
        )
        docker_user = subprocess.run(
            ["iptables", "-L", "DOCKER-USER", "-n", "--line-numbers"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as e:
        return Check(
            "EDO_FORWARD precedence", False, Severity.WARNING, detail=str(e)
        )

    in_docker_user = (
        docker_user.returncode == 0 and "EDO_FORWARD" in docker_user.stdout
    )
    in_forward = forward.returncode == 0 and "EDO_FORWARD" in forward.stdout
    docker_installed = docker_user.returncode == 0

    if in_docker_user:
        return Check(
            "EDO_FORWARD precedence",
            True,
            Severity.INFO,
            detail="hooked in DOCKER-USER (survives docker restarts)",
        )
    if in_forward and docker_installed:
        return Check(
            "EDO_FORWARD precedence",
            False,
            Severity.CRITICAL,
            detail="hooked in FORWARD but DOCKER-USER exists — Docker's chains will run first",
            hint=(
                "re-run `edo init` to fix automatically, or manually: "
                "`sudo iptables -D FORWARD -j EDO_FORWARD && "
                "sudo iptables -I DOCKER-USER 1 -j EDO_FORWARD`"
            ),
        )
    if in_forward:
        return Check(
            "EDO_FORWARD precedence",
            True,
            Severity.INFO,
            detail="hooked in FORWARD (Docker not installed — acceptable)",
        )
    return Check(
        "EDO_FORWARD precedence",
        False,
        Severity.WARNING,
        detail="EDO_FORWARD is not hooked into any chain",
        hint="run `edo init` to install the firewall",
    )


def check_wg_port_accepted(port: int = 51820) -> Check:
    """Verify the WireGuard handshake port is reachable on INPUT.

    This is the single most common reason a fresh deployment "looks right"
    but never sees a handshake: firewalld (or ufw, or a default-deny INPUT
    policy) silently drops the UDP handshake before it reaches ``wg0``.
    """
    try:
        from src.network import firewalld_active, wg_port_accepted
    except ImportError as e:
        return Check(
            f"wg port {port}/udp accepted",
            False,
            Severity.WARNING,
            detail=f"could not import network helpers: {e}",
        )
    if wg_port_accepted(port):
        return Check(
            f"wg port {port}/udp accepted",
            True,
            Severity.INFO,
            detail="firewalld port-list or EDO_INPUT chain",
        )
    if firewalld_active():
        return Check(
            f"wg port {port}/udp accepted",
            False,
            Severity.WARNING,
            detail="firewalld is active but this port is not in its open-ports list",
            hint=(
                f"`edo init` will open it automatically. To do it manually now: "
                f"sudo firewall-cmd --add-port={port}/udp --permanent && sudo firewall-cmd --reload"
            ),
        )
    return Check(
        f"wg port {port}/udp accepted",
        False,
        Severity.WARNING,
        detail="no edo INPUT rule and firewalld is not running",
        hint=(
            "if your host has a default-deny INPUT policy or runs another firewall, "
            f"open {port}/udp manually or rerun `edo init` to install edo's EDO_INPUT rule"
        ),
    )


def check_wg_interface_up(interface: str = "wg0") -> Check:
    """Stricter than :func:`check_wg_interface_state` — fails if the
    interface is missing or down. Used as a gate on commands that mutate
    live peer state (``add-peer`` / ``remove-peer``); without ``wg0`` up,
    those commands change config files on disk but produce clients that
    can never handshake.
    """
    if not shutil.which("wg"):
        return Check(
            f"{interface} up",
            False,
            Severity.CRITICAL,
            detail="wg command missing",
            hint=install_hint("wg"),
        )
    try:
        proc = subprocess.run(
            ["wg", "show", interface],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as e:
        return Check(
            f"{interface} up", False, Severity.CRITICAL, detail=str(e)
        )
    if proc.returncode == 0:
        return Check(
            f"{interface} up", True, Severity.INFO, detail="up and configured"
        )
    stderr = (proc.stderr or "").strip() or "interface not running"
    return Check(
        f"{interface} up",
        False,
        Severity.CRITICAL,
        detail=stderr,
        hint=(
            f"bring it up: `sudo edo init --endpoint <host>` (idempotent), or "
            f"`sudo wg-quick up {interface}` directly. To survive reboots: "
            f"`sudo systemctl enable wg-quick@{interface}`"
        ),
    )


def check_wg_interface_state(interface: str = "wg0") -> Check:
    if not shutil.which("ip"):
        return Check(
            f"{interface} state",
            False,
            Severity.WARNING,
            detail="ip command missing",
            hint=install_hint("ip"),
        )
    try:
        proc = subprocess.run(
            ["ip", "link", "show", interface],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as e:
        return Check(f"{interface} state", False, Severity.WARNING, detail=str(e))
    if proc.returncode == 0:
        return Check(
            f"{interface} state",
            True,
            Severity.INFO,
            detail="interface present",
            hint=f"if it wasn't created by edo, bring it down first: sudo wg-quick down {interface}",
        )
    return Check(
        f"{interface} state",
        True,
        Severity.INFO,
        detail="not present (will be created by edo init)",
    )


# ---- aggregate ----------------------------------------------------------
def run_all_checks(include_runtime: bool = True) -> PreflightReport:
    """Run every check.

    ``include_runtime=False`` skips checks that talk to running services
    (docker daemon, network state). Useful when you want a quick "is anything
    installed?" pass without touching live infrastructure.
    """
    report = PreflightReport()
    report.checks.append(check_root())

    # Required CLI tools.
    for binary in ("wg", "wg-quick", "iptables", "ip", "sysctl"):
        report.checks.append(check_binary(binary, severity=Severity.CRITICAL))
    # docker CLI is only needed for the compose flow; treat as warning.
    report.checks.append(check_binary("docker", severity=Severity.WARNING))

    report.checks.append(check_python_pkg("docker", severity=Severity.CRITICAL))

    report.checks.append(check_kernel_module("wireguard"))
    report.checks.append(check_ip_forward())
    report.checks.append(check_default_route())

    if include_runtime:
        report.checks.append(check_docker_daemon())
        report.checks.append(check_docker_subnet_clear())
        report.checks.append(check_wg_interface_state())
        report.checks.append(check_port_free(51820, "udp"))
        report.checks.append(check_wg_port_accepted(51820))
        report.checks.append(check_edo_chain_precedence())

    return report


def quick_checks_for(command: str) -> PreflightReport:
    """The subset of checks worth running before a specific mutating command.

    Kept tight on purpose: a 200ms preflight before ``init`` is fine, but
    blocking ``status`` on full checks would be annoying.
    """
    report = PreflightReport()
    report.checks.append(check_root())

    if command in {"init", "add-peer", "remove-peer"}:
        for b in ("wg", "wg-quick", "iptables", "ip"):
            report.checks.append(check_binary(b))
        report.checks.append(check_kernel_module("wireguard"))

    if command in {"add-peer", "remove-peer"}:
        # Without wg0 actually running, add-peer happily updates the config
        # file and DB but the generated client config can never handshake.
        # Same goes for remove-peer — the DB drop "succeeds" while the live
        # peer entry stays around until wg-quick down/up.
        report.checks.append(check_wg_interface_up())

    if command == "add-peer":
        # Most common silent failure mode for add-peer: port isn't open,
        # so the new client config will never handshake. Flag it early.
        report.checks.append(check_wg_port_accepted(51820))

    if command in {"init", "summon"}:
        report.checks.append(check_python_pkg("docker"))
        # Only ping the daemon if the SDK loaded.
        if any(c.name == "python pkg: docker" and c.ok for c in report.checks):
            report.checks.append(check_docker_daemon())

    if command == "init":
        report.checks.append(check_default_route())

    return report
