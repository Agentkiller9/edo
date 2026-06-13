"""Routing and firewall plane for edo.

Designed around three guarantees:

  1. **Client isolation.**     Traffic where both src and dst are inside the
                               WireGuard subnet is DROPped — participants
                               cannot scan or attack each other.
  2. **Egress containment.**   Containers cannot reach the public internet
                               via the host's default interface.
  3. **Reverse-shell channel.**Containers may originate connections to the
                               WireGuard subnet so participants can catch
                               callbacks during challenges.

All rules live in a dedicated chain (``EDO_FORWARD``) hooked at the top of
``FORWARD``. That makes apply/remove atomic — we flush our chain on apply,
and on remove we unhook + flush + delete without touching the user's other
iptables rules. Docker's own DOCKER / DOCKER-USER chains are left alone.
"""
from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

# ---- topology constants -------------------------------------------------
WG_SUBNET = ipaddress.IPv4Network("10.8.0.0/24")
DOCKER_SUBNET = ipaddress.IPv4Network("10.9.0.0/24")

WG_INTERFACE = "wg0"
DOCKER_BRIDGE = "edo_br0"

WG_SERVER_IP = "10.8.0.1"
DOCKER_GATEWAY_IP = "10.9.0.1"

EDO_CHAIN = "EDO_FORWARD"
EDO_INPUT_CHAIN = "EDO_INPUT"


@dataclass
class RuleResult:
    success: bool
    rule: List[str]
    stderr: str = ""


@dataclass
class FirewallApplyResult:
    public_interface: str
    rules: List[RuleResult] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return all(r.success for r in self.rules)


# ---- subprocess helpers -------------------------------------------------
def _run(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    logger.debug("exec: %s", " ".join(cmd))
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=check)
    except FileNotFoundError as e:
        # Translate missing-binary failures into actionable hints. Imported
        # lazily to avoid a circular import on module load.
        from src.preflight import install_hint

        raise RuntimeError(
            f"required binary not found: {cmd[0]}\n"
            f"  install: {install_hint(cmd[0])}"
        ) from e


def get_public_interface() -> Optional[str]:
    """Resolve the host's default-route interface.

    Returns ``None`` if no IPv4 default route exists (machine has no internet).
    """
    try:
        proc = _run(["ip", "-4", "route", "show", "default"])
    except subprocess.CalledProcessError as e:
        logger.error("could not query default route: %s", e.stderr.strip())
        return None
    tokens = proc.stdout.split()
    if "dev" in tokens:
        idx = tokens.index("dev")
        if idx + 1 < len(tokens):
            return tokens[idx + 1]
    return None


# ---- iptables primitives ------------------------------------------------
def _iptables_check(rule: List[str]) -> bool:
    """``iptables -C`` returns 0 if the rule exists, non-zero otherwise."""
    try:
        proc = subprocess.run(
            ["iptables", "-C", *rule], capture_output=True, text=True
        )
    except OSError:
        return False
    return proc.returncode == 0


def _iptables_append(rule: List[str]) -> RuleResult:
    if _iptables_check(rule):
        logger.debug("rule already present, skipping: %s", rule)
        return RuleResult(success=True, rule=rule)
    try:
        _run(["iptables", "-A", *rule])
        return RuleResult(success=True, rule=rule)
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or "").strip()
        logger.error("iptables -A failed: %s -- %s", rule, msg)
        return RuleResult(success=False, rule=rule, stderr=msg)


def _iptables_delete(rule: List[str]) -> RuleResult:
    if not _iptables_check(rule):
        return RuleResult(success=True, rule=rule)
    try:
        _run(["iptables", "-D", *rule])
        return RuleResult(success=True, rule=rule)
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or "").strip()
        logger.error("iptables -D failed: %s -- %s", rule, msg)
        return RuleResult(success=False, rule=rule, stderr=msg)


def _chain_exists(chain: str) -> bool:
    try:
        proc = subprocess.run(
            ["iptables", "-L", chain, "-n"], capture_output=True, text=True
        )
    except OSError:
        # iptables binary missing entirely — caller treats this as "no chain".
        return False
    return proc.returncode == 0


# ---- firewalld interop --------------------------------------------------
def firewalld_active() -> bool:
    """Return True when firewalld is installed *and* the daemon is running.

    RHEL/AlmaLinux/Rocky default to firewalld. When it's active, raw
    iptables additions still appear in the chains but firewalld rewrites
    the ruleset on reload and silently undoes them — so we delegate the
    port opening to ``firewall-cmd`` instead.
    """
    if not shutil.which("firewall-cmd"):
        return False
    try:
        proc = subprocess.run(
            ["firewall-cmd", "--state"], capture_output=True, text=True
        )
    except OSError:
        return False
    return proc.returncode == 0 and "running" in proc.stdout.lower()


def _firewalld_port_listed(port: int, proto: str = "udp") -> bool:
    try:
        proc = subprocess.run(
            ["firewall-cmd", "--list-ports"], capture_output=True, text=True
        )
    except OSError:
        return False
    return proc.returncode == 0 and f"{port}/{proto}" in proc.stdout


def wg_port_accepted(port: int = 51820, proto: str = "udp") -> bool:
    """Best-effort: is the WG handshake port currently accepted on INPUT?

    Used by the doctor preflight. Returns True if either firewalld lists
    the port or edo's INPUT chain has a matching ACCEPT.
    """
    if firewalld_active() and _firewalld_port_listed(port, proto):
        return True
    if _chain_exists(EDO_INPUT_CHAIN):
        try:
            proc = subprocess.run(
                ["iptables", "-L", EDO_INPUT_CHAIN, "-n"],
                capture_output=True,
                text=True,
            )
        except OSError:
            return False
        if proc.returncode == 0 and f"dpt:{port}" in proc.stdout:
            return True
    return False


def apply_wg_input_rule(port: int = 51820) -> RuleResult:
    """Open the WireGuard listener port on the host's INPUT plane.

    Routes through firewalld when active so a future reload doesn't wipe
    the rule; otherwise installs a dedicated ``EDO_INPUT`` chain hooked at
    the top of INPUT.
    """
    if firewalld_active():
        try:
            _run(["firewall-cmd", f"--add-port={port}/udp", "--permanent"])
            _run(["firewall-cmd", "--reload"])
            logger.info("firewalld: opened %d/udp permanently", port)
            return RuleResult(
                success=True, rule=["firewalld", f"{port}/udp"]
            )
        except subprocess.CalledProcessError as e:
            msg = (e.stderr or "").strip() or str(e)
            return RuleResult(
                success=False, rule=["firewalld", f"{port}/udp"], stderr=msg
            )

    # No firewalld — manage our own INPUT chain.
    subprocess.run(
        ["iptables", "-N", EDO_INPUT_CHAIN], capture_output=True, text=True
    )
    hook = ["INPUT", "-j", EDO_INPUT_CHAIN]
    if not _iptables_check(hook):
        try:
            _run(["iptables", "-I", "INPUT", "1", "-j", EDO_INPUT_CHAIN])
        except subprocess.CalledProcessError as e:
            return RuleResult(
                success=False,
                rule=hook,
                stderr=(e.stderr or "").strip(),
            )

    try:
        _run(["iptables", "-F", EDO_INPUT_CHAIN])
    except subprocess.CalledProcessError as e:
        return RuleResult(
            success=False,
            rule=["-F", EDO_INPUT_CHAIN],
            stderr=(e.stderr or "").strip(),
        )

    rule = [
        EDO_INPUT_CHAIN,
        "-p", "udp",
        "--dport", str(port),
        "-m", "comment", "--comment", "edo: WireGuard handshake",
        "-j", "ACCEPT",
    ]
    return _iptables_append(rule)


def remove_wg_input_rule(port: int = 51820) -> RuleResult:
    """Inverse of :func:`apply_wg_input_rule`. Idempotent."""
    if firewalld_active():
        try:
            _run(
                ["firewall-cmd", f"--remove-port={port}/udp", "--permanent"]
            )
            _run(["firewall-cmd", "--reload"])
            return RuleResult(
                success=True, rule=["firewalld", f"{port}/udp"]
            )
        except subprocess.CalledProcessError as e:
            return RuleResult(
                success=False,
                rule=["firewalld", f"{port}/udp"],
                stderr=(e.stderr or "").strip(),
            )

    hook = ["INPUT", "-j", EDO_INPUT_CHAIN]
    if _iptables_check(hook):
        _iptables_delete(hook)
    if _chain_exists(EDO_INPUT_CHAIN):
        try:
            _run(["iptables", "-F", EDO_INPUT_CHAIN])
            _run(["iptables", "-X", EDO_INPUT_CHAIN])
        except subprocess.CalledProcessError as e:
            return RuleResult(
                success=False,
                rule=["-X", EDO_INPUT_CHAIN],
                stderr=(e.stderr or "").strip(),
            )
    return RuleResult(success=True, rule=[EDO_INPUT_CHAIN, "removed"])


# ---- rule set -----------------------------------------------------------
def _build_chain_rules(public_iface: str) -> List[List[str]]:
    """Rules added to EDO_FORWARD, *in evaluation order*.

    First match wins; order is load-bearing — do not reshuffle without
    re-checking each goal in the module docstring.
    """
    wg = str(WG_SUBNET)
    docker = str(DOCKER_SUBNET)
    return [
        # (1) Client isolation — drop intra-VPN traffic before anything else.
        [EDO_CHAIN, "-s", wg, "-d", wg, "-j", "DROP"],
        # (2) VPN ↔ Docker bridge: bidirectional forwarding allowed.
        [EDO_CHAIN, "-i", WG_INTERFACE, "-o", DOCKER_BRIDGE, "-j", "ACCEPT"],
        [EDO_CHAIN, "-i", DOCKER_BRIDGE, "-o", WG_INTERFACE, "-j", "ACCEPT"],
        # (3) Reverse-shell exception — docker → wg subnet explicitly accepted
        #     so it cannot be caught by the egress drop in (4).
        [EDO_CHAIN, "-s", docker, "-d", wg, "-j", "ACCEPT"],
        # (4) Egress containment — anything from the docker subnet trying to
        #     exit through the public interface is dropped.
        [EDO_CHAIN, "-s", docker, "-o", public_iface, "-j", "DROP"],
    ]


# ---- public API ---------------------------------------------------------
def apply_firewall(wg_port: int = 51820) -> FirewallApplyResult:
    """Idempotently install all edo firewall rules.

    Adds the FORWARD rules **and** opens UDP ``wg_port`` on the host's
    INPUT plane so the WireGuard handshake can actually reach the
    listener — historically this was assumed and bit users on RHEL-family
    hosts where firewalld blocks everything by default.

    Raises ``RuntimeError`` if any rule fails to install; partially-applied
    rules are flushed before raising so the host is left in a clean state.
    """
    public_iface = get_public_interface()
    if not public_iface:
        raise RuntimeError(
            "Unable to determine public interface; refusing to apply firewall"
        )

    # Enable forwarding — without this, FORWARD rules are moot.
    try:
        _run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"failed to enable net.ipv4.ip_forward: {(e.stderr or '').strip()}"
        ) from e

    # Ensure the chain exists. -N fails with code 1 if the chain already
    # exists; that is fine — swallow the failure rather than rely on
    # parsing stderr.
    subprocess.run(["iptables", "-N", EDO_CHAIN], capture_output=True, text=True)

    # Hook EDO_FORWARD at position 1 of FORWARD if not already hooked.
    hook = ["FORWARD", "-j", EDO_CHAIN]
    if not _iptables_check(hook):
        try:
            _run(["iptables", "-I", "FORWARD", "1", "-j", EDO_CHAIN])
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"failed to hook {EDO_CHAIN} into FORWARD: {(e.stderr or '').strip()}"
            ) from e

    # Start clean: flush prior contents of our chain. Anything previously
    # added by edo is now gone.
    try:
        _run(["iptables", "-F", EDO_CHAIN])
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"failed to flush {EDO_CHAIN}: {(e.stderr or '').strip()}"
        ) from e

    result = FirewallApplyResult(public_interface=public_iface)
    for rule in _build_chain_rules(public_iface):
        res = _iptables_append(rule)
        result.rules.append(res)
        if not res.success:
            # Roll back: flush the chain so we don't leave half-installed
            # policy in place.
            logger.error("rolling back firewall after rule failure: %s", rule)
            subprocess.run(
                ["iptables", "-F", EDO_CHAIN], capture_output=True, text=True
            )
            raise RuntimeError(
                f"failed to install rule {rule}: {res.stderr}"
            )
    # Finally, open the WireGuard handshake port on INPUT. We do this last
    # so a failure here doesn't leave FORWARD half-applied.
    input_result = apply_wg_input_rule(wg_port)
    result.rules.append(input_result)
    if not input_result.success:
        logger.error(
            "could not open %d/udp for WireGuard: %s",
            wg_port,
            input_result.stderr,
        )
        # Don't roll back FORWARD — operators may want to fix the port
        # opening manually rather than re-install everything.

    logger.info(
        "firewall applied (public iface=%s, %d rules)",
        public_iface,
        len(result.rules),
    )
    return result


def remove_firewall(wg_port: int = 51820) -> List[RuleResult]:
    """Unhook, flush, and delete the edo chains. Idempotent."""
    results: List[RuleResult] = []
    hook = ["FORWARD", "-j", EDO_CHAIN]
    if _iptables_check(hook):
        results.append(_iptables_delete(hook))

    if _chain_exists(EDO_CHAIN):
        try:
            _run(["iptables", "-F", EDO_CHAIN])
            results.append(
                RuleResult(success=True, rule=["-F", EDO_CHAIN])
            )
        except subprocess.CalledProcessError as e:
            results.append(
                RuleResult(
                    success=False,
                    rule=["-F", EDO_CHAIN],
                    stderr=(e.stderr or "").strip(),
                )
            )
        try:
            _run(["iptables", "-X", EDO_CHAIN])
            results.append(
                RuleResult(success=True, rule=["-X", EDO_CHAIN])
            )
        except subprocess.CalledProcessError as e:
            results.append(
                RuleResult(
                    success=False,
                    rule=["-X", EDO_CHAIN],
                    stderr=(e.stderr or "").strip(),
                )
            )
    # Also drop the WG input rule we installed.
    results.append(remove_wg_input_rule(wg_port))

    logger.info("firewall removed (%d ops)", len(results))
    return results


def iter_subnet_hosts(network: ipaddress.IPv4Network, exclude: List[str]) -> str:
    """Find the first usable host IP not in ``exclude``.

    Raises ``RuntimeError`` if the subnet is exhausted.
    """
    blocked = set(exclude)
    for host in network.hosts():
        candidate = str(host)
        if candidate not in blocked:
            return candidate
    raise RuntimeError(f"subnet {network} is exhausted")
