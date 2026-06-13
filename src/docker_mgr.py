"""Docker control plane for edo.

Supports two challenge layouts:

  * **Dockerfile** — built via the docker SDK, run with a static IPv4 on
    ``edo_br0``, and recorded in the DB.
  * **docker-compose.yml** — orchestrated via the ``docker compose`` CLI
    (more reliable than the SDK for compose semantics), with each spawned
    container then attached to ``edo_br0`` with a static IP and logged.

Every deployment is transactional: if any sub-step fails, already-created
images/containers/DB rows are torn down so the host is left as it was.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# Deferred import: the docker SDK isn't required to *load* this module —
# only to *use* it. That lets `edo doctor` run and tell the user the SDK is
# missing instead of crashing at import time before the CLI starts.
try:
    import docker
    from docker.errors import (
        APIError,
        BuildError,
        DockerException,
        ImageNotFound,
        NotFound,
    )

    _DOCKER_SDK_AVAILABLE = True
except ImportError:
    docker = None  # type: ignore[assignment]
    _DOCKER_SDK_AVAILABLE = False

    # Stand-in classes keep ``except`` blocks elsewhere in this module valid
    # without the real SDK. They never match a real docker error because
    # ``_require_docker()`` raises first if the SDK is absent.
    class APIError(Exception):  # type: ignore[no-redef]
        pass

    class BuildError(Exception):  # type: ignore[no-redef]
        pass

    class DockerException(Exception):  # type: ignore[no-redef]
        pass

    class ImageNotFound(Exception):  # type: ignore[no-redef]
        pass

    class NotFound(Exception):  # type: ignore[no-redef]
        pass


from src.db_mgr import Container, DatabaseManager
from src.network import (
    DOCKER_BRIDGE,
    DOCKER_GATEWAY_IP,
    DOCKER_SUBNET,
    iter_subnet_hosts,
)

logger = logging.getLogger(__name__)

COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
)


@dataclass
class SecurityProfile:
    """Container-level security and resource controls.

    Defaults are conservative: ``no-new-privileges`` blocks setuid
    escalation paths from inside the container, and ``NET_RAW`` is dropped
    so a compromised container can't sniff or spoof packets on the docker
    bridge (a real lateral-movement vector when multiple challenges share
    edo_br0). Everything else mirrors Docker's defaults so we don't break
    existing challenges.

    All resource limits are opt-in. Operators tune them per challenge via
    ``edo summon --memory 512m --cpus 1 --pids-limit 100``.
    """

    no_new_privileges: bool = True
    cap_drop: List[str] = field(default_factory=lambda: ["NET_RAW"])
    cap_add: List[str] = field(default_factory=list)
    read_only_rootfs: bool = False
    memory: Optional[str] = None       # e.g. "512m", "1g"
    cpus: Optional[float] = None        # e.g. 0.5, 1.0
    pids_limit: Optional[int] = None
    restart_policy: str = "unless-stopped"

    def summary(self) -> str:
        """One-line human summary suitable for logging after deploy."""
        bits: List[str] = []
        if self.no_new_privileges:
            bits.append("no-new-privs")
        if self.cap_drop:
            bits.append(f"cap-drop={'+'.join(self.cap_drop)}")
        if self.cap_add:
            bits.append(f"cap-add={'+'.join(self.cap_add)}")
        if self.read_only_rootfs:
            bits.append("read-only")
        if self.memory:
            bits.append(f"mem={self.memory}")
        if self.cpus is not None:
            bits.append(f"cpus={self.cpus}")
        if self.pids_limit is not None:
            bits.append(f"pids={self.pids_limit}")
        bits.append(f"restart={self.restart_policy}")
        return " ".join(bits)


def _build_secure_host_config(client: "docker.DockerClient", profile: SecurityProfile) -> dict:
    """Translate a :class:`SecurityProfile` into a Docker host_config dict."""
    kwargs: dict = {"restart_policy": {"Name": profile.restart_policy}}

    security_opt: List[str] = []
    if profile.no_new_privileges:
        security_opt.append("no-new-privileges:true")
    if security_opt:
        kwargs["security_opt"] = security_opt

    if profile.cap_drop:
        kwargs["cap_drop"] = list(profile.cap_drop)
    if profile.cap_add:
        kwargs["cap_add"] = list(profile.cap_add)

    if profile.memory:
        kwargs["mem_limit"] = profile.memory
    if profile.cpus is not None:
        kwargs["nano_cpus"] = int(profile.cpus * 1_000_000_000)
    if profile.pids_limit is not None:
        kwargs["pids_limit"] = profile.pids_limit
    if profile.read_only_rootfs:
        kwargs["read_only"] = True
        # Most challenges need *somewhere* writable; /tmp tmpfs is the
        # least-surprising default. Operators who want a fully sealed
        # rootfs can omit /tmp from their Dockerfile usage.
        kwargs["tmpfs"] = {"/tmp": "rw,size=64m,exec"}

    return client.api.create_host_config(**kwargs)


@dataclass
class DeployResult:
    success: bool
    containers: List[Container] = field(default_factory=list)
    error: Optional[str] = None
    image_tag: Optional[str] = None
    security_summary: Optional[str] = None


# ---- helpers ------------------------------------------------------------
def _run(
    cmd: List[str], cwd: Optional[Path] = None, check: bool = True
) -> subprocess.CompletedProcess:
    logger.debug("exec: %s (cwd=%s)", " ".join(cmd), cwd)
    try:
        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=check,
        )
    except FileNotFoundError as e:
        from src.preflight import install_hint

        raise RuntimeError(
            f"required binary not found: {cmd[0]}\n"
            f"  install: {install_hint(cmd[0])}"
        ) from e


def _require_docker() -> None:
    """Fail with a clean message if the docker SDK never loaded."""
    if not _DOCKER_SDK_AVAILABLE:
        raise RuntimeError(
            "docker python SDK not installed (pip install docker).\n"
            "  Common gotcha: `sudo python3` ignores activated venvs — use the\n"
            "  venv's interpreter directly: `sudo ./myvenv/bin/python edo.py`."
        )


_client_cache: Optional["docker.DockerClient"] = None


def _client() -> "docker.DockerClient":
    """Cached docker client. First call validates the daemon is reachable."""
    global _client_cache
    if _client_cache is not None:
        return _client_cache
    _require_docker()
    try:
        client = docker.from_env()
        client.ping()
    except DockerException as e:
        msg = str(e)
        low = msg.lower()
        if "permission denied" in low:
            hint = (
                "permission denied on the docker socket. Run with sudo, or add "
                "your user to the docker group: sudo usermod -aG docker $USER (then log back in)."
            )
        elif (
            "connection refused" in low
            or "no such file" in low
            or "cannot connect" in low
            or "failureerror" in low
        ):
            hint = (
                "docker daemon not reachable. Start it: sudo systemctl start docker "
                "(and `sudo systemctl enable docker` to bring it up at boot)."
            )
        else:
            hint = "is docker installed and running?"
        raise RuntimeError(f"docker unavailable: {msg}\n  hint: {hint}") from e
    _client_cache = client
    return client


def _normalize_project_name(name: str) -> str:
    return "edo_" + re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def detect_layout(path: Path) -> Optional[str]:
    """Return ``"compose"``, ``"dockerfile"``, or ``None``."""
    for cf in COMPOSE_FILES:
        if (path / cf).is_file():
            return "compose"
    if (path / "Dockerfile").is_file():
        return "dockerfile"
    return None


# ---- network management -------------------------------------------------
#
# We create edo_br0 in Docker's **routed gateway mode**
# (com.docker.network.bridge.gateway_mode_ipv4=routed, Docker 24+). In this
# mode:
#
#   * Docker does NOT install masquerade/SNAT for the bridge — containers
#     reach the WG subnet with their real 10.9.0.x addresses, which is
#     what makes reverse shells work (the catcher sees the true source).
#   * Docker does NOT subject this bridge to DOCKER-FORWARD's default-deny
#     filtering — wg0→edo_br0 traffic isn't blocked by Docker's own chain
#     ordering trick. (Our EDO_FORWARD rules still enforce isolation and
#     egress containment.)
#   * Outbound from containers retains the source IP, so participants can
#     ping containers and containers can ping participants directly.
#
# Pre-existing edo_br0 networks created by older edo versions are in
# legacy NAT mode. ``ensure_network`` detects that and refuses to use them
# silently — operators must teardown/purge so the bridge can be recreated
# routed.
def _network_is_routed(net: "docker.models.networks.Network") -> bool:
    opts = (net.attrs.get("Options") or {})
    return opts.get("com.docker.network.bridge.gateway_mode_ipv4") == "routed"


def ensure_network() -> str:
    """Create the dedicated edo bridge in routed gateway mode.

    Returns the network ID. Raises ``RuntimeError`` if a legacy
    (non-routed) edo_br0 already exists — recreating it in place would
    disrupt running containers, so we make the operator opt in via
    ``edo purge``.
    """
    client = _client()
    try:
        existing = client.networks.get(DOCKER_BRIDGE)
        if _network_is_routed(existing):
            return existing.id
        raise RuntimeError(
            f"docker network '{DOCKER_BRIDGE}' exists but is in legacy NAT mode.\n"
            "  Reverse shells and direct pings won't work cleanly until the bridge\n"
            "  is recreated in routed mode. To migrate:\n"
            "    sudo python3 edo.py purge        # stops edo containers, removes the bridge\n"
            "    sudo python3 edo.py init ...     # recreates in routed mode"
        )
    except NotFound:
        pass

    ipam_pool = docker.types.IPAMPool(
        subnet=str(DOCKER_SUBNET), gateway=DOCKER_GATEWAY_IP
    )
    ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])
    options = {
        "com.docker.network.bridge.name": DOCKER_BRIDGE,
        # Routed mode (Docker 24+). The daemon will reject this option on
        # older versions — we surface a clean message rather than letting
        # the SDK exception escape.
        "com.docker.network.bridge.gateway_mode_ipv4": "routed",
    }
    try:
        net = client.networks.create(
            name=DOCKER_BRIDGE,
            driver="bridge",
            ipam=ipam_config,
            options=options,
            check_duplicate=True,
        )
    except APIError as e:
        msg = str(e)
        if "gateway_mode" in msg or "unknown option" in msg.lower():
            raise RuntimeError(
                "Docker rejected the routed-mode option. routed bridges require "
                "Docker 24.0+ — upgrade Docker on this host. Current error: "
                f"{msg}"
            ) from e
        raise
    logger.info(
        "created docker network %s on %s (routed mode)",
        DOCKER_BRIDGE,
        DOCKER_SUBNET,
    )
    return net.id


def remove_network() -> bool:
    client = _client()
    try:
        net = client.networks.get(DOCKER_BRIDGE)
        net.remove()
        return True
    except NotFound:
        return False
    except APIError as e:
        logger.error("failed to remove docker network %s: %s", DOCKER_BRIDGE, e)
        return False


def find_next_container_ip(db: DatabaseManager, also_used: List[str]) -> str:
    blocked = list(db.get_used_container_ips()) + [DOCKER_GATEWAY_IP] + list(also_used)
    return iter_subnet_hosts(DOCKER_SUBNET, blocked)


# ---- Dockerfile deployment ---------------------------------------------
def deploy_dockerfile(
    db: DatabaseManager,
    challenge_name: str,
    path: Path,
    security: Optional[SecurityProfile] = None,
) -> DeployResult:
    if not (path / "Dockerfile").is_file():
        return DeployResult(success=False, error=f"no Dockerfile in {path}")

    profile = security or SecurityProfile()
    ensure_network()
    client = _client()
    image_tag = f"edo/{_normalize_project_name(challenge_name).removeprefix('edo_')}:latest"
    assigned_ip = find_next_container_ip(db, also_used=[])

    # ---- build ----
    try:
        logger.info("building image %s from %s", image_tag, path)
        image, _logs = client.images.build(path=str(path), tag=image_tag, rm=True)
    except (BuildError, APIError) as e:
        msg = str(e)
        logger.error("image build failed: %s", msg)
        return DeployResult(success=False, error=f"build failed: {msg}")

    # ---- create + start ----
    container = None
    try:
        endpoint_cfg = client.api.create_endpoint_config(ipv4_address=assigned_ip)
        networking_cfg = client.api.create_networking_config(
            {DOCKER_BRIDGE: endpoint_cfg}
        )
        host_cfg = _build_secure_host_config(client, profile)
        created = client.api.create_container(
            image=image_tag,
            name=_normalize_project_name(challenge_name),
            networking_config=networking_cfg,
            host_config=host_cfg,
            labels={
                "edo.challenge": challenge_name,
                "edo.managed": "true",
                "edo.security": profile.summary(),
            },
        )
        client.api.start(created["Id"])
        container = client.containers.get(created["Id"])
    except APIError as e:
        msg = str(e)
        logger.error("container start failed: %s", msg)
        _cleanup_partial(client, image_tag=image_tag, container=container)
        return DeployResult(
            success=False, error=f"run failed: {msg}", image_tag=image_tag
        )

    # ---- DB record ----
    try:
        record = db.add_container(
            container_id=container.id,
            challenge_name=challenge_name,
            source_path=str(path),
            assigned_ip=assigned_ip,
            status="running",
        )
    except Exception as e:
        logger.exception("DB logging failed, tearing down container")
        _cleanup_partial(client, image_tag=image_tag, container=container)
        return DeployResult(
            success=False, error=f"db logging failed: {e}", image_tag=image_tag
        )

    logger.info(
        "deployed %s as %s @ %s [%s]",
        challenge_name,
        container.short_id,
        assigned_ip,
        profile.summary(),
    )
    return DeployResult(
        success=True,
        containers=[record],
        image_tag=image_tag,
        security_summary=profile.summary(),
    )


def _cleanup_partial(
    client: "docker.DockerClient",
    image_tag: Optional[str] = None,
    container: Optional["docker.models.containers.Container"] = None,
) -> None:
    if container is not None:
        try:
            container.remove(force=True)
        except APIError as e:
            logger.warning("cleanup: container remove failed: %s", e)
    if image_tag is not None:
        try:
            client.images.remove(image_tag, force=True)
        except (APIError, ImageNotFound) as e:
            logger.warning("cleanup: image remove failed: %s", e)


# ---- compose deployment ------------------------------------------------
def deploy_compose(
    db: DatabaseManager,
    challenge_name: str,
    path: Path,
    security: Optional[SecurityProfile] = None,
) -> DeployResult:
    compose_file = next(
        (path / cf for cf in COMPOSE_FILES if (path / cf).is_file()), None
    )
    if compose_file is None:
        return DeployResult(
            success=False, error=f"no compose file found in {path}"
        )

    # Compose files own their service spec — Docker won't let us inject
    # security_opt / cap_drop / resource limits after the fact. Warn so the
    # operator can move the constraints into the compose YAML instead.
    if security is not None and security != SecurityProfile():
        logger.warning(
            "compose deployment ignores edo hardening flags; declare "
            "security_opt / cap_drop / mem_limit / cpus in %s instead",
            compose_file.name,
        )
    if shutil.which("docker") is None:
        return DeployResult(success=False, error="docker CLI not on PATH")

    ensure_network()
    project = _normalize_project_name(challenge_name)

    # ---- up ----
    try:
        _run(
            ["docker", "compose", "-p", project, "up", "-d", "--build"],
            cwd=path,
        )
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or "").strip()
        logger.error("compose up failed: %s", msg)
        # Try a graceful down so we don't leak half-created resources.
        subprocess.run(
            ["docker", "compose", "-p", project, "down", "-v"],
            cwd=str(path),
            capture_output=True,
            text=True,
        )
        return DeployResult(success=False, error=f"compose up failed: {msg}")

    # ---- collect container IDs ----
    try:
        ps = _run(["docker", "compose", "-p", project, "ps", "-q"], cwd=path)
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or "").strip()
        return DeployResult(success=False, error=f"compose ps failed: {msg}")

    container_ids = [cid.strip() for cid in ps.stdout.splitlines() if cid.strip()]
    if not container_ids:
        return DeployResult(
            success=False, error="compose up succeeded but no containers found"
        )

    # ---- attach to edo bridge + log ----
    client = _client()
    records: List[Container] = []
    locally_used: List[str] = []

    for cid in container_ids:
        try:
            cont = client.containers.get(cid)
            assigned_ip = find_next_container_ip(db, also_used=locally_used)
            try:
                client.api.connect_container_to_network(
                    cid, DOCKER_BRIDGE, ipv4_address=assigned_ip
                )
                locally_used.append(assigned_ip)
            except APIError as e:
                # Likely already attached; read the existing IP off the
                # container and use that instead.
                logger.debug(
                    "attach to %s skipped for %s: %s",
                    DOCKER_BRIDGE,
                    cid,
                    e,
                )
                cont.reload()
                networks = (
                    cont.attrs.get("NetworkSettings", {})
                    .get("Networks", {})
                    .get(DOCKER_BRIDGE, {})
                )
                assigned_ip = networks.get("IPAddress") or assigned_ip

            record = db.add_container(
                container_id=cid,
                challenge_name=f"{challenge_name}/{cont.name}",
                source_path=str(path),
                assigned_ip=assigned_ip,
                status="running",
            )
            records.append(record)
        except (APIError, NotFound) as e:
            logger.error("failed to register container %s: %s", cid, e)
            # Roll the whole compose project back.
            for r in records:
                try:
                    db.remove_container(r.container_id)
                except Exception:
                    logger.warning(
                        "could not remove DB record for %s during rollback",
                        r.container_id,
                    )
            subprocess.run(
                ["docker", "compose", "-p", project, "down", "-v"],
                cwd=str(path),
                capture_output=True,
                text=True,
            )
            return DeployResult(
                success=False, error=f"container registration failed: {e}"
            )

    logger.info(
        "compose deployed: project=%s, %d container(s)", project, len(records)
    )
    return DeployResult(success=True, containers=records)


# ---- teardown ----------------------------------------------------------
def teardown_container(db: DatabaseManager, container_id: str) -> bool:
    client = _client()
    try:
        c = client.containers.get(container_id)
        c.stop(timeout=10)
        c.remove(force=True)
    except NotFound:
        logger.warning(
            "container %s not found in docker; clearing DB record", container_id
        )
    except APIError as e:
        logger.error("teardown failed for %s: %s", container_id, e)
        return False
    db.remove_container(container_id)
    return True


def teardown_compose(
    db: DatabaseManager, source_path: Path, challenge_name: str
) -> bool:
    project = _normalize_project_name(challenge_name)
    try:
        _run(
            ["docker", "compose", "-p", project, "down", "-v"], cwd=source_path
        )
    except subprocess.CalledProcessError as e:
        logger.error("compose down failed: %s", (e.stderr or "").strip())
        return False
    for c in db.get_active_containers():
        if c.source_path == str(source_path) and c.challenge_name.startswith(
            challenge_name
        ):
            db.remove_container(c.container_id)
    return True


def teardown_all(db: DatabaseManager) -> int:
    """Tear down every container edo knows about. Returns count removed."""
    count = 0
    for c in db.get_active_containers():
        if teardown_container(db, c.container_id):
            count += 1
    return count
