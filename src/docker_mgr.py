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

try:
    import docker
    from docker.errors import APIError, BuildError, ImageNotFound, NotFound
except ImportError as e:  # pragma: no cover - dependency failure path
    raise ImportError(
        "The 'docker' Python package is required. Install with: pip install docker"
    ) from e

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
class DeployResult:
    success: bool
    containers: List[Container] = field(default_factory=list)
    error: Optional[str] = None
    image_tag: Optional[str] = None


# ---- helpers ------------------------------------------------------------
def _run(
    cmd: List[str], cwd: Optional[Path] = None, check: bool = True
) -> subprocess.CompletedProcess:
    logger.debug("exec: %s (cwd=%s)", " ".join(cmd), cwd)
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=check,
    )


def _client() -> "docker.DockerClient":
    return docker.from_env()


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
def ensure_network() -> str:
    """Create the dedicated edo bridge network if it doesn't already exist.

    Returns the network ID.
    """
    client = _client()
    try:
        return client.networks.get(DOCKER_BRIDGE).id
    except NotFound:
        pass

    ipam_pool = docker.types.IPAMPool(
        subnet=str(DOCKER_SUBNET), gateway=DOCKER_GATEWAY_IP
    )
    ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])
    net = client.networks.create(
        name=DOCKER_BRIDGE,
        driver="bridge",
        ipam=ipam_config,
        options={"com.docker.network.bridge.name": DOCKER_BRIDGE},
        check_duplicate=True,
    )
    logger.info("created docker network %s on %s", DOCKER_BRIDGE, DOCKER_SUBNET)
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
    db: DatabaseManager, challenge_name: str, path: Path
) -> DeployResult:
    if not (path / "Dockerfile").is_file():
        return DeployResult(success=False, error=f"no Dockerfile in {path}")

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
        host_cfg = client.api.create_host_config(
            restart_policy={"Name": "unless-stopped"}
        )
        created = client.api.create_container(
            image=image_tag,
            name=_normalize_project_name(challenge_name),
            networking_config=networking_cfg,
            host_config=host_cfg,
            labels={"edo.challenge": challenge_name, "edo.managed": "true"},
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
        "deployed %s as %s @ %s", challenge_name, container.short_id, assigned_ip
    )
    return DeployResult(
        success=True, containers=[record], image_tag=image_tag
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
    db: DatabaseManager, challenge_name: str, path: Path
) -> DeployResult:
    compose_file = next(
        (path / cf for cf in COMPOSE_FILES if (path / cf).is_file()), None
    )
    if compose_file is None:
        return DeployResult(
            success=False, error=f"no compose file found in {path}"
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
