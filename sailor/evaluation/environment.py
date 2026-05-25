"""DockerEnvironment — isolated, reproducible build environment for CVE evaluation.

Each CVE runs in its own Docker container with a volume-mounted workspace
so that build artifacts are accessible on the host for Sailor pipelines.
"""

from __future__ import annotations

import logging
import subprocess
import time
import uuid
from pathlib import Path
from typing import Optional

from sailor.models.schemas import CVERecord

logger = logging.getLogger("sailor.evaluation.environment")


class EnvironmentSetupError(RuntimeError):
    """Raised when DockerEnvironment.setup() fails at any step."""


class DockerEnvironment:
    """Docker-based build isolation for CVE evaluation.

    Responsibilities:
      - Pull base image
      - Install dependencies
      - Clone project at the vulnerable commit
      - Run build commands to produce compile_commands.json
      - Expose project source on the host via volume mount

    Args:
        record: CVERecord describing the target project.
        workspace: Host directory used as the Docker volume mount base.
    """

    def __init__(self, record: CVERecord, workspace: Path) -> None:
        self._record = record
        self._workspace = workspace
        self._container_id: Optional[str] = None
        self._project_root: Optional[Path] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def setup(self) -> Path:
        """Full environment setup sequence.

        Steps:
            1. Pull docker image.
            2. Start container with workspace volume.
            3. Install dependencies (apt-get).
            4. Clone repository at the vulnerable commit.
            5. Run build commands.
            6. Return project_root path on the host.

        Returns:
            Path to the checked-out project source on the host.

        Raises:
            EnvironmentSetupError: On any failure.
        """
        rec = self._record
        container_name = f"sailor-{rec.cve_id.lower()}-{uuid.uuid4().hex[:8]}"
        host_project_dir = self._workspace / rec.cve_id / "project"
        host_project_dir.mkdir(parents=True, exist_ok=True)

        try:
            self._pull_image(rec.docker_image)
            self._start_container(container_name, host_project_dir, rec)
            self._install_dependencies(rec.dependencies)
            self._clone_and_checkout(rec.project_url, rec.vulnerable_commit, rec.cve_id)
            self._run_build_commands(rec)
        except EnvironmentSetupError:
            raise
        except Exception as exc:
            raise EnvironmentSetupError(
                f"Unexpected error during environment setup for {rec.cve_id}: {exc}"
            ) from exc

        # Directory name comes from the git URL, not rec.project
        _project_dir_name = (
            rec.project_url.rstrip("/").rstrip(".git").rsplit("/", 1)[-1]
        )
        self._project_root = host_project_dir / _project_dir_name
        logger.info("Environment ready at %s", self._project_root)
        return self._project_root

    def get_project_root(self) -> Path:
        """Return the path to the checked-out project source on the host."""
        if self._project_root is None:
            raise RuntimeError("setup() has not been called yet.")
        return self._project_root

    def get_compile_commands_path(self) -> Optional[Path]:
        """Return path to compile_commands.json if it was generated."""
        if self._project_root is None:
            return None
        candidate = self._project_root / "compile_commands.json"
        return candidate if candidate.exists() else None

    def teardown(self) -> None:
        """Remove the Docker container, keeping workspace on host."""
        if self._container_id:
            try:
                subprocess.run(
                    ["docker", "rm", "-f", self._container_id],
                    check=True,
                    capture_output=True,
                )
                logger.info("Removed container %s", self._container_id)
            except subprocess.CalledProcessError as exc:
                logger.warning(
                    "Failed to remove container %s: %s", self._container_id, exc
                )
            finally:
                self._container_id = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _pull_image(self, image: str) -> None:
        t0 = time.perf_counter()
        logger.info("Pulling image %s …", image)
        rc, _, stderr = self._run_host(["docker", "pull", image], timeout=300)
        if rc != 0:
            raise EnvironmentSetupError(f"docker pull {image} failed: {stderr}")
        logger.info("Pulled %s in %.1fs", image, time.perf_counter() - t0)

    def _start_container(
        self, name: str, host_project_dir: Path, rec: CVERecord
    ) -> None:
        env_args: list[str] = []
        for k, v in rec.env_vars.items():
            env_args += ["-e", f"{k}={v}"]
        cmd = [
            "docker", "run", "-d",
            "--name", name,
            "-v", f"{host_project_dir}:/workspace",
            *env_args,
            rec.docker_image,
            "tail", "-f", "/dev/null",
        ]
        rc, stdout, stderr = self._run_host(cmd, timeout=60)
        if rc != 0:
            raise EnvironmentSetupError(f"docker run failed: {stderr}")
        self._container_id = stdout.strip()
        logger.info("Started container %s (%s)", name, self._container_id[:12])

    def _install_dependencies(self, packages: list[str]) -> None:
        if not packages:
            return
        t0 = time.perf_counter()
        pkg_list = " ".join(packages)
        logger.info("Installing packages: %s", pkg_list)
        rc, _, stderr = self._run_in_container(
            f"apt-get update -qq && apt-get install -y --no-install-recommends {pkg_list}",
            timeout=600,
        )
        if rc != 0:
            raise EnvironmentSetupError(f"apt-get install failed: {stderr}")
        logger.info("Dependencies installed in %.1fs", time.perf_counter() - t0)

    def _clone_and_checkout(self, url: str, commit: str, cve_id: str) -> None:
        import re as _re
        _IS_HASH = _re.compile(r'^[0-9a-f]{7,40}$')
        t0 = time.perf_counter()
        project_name = url.rstrip("/").rstrip(".git").rsplit("/", 1)[-1]
        logger.info("Cloning %s …", url)
        if commit and not _IS_HASH.match(commit):
            # Tag/branch name — use --branch for a fast single-revision fetch
            clone_cmd = (
                f"GIT_SSL_NO_VERIFY=true git clone --branch {commit} --depth=1 "
                f"{url} /workspace/{project_name}"
            )
        else:
            clone_cmd = (
                f"GIT_SSL_NO_VERIFY=true git clone {url} /workspace/{project_name}"
            )
        rc, _, stderr = self._run_in_container(clone_cmd, timeout=600)
        if rc != 0:
            raise EnvironmentSetupError(f"git clone failed: {stderr}")

        if commit and _IS_HASH.match(commit):
            checkout_cmd = f"git -C /workspace/{project_name} checkout {commit}"
            rc, _, stderr = self._run_in_container(checkout_cmd, timeout=60)
            if rc != 0:
                raise EnvironmentSetupError(
                    f"git checkout {commit} failed: {stderr}"
                )
        logger.info("Cloned and checked out in %.1fs", time.perf_counter() - t0)

    def _run_build_commands(self, rec: CVERecord) -> None:
        project_name = (
            rec.project_url.rstrip("/").rstrip(".git").rsplit("/", 1)[-1]
        )
        work_dir = f"/workspace/{project_name}"

        env_prefix = " ".join(f"{k}={v}" for k, v in rec.env_vars.items())
        if rec.extra_cflags:
            env_prefix = f"CFLAGS='{rec.extra_cflags}' CXXFLAGS='{rec.extra_cflags}' {env_prefix}"

        for cmd in rec.build_commands:
            full_cmd = f"cd {work_dir} && {env_prefix} {cmd}"
            t0 = time.perf_counter()
            logger.info("Build: %s", cmd)
            rc, _, stderr = self._run_in_container(full_cmd, timeout=1800)
            if rc != 0:
                raise EnvironmentSetupError(
                    f"Build command failed ({cmd}): {stderr[-2000:]}"
                )
            logger.info("  → done in %.1fs", time.perf_counter() - t0)

    def _run_in_container(
        self, command: str, timeout: int = 600
    ) -> tuple[int, str, str]:
        """Execute a shell command inside the Docker container.

        Args:
            command: Shell command string.
            timeout: Maximum seconds to wait.

        Returns:
            (exit_code, stdout, stderr).
        """
        if self._container_id is None:
            raise RuntimeError("Container is not running.")
        return self._run_host(
            ["docker", "exec", self._container_id, "bash", "-c", command],
            timeout=timeout,
        )

    @staticmethod
    def _run_host(
        cmd: list[str], timeout: int = 120
    ) -> tuple[int, str, str]:
        """Run a command on the host and return (exit_code, stdout, stderr)."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return 1, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
        except Exception as exc:
            return 1, "", str(exc)

    def _generate_compile_commands(self) -> bool:
        """Attempt to generate compile_commands.json using bear or cmake.

        Returns:
            True if compile_commands.json was successfully generated.
        """
        rec = self._record
        project_name = (
            rec.project_url.rstrip("/").rstrip(".git").rsplit("/", 1)[-1]
        )
        work_dir = f"/workspace/{project_name}"

        # Check if bear is available
        rc, _, _ = self._run_in_container("which bear", timeout=10)
        if rc == 0:
            rc, _, _ = self._run_in_container(
                f"cd {work_dir} && bear -- make -j4", timeout=600
            )
            return rc == 0

        # Fallback: cmake
        rc, _, _ = self._run_in_container("which cmake", timeout=10)
        if rc == 0:
            rc, _, _ = self._run_in_container(
                f"cd {work_dir} && cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .", timeout=120
            )
            return rc == 0

        return False
