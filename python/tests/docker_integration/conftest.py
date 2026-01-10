"""
Pytest configuration and fixtures for Docker integration tests.
"""

import os
import socket
import subprocess
import time
import pytest


# Docker service configuration
DOCKER_SERVICES = {
    "vulnerable-web": {"host": "localhost", "port": 8080, "protocol": "tcp"},
    "ftp-server": {"host": "localhost", "port": 2121, "protocol": "tcp"},
    "smtp-server": {"host": "localhost", "port": 2525, "protocol": "tcp"},
    "dns-server": {"host": "localhost", "port": 5353, "protocol": "udp"},
    "smb-server": {"host": "localhost", "port": 4445, "protocol": "tcp"},
    "mysql-server": {"host": "localhost", "port": 3307, "protocol": "tcp"},
}


def check_port(host: str, port: int, protocol: str = "tcp", timeout: float = 2.0) -> bool:
    """Check if a port is open and accepting connections."""
    try:
        if protocol == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error:
        return False


def is_docker_running() -> bool:
    """Check if Docker daemon is running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def are_containers_running() -> bool:
    """Check if CPTC11 containers are running."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "label=cptc11.role", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return len(result.stdout.strip().split('\n')) > 0 and result.stdout.strip() != ''
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


@pytest.fixture(scope="session")
def docker_available():
    """Session-scoped fixture to check Docker availability."""
    if os.environ.get("SKIP_DOCKER_TESTS"):
        pytest.skip("SKIP_DOCKER_TESTS environment variable set")

    if not is_docker_running():
        pytest.skip("Docker daemon is not running")

    if not are_containers_running():
        pytest.skip("CPTC11 Docker containers are not running. Run 'docker-compose up -d' first.")

    return True


@pytest.fixture(scope="session")
def docker_host():
    """Get the Docker host address."""
    return os.environ.get("DOCKER_HOST", "localhost")


@pytest.fixture(scope="module")
def web_service(docker_available, docker_host):
    """Fixture for web service connection details."""
    service = DOCKER_SERVICES["vulnerable-web"]
    host = docker_host
    port = service["port"]

    if not check_port(host, port):
        pytest.skip(f"Web service not available at {host}:{port}")

    return {"host": host, "port": port, "url": f"http://{host}:{port}"}


@pytest.fixture(scope="module")
def ftp_service(docker_available, docker_host):
    """Fixture for FTP service connection details."""
    service = DOCKER_SERVICES["ftp-server"]
    host = docker_host
    port = service["port"]

    if not check_port(host, port):
        pytest.skip(f"FTP service not available at {host}:{port}")

    return {
        "host": host,
        "port": port,
        "valid_user": "ftpuser",
        "valid_pass": "ftppass123",
        "invalid_user": "baduser",
        "invalid_pass": "badpass"
    }


@pytest.fixture(scope="module")
def smtp_service(docker_available, docker_host):
    """Fixture for SMTP service connection details."""
    service = DOCKER_SERVICES["smtp-server"]
    host = docker_host
    port = service["port"]

    if not check_port(host, port):
        pytest.skip(f"SMTP service not available at {host}:{port}")

    return {
        "host": host,
        "port": port,
        "valid_user": "smtpuser",
        "valid_pass": "smtppass123"
    }


@pytest.fixture(scope="module")
def dns_service(docker_available, docker_host):
    """Fixture for DNS service connection details."""
    service = DOCKER_SERVICES["dns-server"]
    host = docker_host
    port = service["port"]

    # UDP port check is less reliable, just return the config
    return {
        "host": host,
        "port": port,
        "domain": "testlab.local"
    }


@pytest.fixture(scope="module")
def smb_service(docker_available, docker_host):
    """Fixture for SMB service connection details."""
    service = DOCKER_SERVICES["smb-server"]
    host = docker_host
    port = service["port"]

    if not check_port(host, port):
        pytest.skip(f"SMB service not available at {host}:{port}")

    return {
        "host": host,
        "port": port,
        "valid_user": "smbuser",
        "valid_pass": "smbpass123",
        "shares": ["public", "private", "backup", "it", "hr", "finance"]
    }


@pytest.fixture(scope="module")
def mysql_service(docker_available, docker_host):
    """Fixture for MySQL service connection details."""
    service = DOCKER_SERVICES["mysql-server"]
    host = docker_host
    port = service["port"]

    if not check_port(host, port):
        pytest.skip(f"MySQL service not available at {host}:{port}")

    return {
        "host": host,
        "port": port,
        "user": "webuser",
        "password": "webpass123",
        "database": "webapp"
    }
