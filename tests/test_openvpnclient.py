"""Test the OpenVPNClient class.

The client server model uses trusted fingerprints to authenticate the server. See:
https://github.com/openvpn/openvpn/blob/master/doc/man-sections/example-fingerprint.rst

Test cases:
1. Connect and disconnect the OpenVPN client manually
2. Connect and disconnect the OpenVPN client automatically using the context manager
3. Disconnect OpenVPN client automatically on SIGINT (Ctrl+C)
4. Disconnect when not connected
5. Connect when already connected
6. Invalid client configuration syntax
7. Server not reachable (invalid ip)
8. Wrong path to ovpn config file
9. Connection attempt timeout
"""
# ruff: noqa: S101, test code should use asserts

from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path
from subprocess import DEVNULL, PIPE, Popen
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

import pytest

from openvpnclient import PID_FILE, STDERR_FILE, STDOUT_FILE, OpenVPNClient, Status

TEST_PASSWORD = "testpass"


@pytest.fixture(autouse=True)
def check_no_lingering_files() -> Generator[None, None, None]:
    """Check if the files are removed after each test."""
    yield
    assert not PID_FILE.exists()
    assert not STDERR_FILE.exists()
    assert not STDOUT_FILE.exists()


@pytest.fixture(params=["", "rsa", "rsa_askpass"])
def openvpn_client(request, paths: dict[str]) -> OpenVPNClient:
    """Return an OpenVPNClient instance for either default or RSA config."""
    if request.param == "rsa":
        return OpenVPNClient(ovpn_file=paths["clientconfig"])
    elif request.param == "rsa_askpass":
        return OpenVPNClient(
            ovpn_file=paths["clientconfig_rsa_askpass"],
            askpass_file=paths["client_askpass"],
        )
    return OpenVPNClient(ovpn_file=paths["clientconfig"])


@pytest.fixture(scope="module")
def server_details() -> dict[str]:
    """Information about the test server."""
    return {
        "public_port": "42812",
        "public_ip": "127.0.0.1",
        "base_ip": "127.0.0.0",
        "netmask": "255.255.255.0",
    }


@pytest.fixture(scope="module")
def tmp_dir(tmpdir_factory: pytest.TempdirFactory) -> str:
    """Temporary directory for various storage."""
    return str(tmpdir_factory.mktemp("ovpn"))


@pytest.fixture(scope="module")
def paths(tmp_dir: str) -> dict[str]:
    """OpenVPN configuration file paths."""
    return {
        "servercrt": tmp_dir + "/server.crt",
        "serverpkey": tmp_dir + "/server.key",
        "clientcrt": tmp_dir + "/client.crt",
        "clientpkey": tmp_dir + "/client.key",
        "clientcrt_rsa": tmp_dir + "/client_rsa.crt",
        "clientpkey_rsa": tmp_dir + "/client_rsa.key",
        "clientcrt_rsa_askpass": tmp_dir + "/client_rsa_askpass.crt",
        "clientpkey_rsa_askpass": tmp_dir + "/client_rsa_askpass.key",
        "client_askpass": tmp_dir + "/askpass.pass",
        "clientconfig": tmp_dir + "/client.ovpn",
        "clientconfig_rsa": tmp_dir + "/client_rsa.ovpn",
        "clientconfig_rsa_askpass": tmp_dir + "/client_rsa_askpass.ovpn",
        "clientconfig_badserver": tmp_dir + "/badserver.ovpn",
        "clientconfig_badsyntax": tmp_dir + "/badsyntax.ovpn",
        "not_a_config_path": tmp_dir,
    }


@pytest.fixture(scope="module")
def fingerprint(
    gen_creds: Callable[[str, str, str], None], paths: dict[str]
) -> dict[str, str]:
    """Generate client/server certificates at `paths` and return their fingerprints."""
    gen_creds("CLIENT", paths["clientpkey"], paths["clientcrt"])
    gen_creds("CLIENT_RSA", paths["clientpkey_rsa"], paths["clientcrt_rsa"])
    gen_creds("CLIENT_RSA_ASKPASS", paths["clientpkey_rsa_askpass"], paths["clientcrt_rsa_askpass"])
    gen_creds("SERVER", paths["serverpkey"], paths["servercrt"])

    with open(paths["client_askpass"], "w", encoding="ascii") as f:
        f.write(TEST_PASSWORD + "\n")


    def get_fingerprint(certpath: str) -> str:
        fingerprint_cmd = f"openssl x509 -fingerprint -sha256 -in {certpath} -noout"
        return (
            subprocess.run(
                fingerprint_cmd.split(),
                stdout=PIPE,
                text=True,
                check=True,
            )
            .stdout.split("=")[1]
            .strip()
        )

    return {
        "client": get_fingerprint(paths["clientcrt"]),
        "client_rsa": get_fingerprint(paths["clientcrt_rsa"]),
        "client_rsa_askpass": get_fingerprint(paths["clientcrt_rsa_askpass"]),
        "server": get_fingerprint(paths["servercrt"]),
    }


@pytest.fixture(scope="module")
def gen_creds() -> str:
    """Create a self-signed certificate."""
    keygen_eliptic_cmd = "openssl ecparam -name secp384r1 -genkey -noout -out %s"
    keygen_rsa_cmd = 'openssl genrsa -out %s 2048'
    keygen_rsa_askpass_cmd = 'openssl genrsa -out %s -passout pass:%s 2048'
    gen_cert_cmd = (
        "openssl req -x509 "
        "-new -key %s "
        "-out %s "
        "-sha256 -days 1 -nodes "
        "-subj /CN=TEST%s"
    )

    def gen(ident: str, keypath: str, certpath: str) -> None:
        subprocess.run((keygen_eliptic_cmd % keypath).split(), check=True)
        subprocess.run((keygen_rsa_cmd % keypath).split(), check=True)
        subprocess.run((keygen_rsa_askpass_cmd % (keypath, TEST_PASSWORD)).split(), check=True)
        subprocess.run((gen_cert_cmd % (keypath, certpath, ident)).split(), check=True)

    return gen

@pytest.fixture(scope="module", autouse=True)
def gen_clientconfs(
    server_details: dict[str], fingerprint: dict[str], paths: dict[str]
) -> None:
    """Create mock client configurations."""
    def generate_config(
       remote_ip: str,
       remote_port: str,
       key: str,
       cert: str,
       fingerprint_: str 
    ) -> str:
        """Generate a basic OpenVPN client configuration."""
        return (
            "client\n"
            f"remote {remote_ip} {remote_port}\n"
            "explicit-exit-notify 5\n"
            "<key>\n"
            f"{key}\n"
            "</key>\n"
            "<cert>\n"
            f"{cert}\n"
            "</cert>\n"
            f"peer-fingerprint {fingerprint_}"
        )

    conf = generate_config(
        remote_ip = server_details['public_ip'],
        remote_port = server_details['public_port'],
        key = Path(paths['clientpkey']).read_text(encoding='ascii'),
        cert = Path(paths['clientcrt']).read_text(encoding='ascii'),
        fingerprint_ = fingerprint['server']
    )
    conf_rsa = generate_config(
        remote_ip=server_details['public_ip'],
        remote_port=server_details['public_port'],
        key=Path(paths['clientpkey_rsa']).read_text(encoding='ascii'),
        cert=Path(paths['clientcrt_rsa']).read_text(encoding='ascii'),
        fingerprint_=fingerprint['server']
    )
    conf_rsa_askpass = generate_config(
        remote_ip=server_details['public_ip'],
        remote_port=server_details['public_port'],
        key=Path(paths['clientpkey_rsa_askpass']).read_text(encoding='ascii'),
        cert=Path(paths['clientcrt_rsa_askpass']).read_text(encoding='ascii'),
        fingerprint_=fingerprint['server']
    )

    with Path(paths["clientconfig"]).open("w", encoding="ascii") as f:
        f.write(conf)

    with Path(paths["clientconfig_rsa"]).open("w", encoding="ascii") as f:
        f.write(conf_rsa)

    with Path(paths["clientconfig_rsa_askpass"]).open("w", encoding="ascii") as f:
        f.write(conf_rsa_askpass)

    with Path(paths["clientconfig_badserver"]).open("w", encoding="ascii") as f:
        f.write(conf.replace("1", "3"))

    with Path(paths["clientconfig_badsyntax"]).open("w", encoding="ascii") as f:
        f.write(conf.replace("client", "testing"))


@pytest.fixture(scope="module", autouse=True)
def local_server(
    server_details: dict, paths: dict[str], fingerprint: dict[str]
) -> Generator[None, None, None]:
    """Start a local OpenVPN server for the duration of the test session."""
    must_supply_password = OpenVPNClient._must_supply_password()  # noqa: SLF001
    sudo_pw_option = "-S " if must_supply_password else ""
    ovpn_server_cmd = (
        f"sudo {sudo_pw_option}"
        "openvpn "
        f"--server {server_details['base_ip']} {server_details['netmask']} "
        f"--port {server_details['public_port']} "
        f"--peer-fingerprint {fingerprint['client']} "
        f"--peer-fingerprint {fingerprint['client_rsa']} "
        f"--peer-fingerprint {fingerprint['client_rsa_askpass']} "
        f"--cert {paths['servercrt']} "
        f"--key {paths['serverpkey']} "
        "--dev tun_server "
        "--dh none "
        "--verb 3 "
    )

    srv_proc = Popen(
        ovpn_server_cmd.split(), text=True, stdin=PIPE, stdout=PIPE, stderr=PIPE
    )
    if must_supply_password:
        srv_proc.stdin.write(os.environ["SUDO_PASSWORD"] + "\n")
        srv_proc.stdin.flush()

    yield

    kill_srv_cmd = f"sudo {sudo_pw_option}kill {srv_proc.pid}"
    kill_proc = Popen(
        kill_srv_cmd.split(), text=True, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL
    )
    if must_supply_password:
        kill_proc.stdin.write(os.environ["SUDO_PASSWORD"] + "\n")
        kill_proc.stdin.flush()


def test_connect_then_disconnect(openvpn_client: OpenVPNClient) -> None:
    """The basic use case: connect and disconnect."""
    openvpn_client.connect()
    assert openvpn_client.status is Status.CONNECTED
    openvpn_client.disconnect()
    assert OpenVPNClient._get_pid() == -1  # noqa: SLF001

def test_context_manager(openvpn_client: OpenVPNClient) -> None:
    """Test that the context manager works as the above test."""
    with openvpn_client as open_vpn:
        assert open_vpn.status is Status.CONNECTED

    assert OpenVPNClient._get_pid() == -1  # noqa: SLF001


def test_ctrlc_disconnects(paths: dict) -> None:
    """If user cancels with ctrl+c, the client should disconnect if instructed so."""
    client = OpenVPNClient(paths["clientconfig"])
    client.connect(sigint_disconnect=True)
    with pytest.raises(KeyboardInterrupt):
        os.kill(os.getpid(), signal.SIGINT)

    assert client._get_pid() == -1  # noqa: SLF001
    assert client.status is Status.USER_CANCELLED


def test_disconnect_when_not_connected(openvpn_client: OpenVPNClient) -> None:
    """Disconnecting when not connected should raise an error."""
    with pytest.raises(ProcessLookupError):
        openvpn_client.disconnect()


def test_already_connected(openvpn_client: OpenVPNClient) -> None:
    """Refuse to connect if already connected."""
    openvpn_client.connect()
    with pytest.raises(ConnectionRefusedError):
        openvpn_client.connect()

    openvpn_client.disconnect()


def test_invalid_client_config_syntax(paths: dict) -> None:
    """Invalid client configuration should raise an error."""
    with pytest.raises(TimeoutError):  # noqa: SIM117
        with OpenVPNClient(paths["clientconfig_badsyntax"]):
            raise AssertionError("Should not reach here")  # noqa: EM101, TRY003


def test_server_not_reachable(paths: dict) -> None:
    """Make sure no connection is made when the server is unreachable."""
    with pytest.raises(TimeoutError):  # noqa: SIM117
        with OpenVPNClient(paths["clientconfig_badserver"]):
            raise AssertionError("Should not reach here")  # noqa: EM101, TRY003

def test_invalid_paths(paths: dict) -> None:
    """Make sure an invalid path is found and not used to connect."""
    with pytest.raises(FileNotFoundError):  # noqa: SIM117
        with OpenVPNClient(paths["not_a_config_path"]):
            raise AssertionError("Should not reach here")  # noqa: EM101, TRY003


def test_connection_attempt_timeout(paths: dict) -> None:
    """Make sure a connection time out is handled correctly."""
    with pytest.raises(TimeoutError):  # noqa: SIM117
        with OpenVPNClient(paths["clientconfig"], connect_timeout=0.5):
            raise AssertionError("Should not reach here")  # noqa: EM101, TRY003
