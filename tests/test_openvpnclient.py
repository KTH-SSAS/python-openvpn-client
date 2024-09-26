from __future__ import annotations

import os
import signal
import time
from subprocess import DEVNULL, PIPE, Popen, call
from textwrap import dedent

import psutil
import pytest
from openvpnclient import OpenVPNClient, Status

"""
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


@pytest.fixture(autouse=True, scope="function")
def await_openvpn_cleanup():
    """The timeout ensures that the OpenVPN client's socket has enough time to
    close before the next test runs.
    """
    yield
    time.sleep(6)


@pytest.fixture(scope="function")
def openvpn_client(ovpn_paths) -> OpenVPNClient:
    return OpenVPNClient(ovpn_paths["clientconfig"])


@pytest.fixture(scope="module")
def server_details() -> dict[str]:
    return {
        "public_port": "42812",
        "public_ip": "127.62.213.1",
        "base_ip": "127.62.213.0",
        "netmask": "255.255.255.0",
    }


@pytest.fixture(scope="module")
def ovpn_paths(tmpdir_factory) -> dict[str]:
    dir = tmpdir_factory.mktemp("ovpn")
    return {
        "cert": f"{dir}/cert.pem",
        "certkey": f"{dir}/certkey.pem",
        "clientconfig": f"{dir}/client.ovpn",
        "clientconfig_badserver": f"{dir}/badserver.ovpn",
        "clientconfig_invalidsyntax": f"{dir}/invalidsyntax.ovpn",
        "not_a_config_path": dir,
    }


@pytest.fixture(scope="module", autouse=True)
def create_cert(ovpn_paths) -> None:
    gen_cert_cmd = f"""
        openssl req -x509
        -newkey rsa:1024
        -keyout {ovpn_paths['certkey']}
        -out {ovpn_paths['cert']}
        -sha256 -days 1 -nodes
        -subj /C=SE/ST=TWMN/L=TWMN/O=TWMN/OU=TWMN/CN=TWMN
    """.replace("\n", " ")
    call(gen_cert_cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL)


@pytest.fixture(scope="module", autouse=True)
def generate_clientconfigs(server_details, ovpn_paths) -> None:
    client_conf = f"""
        client
        remote {server_details['public_ip']} {server_details['public_port']}
        explicit-exit-notify 5
        ca {ovpn_paths['cert']}
        cert {ovpn_paths['cert']}
        key {ovpn_paths['certkey']}
    """
    breakpoint()

    conf = dedent(client_conf)
    with open(ovpn_paths["clientconfig"], "w") as f:
        f.write(conf)
    with open(ovpn_paths["clientconfig_badserver"], "w") as f:
        f.write(conf.replace("1", "3"))
    with open(ovpn_paths["clientconfig_invalidsyntax"], "w") as f:
        f.write(conf.replace("client", "ethhak"))


@pytest.fixture(scope="module", autouse=True)
def start_and_stop_openvpn_server(server_details: dict, ovpn_paths: dict):
    ovpn_server_cmd = f"""
        sudo openvpn
        --server {server_details['base_ip']} {server_details['netmask']}
        --port {server_details['public_port']}
        --dev tun_server
        --ca {ovpn_paths['cert']}
        --cert {ovpn_paths['cert']}
        --key {ovpn_paths['certkey']}
        --dh none
        --verb 3
    """.replace("\n", " ")

    pid = Popen(ovpn_server_cmd.split(), stderr=PIPE, stdout=PIPE).pid

    print(f"\n\r{time.ctime()}: OpenVPN test server started")

    yield

    psutil.Process(pid).kill()
    print(f"\n\r{time.ctime()}: OpenVPN test server terminated")


def test_connect_then_disconnect(openvpn_client: OpenVPNClient) -> None:
    openvpn_client.connect()
    assert openvpn_client.status is Status.CONNECTED

    openvpn_client.disconnect()
    assert OpenVPNClient._get_pid() == -1


def test_context_manager(openvpn_client: OpenVPNClient) -> None:
    with openvpn_client as open_vpn:
        assert open_vpn.status is Status.CONNECTED
    assert OpenVPNClient._get_pid() == -1


def test_ctrlc_disconnects(openvpn_client: OpenVPNClient) -> None:
    openvpn_client.connect()

    os.kill(os.getpid(), signal.SIGINT)
    assert openvpn_client._get_pid() == -1
    assert openvpn_client.status is Status.USER_CANCELLED


def test_disconnect_when_not_connected(openvpn_client: OpenVPNClient) -> None:
    with pytest.raises(ProcessLookupError):
        openvpn_client.disconnect()


def test_already_connected(openvpn_client: OpenVPNClient) -> None:
    openvpn_client.connect()
    with pytest.raises(ConnectionError):
        openvpn_client.connect()
    openvpn_client.disconnect()


def test_invalid_client_config_syntax(ovpn_paths: dict) -> None:
    with pytest.raises(ConnectionRefusedError):
        with OpenVPNClient(ovpn_paths["clientconfig_invalidsyntax"]):
            assert False


def test_server_not_reachable(ovpn_paths: dict) -> None:
    with pytest.raises(TimeoutError):
        with OpenVPNClient(ovpn_paths["clientconfig_badserver"]):
            assert False


def test_invalid_ovpn_paths(ovpn_paths: dict) -> None:
    with pytest.raises(TimeoutError):
        with OpenVPNClient(ovpn_paths["not_a_config_path"]):
            assert False


def test_connection_attempt_timeout(ovpn_paths: dict) -> None:
    with pytest.raises(TimeoutError):
        with OpenVPNClient(ovpn_paths["clientconfig"], connect_timeout=0.5):
            assert False
