"""OpenVPN client module."""

from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
from enum import Enum
from pathlib import Path
from subprocess import PIPE, CalledProcessError, check_call
from tempfile import gettempdir
from time import sleep
from types import TracebackType  # noqa: TCH003, used to type annotate

from docopt import docopt
from typing_extensions import Self

PID_FILE = f"{gettempdir()}/openvpnclient.pid"
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setFormatter(
    logging.Formatter(
        "\r\n%(asctime)s OpenVPN: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
)
logger.addHandler(console_handler)


class Status(Enum):
    """Status codes for the OpenVPN client."""

    CONNECTED = (1,)
    DISCONNECTED = (2,)
    CONNECTION_FAILED = (3,)
    IDLE = (4,)
    USER_CANCELLED = (5,)
    CONNECTION_TIMEOUT = (6,)


class OpenVPNClient:
    """Module for managing an OpenVPN connection."""

    status: Status = Status.IDLE
    timer: threading.Timer
    lock: threading.Lock

    def __init__(self, ovpn_file: str, connect_timeout: int = 5) -> None:
        """Initialize the OpenVPN client.

        :param ovpn_file: The OpenVPN configuration file
        :type ovpn_file: str
        :param connect_timeout: The connection attempt limit in seconds
        :type connect_timeout: int, optional
        :raises ValueError: If connect_timeout is less than, or equal to, 0
        :raises FileNotFoundError: If the configuration file is not found
        :raises RuntimeError: If OpenVPN is not installed or not available on the PATH
        """
        if connect_timeout <= 0:
            err_msg = "Connection timeout must be at least 1 second"
            raise ValueError(err_msg)

        if not Path(ovpn_file).exists() or not Path(ovpn_file).is_file():
            err_msg = f"File '{ovpn_file}' not found, or is not a file"
            raise FileNotFoundError(err_msg)

        if not shutil.which("openvpn"):
            err_msg = "OpenVPN must be installed and available on the PATH"
            raise RuntimeError(err_msg)

        self.ovpn_file = Path(ovpn_file)
        self.ovpn_dir = self.ovpn_file.parent
        self.connect_timeout = connect_timeout
        self.lock = threading.Lock()

    def __enter__(self) -> Self:
        """Auto-connect when using a context manager."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:  # noqa: ANN001, F841, RUF100
        """Disconnect when using a context manager."""
        self.disconnect()

    def connect(
        self, *, await_vpn_exit: bool = True, sigint_disconnect: bool = False
    ) -> None:
        """Connect to the OpenVPN server using the provided configuration file.

        :param await_vpn_exit: If True, the script won't return until the VPN
            connection is closed, thus set this to False if this should run
            in the background
        :type await_vpn_exit: bool, optional
        :param sigint_disconnect: If True, the connection will be closed when
            the script recieves a SIGINT
        :type sigint_disconnect: bool, optional
        :raises ValueError: If the environment variable SUDO_PASSWORD is not set
            when the user does not have passwordless sudo enabled
        :raises ConnectionRefusedError: If the client is already connected
        :raises TimeoutError: If the connection attempt times out

        """
        if OpenVPNClient._get_pid() != -1:
            err_msg = "Already connected"
            raise ConnectionRefusedError(err_msg)

        # since openvpn requires root we need to check if the user has:
        # 1. supplied the password in the environment variable, or
        # 2. has passwordless sudo enabled
        must_supply_password = self._is_password_required()
        if must_supply_password and not os.environ.get("SUDO_PASSWORD"):
            err_msg = "Environment variable SUDO_PASSWORD must be set"
            raise ValueError(err_msg)

        self.lock.acquire()
        self._setup_handlers(sigint_disconnect=sigint_disconnect)

        self._start_process(
            must_supply_password=must_supply_password,
            await_vpn_exit=await_vpn_exit,
        )

        with self.lock:
            self.timer.cancel()
            signal.signal(signal.SIGUSR1, signal.SIG_IGN)
            if self.status is Status.CONNECTED:
                logger.info("Connection successful")
            elif self.status is Status.CONNECTION_TIMEOUT:
                OpenVPNClient.disconnect()
                err_msg = f"Did not connect in {self.connect_timeout} seconds"
                raise TimeoutError(err_msg)
            elif self.status is Status.USER_CANCELLED:
                OpenVPNClient.disconnect()
            elif self.status is Status.CONNECTION_FAILED:
                OpenVPNClient._remove_pid_file()
                err_msg = "Connection failed"
                raise ConnectionRefusedError(err_msg)

    def _start_process(
        self, *, must_supply_password: bool, await_vpn_exit: bool
    ) -> None:
        sudo_pw_option = "-S" if must_supply_password else ""
        cmd = (
            f"sudo {sudo_pw_option} openvpn --cd {self.ovpn_dir} --config {self.ovpn_file} "
            f"--dev tun_ovpn --connect-retry-max 3 --connect-timeout {self.connect_timeout} "
            "--script-security 2 --route-delay 1 --route-up"
        ).split()
        cmd.append(  # command to run on route-up should be 'one argument'
            f"{sys.executable} -c 'import os, signal; os.kill({os.getpid()}, signal.SIGUSR1)'"
        )
        self.proc = subprocess.Popen(
            cmd,
            stdin=PIPE,
            stdout=PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        OpenVPNClient._register_pid(self.proc.pid)

        def on_process_exit() -> None:
            returncode = self.proc.wait()
            log_msg = f"Process exited (exitcode: {returncode})"
            if returncode != 0:  # abnormal exit
                self.status = Status.CONNECTION_FAILED
                log_msg += f"\n\routput: {self.proc.stdout.read()}"
                logger.info(log_msg)
                raise ConnectionRefusedError(log_msg)

            logger.info(log_msg)
            self.status = Status.DISCONNECTED

        def excepthook(args: tuple[type, BaseException, TracebackType]) -> None:
            self.lock.release()
            raise args[0](args[1])

        if await_vpn_exit:
            threading.excepthook = excepthook
            threading.Thread(target=on_process_exit).start()

        if must_supply_password:
            self.proc.stdin.write(os.environ["SUDO_PASSWORD"] + "\n")
            self.proc.stdin.flush()
            sleep(1)

    def _setup_handlers(self, *, sigint_disconnect: bool) -> None:
        # when the openvpn process has connected the remote server
        def on_connected(*_) -> None:  # noqa: ANN002
            self.status = Status.CONNECTED
            self.lock.release()

        # when the openvpn process has not connected within the timeout
        def on_connect_timeout(*_) -> None:  # noqa: ANN002
            self.status = Status.CONNECTION_TIMEOUT
            self.lock.release()

        # when a SIGINT is received
        def on_user_cancelled(*_) -> None:  # noqa: ANN002
            if self.status is Status.CONNECTED:
                OpenVPNClient.disconnect()
            else:
                self.lock.release()

            self.status = Status.USER_CANCELLED
            raise KeyboardInterrupt

        if sigint_disconnect:
            signal.signal(signal.SIGINT, on_user_cancelled)

        signal.signal(signal.SIGUSR1, on_connected)
        self.timer = threading.Timer(self.connect_timeout, on_connect_timeout)
        self.timer.start()

    @staticmethod
    def _is_password_required() -> bool:
        """Check if the current user has passwordless sudo.

        :return: True if the user has passwordless sudo, False otherwise.
        :rtype: bool
        """
        try:
            check_call("sudo -n true".split(), stdout=PIPE, stderr=PIPE)
        except CalledProcessError:
            return True
        else:
            return False

    @staticmethod
    def _register_pid(pid: int) -> None:
        """Store the PID of the active OpenVPN process.

        :param pid: The process ID
        :type pid: int
        """
        with Path(PID_FILE).open("w", encoding="ascii") as f:
            f.write(str(pid))

    @staticmethod
    def _get_pid() -> int:
        """Retrieve the PID of the active OpenVPN process.

        :return: The process ID
        :rtype: int
        """
        try:
            with Path(PID_FILE).open(encoding="ascii") as f:
                try:
                    return int(f.read().strip())
                except ValueError:
                    err_msg = f"PID in '{PID_FILE}' is not an integer"
                    logger.exception(err_msg)
                    raise
        except FileNotFoundError:
            return -1

    @staticmethod
    def _remove_pid_file() -> None:
        """Remove the PID file.

        :raises FileNotFoundError: If the PID file doesn't exist
        """
        try:
            Path(PID_FILE).unlink()
        except FileNotFoundError:
            err_msg = f"PID file '{PID_FILE}' not found"
            logger.info(err_msg)
            raise FileNotFoundError(err_msg) from None

    @staticmethod
    def disconnect() -> None:
        """Disconnect the current OpenVPN connection.

        :raises ProcessLookupError: If the PID file can't be tied to a process
        :raises TimeoutError: If the process doesn't terminate normally

        """
        pid = OpenVPNClient._get_pid()
        if pid == -1:
            err_msg = "No ongoing connection found"
            raise ProcessLookupError(err_msg)

        OpenVPNClient._remove_pid_file()
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            err_msg = f"Process with PID {pid} has already exited"
            raise ProcessLookupError(err_msg) from None

        try:
            os.kill(pid, 0)
        except OSError:
            subprocess.run(f"sudo kill -9 {pid}".split(), check=True)
            err_msg = "Process didn't terminate normally, killing instead"
            raise TimeoutError(err_msg) from None


usage = """
    Usage:
        openvpnclient.py --config=<config_file>
        openvpnclient.py --disconnect

    Options:
        -h --help                Show this help message
        --config=<config_file>   Configuration file (.ovpn)
        --disconnect             Disconnect ongoing connection

    Notes:
        It's understood that ca/crt/pkey files referenced in the .ovpn file
        are locatable by OpenVPN.
"""
if __name__ == "__main__":
    args = docopt(usage)

    if args["--disconnect"]:
        OpenVPNClient.disconnect()
    elif args["--config"]:
        config_file = args["--config"]
        OpenVPNClient(config_file).connect(await_vpn_exit=False, sigint_disconnect=True)
    else:
        print(usage)  # noqa: T201, used as executable here
        sys.exit(1)
