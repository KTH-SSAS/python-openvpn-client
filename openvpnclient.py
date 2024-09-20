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
from types import TracebackType  # noqa: TCH003, used to type annotate

import psutil
from docopt import docopt
from typing_extensions import Self

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setFormatter(
    logging.Formatter(
        "\r\n%(asctime)s OpenVPN: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
)
logger.addHandler(console_handler)


PID_FILE = f"{gettempdir()}/openvpnclient.pid"


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

        Args:
        ----
            ovpn_file (str): The OpenVPN configuration file
            connect_timeout (int): The connection attempt limit in seconds

        Raises:
        ------
            ValueError: If connect_timeout is less than, or equal to, 0
            FileNotFoundError: If the configuration file is not found
            RuntimeError: If OpenVPN is not installed or not available on the PATH

        """
        if connect_timeout <= 0:
            err_msg = "Connection timeout must be at least 1 second"
            raise ValueError(err_msg)

        if not Path(ovpn_file).exists():
            err_msg = f"File '{self.ovpn_file}' not found"
            raise FileNotFoundError(err_msg)

        if not shutil.which("openvpn"):
            err_msg = "OpenVPN must be installed and available on the PATH"
            raise RuntimeError(err_msg)

        self.ovpn_file = Path(ovpn_file)
        self.ovpn_dir = self.ovpn_file.parent
        self.connect_timeout = connect_timeout
        self.lock = threading.Lock()

    def __enter__(self) -> Self:
        """Connect to the OpenVPN server when entering a context manager."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:  # noqa: ANN001, F841, RUF100
        """Disconnect from the OpenVPN server when exiting a context manager."""
        self.disconnect()

    def connect(
        self, *, alive_on_parent_exit: bool = False, close_on_sigint: bool = False
    ) -> None:
        """Connect to the OpenVPN server using the provided configuration file.

        Args:
        ----
            alive_on_parent_exit (bool): If True, the connection will not be
            terminated when the script is exited
            close_on_sigint (bool): If True, the connection will be closed when
            the script recieves a SIGINT

        Raises:
        ------
            ConnectionError: If the client is already connected
            TimeoutError: If the connection attempt times out

        """
        if OpenVPNClient._get_pid() != -1:
            err_msg = "Already connected"
            raise ConnectionError(err_msg)

        # since openvpn requires root we need to check if the user has:
        # 1. supplied the password in the environment variable, or
        # 2. has passwordless sudo enabled
        must_supply_password = self._is_password_required()
        if must_supply_password and not os.environ.get("SUDO_PASSWORD"):
            err_msg = "Environment variable SUDO_PASSWORD must be set"
            raise ValueError(err_msg)

        self.lock.acquire()
        self._setup_handlers(close_on_sigint=close_on_sigint)

        self._start_process(
            must_supply_password=must_supply_password,
            alive_on_parent_exit=alive_on_parent_exit,
        )

        with self.lock:
            self.timer.cancel()
            signal.signal(signal.SIGUSR1, signal.SIG_IGN)
            if self.status is Status.CONNECTED:
                logger.info("OpenVPN connection successful")
            elif self.status is Status.CONNECTION_TIMEOUT:
                OpenVPNClient.disconnect()
                err_msg = f"Did not connect in {self.connect_timeout} seconds"
                raise TimeoutError(err_msg)
            elif self.status is Status.USER_CANCELLED:
                OpenVPNClient.disconnect()
            elif self.status is Status.CONNECTION_FAILED:
                OpenVPNClient._remove_pid_file()
                err_msg = "OpenVPN connection failed"
                raise ConnectionRefusedError(err_msg)

    def _start_process(
        self, *, must_supply_password: bool, alive_on_parent_exit: bool
    ) -> None:
        sudo_pw_option = "-S" if must_supply_password else ""
        cmd = (
            f"sudo {sudo_pw_option} openvpn --cd {self.ovpn_dir} --config {self.ovpn_file} "
            f"--dev tun_ovpn --connect-retry-max 3 --connect-timeout {self.connect_timeout} "
            "--script-security 2 --route-delay 1 --route-up"
        ).split()
        cmd.append(
            f"{sys.executable} -c 'import os, signal; os.kill({os.getpid()}, signal.SIGUSR1)'"
        )
        self.proc = subprocess.Popen(
            cmd,
            stderr=subprocess.STDOUT,
            stdout=PIPE,
            text=True,
            start_new_session=True,
        )
        OpenVPNClient._register_pid(self.proc.pid)

        def on_process_exited() -> None:
            if alive_on_parent_exit:
                return

            returncode = self.proc.wait()
            log_msg = f"OpenVPN process exited with code {returncode}"
            logger.info(log_msg)
            if returncode != 0:
                self.status = Status.CONNECTION_FAILED
                msg = (
                    f"\rOpenVPN process failed with exit code {returncode}\n"
                    f"\routput: {self.proc.stdout.read()}"
                )
                logger.info(msg)
                raise ConnectionRefusedError(msg)

            self.status = Status.DISCONNECTED

        def excepthook(args: tuple[type, BaseException, TracebackType]) -> None:
            self.lock.release()
            raise args[0](args[1])

        threading.excepthook = excepthook

        def if_password_required() -> None:
            # this statement will block until the process exits
            self.proc.communicate(input=os.environ["SUDO_PASSWORD"] + "\n")

        if not alive_on_parent_exit:
            threading.Thread(target=on_process_exited).start()

        if must_supply_password:
            threading.Thread(target=if_password_required).start()

    def _setup_handlers(self, *, close_on_sigint: bool) -> None:
        # when the openvpn process has connected the remote server
        def on_connected(*_) -> None:  # noqa: ANN002, not relevant for functionality
            self.status = Status.CONNECTED
            self.lock.release()

        # when the openvpn process has not connected within the timeout
        def on_connect_timeout(*_) -> None:  # noqa: ANN002, not relevant for functionality
            self.status = Status.CONNECTION_TIMEOUT
            self.lock.release()

        # when the user sends a SIGINT
        def on_user_cancelled(*_) -> None:  # noqa: ANN002, not relevant for functionality
            if self.status is Status.CONNECTED:
                OpenVPNClient.disconnect()
            else:
                self.status = Status.USER_CANCELLED
                self.lock.release()

            raise KeyboardInterrupt

        if close_on_sigint:
            signal.signal(signal.SIGINT, on_user_cancelled)

        signal.signal(signal.SIGUSR1, on_connected)
        self.timer = threading.Timer(self.connect_timeout, on_connect_timeout)
        self.timer.start()

    @staticmethod
    def _is_password_required() -> bool:
        """Check if the current user has passwordless sudo."""
        try:
            check_call("sudo -n true".split(), stdout=PIPE, stderr=PIPE)
        except CalledProcessError:
            return True
        else:
            return False

    @staticmethod
    def _register_pid(pid: int) -> None:
        """Store the PID of the active OpenVPN process.

        Args:
        ----
            pid (int): The process ID

        """
        with Path(PID_FILE).open("w", encoding="ascii") as f:
            f.write(str(pid))

    @staticmethod
    def _get_pid() -> int:
        """Retrieve the PID of the active OpenVPN process.

        Return:
        ------
            int: The process ID

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
        """Remove the PID file."""
        logger.info(f"Removing PID file: {PID_FILE}")  # noqa: G004
        try:
            Path(PID_FILE).unlink()
        except FileNotFoundError:
            err_msg = f"PID file '{PID_FILE}' not found"
            logger.info(err_msg)
            raise FileNotFoundError(err_msg) from None

    @staticmethod
    def disconnect() -> None:
        """Disconnect the current OpenVPN connection.

        Raise:
        ------
            ProcessLookupError: If the PID file is not found or the PID file is corrupt
            TimeoutError: If the process doesn't terminate in 5 seconds

        """
        pid = OpenVPNClient._get_pid()
        if pid == -1:
            err_msg = "No ongoing connection found"
            raise ProcessLookupError(err_msg)

        OpenVPNClient._remove_pid_file()
        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            err_msg = f"Process with PID {pid} already exited, removed PID file"
            raise ProcessLookupError(err_msg) from None

        proc.terminate()  # 'explicit-exit-notify' requires SIGTERM
        timeout = 5
        try:
            psutil.wait_procs([proc], timeout=timeout)
            logger.info("Process terminated")
        except TimeoutError:
            proc.kill()
            err_msg = f"Process didn't terminate in {timeout}, killed instead"
            raise TimeoutError(err_msg) from None


usage = """
    Usage:
        openvpnclient.py --config=<config_file>
        openvpnclient.py --disconnect

    Options:
        -h --help     Show this help message
        --config=<config_file>   Configuration file (.ovpn)
        --disconnect   Disconnect ongoing connection
"""
if __name__ == "__main__":
    args = docopt(usage)

    if args["--disconnect"]:
        OpenVPNClient.disconnect()
    elif args["--config"]:
        config_file = args["--config"]
        OpenVPNClient(config_file, connect_timeout=10).connect(
            alive_on_parent_exit=True, close_on_sigint=True
        )
    else:
        print(usage)  # noqa: T201, used as executable here
        sys.exit(1)
