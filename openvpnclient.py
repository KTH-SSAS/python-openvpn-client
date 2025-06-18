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
from argparse import ArgumentParser
import shlex

import psutil

PID_FILE = Path(gettempdir()) / "openvpnclient.pid"
STDERR_FILE = Path(gettempdir()) / "openvpnclient.stderr"
STDOUT_FILE = Path(gettempdir()) / "openvpnclient.stdout"
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

    CONNECTED = 1
    IDLE = 2
    USER_CANCELLED = 3
    CONNECTION_TIMEOUT = 4


class OpenVPNClient:
    """Module for managing an OpenVPN connection."""

    status: Status = Status.IDLE
    timer: threading.Timer
    lock: threading.Lock

    def __init__(
        self,
        ovpn_file: str,
        askpass_file: str = "",
        connect_timeout: int = 5
    ) -> None:
        """Initialize the OpenVPN client.

        :param ovpn_file: The OpenVPN configuration file
        :param connect_timeout: The connection attempt limit in seconds
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

        if askpass_file:
            askpass_path = Path(askpass_file)
            if not askpass_path.exists() or not askpass_path.is_file():
                err_msg = f"File '{askpass_file}' not found, or is not a file"
                raise FileNotFoundError(err_msg)

            os.environ["SUDO_ASKPASS"] = str(askpass_path)

        if not shutil.which("openvpn"):
            err_msg = "OpenVPN must be installed and available on the PATH"
            raise RuntimeError(err_msg)

        self.ovpn_file = Path(ovpn_file)
        self.askpass_file = Path(askpass_file) if askpass_file else None
        self.ovpn_dir = self.ovpn_file.parent
        self.connect_timeout = connect_timeout
        self.lock = threading.Lock()

    def __enter__(self) -> 'OpenVPNClient':
        """Auto-connect when using a context manager."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:  # noqa: ANN001, F841, RUF100
        """Disconnect when using a context manager."""
        self.disconnect()

    def connect(self, *, sigint_disconnect: bool = False) -> None:
        """Establish a connection using the provided configuration file.

        :param sigint_disconnect: If True, the connection will be closed when
            the script recieves a SIGINT
        :raises ValueError: If the environment variable SUDO_PASSWORD is not set
            when the user does not have passwordless sudo enabled
        :raises ConnectionRefusedError: If the client is already connected
        :raises TimeoutError: If the connection attempt times out
        :raises RuntimeError: If the connection status is unknown
            (shouldn't occur).
        """
        if OpenVPNClient._get_pid() != -1:
            err_msg = "Already connected"
            raise ConnectionRefusedError(err_msg)

        self.lock.acquire()
        self._setup_handlers(sigint_disconnect=sigint_disconnect)
        self._start_process()

        with self.lock:
            self.timer.cancel()
            signal.signal(signal.SIGUSR1, signal.SIG_IGN)
            if self.status is Status.CONNECTED:
                logger.info("Connection successful")
            elif self.status is Status.CONNECTION_TIMEOUT:
                logger.info("Connection attempt timed out")
                OpenVPNClient.disconnect()
                err_msg = f"Did not connect in {self.connect_timeout} seconds"
                raise TimeoutError(err_msg)
            elif self.status is Status.USER_CANCELLED:
                logger.info("User cancelled during connection")
                OpenVPNClient.disconnect()
            else:
                err_msg = f"Unknown status {self.status}"
                raise RuntimeError(err_msg)

    def _start_process(self) -> None:
        # since openvpn requires root we need to check if the user has:
        # 1. supplied the password in the environment variable, or
        # 2. has passwordless sudo enabled
        must_supply_password = OpenVPNClient._must_supply_password()
        sudo_pw_option = "-S " if must_supply_password else ""
        askpass_option = f"--askpass '{self.askpass_file}'" if self.askpass_file else ''
        route_up_cmd = f'{sys.executable} -c "import os, signal; os.kill({os.getpid()}, signal.SIGUSR1)"'
        cmd = (
            f"sudo {sudo_pw_option} openvpn --cd {self.ovpn_dir} --config '{self.ovpn_file}' {askpass_option} "
            f"--dev tun_ovpn --connect-retry-max 3 --connect-timeout {self.connect_timeout} "
            f"--script-security 2 --route-delay 1 --route-up '{route_up_cmd}'"
        )
        cmd = shlex.split(cmd)
        self.proc = subprocess.Popen(
            cmd,
            stdin=PIPE,
            stdout=STDOUT_FILE.open("w"),
            stderr=STDERR_FILE.open("w"),
            text=True,
        )
        if must_supply_password:
            self.proc.stdin.write(os.environ["SUDO_PASSWORD"] + "\n")
            self.proc.stdin.flush()

        PID_FILE.write_text(str(self.proc.pid), encoding="ascii")

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
    def _on_process_exit(pid: int, *, timeout: int | None = None) -> None:
        """Wait for the OpenVPN process to exit and log the result.

        :param pid: The PID of the OpenVPN process
        :param timeout: The time to wait for the process to exit, defaults to unlimited
        :raises ConnectionRefusedError: If the OpenVPN process wrote on stderr
        """
        psutil.Process(pid).wait(timeout=timeout)
        log_msg = "Process exited"
        stderr = Path(STDERR_FILE).read_text(encoding="ascii").strip()
        stdout = Path(STDOUT_FILE).read_text(encoding="ascii").strip()
        OpenVPNClient._cleanup()

        # unavoidable error from trying to remove a potentially pre-existing tun/tap
        stderr = stderr.replace(
            "ifconfig: ioctl (SIOCDIFADDR): Can't assign requested address", ""
        )
        if stderr:
            log_msg += "error/output:" + "\nSTDOUT:\n" + stdout + "\nSTDERR:\n" + stderr
            logger.info(log_msg)
            raise ConnectionRefusedError(log_msg)

        logger.info(log_msg)

    @staticmethod
    def _must_supply_password() -> bool:
        """Check if passwordless sudo is available or if password is in environment.

        :raises ValueError: If $SUDO_PASSWORD is required but unset
        :return: False if passwordless sudo, True otherwise.
        """
        try:
            check_call("sudo -n true".split(), stdout=PIPE, stderr=PIPE)
        except CalledProcessError:
            if not os.environ.get("SUDO_PASSWORD"):
                err_msg = "Environment variable SUDO_PASSWORD must be set"
                raise ValueError(err_msg) from None

            return True
        else:
            return False

    @staticmethod
    def _get_pid() -> int:
        """Retrieve the PID of the active OpenVPN process.

        :raises ValueError: If the PID file contains an invalid value
        :return: The process ID
        """
        try:
            return int(Path(PID_FILE).read_text(encoding="ascii").strip())
        except FileNotFoundError:
            return -1
        except ValueError:
            err_msg = f"PID in '{PID_FILE}' is not an integer"
            logger.exception(err_msg)
            raise

    @staticmethod
    def _cleanup() -> None:
        """Remove the temporary files.

        :raises FileNotFoundError: If a file doesn't exist
        """
        err_msg = "File(s) non-existent:"
        failed = False
        try:
            PID_FILE.unlink()
        except FileNotFoundError:
            failed = True
            err_msg += f"\n - {PID_FILE}"

        try:
            STDERR_FILE.unlink()
        except FileNotFoundError:
            failed = True
            err_msg = f"\n - {STDERR_FILE}"

        try:
            STDOUT_FILE.unlink()
        except FileNotFoundError:
            failed = True
            err_msg = f"\n - {STDOUT_FILE}"

        if failed:
            logger.info(err_msg)
            raise FileNotFoundError(err_msg)

    @staticmethod
    def disconnect() -> None:
        """Disconnect the current connection.

        :raises ProcessLookupError: If the PID file can't be tied to a process
        """
        pid = OpenVPNClient._get_pid()
        if pid == -1:
            err_msg = "No ongoing connection found (pid not registered)"
            logger.info(err_msg)
            raise ProcessLookupError(err_msg)

        try:
            process = psutil.Process(pid)
        except psutil.NoSuchProcess:
            err_msg = "Process has already exited"
            logger.info(err_msg)
            raise ProcessLookupError(err_msg) from None

        must_supply_password = OpenVPNClient._must_supply_password()
        sudo_pw_option = "-S " if must_supply_password else ""

        cmd = f"sudo {sudo_pw_option}kill {process.pid}".split()
        subprocess.Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, text=True)
        if must_supply_password:
            process.stdin.write(os.environ["SUDO_PASSWORD"] + "\n")
            process.stdin.flush()

        try:
            OpenVPNClient._on_process_exit(pid=process.pid, timeout=30)
        except psutil.TimeoutExpired:
            msg = "Failed to terminate OpenVPN process, killing instead"
            logger.info(msg)

            cmd = f"sudo kill -INT {process.pid}".split()
            subprocess.Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, text=True)
            if must_supply_password:
                process.stdin.write(os.environ["SUDO_PASSWORD"] + "\n")
                process.stdin.flush()

            OpenVPNClient._on_process_exit(pid=process.pid, timeout=30)


if __name__ == "__main__":
    argparse = ArgumentParser(description="OpenVPN Client")
    argparse.add_argument("--config", type=str, help="Configuration file (.ovpn)")
    argparse.add_argument("--askpass", type=str, help="File for password input for the .ovpn file")
    argparse.add_argument("--disconnect", action="store_true", help="Disconnect ongoing connection")
    
    args = argparse.parse_args()

    if args.disconnect:
        OpenVPNClient.disconnect()
        sys.exit(0)
    if args.config:
        OpenVPNClient(
            ovpn_file=args.config,
            askpass_file=args.askpass,
            connect_timeout=20
        ).connect(sigint_disconnect=True)
