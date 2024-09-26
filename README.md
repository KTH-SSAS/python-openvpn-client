# Module openvpnclient.py
This standalone module is intended to handle OpenVPN connections to a remote
server. It works on macOS-latest and Ubuntu (24.04).

Note: Testing requires OpenVPN >= 2.6 since `peer-fingerprint` which was
first introduced then.

## Setup
```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Usage
Invoke from command line
```bash
# connect
python3 openvpnclient.py --config=/full/path/to/ovpn/file

# disconnect
python3 openvpnclient.py --disconnect
```

Use as dependency in script
```python
from openvpnclient import OpenVPNClient

# context handler
with OpenVPNClient(ovpn_file) as vpn:
    ...

# manual start and stop
vpn = OpenVPNClient(ovpn_file)
vpn.connect()
...
vpn.disconnect()

# do not close the connection despite script exit
vpn = OpenVPNClient(ovpn_file)
vpn.connect(stay_alive_on_exit=True)
# <script end>
```

## Testing
**Test cases**
1. Connect and disconnect the OpenVPN client manually
2. Connect and disconnect the OpenVPN client automatically using the context manager
3. Disconnect OpenVPN client automatically on SIGINT (Ctrl+C)
4. Disconnect when not connected
5. Connect when already connected
6. Invalid client configuration syntax
7. Server not reachable (invalid ip)
8. Wrong path to ovpn config file
9. Connection attempt timeout

It is possible that the host OS/computer is not fast enough to close the sockets
being opened by the repeated OpenVPN client connections and therefore an autouse fixture (`await_openvpn_cleanup`) forces a timeout between all tests. Update this timeout if the socket
appears to be busy.

Run with minimalistic output
```bash
pytest --tap tests/test_openvpnclient.py
```

Run with verbose output
```bash
pytest -s -v tests/test_openvpnclient.py
```

### Run Tests With Coverage Report
- `--cov=./` flag is used to specify the directory of files that should be tested for coverage.
- `--cov-report annotate` flag is used to generate an annotated coverage report.

```bash
pytest --cov=./ tests/test_openvpnclient.py --cov-report annotate
```
