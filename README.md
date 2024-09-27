# Python OpenVPN Client
This python package allows simple connections and disconnections from
OpenVPN servers given a `config.ovpn` file. It's tested to work on macOS
and Linux (images: `macOS-latest` and `ubuntu-24.04`).

Note: Testing requires OpenVPN >= 2.6 since the used `peer-fingerprint`
feature was first introduced then.

## Command line usage
```bash
# connect
python3 -m openvpnclient --config=path/to/ovpn/config

# disconnect
python3 -m openvpnclient --disconnect
```

## Usage in code
```python
from openvpnclient import OpenVPNClient

# manually connect and disconnect
vpn = OpenVPNClient(ovpn_file)
vpn.connect()
# interact with network
vpn.disconnect()

# utilize context handler
with OpenVPNClient(ovpn_file):
    # interact with network
```

## Test cases
1. Manually connect and disconnect the OpenVPN client
1. Use context manager to connect and disconnect the OpenVPN client
1. Disconnect client on SIGINT (ctrl+c)
1. Disconnect when not connected
1. Connect when already connected
1. Invalid configuration syntax
1. Unreachable server
1. Invalid path to ovpn config file
1. Connection attempt timeout

An autouse fixture (`await_openvpn_cleanup`) forces a delay between
all tests. Given the rapid closing and opening of the same socket, this
timeout can be updated to avoid having a busy socket.

## Contributing
Create virtual environment and install dependencies:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r prod-requirements.txt
```

After making changes, make sure the tests pass:
```bash
pip install -r test-requirements.txt
pytest tests/test_openvpnclient.py -s -v
```

## Distributing the package
```bash
# inside the virtual environment
pip install build twine
python -m build
twine upload dist/*
```
