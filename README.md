# Python OpenVPN Client
This package allows an OpenVPN connection to be established
seamlessly given a `config.ovpn` file and then later be
disconnected when instructed to. The functionality is tested to
work on macOS and Linux (images: `macOS-latest` and `ubuntu-24.04`).

Note: Testing requires `openvpn >= 2.6` since the used `peer-fingerprint`
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

Create a PR from the feature branch with the incorporated
changes.

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
timeout can be adjusted to make sure the socket is ready for
subsequent test.
