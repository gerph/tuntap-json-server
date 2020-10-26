# Tun-Tap JSON Server

This tool provides a means by which emulators may communicate with one another over a virtual network. The intended use is that the emulators which need to transmit ethernet frames do so through the server. This lets them communicate with other emulator systems connected to the same server.
The server may be connected to a 'tap' interface, which allows it to communicate with other systems on the same network.

Providing a connection to a network in this manner allows the emulator to run without any privileges, whilst the network communication is left to a separate process.

## Communications

The TCP server listens on port 33445 by default, awaiting connections from clients. It communicates ethernet frames encoded in JSON lines. Each line is a JSON encoded map containing the following fields:

* `frame_type`:   The frame type, as an integer
* `src`:          Source MAC address as a list of 6 integers.
* `dst`:          Destination MAC address as a list of 6 integers.
* `data`:         Data as base 64 encoded bytes.

Any frames sent to the server will be replicated other connected clients, including the tap if present.


## Usage

When no external connection is required, a tap is unnecessary and the service can be run on any system:

    ./tap_jsonserver.py --port <port number>

