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

## MAC learning and port security

The server behaves as a MAC-learning Ethernet switch, not a hub: it doesn't just replicate every frame to everyone.

* Source MAC addresses are learned per connected client, and per the tap if one is configured.
* A frame addressed to a known unicast MAC is delivered only to the client (or the tap) that owns it.
* Broadcast, multicast, and frames addressed to an unknown MAC are flooded to every other connected client, and to the tap if configured.

Because this switch is designed to be reachable by many mutually-untrusting clients, potentially over the open internet, while the tap bridges to a real network, it applies stricter rules than a typical switch about how a learned MAC address can change ownership:

* **Client vs client (port security)**: a MAC address already learned on one client cannot be claimed by another client - the second client is disconnected instead, and the original owner is left alone.
* **Client vs tap (a strict boundary, in both directions)**: a client can never silently take over a MAC currently attributed to the tap, and the tap can never silently take over a MAC currently attributed to a client. Either mismatch just drops the offending frame and logs it - nothing is disconnected, since there's no tap "connection" to drop.
* An entry's ownership can only change in one of two ways: the owning client disconnecting (immediate), or a tap-learned entry ageing out from inactivity (`--tap-mac-age`, default 300 seconds). Once that happens, a fresh claim from either side is accepted normally.
* The console's `clear mac address-table` command (see below) forgets all learned entries without disconnecting anyone - traffic just floods again until each source is relearned, which happens automatically on its next frame.

## Usage

    ./tap_jsonserver.py [options]

* `--port <port>` - TCP port to listen on for client connections (default: `33445`).
* `--tap-device <device>` - tap device to attach to: a file path on macOS, an interface name on Linux (see "Setting up the TAP" below for platform-specific setup). Supplying this enables the tap; omit it to run without one.
* `--tap-mac-age <seconds>` - how long a MAC address learned via the tap is remembered with no traffic before it's aged out of the switch's MAC table (default: `300`).
* `--log-level <LEVEL>` - logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` (default: `INFO`).

When no external connection is required, a tap is unnecessary and the service can be run on any system:

    ./tap_jsonserver.py --port <port number>

With a tap attached (Linux example):

    ./tap_jsonserver.py --port <port number> --tap-device tap0

## Setting up the TAP

On macOS, this seems to be partially achievable by:

We use the tuntap driver - you will need this to be installed.

Create a new bridge through the network configuration, using the interface you want to access the network from:

* Go to Settings->Network.
* Select the cog under the interfaces select 'Manage virtual interfaces'
* Add an interface.
* Give it an appropriate name (I chose 'Wifi Bridge')
* Select the interface you want to bridge (eg the Wifi interface)
* This will then tell you the BSD name of the bridge

To get the data to be written to the tap, it is necessary to bring the tap interface up:

* `ifconfig <tap interface> up`

If you want to communicate with the outside world (not just with yourself), you will need to add the tap to the bridge:

* `ifconfig bridge1 addm <tap interface>`

It may be necessary to configure the system to forward packets:

* `sysctl -w net.link.ether.inet.proxyall=1`
* `sysctl -w net.inet.ip.forwarding=1`

Even still, I couldn't get ICMP packets to make it all the way through the wifi interface.

On Linux you can set things up with:

Create an interface which you will use for the communication:

* `tunctl -t <tap name>`

Create a bridge for your interfaces you will group together:

* `brctl addbr br0`
* `brctl addif br0 <bridged interface>`
* `brctl addif br0 <tap interface>`

## Packet capture

Every run of the switch also opens a FIFO called `mirror0`, next to the script itself (fixed, not configurable, and gitignored). Every frame passing through the switch is mirrored to it as a live pcap stream - like a SPAN/mirror port on a real switch. Point a capture tool at it directly:

    tshark -i mirror0

or:

    wireshark -k -i mirror0

It's best-effort: with nothing reading the FIFO, or a reader that can't keep up, frames are silently dropped rather than adding any delay to the switch's actual job of moving traffic. Restarting the capture tool is safe - a new reader always gets a fresh pcap header rather than a corrupted stream.

## Console

Every run of the switch opens a console on a Unix domain socket called `console0`, next to the script itself (fixed, not configurable, and gitignored). Connect to it locally with `socat`:

    socat - UNIX-CONNECT:console0

or with `nc`:

    nc -U console0

Commands support Cisco-style partial matching, including matching a whole command when the words given are unambiguous even if incomplete (e.g. `sh int` or just `show mac` both work):

* `show interfaces status` - lists connected clients and the tap (if configured), each with a port number.
* `show mac address-table` - lists learned MAC addresses, their owning port (matching `show interfaces status`), and (for tap-learned entries) time until they age out.
* `clear mac address-table` - forgets all learned MAC addresses. This only affects switching decisions (traffic floods until relearned, which happens automatically on the next frame from each source) - it does not disconnect anyone.
* `clear interface <port>` - disconnects the client with that port (from `show interfaces status`).
* `show logging` / `logging level <LEVEL>` - reads or changes the logging verbosity while running.
* `help` (or `?`) - lists the available commands.
* `exit` - closes the console session.
