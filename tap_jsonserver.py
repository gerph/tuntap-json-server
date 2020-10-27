#!/usr/bin/env python
"""
Network HUB to allow network systems to communcate.

This tool is intended to allow emulated systems to communicate over ethernet protocols
without having to deal, themselves, with the tap configuration and distribution. It
allows multiple clients to connect and attached together, or to a given tap. This is
particularly useful when the rights to access the tap are only available to a priviledged
user - one you don't want to give the emulated system access to.

In the configuration where no tap is present, the clients which connect will communicate
with each other, but have no external effect.

In the configuration where the tap is present, the clients will be able to communicate
with whatever devices that tap is connected to - the host system, by default, but when
a bridge is installed, this will allow wider communications.


Transmission format
-------------------
The on-wire format for a frame is a line containing JSON-encoded data.
Each line should be a map containing the following fields:

    'frame_type':   The frame type, as an integer
    'src':          Source MAC address as a list of 6 integers.
    'dst':          Destination MAC address as a list of 6 integers.
    'data':         Data as base 64 encoded bytes.

Frames which are not recognised will be dropped.
Each frame received will be replicated yo all the connected clients, and to the TAP if
one is configured.


Setting up the TAP
------------------

On macOS, this seems to be partially achievable by:

    We use the tuntap driver - you will need this to be installed.

    Create a new bridge through the network configuration, using the interface you
    want to access the network from:

    * Go to Settings->Network.
    * Select the cog under the interfaces select 'Manage virtual interfaces'
    * Add an interface.
    * Give it an appropriate name (I chose 'Wifi Bridge')
    * Select the interface you want to bridge (eg the Wifi interface)
    * This will then tell you the BSD name of the bridge

    To get the data to be written to the tap, it is necessary to bring the tap interface up:

    * `ifconfig <tap interface> up`

    If you want to communicate with the outside world (not just with yourself), you will need
    to add the tap to the bridge:

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
"""


import argparse
import os
import sys
from select import select

use_scapy = False

if use_scapy:
    from scapy.all import Ether

import base64
import fcntl
import json
import socket
import struct
import sys
import Queue


class Dump(object):

    def __init__(self, fh=None):
        if fh is None:
            fh = sys.stdout

        self.offset_base = 0
        self.fh = fh
        self.columns = 16
        self.offset_label = 'Offset'
        self.text_label = 'Text'
        self.indent = ''
        self.width = 1  # Must be 1, 2, 4, 8
        self.little_endian = True
        self.heading = True
        self.heading_every = 16
        self.heading_breaks = True
        self.text = True
        self.text_high = False

    def writeln(self, msg):
        self.fh.write(msg + '\n')

    def format_offset(self, offset):
        return '{:8x}'.format(offset + self.offset_base)

    def format_chars(self, data):
        if self.text_high:
            valid = lambda c: (c >= 32 and c < 0x7f) or (c > 0xa0)
        else:
            valid = lambda c: c >= 32 and c < 0x7f
        return ''.join(chr(c) if valid(c) else '.' for c in data)

    def show(self, data):
        units = self.width
        columns = (self.columns + self.width - 1) & ~(self.width - 1)

        row_count = 0
        for offset in range(0, len(data), columns):
            if self.heading:
                if (row_count % self.heading_every) == 0:
                    if row_count != 0 and self.heading_breaks:
                        self.writeln('')

                    rowtitle = '{:>8}'.format(self.offset_label)
                    if columns < 16:
                        rowcolumns = ' '.join('+{:x}'.format(v) for v in range(0, columns, units))
                    elif columns == 16:
                        if self.offset_base % 16 == 0:
                            rowcolumns = ' '.join('{:{}x}'.format(v, units * 2) for v in range(0, columns, units))
                        else:
                            rowcolumns = ' '.join('{:{}}'.format('+{:x}'.format(v), units * 2) for v in range(0, columns + (self.offset_base % 16), units))
                    else:
                        rowcolumns = '+'.join('{:{}x}'.format(v, units * 2) for v in range(0, columns, units))

                    if self.text:
                        rowtext = ' : {}'.format(self.text_label)
                    self.writeln("{}{} : {}{}".format(self.indent,
                                                      rowtitle,
                                                      rowcolumns,
                                                      rowtext))

            rowdata = data[offset:offset + self.columns]
            rowbytevalues = [ord(c) for c in rowdata]
            if units == 1:
                rowvalues = rowbytevalues
            else:
                if len(rowdata) % units != 0:
                    rowdata += '\x00' * (units - (rowdata % units))
                if units == 2:
                    format_string = 'H'
                elif units == 4:
                    format_string = 'L'
                elif units == 8:
                    format_string = 'Q'
                format_string = format_string * (len(rowdata) / units)
                if self.little_endian:
                    format_string = '<' + format_string
                else:
                    format_string = '>' + format_string
                rowvalues = struct.unpack(format_string, rowdata)

            rowdesc = ' '.join('{:0{}x}'.format(v, units * 2) for v in rowvalues)
            if len(rowvalues) < self.columns / units:
                rowdesc += ((' ' * (units * 2)) + ' ') * (self.columns / units - len(rowvalues))

            if self.text:
                rowchars = self.format_chars(rowbytevalues)
                rowtext = ' : {}'.format(rowchars)
            else:
                rowtext = ''

            rowtitle = self.format_offset(offset)

            self.writeln("{}{} : {}{}".format(self.indent, rowtitle, rowdesc, rowtext))
            row_count += 1


class Frame(object):

    def __init__(self, data, frame_type, src_mac, dst_mac):
        self.data = data
        self.frame_type = frame_type
        self.src_mac = src_mac
        self.dst_mac = dst_mac


class Client(object):
    """
    Client holds a client to whom we have connected - we exchange frames.
    """
    read_size = 1024 * 64

    def __init__(self, socket):
        self.socket = socket
        self.name = socket.getpeername()
        self.socket_read = []

    def __repr__(self):
        return "<{}({})>".format(self.__class__.__name__,
                                 self.name)

    def frame_to_json(self, frame):
        send_data = {
                'frame_type': frame.frame_type,
                'src': frame.src_mac,
                'dst': frame.dst_mac,
                'data': base64.b64encode(frame.data),
            }
        return json.dumps(send_data)

    def json_to_frame(self, json_line):
        try:
            recv_data = json.loads(json_line)

            data = base64.b64decode(recv_data['data'])
            frame_type = recv_data['frame_type']

            src_mac = recv_data['src']
            if not isinstance(src_mac, list) or len(src_mac) != 6:
                raise ValueError("src address malformed (received %r)" % (src_mac,))

            dst_mac = recv_data['dst']
            if not isinstance(dst_mac, list) or len(src_mac) != 6:
                raise ValueError("dst address malformed (received %r)" % (dst_mac,))

        except Exception as exc:
            # FIXME: Debug option?
            if self.debug_etherdriverjson:
                print("Ethernet JSON frame invalid: %s" % (exc,))
            return None
        return Frame(data, frame_type, src_mac, dst_mac)

    def transmit(self, frame):
        if not self.socket:
            print("transmit: pointless call when socket was closed")
            # We're closed, so discard
            return

        json_data = self.frame_to_json(frame)
        self.socket.send(json_data + "\n")

    def receive(self):
        """
        Return a list of frames or None if disconnected.
        """
        if not self.socket:
            # We're closed, so nothing to receive - report as disconnected.
            return None

        frames = []

        try:
            data = self.socket.recv(self.read_size)
        except socket.error:
            # Any socket error means that we're had a disconnect
            data = ''
        if data == '':
            # No data means that we were disconnected, so we drop the connection
            self.socket.close()
            self.socket = None
            return None

        while '\n' in data:
            (left, data) = data.split('\n', 1)
            self.socket_read.append(left)
            try:
                frame = self.json_to_frame(''.join(self.socket_read))
                if frame:
                    frames.append(frame)
            except Exception as exc:
                print("Could not process frame: %s" % (exc,))
                pass
            self.socket_read = []
        if data:
            self.socket_read.append(data)

        return frames


class Server(object):

    def __init__(self, host='', port=33445):
        self.host = host
        self.port = port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)

    def receive(self):
        """
        Receive from listening socket - we got a connection.

        There's apparently someone waiting on the socket, so we need to accept their connection
        """
        try:
            (socket, _) = self.socket.accept()
            # We got a connection - give them a client.
            return Client(socket)
        except Exception as exc:
            print("Nobody's really there?!")
            pass
        return None


class TAP(object):
    read_size = 1024 * 64

    # Linux constants
    TUNSETIFF = 0x400454ca
    TUNSETOWNER = TUNSETIFF + 2
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000


    def __init__(self, filename='/dev/tap0', device='tap0'):
        if sys.platform == 'darwin':
            self.socket = os.open(filename, os.O_RDWR)
            self.name = 'filename'
        else:
            self.socket = os.open('/dev/net/tun', os.O_RDWR)
            ifr = struct.pack('16sH', device, self.IFF_TAP | self.IFF_NO_PI)
            fcntl.ioctl(self.socket, self.TUNSETIFF, ifr)
            #fcntl.ioctl(self.socket, self.TUNSETOWNER, 1000)
            self.name = device

    def __repr__(self):
        return "<{}({})>".format(self.__class__.__name__,
                                 self.name)

    def transmit(self, frame):
        src_mac = bytes(bytearray(frame.src_mac))
        dst_mac = bytes(bytearray(frame.dst_mac))
        frame_type = struct.pack('>H', frame.frame_type)
        packet = b''.join([dst_mac, src_mac, frame_type, frame.data])
        os.write(self.socket, packet)

    def receive(self):
        frame = os.read(self.socket, self.read_size)

        # Framing format:
        # 6 bytes:  Destination MAC
        # 6 bytes:  Source MAC
        # 2 bytes:  Ethernet type (eg 0x800)
        # ...       Payload

        dst_mac = [ord(c) for c in frame[0:6]]
        src_mac = [ord(c) for c in frame[6:12]]
        (frame_type,) = struct.unpack('>H', frame[12:14])
        data = frame[14:]

        return [Frame(data, frame_type, src_mac, dst_mac)]


def setup_argparse():
    parser = argparse.ArgumentParser(usage="%s [<options>]" % (os.path.basename(sys.argv[0]),),
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--port', type=int, action='store', default=33445,
                        help="Port to listen for connections on")
    parser.add_argument('--tap-enable', action='store_true',
                        help="Enable use of the tap")
    parser.add_argument('--tap-filename', action='store', default='/dev/tap0',
                        help="Tap filename to connect to (on macOS)")
    parser.add_argument('--tap-device', action='store', default='tap0',
                        help="Tap device to connect to (on Linux)")
    return parser


def main():
    parser = setup_argparse()
    options = parser.parse_args()

    dumper = Dump()

    server = Server(port=options.port)
    if options.tap_enable:
        tap = TAP()
    else:
        tap = None

    clients = {}
    rlist = [server.socket]
    if tap:
        rlist.append(tap.socket)

    queued_frames = Queue.LifoQueue()

    try:
        print("Awaiting connections and packets")
        while True:
            (ready, _, _) = select(rlist,[],[])
            #if ready:
            #    print("Ready sockets: %r" % (ready,))
            for socket in ready:
                if tap and socket == tap.socket:
                    frames = tap.receive()
                    if frames:
                        for frame in frames:
                            queued_frames.put((tap, frame))


                elif socket == server.socket:
                    client = server.receive()
                    if client:
                        print("Got a client %r" % (client,))
                        clients[client.socket] = client
                        rlist.append(client.socket)

                elif socket in clients:
                    client = clients[socket]
                    frames = client.receive()
                    if frames is None:
                        # They disconnected, remove from our list
                        print("Disconnected client %r" % (client,))
                        del clients[socket]
                        rlist.remove(socket)
                    else:
                        for frame in frames:
                            queued_frames.put((client, frame))

                # Let's try sending the frames to all the clients
                if not queued_frames.empty():
                    ports = list(clients.values())
                    if tap:
                        ports.append(tap)

                    while True:
                        try:
                            (receiver_port, frame) = queued_frames.get_nowait()
                            print("Distributing frame type &%04x (%i bytes) from %r" % (frame.frame_type,
                                                                                        len(frame.data),
                                                                                        receiver_port,))
                            for port in ports:
                                if port == receiver_port:
                                    # Never reflect frames to their sender
                                    continue
                                print("Transmit to port %r" % (port,))
                                port.transmit(frame)

                                # Move this into the Frame class and reconstruct the ethernet frame?
                                #if use_scapy:
                                #    ether = Ether(frame)
                                #    ether.show()
                        except Queue.Empty:
                            break

    except KeyboardInterrupt:
        print "HUB terminated."


if __name__ == '__main__':
    sys.exit(main())
