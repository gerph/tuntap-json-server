"""The wire protocols the switch speaks: JSON-encoded ethernet frames over
TCP (Client/Server) and raw ethernet frames over a tun/tap device (TAP)."""

import base64
import fcntl
import json
import logging
import os
import socket
import struct
import sys
from collections import deque

from .logutil import log_event


class Frame(object):

    def __init__(self, data, frame_type, src_mac, dst_mac):
        self.data = data
        self.frame_type = frame_type
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        # Filled in lazily by the first Client that transmits this frame, and
        # reused by every other Client it's also flooded to - a broadcast/
        # multicast frame would otherwise re-run json.dumps()+base64 once
        # per destination client.
        self.encoded = None

    def to_ethernet_bytes(self):
        """The frame as it would appear on the wire: dst+src+ethertype+payload."""
        return b''.join([bytes(bytearray(self.dst_mac)),
                          bytes(bytearray(self.src_mac)),
                          struct.pack('>H', self.frame_type),
                          self.data])


class Client(object):
    """
    Client holds a client to whom we have connected - we exchange frames.
    """
    read_size = 1024 * 64
    max_pending = 1024 * 1024  # bytes buffered waiting for a '\n' before we give up
                               # on the client - a real frame line is a couple of KB.
    max_write_pending = 1024 * 1024  # bytes queued for a slow reader before we give up

    def __init__(self, socket):
        self.socket = socket
        self.name = socket.getpeername()
        self.socket_read = []
        self.write_buffer = bytearray()

    def __repr__(self):
        return "<{}({})>".format(self.__class__.__name__,
                                 self.name)

    def pending_size(self):
        return sum(len(chunk) for chunk in self.socket_read)

    def frame_to_json(self, frame):
        send_data = {
                'frame_type': frame.frame_type,
                'src': frame.src_mac,
                'dst': frame.dst_mac,
                'data': base64.b64encode(frame.data).decode('ascii'),
            }
        # Compact separators: no functional difference, just fewer bytes for
        # the receiver to ship and parse.
        return json.dumps(send_data, separators=(',', ':'))

    @staticmethod
    def _valid_mac(value):
        """A MAC is a list of 6 ints in 0-255 - not just any 6-element list.
        Anything looser (nested lists, strings, bools, out-of-range ints) can
        later blow up as an unhashable/unpackable mac_table key or TAP frame."""
        return (isinstance(value, list) and len(value) == 6 and
                all(isinstance(b, int) and not isinstance(b, bool) and 0 <= b <= 255 for b in value))

    def json_to_frame(self, json_line):
        try:
            recv_data = json.loads(json_line)

            data = base64.b64decode(recv_data['data'])

            frame_type = recv_data['frame_type']
            if (not isinstance(frame_type, int) or isinstance(frame_type, bool)
                    or not (0 <= frame_type <= 0xffff)):
                raise ValueError("frame_type malformed (received %r)" % (frame_type,))

            src_mac = recv_data['src']
            if not self._valid_mac(src_mac):
                raise ValueError("src address malformed (received %r)" % (src_mac,))

            dst_mac = recv_data['dst']
            if not self._valid_mac(dst_mac):
                raise ValueError("dst address malformed (received %r)" % (dst_mac,))

        except Exception:
            return None
        return Frame(data, frame_type, src_mac, dst_mac)

    def transmit(self, frame):
        if not self.socket:
            # A previous transmit in this batch already found the peer gone.
            return

        if frame.encoded is None:
            frame.encoded = (self.frame_to_json(frame) + "\n").encode('utf-8')
        self.write_buffer += frame.encoded
        self.flush()

    def wants_write(self):
        """Whether the main loop should watch this client for writability."""
        return bool(self.socket) and bool(self.write_buffer)

    def flush(self):
        """Send as much of the buffered output as the socket will accept
        right now, without blocking. The main loop calls this again once
        select() reports the socket writable, to drain the rest - this is
        what stops one slow reader from stalling delivery to every other
        client (sockets are non-blocking; see Server.receive())."""
        if not self.socket or not self.write_buffer:
            return

        try:
            sent = self.socket.send(self.write_buffer)
            del self.write_buffer[:sent]
        except BlockingIOError:
            # The socket's send buffer is full right now - nothing went out,
            # but still fall through to the overflow check below: a peer
            # that never reads at all would otherwise never hit it.
            pass
        except OSError:
            # The peer disconnected between our last receive() and this
            # transmit()/flush() - tear down the same way receive() would.
            self.socket.close()
            self.socket = None
            return

        if len(self.write_buffer) > self.max_write_pending:
            log_event(logging.WARNING, 'FRAME', 'WRITEOVERFLOW',
                      "Dropping %r: %i bytes queued for a slow reader (limit %i)",
                      self, len(self.write_buffer), self.max_write_pending)
            self.socket.close()
            self.socket = None

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
            data = b''
        if not data:
            # No data means that we were disconnected, so we drop the connection
            self.socket.close()
            self.socket = None
            return None

        while b'\n' in data:
            (left, data) = data.split(b'\n', 1)
            self.socket_read.append(left)
            try:
                frame = self.json_to_frame(b''.join(self.socket_read).decode('utf-8'))
                if frame:
                    frames.append(frame)
            except Exception as exc:
                log_event(logging.WARNING, 'FRAME', 'BADFRAME', "Could not process frame: %s", exc)
                pass
            self.socket_read = []
        if data:
            self.socket_read.append(data)
            if self.pending_size() > self.max_pending:
                log_event(logging.WARNING, 'FRAME', 'OVERFLOW',
                          "Dropping %r: %i bytes buffered with no complete line (limit %i)",
                          self, self.pending_size(), self.max_pending)
                self.socket.close()
                self.socket = None
                return None

        return frames


class Server(object):

    def __init__(self, host='', port=33445):
        self.host = host
        self.port = port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)

    def receive(self):
        """
        Receive from listening socket - we got a connection.

        There's apparently someone waiting on the socket, so we need to accept their connection
        """
        try:
            (conn, _) = self.socket.accept()
            # We got a connection - give them a client. Small, latency-sensitive
            # frames rather than bulk transfer, so disable Nagle's algorithm.
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            # Non-blocking so a full send buffer (slow/stalled peer) can never
            # block the main select() loop - see Client.flush().
            conn.setblocking(False)
            return Client(conn)
        except Exception as exc:
            log_event(logging.WARNING, 'SYS', 'ACCEPTFAIL', "accept() failed: %s", exc)
        return None


class TAP(object):
    read_size = 1024 * 64
    max_write_pending = 1024 * 1024  # bytes queued for a congested tap before we
                                     # start dropping new frames rather than grow further

    # Linux constants
    TUNSETIFF = 0x400454ca
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000


    def __init__(self, device='tap0'):
        # On macOS, `device` is a file path to the tap device itself; on
        # Linux it's the interface name to attach to via the shared
        # /dev/net/tun clone device (TUNSETIFF) - there's no per-interface
        # file to open directly.
        path = device if sys.platform == 'darwin' else '/dev/net/tun'
        # Non-blocking so a congested tap (its queue can't drain as fast as
        # we're writing) can never block the main select() loop - same
        # discipline as Client, see Client.flush().
        self.socket = os.open(path, os.O_RDWR | os.O_NONBLOCK)
        if sys.platform != 'darwin':
            ifr = struct.pack('16sH', device.encode('utf-8'), self.IFF_TAP | self.IFF_NO_PI)
            fcntl.ioctl(self.socket, self.TUNSETIFF, ifr)
        self.name = device
        # A queue of whole frames, not a byte stream: a tap write() is
        # packet-oriented, so each os.write() call must be exactly one
        # frame - concatenating two queued frames into a single write()
        # would hand the kernel one malformed packet instead of two.
        self.write_queue = deque()
        self._queued_bytes = 0

    def __repr__(self):
        return "<{}({})>".format(self.__class__.__name__,
                                 self.name)

    def wants_write(self):
        """Whether the main loop should watch this tap for writability."""
        return bool(self.write_queue)

    def transmit(self, frame):
        packet = frame.to_ethernet_bytes()
        if self._queued_bytes + len(packet) > self.max_write_pending:
            # Unlike a slow Client, there's no connection to drop here - the
            # tap has to stay up. So the tap's own equivalent of a NIC's tx
            # ring dropping packets under congestion is to drop the newest
            # frame rather than let the queue grow without bound.
            log_event(logging.WARNING, 'LINK', 'TAPOVERFLOW',
                      "Dropping frame to tap %r: %i bytes already queued for a congested tap (limit %i)",
                      self, self._queued_bytes, self.max_write_pending)
            return
        self.write_queue.append(packet)
        self._queued_bytes += len(packet)
        self.flush()

    def flush(self):
        """Send as many complete queued frames as the tap will accept right
        now, without blocking. The main loop calls this again once select()
        reports the tap writable, to drain the rest. Each frame is written
        whole or not at all - never partially, which would otherwise corrupt
        the frame boundary for whatever's queued behind it."""
        while self.write_queue:
            packet = self.write_queue[0]
            try:
                sent = os.write(self.socket, packet)
            except BlockingIOError:
                return
            except OSError as exc:
                log_event(logging.WARNING, 'LINK', 'TAPWRITEFAIL',
                          "Failed to write to tap %r: %s (dropping this frame, tap stays up)", self, exc)
                self.write_queue.popleft()
                self._queued_bytes -= len(packet)
                continue
            if sent != len(packet):
                # A tap write is defined to be exactly one packet - if the
                # kernel ever only takes part of one, there's no way to send
                # the rest without corrupting whatever frame comes next, so
                # drop it whole rather than risk desyncing the tap.
                log_event(logging.WARNING, 'LINK', 'TAPSHORTWRITE',
                          "Short write to tap %r: %i of %i bytes (dropping this frame)",
                          self, sent, len(packet))
            self.write_queue.popleft()
            self._queued_bytes -= len(packet)

    def receive(self):
        try:
            frame = os.read(self.socket, self.read_size)
        except OSError as exc:
            log_event(logging.WARNING, 'LINK', 'TAPREADFAIL',
                      "Failed to read from tap %r: %s (tap stays up)", self, exc)
            return []

        # Framing format:
        # 6 bytes:  Destination MAC
        # 6 bytes:  Source MAC
        # 2 bytes:  Ethernet type (eg 0x800)
        # ...       Payload

        if len(frame) < 14:
            log_event(logging.WARNING, 'LINK', 'TAPSHORTREAD',
                      "Short read from tap %r: %i bytes (dropping)", self, len(frame))
            return []

        dst_mac = list(frame[0:6])
        src_mac = list(frame[6:12])
        (frame_type,) = struct.unpack('>H', frame[12:14])
        data = frame[14:]

        return [Frame(data, frame_type, src_mac, dst_mac)]
