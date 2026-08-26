"""Passive frame mirroring: every frame that transits the switch is copied,
best-effort, to a FIFO that a packet-capture tool (tshark/Wireshark) can
read pcap records from directly - a SPAN/mirror port, not a real interface.
"""

import errno
import logging
import os
import select
import stat
import struct
import time

from .logutil import log_event


PCAP_MAGIC = 0xa1b2c3d4
PCAP_SNAPLEN = 65535
LINKTYPE_ETHERNET = 1


class Mirror(object):
    """Writes pcap records for every frame passed to record() to the FIFO at
    `path`, if and only if something is currently reading it.

    Never blocks the caller and never buffers: with no reader attached, or a
    reader that can't keep up, frames are silently dropped - the same thing
    a hardware SPAN port does under overload - rather than add latency to
    the switch's actual job of moving traffic.
    """

    recheck_interval = 1.0  # seconds between attempts to attach a reader, and
                            # between checks that an attached one is still there

    def __init__(self, path):
        self.path = path
        try:
            # Only remove it if it's actually a FIFO - see CLIServer's same
            # check for the reasoning (stale file from an unclean shutdown
            # vs. something else planted at this path).
            if stat.S_ISFIFO(os.lstat(path).st_mode):
                os.unlink(path)
        except FileNotFoundError:
            pass
        os.mkfifo(path, 0o600)
        os.chmod(path, 0o600)  # mkfifo's mode is subject to umask
        self.fd = None
        self._poller = None
        self._next_check = 0.0

    def tick(self):
        """Either try to attach a reader, or - if one's already attached -
        confirm it's still actually there. Call this regularly (the main
        loop calls it every iteration; record() also calls it so a session
        starting with no traffic flowing doesn't wait for the next tick).

        This matters because a broken pipe only ever surfaces through an
        actual write() failing, or (checked here, non-invasively) a poll()
        error event - and that error event is a live status, not a latch:
        it's only visible while there's truly no reader, and clears the
        instant a new one attaches. If we only ever checked reactively on
        the next record() call, a reader that disconnects and a new one
        that reconnects before the next frame arrives would go unnoticed -
        we'd keep writing to the new reader as if it were the old session
        and never send it the pcap header it needs. Checking on a timer
        independent of frame traffic is what catches that window.
        """
        now = time.monotonic()
        if now < self._next_check:
            return
        self._next_check = now + self.recheck_interval
        if self.fd is None:
            self._try_attach()
        elif self._poller.poll(0):
            # POLLERR/POLLHUP: the reader that was here is gone. Detach now,
            # so the next tick's attach attempt sends whatever reader shows
            # up next a proper header instead of silently resuming as if
            # nothing happened.
            self._detach()

    def _try_attach(self):
        try:
            # O_NONBLOCK on a FIFO open for write fails fast (ENXIO) rather
            # than blocking until a reader shows up.
            self.fd = os.open(self.path, os.O_WRONLY | os.O_NONBLOCK)
        except OSError as exc:
            if exc.errno != errno.ENXIO:
                log_event(logging.WARNING, 'SYS', 'MIRROROPENFAIL',
                          "Could not open mirror FIFO %r: %s", self.path, exc)
            return
        log_event(logging.INFO, 'LINK', 'MIRRORUP', "Packet capture attached to %r", self.path)
        self._poller = select.poll()
        self._poller.register(self.fd, select.POLLERR | select.POLLHUP)
        header = struct.pack('<IHHiIII', PCAP_MAGIC, 2, 4, 0, 0, PCAP_SNAPLEN, LINKTYPE_ETHERNET)
        self._write_or_detach(header)

    def _detach(self):
        if self.fd is not None:
            log_event(logging.INFO, 'LINK', 'MIRRORDOWN', "Packet capture detached from %r", self.path)
            os.close(self.fd)
            self.fd = None
            self._poller = None

    def _write_or_detach(self, data):
        """Write `data` to the mirror fd. Any failure - the reader can't
        take it right now, has gone away, or only accepted part of it (which
        would desync the pcap stream for every record after this one) -
        just detaches; the next reader gets a fresh header and a clean start."""
        try:
            sent = os.write(self.fd, data)
        except BlockingIOError:
            return
        except OSError:
            self._detach()
            return
        if sent != len(data):
            self._detach()

    def record(self, frame):
        if self.fd is None:
            self.tick()
            if self.fd is None:
                return

        packet = frame.to_ethernet_bytes()
        now_ns = time.time_ns()
        sec, rem_ns = divmod(now_ns, 1_000_000_000)
        header = struct.pack('<IIII', sec, rem_ns // 1000, len(packet), len(packet))
        self._write_or_detach(header + packet)

    def close(self):
        self._detach()
        if os.path.exists(self.path):
            os.unlink(self.path)
