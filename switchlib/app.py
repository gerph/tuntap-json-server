"""Argument parsing and the main select() event loop that ties the protocol,
switching, console, and mirror pieces together."""

import argparse
import logging
import os
import sys
import time
from collections import deque
from select import select

from .console import CLIServer, resolve_cli_command
from .logutil import log_event
from .mirror import Mirror
from .protocol import Server, TAP
from .switching import age_mac_table, learn_source, purge_mac_table_for_port, resolve_targets


SELECT_TIMEOUT = 5.0  # seconds; poll granularity so select() wakes periodically
                      # to age out stale TAP-learned MAC entries even when idle.

AGE_CHECK_INTERVAL = 1.0  # seconds; how often to bother scanning the whole MAC
                          # table for expired entries - no need to do it on every
                          # select() wakeup, which can happen many times a second
                          # under load. Aging deadlines are on the order of minutes
                          # (--tap-mac-age), so a second of slack is irrelevant.


def _cli_socket_path():
    # Next to the originally-invoked script, regardless of which module this
    # function itself happens to live in - sys.argv[0], not __file__.
    return os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'console0')


def _mirror_fifo_path():
    return os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'mirror0')


def setup_argparse():
    parser = argparse.ArgumentParser(usage="%s [<options>]" % (os.path.basename(sys.argv[0]),),
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--port', type=int, action='store', default=33445,
                        help="Port to listen for connections on")
    parser.add_argument('--tap-device', action='store', default=None,
                        help="Tap device to attach to: a file path on macOS, "
                             "an interface name on Linux. Supplying this enables "
                             "the tap; omit it to run without one")
    parser.add_argument('--tap-mac-age', type=float, action='store', default=300.0,
                        help="Seconds of inactivity before a MAC address learned via "
                             "the tap is aged out of the switch's MAC table")
    parser.add_argument('--log-level', action='store', default='INFO',
                        choices=('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'),
                        help="Logging verbosity")
    return parser


def _drop_dead_clients(clients, rlist, mac_table):
    """Remove any client whose socket was closed by a failed receive() or
    flush() (e.g. a slow reader that overflowed its write buffer)."""
    for stale_socket, stale_client in list(clients.items()):
        if not stale_client.socket:
            log_event(logging.INFO, 'LINK', 'CLIENTDOWN', "Client %r disconnected", stale_client)
            purge_mac_table_for_port(mac_table, stale_client)
            del clients[stale_socket]
            rlist.remove(stale_socket)


def _drop_dead_cli_sessions(cli_sessions, rlist):
    """Remove any CLI session whose socket was closed by a failed send()/
    flush() (a receive() failure or the exit command already clean up their
    own session immediately, since that's the one being processed right
    there - this only catches a write failure discovered asynchronously,
    e.g. via the writable-set flush())."""
    for stale_socket, stale_session in list(cli_sessions.items()):
        if not stale_session.socket:
            log_event(logging.INFO, 'LINK', 'CLIDOWN', "CLI session %r disconnected", stale_session)
            del cli_sessions[stale_socket]
            rlist.remove(stale_socket)


def main():
    parser = setup_argparse()
    options = parser.parse_args()

    logging.basicConfig(level=getattr(logging, options.log_level), format='%(asctime)s %(message)s')

    server = Server(port=options.port)
    if options.tap_device:
        tap = TAP(device=options.tap_device)
    else:
        tap = None
    cli_server = CLIServer(_cli_socket_path())
    mirror = Mirror(_mirror_fifo_path())

    clients = {}
    cli_sessions = {}
    mac_table = {}
    rlist = [server.socket, cli_server.socket]
    if tap:
        rlist.append(tap.socket)

    queued_frames = deque()
    next_age_check = 0.0

    try:
        log_event(logging.INFO, 'SYS', 'START', "Awaiting connections and packets")
        while True:
            wlist = [sock for sock, client in clients.items() if client.wants_write()]
            wlist.extend(sock for sock, session in cli_sessions.items() if session.wants_write())
            if tap and tap.wants_write():
                wlist.append(tap.socket)
            (ready, writable, _) = select(rlist, wlist, [], SELECT_TIMEOUT)

            now = time.monotonic()
            if now >= next_age_check:
                age_mac_table(mac_table)
                next_age_check = now + AGE_CHECK_INTERVAL
            mirror.tick()  # self-throttled; needed even when no frame arrives
                           # to notice (see Mirror.tick()) a capture reader
                           # that has gone away and been replaced by a new one

            for sock in writable:
                if tap and sock == tap.socket:
                    tap.flush()
                elif sock in cli_sessions:
                    cli_sessions[sock].flush()
                else:
                    clients[sock].flush()
            _drop_dead_clients(clients, rlist, mac_table)
            _drop_dead_cli_sessions(cli_sessions, rlist)

            for socket in ready:
                if tap and socket == tap.socket:
                    frames = tap.receive()
                    if frames:
                        for frame in frames:
                            if learn_source(mac_table, tap, tap, frame.src_mac, options.tap_mac_age) == 'ok':
                                queued_frames.append((tap, frame))


                elif socket == server.socket:
                    client = server.receive()
                    if client:
                        log_event(logging.INFO, 'LINK', 'CLIENTUP', "Client %r connected", client)
                        clients[client.socket] = client
                        rlist.append(client.socket)

                elif socket == cli_server.socket:
                    session = cli_server.receive()
                    if session:
                        log_event(logging.INFO, 'LINK', 'CLIUP', "CLI session %r connected", session)
                        cli_sessions[session.socket] = session
                        rlist.append(session.socket)
                        session.send("% ")

                elif socket in cli_sessions:
                    session = cli_sessions[socket]
                    lines = session.receive_lines()
                    if lines is None:
                        log_event(logging.INFO, 'LINK', 'CLIDOWN', "CLI session %r disconnected", session)
                        del cli_sessions[socket]
                        rlist.remove(socket)
                    else:
                        for line in lines:
                            if not line:
                                session.send("% ")
                                continue
                            try:
                                result = resolve_cli_command(line.split())
                                if isinstance(result, str):
                                    session.send(result + "\n% ")
                                    continue
                                handler, arg = result
                                output = handler(arg, clients, tap, mac_table, rlist)
                            except Exception as exc:
                                # A bug in a CLI handler must never take the
                                # switch down with it - same discipline as
                                # the transmit() guards elsewhere.
                                log_event(logging.ERROR, 'SYS', 'CLIERROR',
                                          "CLI command %r raised %s: %s",
                                          line, type(exc).__name__, exc)
                                session.send("% Internal error processing command\n% ")
                                continue
                            if output is None:
                                log_event(logging.INFO, 'LINK', 'CLIDOWN',
                                          "CLI session %r disconnected", session)
                                if session.socket:
                                    session.socket.close()
                                    session.socket = None
                                del cli_sessions[socket]
                                rlist.remove(socket)
                                break
                            session.send(output + "\n% ")

                elif socket in clients:
                    client = clients[socket]
                    frames = client.receive()
                    if frames is None:
                        # They disconnected, remove from our list
                        log_event(logging.INFO, 'LINK', 'CLIENTDOWN', "Client %r disconnected", client)
                        purge_mac_table_for_port(mac_table, client)
                        del clients[socket]
                        rlist.remove(socket)
                    else:
                        for frame in frames:
                            status = learn_source(mac_table, client, tap, frame.src_mac, options.tap_mac_age)
                            if status == 'conflict':
                                log_event(logging.WARNING, 'PORTSEC', 'KICK',
                                          "Disconnected client %r (duplicate MAC)", client)
                                client.socket.close()
                                client.socket = None
                                purge_mac_table_for_port(mac_table, client)
                                del clients[socket]
                                rlist.remove(socket)
                                break
                            elif status == 'ok':
                                queued_frames.append((client, frame))

                # A send() above (new-session prompt, command output) may
                # have discovered a dead console peer; drop it the same way
                # a failed receive() would.
                _drop_dead_cli_sessions(cli_sessions, rlist)

                # Let's try sending the frames to all the clients
                if queued_frames:
                    ports = list(clients.values())
                    if tap:
                        ports.append(tap)

                    while queued_frames:
                        (receiver_port, frame) = queued_frames.popleft()
                        log_event(logging.DEBUG, 'FRAME', 'DISTRIB', "type &%04x (%i bytes) from %r",
                                  frame.frame_type, len(frame.data), receiver_port)
                        mirror.record(frame)
                        for port in resolve_targets(mac_table, frame.dst_mac, ports, receiver_port):
                            log_event(logging.DEBUG, 'FRAME', 'TX', "to port %r", port)
                            port.transmit(frame)

                    # A transmit() above may have discovered a dead client;
                    # drop it the same way a failed receive() would.
                    _drop_dead_clients(clients, rlist, mac_table)

    except KeyboardInterrupt:
        log_event(logging.INFO, 'SYS', 'SHUTDOWN', "Switch terminated.")
    finally:
        cli_server.close()
        mirror.close()
