"""The CLI console: a Unix domain socket line-based session (CLIServer/
CLISession), its Cisco-style commands, and the partial-match resolver."""

import logging
import os
import socket
import stat
import time

from .logutil import log_event
from .switching import format_mac, purge_mac_table_for_port


class CLIServer(object):
    """Listens on a Unix domain socket for the CLI console."""

    def __init__(self, path):
        self.path = path
        try:
            # Only remove it if it's actually a socket - a stale one from an
            # unclean shutdown. Anything else (e.g. a symlink planted by
            # another local user) is left alone rather than unlinked.
            if stat.S_ISSOCK(os.lstat(path).st_mode):
                os.unlink(path)
        except FileNotFoundError:
            pass
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(path)
        os.chmod(path, 0o600)  # CLI has no auth of its own - restrict to the owner
        self.socket.listen(5)

    def receive(self):
        try:
            (conn, _) = self.socket.accept()
            # Non-blocking so a stalled console peer can never block the
            # main select() loop - same discipline as Client, see
            # Client.flush().
            conn.setblocking(False)
            return CLISession(conn)
        except Exception as exc:
            log_event(logging.WARNING, 'SYS', 'CLIACCEPTFAIL', "CLI accept() failed: %s", exc)
        return None

    def close(self):
        self.socket.close()
        if os.path.exists(self.path):
            os.unlink(self.path)


class CLISession(object):
    """A connected CLI console client - plain line-buffered text, not the
    JSON frame protocol used by Client."""
    read_size = 4096
    max_pending = 64 * 1024  # a command line is short; this is just a safety cap
    max_write_pending = 1024 * 1024  # bytes queued for a slow/stalled console before we give up

    def __init__(self, sock):
        self.socket = sock
        self.buffer = b''
        self.write_buffer = bytearray()

    def __repr__(self):
        return "<CLISession(fd=%s)>" % (self.socket.fileno() if self.socket else 'closed',)

    def receive_lines(self):
        """Return a list of decoded command lines, or None if disconnected."""
        if not self.socket:
            return None
        try:
            data = self.socket.recv(self.read_size)
        except OSError:
            data = b''
        if not data:
            self.socket.close()
            self.socket = None
            return None

        self.buffer += data
        lines = []
        while b'\n' in self.buffer:
            (line, self.buffer) = self.buffer.split(b'\n', 1)
            lines.append(line.decode('utf-8', errors='replace').strip())
        if len(self.buffer) > self.max_pending:
            log_event(logging.WARNING, 'SYS', 'CLIOVERFLOW',
                      "Dropping %r: command line too long", self)
            self.socket.close()
            self.socket = None
            return None
        return lines

    def wants_write(self):
        """Whether the main loop should watch this session for writability."""
        return bool(self.socket) and bool(self.write_buffer)

    def send(self, text):
        if not self.socket:
            return
        self.write_buffer += text.encode('utf-8')
        self.flush()

    def flush(self):
        """Send as much of the buffered output as the socket will accept
        right now, without blocking. The main loop calls this again once
        select() reports the socket writable, to drain the rest - same
        discipline as Client.flush()."""
        if not self.socket or not self.write_buffer:
            return
        try:
            sent = self.socket.send(self.write_buffer)
            del self.write_buffer[:sent]
        except BlockingIOError:
            # Nothing went out, but a peer that never reads at all still
            # needs to hit the overflow check below eventually.
            pass
        except OSError:
            # Same discipline as Client.transmit()/TAP.transmit(): never let
            # a dead peer's write failure escape into the main loop.
            self.socket.close()
            self.socket = None
            return

        if len(self.write_buffer) > self.max_write_pending:
            log_event(logging.WARNING, 'SYS', 'CLIWRITEOVERFLOW',
                      "Dropping %r: %i bytes queued for a slow console (limit %i)",
                      self, len(self.write_buffer), self.max_write_pending)
            self.socket.close()
            self.socket = None


def cli_show_interfaces(arg, clients, tap, mac_table, rlist):
    lines = ["Port  Type    Peer"]
    for client in clients.values():
        if client.socket:
            lines.append("%-5s %-7s %s" % (client.socket.fileno(), "client", client.name))
    if tap:
        lines.append("%-5s %-7s %s" % (tap.socket, "tap", tap.name))
    if not clients and not tap:
        lines.append("(none)")
    return "\n".join(lines)


def cli_show_mac_address_table(arg, clients, tap, mac_table, rlist):
    lines = ["Mac Address         Type    Port    Age"]
    now = time.monotonic()
    for mac, (owner, expiry) in sorted(mac_table.items()):
        kind = "tap" if owner is tap else "client"
        owner_port = owner.socket if kind == "tap" else (owner.socket.fileno() if owner.socket else "-")
        age = "%ds" % (max(0, int(expiry - now)),) if expiry is not None else "-"
        lines.append("%-19s %-7s %-7s %s" % (format_mac(mac), kind, owner_port, age))
    if not mac_table:
        lines.append("(empty)")
    return "\n".join(lines)


def cli_clear_mac_address_table(arg, clients, tap, mac_table, rlist):
    count = len(mac_table)
    mac_table.clear()
    log_event(logging.INFO, 'MAC', 'CLEARED', "MAC address table cleared via CLI (%d entries)", count)
    return "Cleared %d entries" % (count,)


def cli_clear_interface(arg, clients, tap, mac_table, rlist):
    try:
        port = int(arg)
    except ValueError:
        return "%% Invalid interface port: %r" % (arg,)
    for sock, client in list(clients.items()):
        if client.socket and client.socket.fileno() == port:
            log_event(logging.WARNING, 'LINK', 'CLICLEAR', "Client %r disconnected via CLI", client)
            client.socket.close()
            client.socket = None
            purge_mac_table_for_port(mac_table, client)
            del clients[sock]
            rlist.remove(sock)
            return "Cleared interface %d" % (port,)
    return "%% No such interface: port %d" % (port,)


def cli_show_logging(arg, clients, tap, mac_table, rlist):
    return "Current logging level: %s" % (logging.getLevelName(logging.getLogger().level),)


def cli_set_logging_level(arg, clients, tap, mac_table, rlist):
    level_name = arg.upper()
    if level_name not in ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'):
        return "%% Invalid level: %r" % (arg,)
    logging.getLogger().setLevel(getattr(logging, level_name))
    log_event(logging.INFO, 'SYS', 'LOGLEVEL', "Logging level changed to %s via CLI", level_name)
    return "Logging level set to %s" % (level_name,)


def cli_help(arg, clients, tap, mac_table, rlist):
    return "\n".join(' '.join(words) + (" <%s>" % arg_name if arg_name else "")
                     for words, arg_name, _handler in CLI_COMMANDS)


def cli_exit(arg, clients, tap, mac_table, rlist):
    return None


CLI_COMMANDS = [
    (('show', 'interfaces', 'status'), None, cli_show_interfaces),
    (('show', 'mac', 'address-table'), None, cli_show_mac_address_table),
    (('show', 'logging'), None, cli_show_logging),
    (('clear', 'mac', 'address-table'), None, cli_clear_mac_address_table),
    (('clear', 'interface'), 'port', cli_clear_interface),
    (('logging', 'level'), 'level', cli_set_logging_level),
    (('help',), None, cli_help),
    (('?',), None, cli_help),
    (('exit',), None, cli_exit),
]


def resolve_cli_command(tokens):
    """Cisco-style progressive prefix matching over CLI_COMMANDS.
    Returns (handler, arg) on success, or a '%...' error string."""
    candidates = CLI_COMMANDS
    for i, token in enumerate(tokens):
        token = token.lower()
        candidates = [c for c in candidates if len(c[0]) > i and c[0][i].startswith(token)]
        if not candidates:
            return "%% Unknown command: %r" % (token,)
        exact = [c for c in candidates if len(c[0]) == i + 1]
        if len(exact) == 1 and len(candidates) == 1:
            words, arg_name, handler = exact[0]
            remaining = tokens[i + 1:]
            if arg_name and len(remaining) != 1:
                return "%% Command %r requires a <%s> argument" % (' '.join(words), arg_name)
            if not arg_name and remaining:
                return "%% Unknown command: %r" % (' '.join(remaining),)
            return (handler, remaining[0] if arg_name else None)
    if len(candidates) > 1:
        return "% Ambiguous command."
    # Exactly one candidate survived, even though it may have literal words
    # beyond what was typed (e.g. "show mac" for "show mac address-table") -
    # unambiguous, so auto-complete it rather than demanding the rest.
    words, arg_name, handler = candidates[0]
    if arg_name:
        return "%% Command %r requires a <%s> argument" % (' '.join(words), arg_name)
    return (handler, None)
