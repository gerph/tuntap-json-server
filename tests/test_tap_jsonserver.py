import base64
import json
import os
import select
import socket
import subprocess
import sys
import time
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, "tap_jsonserver.py")


class ServerTestCase(unittest.TestCase):
    """Shared subprocess-server lifecycle helpers for the tests below."""

    def _start_server(self, *extra_args):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        self.clients = []
        self.server = subprocess.Popen(
            [sys.executable, "-u", SERVER, "--port", str(port)] + list(extra_args),
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        return port

    def tearDown(self):
        for client in self.clients:
            client.close()
        self._stop_server()
        # The server always creates this next to the script; a graceful
        # shutdown (SIGINT) removes it, but tearDown here uses terminate()
        # (SIGTERM), which the server doesn't specially handle, so clean up
        # explicitly rather than leaving a stale socket file behind.
        console_path = os.path.join(ROOT, "console0")
        if os.path.exists(console_path):
            os.unlink(console_path)

    def _connect(self, port):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                client = socket.create_connection(("127.0.0.1", port), timeout=1)
                client.settimeout(2)
                return client
            except OSError:
                if self.server.poll() is not None:
                    break
                time.sleep(0.05)

        self.fail("JSON server did not accept connections")

    def _wait_for_connections(self, expected):
        deadline = time.monotonic() + 5
        output = b""

        while output.count(b"CLIENTUP") < expected and time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            ready, _, _ = select.select([self.server.stdout], [], [], remaining)
            if not ready:
                break

            data = os.read(self.server.stdout.fileno(), 4096)
            if not data:
                break
            output += data

        if output.count(b"CLIENTUP") != expected:
            decoded = output.decode("utf-8", errors="replace")
            self.fail("Server did not register all clients:\n{}".format(decoded))

    def _stop_server(self):
        if self.server.poll() is None:
            self.server.terminate()
            try:
                self.server.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=2)
        if self.server.stdout:
            self.server.stdout.close()


class JsonServerTest(ServerTestCase):
    def setUp(self):
        port = self._start_server()
        try:
            for _ in range(2):
                self.clients.append(self._connect(port))
            self._wait_for_connections(2)
        except Exception:
            for client in self.clients:
                client.close()
            self._stop_server()
            raise

    def test_forwards_a_json_frame_to_another_client(self):
        frame = {
            "frame_type": 0x0800,
            "src": [2, 0, 0, 0, 0, 1],
            "dst": [2, 0, 0, 0, 0, 2],
            "data": "SGVsbG8sIFJJU0MgT1Mh",
        }
        encoded = (json.dumps(frame) + "\n").encode("utf-8")

        self.clients[0].sendall(encoded)

        received = b""
        while b"\n" not in received:
            chunk = self.clients[1].recv(4096)
            self.assertTrue(chunk, "Server closed the receiving connection")
            received += chunk
        forwarded = json.loads(received.split(b"\n", 1)[0].decode("utf-8"))
        self.assertEqual(forwarded, frame)


class SwitchingTest(ServerTestCase):
    """MAC-learning switch behaviour: known-unicast is delivered only to its
    owning port, and a duplicate source MAC from a second client gets that
    second (not the original) client disconnected."""

    def setUp(self):
        port = self._start_server()
        try:
            for _ in range(3):
                self.clients.append(self._connect(port))
            self._wait_for_connections(3)
        except Exception:
            for client in self.clients:
                client.close()
            self._stop_server()
            raise

    def _send_frame(self, client, src, dst, payload=b"hello"):
        frame = {
            "frame_type": 0x0800,
            "src": src,
            "dst": dst,
            "data": base64.b64encode(payload).decode("ascii"),
        }
        client.sendall((json.dumps(frame) + "\n").encode("utf-8"))

    def _recv_frame(self, client):
        received = b""
        while b"\n" not in received:
            chunk = client.recv(4096)
            self.assertTrue(chunk, "Server closed the receiving connection")
            received += chunk
        return json.loads(received.split(b"\n", 1)[0].decode("utf-8"))

    def _assert_nothing_received(self, client, timeout=0.5):
        client.settimeout(timeout)
        try:
            data = client.recv(4096)
        except socket.timeout:
            return
        finally:
            client.settimeout(2)
        self.assertEqual(data, b"", "Unexpectedly received data: %r" % (data,))

    def test_known_unicast_is_not_flooded(self):
        client_a, client_b, client_c = self.clients
        mac_a = [2, 0, 0, 0, 0, 0xA]
        mac_b = [2, 0, 0, 0, 0, 0xB]
        broadcast = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

        # A's MAC isn't known yet, so this floods - that also learns it.
        self._send_frame(client_a, mac_a, broadcast)
        self._recv_frame(client_b)
        self._recv_frame(client_c)

        # B sends a unicast frame to A's now-known MAC.
        self._send_frame(client_b, mac_b, mac_a)
        forwarded = self._recv_frame(client_a)
        self.assertEqual(forwarded["src"], mac_b)
        self.assertEqual(forwarded["dst"], mac_a)

        # C is uninvolved and must not have received it.
        self._assert_nothing_received(client_c)

    def test_duplicate_mac_disconnects_the_new_client(self):
        client_a, client_b, client_c = self.clients
        mac = [2, 0, 0, 0, 0, 0xA]
        broadcast = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

        # A claims the MAC first.
        self._send_frame(client_a, mac, broadcast)
        self._recv_frame(client_b)
        self._recv_frame(client_c)

        # B claims the same source MAC - the switch must disconnect B, not A.
        self._send_frame(client_b, mac, broadcast)
        client_b.settimeout(5)
        self.assertEqual(client_b.recv(4096), b"",
                         "Duplicate-MAC client was not disconnected")

        # A must still be usable.
        self._send_frame(client_a, mac, broadcast)
        forwarded = self._recv_frame(client_c)
        self.assertEqual(forwarded["src"], mac)


class BufferingLimitTest(ServerTestCase):
    """A client which never sends a newline must be dropped, not allowed to
    buffer unbounded memory."""

    def setUp(self):
        port = self._start_server()
        try:
            self.clients.append(self._connect(port))
            self._wait_for_connections(1)
        except Exception:
            for client in self.clients:
                client.close()
            self._stop_server()
            raise

    def test_client_with_no_newline_is_dropped_once_over_the_limit(self):
        client = self.clients[0]
        junk = b"A" * 65536  # comfortably over Client.max_pending (1MB) after a few sends

        dropped = False
        try:
            for _ in range(64):  # 4MB total
                client.sendall(junk)
        except OSError:
            dropped = True

        if not dropped:
            client.settimeout(5)
            # A close() while unread data is still queued can surface as a
            # clean EOF or as a reset, depending on how much the server had
            # drained before hitting the cap - both mean "the server dropped
            # us", which is what this test is actually checking for.
            try:
                self.assertEqual(client.recv(4096), b"",
                                 "Server went on buffering a line which never ends")
            except ConnectionResetError:
                pass

        self.assertIsNone(self.server.poll(), "Server process died")


class CLITest(ServerTestCase):
    """The console CLI reachable over the fixed console0 Unix domain socket
    next to the script: show/clear commands and partial-match input."""

    def setUp(self):
        port = self._start_server()
        try:
            for _ in range(2):
                self.clients.append(self._connect(port))
            self._wait_for_connections(2)
            self.cli = self._connect_cli()
        except Exception:
            for client in self.clients:
                client.close()
            self._stop_server()
            raise

    def tearDown(self):
        if getattr(self, 'cli', None):
            self.cli.close()
        super().tearDown()

    def _connect_cli(self):
        path = os.path.join(ROOT, "console0")
        deadline = time.monotonic() + 5
        cli = None
        while time.monotonic() < deadline:
            try:
                cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                cli.connect(path)
                break
            except OSError:
                cli.close()
                cli = None
                if self.server.poll() is not None:
                    break
                time.sleep(0.05)
        if cli is None:
            self.fail("CLI console socket did not accept connections")
        cli.settimeout(2)
        initial = cli.recv(65536)
        self.assertEqual(initial, b"% ", "Unexpected initial CLI prompt: %r" % (initial,))
        return cli

    def _send_frame(self, client, src, dst, payload=b"hello"):
        frame = {
            "frame_type": 0x0800,
            "src": src,
            "dst": dst,
            "data": base64.b64encode(payload).decode("ascii"),
        }
        client.sendall((json.dumps(frame) + "\n").encode("utf-8"))

    def _cli_command(self, command):
        self.cli.sendall((command + "\n").encode("utf-8"))
        received = b""
        deadline = time.monotonic() + 5
        while not received.endswith(b"% ") and time.monotonic() < deadline:
            chunk = self.cli.recv(65536)
            self.assertTrue(chunk, "CLI closed the connection unexpectedly")
            received += chunk
        self.assertTrue(received.endswith(b"% "), "No prompt received for: %r" % (command,))
        return received[:-len(b"% ")].rstrip(b"\n").decode("utf-8", errors="replace")

    def _parse_table(self, output):
        lines = output.strip("\n").split("\n")
        return [row.split() for row in lines[1:] if row not in ("(none)", "(empty)")]

    def test_show_interfaces_lists_connected_clients(self):
        output = self._cli_command("show interfaces status")
        for client in self.clients:
            self.assertIn(str(client.getsockname()[1]), output)

    def test_mac_address_table_matches_interface_port(self):
        mac = [2, 0, 0, 0, 0, 0xA]
        self._send_frame(self.clients[0], mac, [0xFF] * 6)
        self.clients[1].recv(4096)  # drain the flood

        int_rows = self._parse_table(self._cli_command("show interfaces status"))
        peer_port = str(self.clients[0].getsockname()[1])
        matching = [row for row in int_rows if peer_port in row[-1]]
        self.assertEqual(len(matching), 1)
        expected_port = matching[0][0]

        mac_rows = self._parse_table(self._cli_command("show mac address-table"))
        self.assertEqual(len(mac_rows), 1)
        self.assertEqual(mac_rows[0][0], "02:00:00:00:00:0a")
        self.assertEqual(mac_rows[0][2], expected_port)

    def test_clear_mac_address_table_does_not_disconnect_clients(self):
        mac = [2, 0, 0, 0, 0, 0xA]
        self._send_frame(self.clients[0], mac, [0xFF] * 6)
        self.clients[1].recv(4096)  # drain the flood

        self.assertIn("02:00:00:00:00:0a", self._cli_command("show mac address-table"))
        self.assertIn("Cleared", self._cli_command("clear mac address-table"))
        self.assertIn("(empty)", self._cli_command("show mac address-table"))

        # Both clients must still be connected and able to exchange a frame.
        self._send_frame(self.clients[0], mac, [0xFF] * 6)
        received = b""
        while b"\n" not in received:
            chunk = self.clients[1].recv(4096)
            self.assertTrue(chunk, "Client was disconnected by clear mac address-table")
            received += chunk

    def test_clear_interface_disconnects_only_that_client(self):
        int_rows = self._parse_table(self._cli_command("show interfaces status"))
        peer_port = str(self.clients[0].getsockname()[1])
        target_port = next(row[0] for row in int_rows if peer_port in row[-1])

        self.assertIn("Cleared interface", self._cli_command("clear interface %s" % (target_port,)))

        self.clients[0].settimeout(2)
        self.assertEqual(self.clients[0].recv(4096), b"", "Target client was not disconnected")

        self.clients[1].settimeout(0.3)
        with self.assertRaises(socket.timeout):
            self.clients[1].recv(4096)
        self.assertIsNone(self.server.poll())

    def test_clear_interface_unknown_port_errors_without_disconnecting_anyone(self):
        self.assertIn("No such interface", self._cli_command("clear interface 999999"))
        for client in self.clients:
            client.settimeout(0.3)
            with self.assertRaises(socket.timeout):
                client.recv(4096)
            client.settimeout(2)

    def test_logging_level_can_be_changed_and_read_back(self):
        self.assertIn("DEBUG", self._cli_command("logging level debug"))
        self.assertIn("DEBUG", self._cli_command("show logging"))

    def test_partial_match_resolves_same_as_full_command(self):
        full = self._cli_command("show interfaces status")
        abbreviated = self._cli_command("sh int")
        self.assertEqual(full, abbreviated)

    def test_unknown_and_ambiguous_commands_keep_session_open(self):
        self.assertIn("Unknown command", self._cli_command("bogus"))
        self.assertIn("Ambiguous", self._cli_command("show"))
        self.assertIn("Port", self._cli_command("show interfaces status"))

    def test_exit_closes_the_session(self):
        self.cli.sendall(b"exit\n")
        self.cli.settimeout(2)
        self.assertEqual(self.cli.recv(4096), b"")
        self.assertIsNone(self.server.poll())


if __name__ == "__main__":
    unittest.main()
