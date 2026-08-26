"""MAC-learning and forwarding: the mac_table (MAC -> (owner_port, expiry))
and the functions that learn from and make forwarding decisions against it."""

import logging
import time

from .logutil import log_event


def format_mac(mac_tuple):
    """Render a MAC (tuple/list of 6 ints) as 'aa:bb:cc:dd:ee:ff' for logging."""
    return ':'.join('%02x' % (b,) for b in mac_tuple)


def purge_mac_table_for_port(mac_table, port):
    """Remove every mac_table entry owned by `port`. Called when a Client is torn down."""
    stale = [key for key, (owner, _expiry) in mac_table.items() if owner is port]
    for key in stale:
        del mac_table[key]


def age_mac_table(mac_table):
    """Expire TAP-owned entries whose aging deadline has passed. Client-owned
    entries have expiry None and are never touched here."""
    now = time.monotonic()
    expired = [key for key, (_owner, expiry) in mac_table.items()
               if expiry is not None and expiry <= now]
    for key in expired:
        log_event(logging.INFO, 'MAC', 'AGEOUT', "MAC %s aged out (TAP entry expired)", format_mac(key))
        del mac_table[key]


def learn_source(mac_table, sender_port, tap, src_mac, tap_mac_age):
    """
    Learn/refresh mac_table[tuple(src_mac)] for a frame arriving on sender_port
    (a Client instance, or the TAP instance).

    Returns:
      'ok'       - learned/refreshed; caller should queue the frame.
      'drop'     - frame must be dropped, no state changed. Covers a client-
                   or TAP-owned MAC being claimed from the other side of that
                   boundary - client<->TAP mismatches are always rejected, not
                   relearned.
      'conflict' - a second, different client claimed a MAC already owned by
                   another client; caller must drop the frame AND disconnect
                   sender_port (the new/duplicate client) - this is the only
                   case ownership can move without a prior disconnect or
                   aging expiry.
    """
    key = tuple(src_mac)
    is_tap_sender = sender_port is tap
    entry = mac_table.get(key)

    if entry is None:
        expiry = time.monotonic() + tap_mac_age if is_tap_sender else None
        mac_table[key] = (sender_port, expiry)
        return 'ok'

    owner, _expiry = entry

    if owner is sender_port:
        if is_tap_sender:
            mac_table[key] = (owner, time.monotonic() + tap_mac_age)
        return 'ok'

    owner_is_tap = owner is tap

    if owner_is_tap or is_tap_sender:
        # A client<->TAP mismatch in either direction: never let the new
        # sender pre-empt the existing owner. The entry only changes once
        # it ages out (TAP-owned) or the owning client disconnects.
        log_event(logging.WARNING, 'PORTSEC', 'BOUNDARY',
                  "MAC %s owned by %r, also seen from %r", format_mac(key), owner, sender_port)
        return 'drop'

    # Both owner and sender are (different) clients - real port-security conflict.
    log_event(logging.WARNING, 'PORTSEC', 'MACCONFLICT',
              "MAC %s already owned by client %r, also claimed by %r", format_mac(key), owner, sender_port)
    return 'conflict'


def resolve_targets(mac_table, dst_mac, ports, sender_port):
    """Return the ports a frame with this dst_mac should be sent to (never
    including sender_port)."""
    if dst_mac[0] & 0x01:
        # I/G bit set: broadcast or multicast - flood to everyone but the sender.
        return [port for port in ports if port is not sender_port]

    owner, _expiry = mac_table.get(tuple(dst_mac), (None, None))
    if owner is None:
        return [port for port in ports if port is not sender_port]  # unknown unicast
    if owner is sender_port:
        return []  # never reflect to sender
    return [owner]
