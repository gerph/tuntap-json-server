#!/usr/bin/env python3
"""
Network switch to allow network systems to communicate.

See README.md for the full description of the switch's behaviour (MAC
learning, port security, CLI console, packet capture) and TAP setup
instructions.


Transmission format
-------------------
The on-wire format for a frame is a line containing JSON-encoded data.
Each line should be a map containing the following fields:

    'frame_type':   The frame type, as an integer
    'src':          Source MAC address as a list of 6 integers.
    'dst':          Destination MAC address as a list of 6 integers.
    'data':         Data as base 64 encoded bytes.

Frames which are not recognised will be dropped.
"""

import sys

from switchlib.app import main


if __name__ == '__main__':
    sys.exit(main())
