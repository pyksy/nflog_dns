#!/usr/bin/env python3

# Copyright Antti Kultanen <antti.kultanen@molukki.com>
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

import socket
import sys

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <BIND_ADDRESS>")
    sys.exit(1)

BIND_ADDRESS = sys.argv[1]

# Create UDP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind to the given address and port 0 (ephemeral)
s.bind((BIND_ADDRESS, 0))

# Get and print the assigned port
assigned_port = s.getsockname()[1]
print(assigned_port, flush=True)

# Wait to receive a packet (data discarded)
s.recvfrom(4096)
