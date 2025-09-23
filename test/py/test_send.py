#!/usr/bin/env python3

import socket
import sys

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <DEST_IP> <DEST_PORT>")
    sys.exit(1)

DEST_IP = sys.argv[1]
try:
    DEST_PORT = int(sys.argv[2])
except ValueError:
    print("Error: DEST_PORT must be an integer.")
    sys.exit(1)

# DNS reply packet: example.com resolves to 127.0.0.1
packet = bytes.fromhex(
    '123481800001000100000000076578616d706c6503636f6d0000010001'
    'c00c000100010000003c00047f000001'
)

# Create UDP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind to source port 53 (requires root)
s.bind(('', 53))

# Send the packet
s.sendto(packet, (DEST_IP, DEST_PORT))
