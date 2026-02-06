#!/usr/bin/env python3

# Copyright Antti Kultanen <antti.kultanen@molukki.com>
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

import socket
import sys

if len(sys.argv) != 4:
    print(f"Usage: {sys.argv[0]} <DEST_IP> <DEST_PORT> <PACKET_TYPE>")
    sys.exit(1)

DEST_IP = sys.argv[1]
try:
    DEST_PORT = int(sys.argv[2])
except ValueError:
    print("Error: DEST_PORT must be an integer.")
    sys.exit(1)
PACKET_TYPE = sys.argv[3].upper()

if PACKET_TYPE == 'A':
    # example.com A 127.0.0.1
    packet = bytes.fromhex(
        '123481800001000100000000076578616d706c6503636f6d0000010001'
        'c00c000100010000003c00047f000001'
    )
elif PACKET_TYPE == 'AAAA':
    # example.com AAAA to ::1
    packet = bytes.fromhex(
        '123481800001000100000000076578616d706c6503636f6d00001c0001'
        'c00c001c00010000003c001000000000000000000000000000000001'
    )
elif PACKET_TYPE == 'CNAME':
    # www.example.com CNAME _
    packet = bytes.fromhex(
        '12348180000100010000000003777777076578616d706c6503636f6d0000050001'
        'c00c000500010000003c0002c010'
    )
elif PACKET_TYPE == 'MX':
    # example.com MX 10 mail.example.com
    packet = bytes.fromhex(
        '123481800001000100000000076578616d706c6503636f6d00000f0001'
        'c00c000f00010000003c0010000a046d61696c076578616d706c6503636f6d00'
    )
elif PACKET_TYPE == 'PTR':
    packet = bytes.fromhex(
        '1234818000010001000000000131013001300331323707696e2d61646472046172706100'
        '000c0001c00c000c00010000003c000d076578616d706c6503636f6d00'
    )
else:
    print(f"Error: PACKET_TYPE must be either 'A', 'AAAA', 'CNAME' or 'PTR', got '{PACKET_TYPE}'")
    sys.exit(1)

# Create UDP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind to source port 53 (requires root)
s.bind((DEST_IP, 53))

# Send the packet
s.sendto(packet, (DEST_IP, DEST_PORT))
