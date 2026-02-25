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

# Detect address family
try:
    socket.inet_pton(socket.AF_INET6, DEST_IP)
    family = socket.AF_INET6
except socket.error:
    family = socket.AF_INET

# Replies
if PACKET_TYPE == 'A' or PACKET_TYPE == 'NOERROR':
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
    # 1.0.0.127.in-addr.arpa PTR example.com
    packet = bytes.fromhex(
        '1234818000010001000000000131013001300331323707696e2d61646472046172706100'
        '000c0001c00c000c00010000003c000d076578616d706c6503636f6d00'
    )
elif PACKET_TYPE == 'TXT':
    # example.com TXT "Example text"
    packet = bytes.fromhex(
        '123481800001000100000000076578616d706c6503636f6d0000100001'
        'c00c001000010000003c000d0c4578616d706c652074657874'
    )

# Errors
elif PACKET_TYPE == 'FORMERR':
    # example.com A query -> FORMERR (RCODE=1)
    packet = bytes.fromhex(
        '1234818100010000000000000'
        '76578616d706c6503636f6d0000010001'
    )
elif PACKET_TYPE == 'SERVFAIL':
    # example.com A query -> SERVFAIL (RCODE=2)
    packet = bytes.fromhex(
        '1234818200010000000000000'
        '76578616d706c6503636f6d0000010001'
    )
elif PACKET_TYPE == 'NXDOMAIN':
    # example.com A query -> NXDOMAIN (RCODE=3)
    packet = bytes.fromhex(
        '1234818300010000000000000'
        '76578616d706c6503636f6d0000010001'
    )
elif PACKET_TYPE == 'NOTIMPL':
    # example.com A query -> NOTIMP/NOTIMPL (RCODE=4)
    packet = bytes.fromhex(
        '1234818400010000000000000'
        '76578616d706c6503636f6d0000010001'
    )
elif PACKET_TYPE == 'REFUSED':
    # example.com A query -> REFUSED (RCODE=5)
    packet = bytes.fromhex(
        '1234818500010000000000000'
        '76578616d706c6503636f6d0000010001'
    )

# Invalids
elif PACKET_TYPE == 'EMPTYPACKET':
    # Empty payload - triggers first check
    packet = bytes.fromhex('')
elif PACKET_TYPE == 'BADIP':
    # Valid length but unparseable IP header
    packet = bytes.fromhex(
        'ffffffffffffffffffffffffffffffffffffffff'  # 20 bytes of garbage
        '0035303900140000'  # UDP header
        '123481800001000100000000076578616d706c6503636f6d0000010001'
    )
elif PACKET_TYPE == 'MALFORMED':
    # Malformed DNS packet
    # Valid IP/UDP headers but corrupted DNS data (truncated mid-question)
    packet = bytes.fromhex(
        # IPv4 header (20 bytes)
        '4500002800000000401100007f0000017f000001'
        # UDP header (8 bytes)
        '0035303900140000'
        # Malformed DNS: header says 1 question but question section is truncated
        # Header: ID=1234, response, 1 question, 1 answer
        '123481800001000100000000'
        # Truncated question: only "exa" instead of "example.com"
        '036578'
    )
elif PACKET_TYPE == 'NOQUESTION':
    # DNS response with error but no question section
    # Header: response, NXDOMAIN, 0 questions, 0 answers
    packet = bytes.fromhex(
        # IPv4 header (20 bytes)
        '4500002000000000401100007f0000017f000001'
        # UDP header (8 bytes)
        '0035303900240000'
        # DNS header only: ID=1234, response with NXDOMAIN, 0 questions
        '123481830000000000000000'
    )
elif PACKET_TYPE == 'QUERY':
    # Valid packet but DNS QUERY (not RESPONSE)
    packet = bytes.fromhex(
        # IPv4 header (20 bytes)
        '4500003800000000401100007f0000017f000001'
        # UDP header (8 bytes)
        '0035303900240000'
        # DNS query (QR bit = 0)
        '123401000001000000000000076578616d706c6503636f6d0000010001'
    )
else:
    print(f"Error: '{PACKET_TYPE}' is not a valid PACKET_TYPE. It can be")
    print(f"a reply: 'A', 'AAAA', 'CNAME', 'MX', 'PTR', 'TXT';")
    print(f"an error: 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMPL', 'REFUSED';")
    print(f"invalid: 'EMPTYPACKET', 'BADIP', 'MALFORMED', 'NOQUESTION', 'QUERY'.")
    sys.exit(1)

# Create UDP socket
s = socket.socket(family, socket.SOCK_DGRAM)

# Bind to source port 53 (requires root)
s.bind((DEST_IP, 53))

# Send the packet
s.sendto(packet, (DEST_IP, DEST_PORT))
