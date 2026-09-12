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
elif PACKET_TYPE == 'NS':
    # example.com NS ns1.example.com
    packet = bytes.fromhex(
        '123481800001000100000000076578616d706c6503636f6d0000010001'
        'c00c000200010000003c0006036e7331c00c'
    )
elif PACKET_TYPE == 'SOA':
    # example.com SOA ns1.example.com hostmaster.example.com (1 3600 1800 604800 60)
    packet = bytes.fromhex(
        '123481800001000100000000076578616d706c6503636f6d0000010001'
        'c00c000600010000003c0027036e7331c00c0a686f73746d6173746572'
        'c00c0000000100000e100000070800093a800000003c'
    )
elif PACKET_TYPE == 'SRV':
    # _sip._tcp.example.com SRV 10 20 5060 sip.example.com
    packet = bytes.fromhex(
        '123481800001000100000000076578616d706c6503636f6d0000010001'
        '045f736970045f746370c00c002100010000003c000c000a001413c403'
        '736970c00c'
    )
elif PACKET_TYPE == 'DNSKEY':
    # example.com DNSKEY flags=256 protocol=3 algorithm=8 (4-byte fake pubkey)
    packet = bytes.fromhex(
        '123481800001000100000000076578616d706c6503636f6d0000010001'
        'c00c003000010000003c000801000308aabbccdd'
    )
elif PACKET_TYPE == 'NSEC3PARAM':
    # example.com NSEC3PARAM algorithm=1 flags=0 iterations=10 salt=1234
    packet = bytes.fromhex(
        '123481800001000100000000076578616d706c6503636f6d0000010001'
        'c00c003300010000003c00070100000a021234'
    )
elif PACKET_TYPE == 'NSAP-PTR':
    # example.com NSAP-PTR ptr.example.com
    packet = bytes.fromhex(
        '123481800001000100000000076578616d706c6503636f6d0000010001'
        'c00c001700010000003c000603707472c00c'
    )
elif PACKET_TYPE == 'CERT':
    # example.com CERT type=PKIX(1) key_tag=12345 algorithm=8 (4-byte fake cert)
    packet = bytes.fromhex(
        '123481800001000100000000076578616d706c6503636f6d0000010001'
        'c00c002500010000003c0009000130390801020304'
    )
elif PACKET_TYPE == 'DNAME':
    # example.com DNAME example.net
    packet = bytes.fromhex(
        '123481800001000100000000076578616d706c6503636f6d0000010001'
        'c00c002700010000003c000d076578616d706c65036e657400'
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
elif PACKET_TYPE == 'NOTIMP':
    # example.com A query -> NOTIMP (RCODE=4)
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
elif PACKET_TYPE == 'YXDOMAIN':
    # example.com A query -> YXDOMAIN (RCODE=6)
    packet = bytes.fromhex(
        '123481860001000000000000076578616d706c6503636f6d0000010001'
    )
elif PACKET_TYPE == 'YXRRSET':
    # example.com A query -> YXRRSET (RCODE=7)
    packet = bytes.fromhex(
        '123481870001000000000000076578616d706c6503636f6d0000010001'
    )
elif PACKET_TYPE == 'NXRRSET':
    # example.com A query -> NXRRSET (RCODE=8)
    packet = bytes.fromhex(
        '123481880001000000000000076578616d706c6503636f6d0000010001'
    )
elif PACKET_TYPE == 'NOTAUTH':
    # example.com A query -> NOTAUTH (RCODE=9)
    packet = bytes.fromhex(
        '123481890001000000000000076578616d706c6503636f6d0000010001'
    )
elif PACKET_TYPE == 'NOTZONE':
    # example.com A query -> NOTZONE (RCODE=10)
    packet = bytes.fromhex(
        '1234818a0001000000000000076578616d706c6503636f6d0000010001'
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
    print(f"a reply: 'A', 'AAAA', 'CNAME', 'MX', 'PTR', 'TXT', 'NS', 'SOA',")
    print(f"         'SRV', 'DNSKEY', 'NSEC3PARAM', 'NSAP-PTR', 'CERT', 'DNAME';")
    print(f"an error: 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED',")
    print(f"          'YXDOMAIN', 'YXRRSET', 'NXRRSET', 'NOTAUTH', 'NOTZONE';")
    print(f"invalid: 'EMPTYPACKET', 'BADIP', 'MALFORMED', 'NOQUESTION', 'QUERY'.")
    sys.exit(1)

# Create UDP socket
s = socket.socket(family, socket.SOCK_DGRAM)

# Bind to source port 53 (requires root)
s.bind((DEST_IP, 53))

# Send the packet
s.sendto(packet, (DEST_IP, DEST_PORT))
