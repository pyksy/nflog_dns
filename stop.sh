#!/bin/bash

# Written by Antti Kultanen <antti.kultanen@molukki.com> since August 2025
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

if [[ "${EUID}" -ne 0 ]]; then
        echo "This script must be run as root" >&2
        exit 1
fi

iptables -D INPUT -p udp --sport 53 -j NFLOG --nflog-group 123
ip6tables -D INPUT -p udp --sport 53 -j NFLOG --nflog-group 123
