#!/bin/bash

# Written by Andreas Jaggi <andreas.jaggi@waterwave.ch> in December 2015
# Written by Antti Kultanen <antti.kultanen@molukki.com>
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file


if [[ "${EUID}" -ne 0 ]]; then
        echo "This script must be run as root" >&2
        exit 1
fi

iptables -I INPUT -p udp --sport 53 -j NFLOG --nflog-group 123
ip6tables -I INPUT -p udp --sport 53 -j NFLOG --nflog-group 123
