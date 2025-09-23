#!/bin/bash

if [[ "${EUID}" -ne 0 ]]; then
        echo "This script must be run as root" >&2
        exit 1
fi

iptables -I INPUT -p udp --sport 53 -j NFLOG --nflog-group 123
ip6tables -I INPUT -p udp --sport 53 -j NFLOG --nflog-group 123
