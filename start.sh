#!/bin/bash

sudo iptables -I INPUT -p udp --sport 53 -j NFLOG --nflog-group 123
sudo ip6tables -I INPUT -p udp --sport 53 -j NFLOG --nflog-group 123
