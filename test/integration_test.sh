#!/bin/bash

# Copyright Antti Kultanen <antti.kultanen@molukki.com>
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

set -e

if [[ "${EUID}" -ne 0 ]]; then
        echo "This script must be run as root" >&2
        exit 1
fi

DIR="$(dirname $(realpath "${0}"))"
cd "${DIR}"

echo "TEST: optarg_test.sh"
bash optarg_test.sh
echo
echo "TEST: endtoend_test.sh ipv4"
bash endtoend_test.sh ipv4
echo
echo "TEST: endtoend_test.sh ipv6"
bash endtoend_test.sh ipv6

