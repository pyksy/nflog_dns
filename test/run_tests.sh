#!/bin/bash

# Copyright Antti Kultanen <antti.kultanen@molukki.com>
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

if [[ "${EUID}" -ne 0 ]]; then
	echo "This script must be run as root" >&2
	exit 1
fi

IP="172.31.53.123"
DIR="$(dirname $(realpath "${0}"))"
declare -a PACKET_TYPES=(
	a
	aaaa
	cname
	ptr
)

fail_count=0

cleanup() {
    echo -n "Clean up ... "
    # Kill nflog_dns if running
    if [ -n "$NFLOGPID" ]; then
        kill -HUP "$NFLOGPID" 2>/dev/null
        wait "$NFLOGPID" 2>/dev/null
    fi
    rm -f "${NFLOGTEMP}" 2>/dev/null
	echo "done"

	echo -n "Tear down iptables ... "
    iptables -D INPUT -t filter -p udp -d "${IP}" --sport 53 -j nflog_dns_logger 2>/dev/null
    iptables -F nflog_dns_logger 2>/dev/null
    iptables -X nflog_dns_logger 2>/dev/null
	echo "done"

	echo -n "Tear down dummy interface ... "
    ip link set down dev nflog0 2>/dev/null
    ip addr del "${IP}"/32 dev nflog0 2>/dev/null
    ip link del nflog0 2>/dev/null
	echo "done"
}

trap cleanup EXIT INT TERM

send_packets() {
	for TYPE in "${PACKET_TYPES[@]}"
	do
		echo -n "Start UDP receiver ... "
		exec 3< <(python3 "${DIR}/py/test_recv.py" "${IP}")
		LISTENPID="${!}"
		read LISTENPORT <&3
		echo "PID ${LISTENPID} UDP port ${LISTENPORT}"

		echo -n "Send ${TYPE^^} reply packet to listener ... "
		python3 "${DIR}/py/test_send.py" "${IP}" "${LISTENPORT}" $TYPE
		echo "done"
	done
}

verify_packets() {
	for TYPE in "${PACKET_TYPES[@]}"
	do
		echo -n "Verify ${TYPE^^} reply was logged ... "
		LOGSTRING="$(grep "${IP} reply ${TYPE^^} .*example\.com" "${NFLOGTEMP}")"
		if [ -n "${LOGSTRING}" ]
		then
			echo "SUCCESS"
		else
			echo "FAIL"
			((fail_count++))
		fi
	done
}

# Clean up iptables just in case
iptables -D INPUT -t filter -p udp -d "${IP}" --sport 53 -j nflog_dns_logger 2>/dev/null
iptables -F nflog_dns_logger 2>/dev/null
iptables -X nflog_dns_logger 2>/dev/null
ip link del nflog0 2>/dev/null

echo -n "Setup dummy interface nflog0 ... "
ip link add nflog0 type dummy
ip addr add "${IP}"/32 dev nflog0
ip link set up dev nflog0
echo "done"

echo -n "Setup iptables NFLOG target ... "
iptables -N nflog_dns_logger
iptables -A nflog_dns_logger -j NFLOG --nflog-group 123
iptables -I INPUT 1 -t filter -p udp -d "${IP}" --sport 53 -j nflog_dns_logger
echo "done"

echo -n "Start nflog_dns ... "
NFLOGTEMP="$(mktemp "/tmp/nflog_XXXXXXXX.temp")"
"${DIR}/../nflog_dns" >"${NFLOGTEMP}" &
NFLOGPID="${!}"
echo "PID ${NFLOGPID}"

send_packets
sleep 2
cat "${NFLOGTEMP}"

echo -n "Stop nflog_dns ... "
kill -HUP "${NFLOGPID}"
echo "done"
sleep 1

verify_packets
rm -f "${NFLOGTEMP}"

((fail_count > 0)) && exit 1 || echo

ARGS=""
NFLOGTEMP="$(mktemp "/tmp/nflog_XXXXXXXX.temp")"
for TYPE in "${PACKET_TYPES[@]}"
do
	ARGS="--${TYPE}=no ${ARGS}"
done
echo -n "Start nflog_dns ${ARGS} ... "
"${DIR}/../nflog_dns" $ARGS >"${NFLOGTEMP}" &
NFLOGPID="${!}"
echo "PID ${NFLOGPID}"

send_packets
sleep 2
cat "${NFLOGTEMP}"

echo -n "Stop nflog_dns ... "
kill -HUP "${NFLOGPID}"
echo "done"
sleep 1

echo "NOTE: Following tests are expected to fail:"
verify_packets
rm -f "${NFLOGTEMP}"

((fail_count == ${#PACKET_TYPES[@]})) || exit 1

echo
