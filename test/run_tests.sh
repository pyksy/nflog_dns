#!/bin/bash

if [[ "${EUID}" -ne 0 ]]; then
	echo "This script must be run as root" >&2
	exit 1
fi

echo "=== Start ==="

NFLOGIP="172.31.53.123"
DIR="$(dirname $(realpath "${0}"))"

echo -n "Setup dummy interface nflog0 ... "
ip link add nflog0 type dummy
ip addr add "${NFLOGIP}"/32 dev nflog0
ip link set up dev nflog0
echo "done"
ip addr show dev nflog0
echo

echo -n "Start UDP receiver ... "
exec 3< <(python3 "${DIR}/py/test_recv.py" "${NFLOGIP}")
LISTENPID="${!}"
read LISTENPORT <&3
echo "PID ${LISTENPID} UDP port ${LISTENPORT}"

echo -n "Setup iptables NFLOG target ... "
iptables -N nflog_dns_logger
iptables -A nflog_dns_logger -j NFLOG --nflog-group 123
iptables -I INPUT 1 -t filter -p udp -d "${NFLOGIP}" --sport 53 --dport "${LISTENPORT}" -j nflog_dns_logger
echo  "done"
iptables -L INPUT -nv
iptables -L nflog_dns_logger -nv
echo

echo -n "Start nflog_dns logging ... "
NFLOGTEMP="$(mktemp "/tmp/nflog_XXXXXXXX.temp")"
"${DIR}/../nflog_dns" >"${NFLOGTEMP}" &
NFLOGPID="${!}"
echo "PID ${NFLOGPID}"

echo -n "Send DNS reply packet to listener ... "
python3 "${DIR}/py/test_send.py" "${NFLOGIP}" "${LISTENPORT}"
echo "done"

sleep 2

echo "nflog_dns logfile content:"
cat "${NFLOGTEMP}"
echo

echo -n "Verify DNS reply was logged ... "
LOGSTRING="$(grep "example\.com.*127\.0\.0\.1" "${NFLOGTEMP}")"
[ -n "${LOGSTRING}" ] && echo "SUCCESS" || echo "FAIL"

echo -n "Stop nflog_dns ... "
kill -HUP "${NFLOGPID}"
rm -f "${NFLOGTEMP}"
echo "done"

echo -n "Tear down iptables  ... "
iptables -D INPUT 1 -t filter
iptables -F nflog_dns_logger
iptables -X nflog_dns_logger
echo "done"

echo -n "Tear down dummy interface ... "
ip link set down dev nflog0
ip addr del "${NFLOGIP}"/32 dev nflog0
ip link del nflog0
echo "done"

echo "=== END ==="

[ -n "${LOGSTRING}" ] && exit 0 || exit 1
