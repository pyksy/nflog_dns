#!/bin/bash

# Copyright Antti Kultanen <antti.kultanen@molukki.com>
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

if [ "${1}" = "ipv4" ] || [ "${1}" = "4" ]
then
	IP="172.31.53.123"
	IPTABLES="iptables"
elif [ "${1}" = "ipv6" ] || [ "${1}" = "6" ]
then
	IP="fd53::1"
	IPTABLES="ip6tables"
else
	echo "Usage: $0 <ipv4|ipv6>"
	exit 1
fi

source common.sh

cleanup() {
    echo -n "Clean up ... "
    # Kill nflog_dns if running
    if [ -n "$NFLOGPID" ]; then
        kill -HUP "$NFLOGPID" 2>/dev/null
        wait "$NFLOGPID" 2>/dev/null
    fi
    rm -f "${NFLOGTEMP}" 2>/dev/null
	echo "done"

	echo -n "Tear down ${IPTABLES} ... "
    ${IPTABLES} -D INPUT -t filter -p udp -d "${IP}" --sport 53 -j nflog_dns_logger 2>/dev/null
    ${IPTABLES} -F nflog_dns_logger 2>/dev/null
    ${IPTABLES} -X nflog_dns_logger 2>/dev/null
	echo "done"

	echo -n "Tear down dummy interface ... "
    ip link set down dev nflog0 2>/dev/null
    ip addr del "${IP}" dev nflog0 2>/dev/null
    ip link del nflog0 2>/dev/null
	echo "done"
}
trap cleanup EXIT INT TERM

send_packets() {
	local -n array_ref=${1}
	for TYPE in "${array_ref[@]}"
	do
		echo -n "Start UDP receiver ... "
		exec 3< <(python3 "${DIR}/py/test_recv.py" "${IP}")
		LISTENPID="${!}"
		read LISTENPORT <&3
		exec 3<&-
		echo "PID ${LISTENPID} UDP port ${LISTENPORT}"

		echo -n "Send ${TYPE^^} reply packet to listener ... "
		python3 "${DIR}/py/test_send.py" "${IP}" "${LISTENPORT}" $TYPE
		echo "done"
	done
}

verify_packets() {
	# Call with any argument to negate the tests
	for TYPE in "${PACKET_TYPES[@]}"
	do
		[ -z "${1}" ] && LOGMSG="logged once" || LOGMSG="not logged"
		echo -n "Verify ${TYPE^^} reply was ${LOGMSG} ... "
		HITCOUNT="$(grep -c "${LOGLEVEL}.* ${IP//./\.} reply ${TYPE^^} .*example\.com" "${NFLOGTEMP}")"
		if [ ${HITCOUNT} -eq 1 ] || [ -n "${1}" -a ${HITCOUNT} -eq 0 ]
		then
			echo "SUCCESS"
		else
			echo "FAIL"
			((fail_count++))
		fi
	done
}

verify_errors() {
	# Call with any argument to negate the tests
	for TYPE in "${ERROR_TYPES[@]}"
	do
		[ -z "${1}" ] && LOGMSG="logged once" || LOGMSG="not logged"
		echo -n "Verify ${TYPE^^} error was ${LOGMSG} ... "
		HITCOUNT="$(grep -c "${LOGLEVEL}.* ${IP//./\.} reply A example\.com -> ${TYPE^^}" "${NFLOGTEMP}")"
		if [ ${HITCOUNT} -eq 1 ] || [ -n "${1}" -a ${HITCOUNT} -eq 0 ]
		then
			echo "SUCCESS"
		else
			echo "FAIL"
			((fail_count++))
		fi
	done
}

send_sigusr1() {
	echo -n "Send SIGUSR1 to nflog_dns to log packet statistics ... "
	if kill -USR1 ${NFLOGPID}
	then
		echo "SUCCESS"
	else
		echo "FAIL"
		((fail_count++))
	fi
}

# Send SIGUSR1 to nflog_dns to immediately output packet statistics; unused as for now.
verify_stats() {
	echo -n "Verify package statistics ${@} ... "
	if grep -q "${LOGLEVEL}.* received_packets=${1} invalid_packets=${2} dns_responses=${3} logged_errors=${4} logged_records=${5}" "${NFLOGTEMP}"
	then
		echo "SUCCESS"
	else
			echo "FAIL"
			((fail_count++))
	fi
}

# Clean up iptables and interface just in case
${IPTABLES} -D INPUT -t filter -p udp -d "${IP}" --sport 53 -j nflog_dns_logger 2>/dev/null
${IPTABLES} -F nflog_dns_logger 2>/dev/null
${IPTABLES} -X nflog_dns_logger 2>/dev/null
ip link del nflog0 2>/dev/null

echo -n "Setup dummy interface nflog0 with IPv${1: -1} address ... "
ip link add nflog0 type dummy
ip addr add "${IP}" dev nflog0
ip link set up dev nflog0
echo "done"

echo -n "Setup ${IPTABLES} NFLOG target with group ${GROUP} ... "
${IPTABLES} -N nflog_dns_logger
${IPTABLES} -A nflog_dns_logger -j NFLOG --nflog-group ${GROUP}
${IPTABLES} -I INPUT 1 -t filter -p udp -d "${IP}" --sport 53 -j nflog_dns_logger
echo "done"

NFLOGTEMP="$(mktemp "/tmp/nflog_XXXXXXXX.temp")"

LOGLEVEL="trace"
ARGS="--group=${GROUP} --level=${LOGLEVEL}" 
echo -n "Start nflog_dns ${ARGS} ... "
"${DIR}/../nflog_dns" $ARGS >"${NFLOGTEMP}" &
NFLOGPID="${!}"
echo "PID ${NFLOGPID}"

sleep 1
send_sigusr1
sleep 2
cat "${NFLOGTEMP}"
verify_stats 0 0 0 0 0

echo -n "Stop nflog_dns ... "
kill -HUP "${NFLOGPID}"
echo "done"
NFLOGPID=""
rm -f "${NFLOGTEMP}"

((fail_count > 0)) && exit 1 || echo

LOGLEVEL="debug"
ARGS="--group=${GROUP} --level=${LOGLEVEL}" 
echo -n "Start nflog_dns ${ARGS} ... "
"${DIR}/../nflog_dns" $ARGS >"${NFLOGTEMP}" &
NFLOGPID="${!}"
echo "PID ${NFLOGPID}"

send_packets PACKET_TYPES
sleep 2

echo -n "Stop nflog_dns ... "
kill -HUP "${NFLOGPID}"
echo "done"
NFLOGPID=""
cat "${NFLOGTEMP}"

verify_packets
verify_errors missing
verify_stats ${#PACKET_TYPES[@]} 0 ${#PACKET_TYPES[@]} 0 ${#PACKET_TYPES[@]}

rm -f "${NFLOGTEMP}"

((fail_count > 0)) && exit 1 || echo

LOGLEVEL="info"
ARGS="--group=${GROUP} --level=${LOGLEVEL}" 
for TYPE in "${PACKET_TYPES[@]}"
do
	ARGS="--log-${TYPE}=no ${ARGS}"
done
echo -n "Start nflog_dns ${ARGS} ... "
"${DIR}/../nflog_dns" $ARGS >"${NFLOGTEMP}" &
NFLOGPID="${!}"
echo "PID ${NFLOGPID}"

send_packets PACKET_TYPES
sleep 2

echo -n "Stop nflog_dns ... "
kill -HUP "${NFLOGPID}"
echo "done"
NFLOGPID=""
cat "${NFLOGTEMP}"

verify_packets missing
verify_errors missing
verify_stats ${#PACKET_TYPES[@]} 0 ${#PACKET_TYPES[@]} 0 0
rm -f "${NFLOGTEMP}"

((fail_count > 0)) && exit 1 || echo

LOGLEVEL="warning"
ARGS="--log-noerror=no --group=${GROUP} --level=${LOGLEVEL}" 
echo -n "Start nflog_dns ${ARGS} ... "
"${DIR}/../nflog_dns" $ARGS >"${NFLOGTEMP}" &
NFLOGPID="${!}"
echo "PID ${NFLOGPID}"

send_packets PACKET_TYPES
sleep 2

echo -n "Stop nflog_dns ... "
kill -HUP "${NFLOGPID}"
echo "done"
NFLOGPID=""
cat "${NFLOGTEMP}"

verify_packets missing
verify_errors missing
verify_stats ${#PACKET_TYPES[@]} 0 ${#PACKET_TYPES[@]} 0 0
rm -f "${NFLOGTEMP}"

((fail_count > 0)) && exit 1 || echo

LOGLEVEL="error"
ARGS="--group=${GROUP} --level=${LOGLEVEL}" 
for TYPE in "${ERROR_TYPES[@]}"
do
	ARGS="--log-${TYPE}=no ${ARGS}"
done
echo -n "Start nflog_dns ${ARGS} ... "
"${DIR}/../nflog_dns" $ARGS >"${NFLOGTEMP}" &
NFLOGPID="${!}"
echo "PID ${NFLOGPID}"

send_packets ERROR_TYPES
sleep 2

echo -n "Stop nflog_dns ... "
kill -HUP "${NFLOGPID}"
echo "done"
NFLOGPID=""
cat "${NFLOGTEMP}"

verify_packets missing
verify_errors missing
verify_stats ${#ERROR_TYPES[@]} 0 ${#ERROR_TYPES[@]} 0 0
rm -f "${NFLOGTEMP}"

((fail_count > 0)) && exit 1 || echo

LOGLEVEL="critical"
ARGS="--log-a=yes --group=${GROUP} --level=${LOGLEVEL}" 
for TYPE in "${ERROR_TYPES[@]}"
do
	ARGS="--log-${TYPE}=yes ${ARGS}"
done
echo -n "Start nflog_dns ${ARGS} ... "
"${DIR}/../nflog_dns" $ARGS >"${NFLOGTEMP}" &
NFLOGPID="${!}"
echo "PID ${NFLOGPID}"

send_packets ERROR_TYPES
sleep 2

echo -n "Stop nflog_dns ... "
kill -HUP "${NFLOGPID}"
echo "done"
NFLOGPID=""
cat "${NFLOGTEMP}"

verify_errors
verify_stats ${#ERROR_TYPES[@]} 0 ${#ERROR_TYPES[@]} ${#ERROR_TYPES[@]}  0
rm -f "${NFLOGTEMP}"
((fail_count > 0)) && exit 1 || echo

LOGLEVEL="trace"
ARGS="--group=${GROUP} --level=${LOGLEVEL}" 
echo -n "Start nflog_dns ${ARGS} ... "
"${DIR}/../nflog_dns" $ARGS >"${NFLOGTEMP}" &
NFLOGPID="${!}"
echo "PID ${NFLOGPID}"

send_packets INVALID_TYPES
sleep 2

echo -n "Stop nflog_dns ... "
kill -HUP "${NFLOGPID}"
echo "done"
NFLOGPID=""
cat "${NFLOGTEMP}"

verify_stats ${#INVALID_TYPES[@]} ${#INVALID_TYPES[@]} 0 0 0
rm -f "${NFLOGTEMP}"
((fail_count > 0)) && exit 1 || echo
