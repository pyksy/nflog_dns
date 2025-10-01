#!/bin/bash

echo "Verify compiled version string $(./nflog_dns --version) matches build version ${1}"
if [ -z "${1}" ]
then
	echo missing version...
	VERSION="$(cut -d '"' -f 2 version.h)"
else
	VERSION="${1}"
fi

./nflog_dns --version | grep -F "version ${VERSION}"
