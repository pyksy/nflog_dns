#!/bin/bash

echo "Verify compiled version string $(./nflog_dns --version) matches build version ${VERSION}"
if [ -z "${VERSION}" ]
then
	VERSION="$(cut -d '"' -f 2 version.h)"
fi

./nflog_dns --version | grep -F "version ${VERSION}"
