#!/bin/bash

VERSION="$(cut -d '"' -f 2 version.h)"

echo "Verify compiled version string $(./nflog_dns --version) matches build version ${VERSION}"
./nflog_dns --version | grep -F "version ${VERSION}"
