#!/bin/bash

if [ -z "${VERSION}" ]
then
	VERSION="$(cut -d '"' -f 2 version.h)"
fi

echo "version: $VERSION"
exit 0
