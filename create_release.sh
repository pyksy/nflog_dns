#!/bin/bash

# Copyright Antti Kultanen <antti.kultanen@molukki.com>
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

if [ "$(git rev-parse --abbrev-ref HEAD)" != "master" ]
then
	echo "Error: must create release in master branch." >&2
	exit 1
fi
if ! git diff-index --quiet HEAD --
then
        echo "Error: You have uncommitted changes. Commit or stash them first." >&2
        exit 1
fi

if [ -n "${1}" ]
then
	if ! grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' <<<"${1}"
	then
		echo "Error: Version must be in semantic format X.Y.Z (e.g., 1.2.3)" >&2
		exit 1
	fi
	RELEASE="${1}"
else
	CURRENTVERSION="$(cut -d '"' -f 2 version.h)"
	echo "Usage: ${0} [VERSION]"
	echo "No arguments given, assuming patchlevel bump"
	echo ""
	echo "Current release version is: ${CURRENTVERSION}"
	echo ""
	MAJORMINOR="${CURRENTVERSION%.*}"
	PATCH="${CURRENTVERSION##*.}"
	RELEASE="${MAJORMINOR}.$((PATCH+1))"
	echo -n "Bump version number to ${RELEASE} (y/n)? "
	read REPLY
	REPLY="${REPLY,}"
	[ "${REPLY:0:1}" = "y" ] || exit 0
	echo
fi

if git rev-parse "v${RELEASE}" >/dev/null 2>&1
then
        echo "Error: Tag v${RELEASE} already exists" >&2
        exit 1
fi

if [ -z "$DEBFULLNAME" ]
then
	export DEBFULLNAME="$(git config user.name)"
fi
if [ -z "$DEBEMAIL" ]
then
	export DEBEMAIL="$(git config user.email)"
fi
echo "Creating release v${RELEASE} as ${DEBFULLNAME} <${DEBEMAIL}>."

echo '#define PROGRAM_VERSION "'${RELEASE}'"' | tee version.h
rm -f debian/changelog.dch
dch -v ${RELEASE}-1 "Release version ${RELEASE}"

# Commit changes
git add version.h debian/changelog
git commit -m "Bump version to ${RELEASE}"

# Create and push tag
git tag v${RELEASE}
git push origin master
git push origin v${RELEASE}
