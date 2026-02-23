#!/bin/bash

# Copyright Antti Kultanen <antti.kultanen@molukki.com>
# nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file

if [ "${1}" = "-h" ] || [ "${1}" = "--help" ]; then
	echo "Usage: $0 [VERSION]"
	echo "Create a new release by bumping version and creating a git tag"
	echo ""
	echo "If VERSION is not specified, performs a patch-level bump"
	echo "VERSION must be in semantic format MAJOR.MINOR.PATCHLEVEL (e.g., 1.2.3)"
	exit 0
fi

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

CURRENTVERSION="$(awk -F'"' '/PROGRAM_VERSION/ {print $2}' version.h)"

if [ -n "${1}" ]
then
	RELEASE="${1}"
	if ! grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' <<<"${RELEASE}"
	then
		echo "Error: Version must be in semantic format X.Y.Z (e.g., 1.2.3)" >&2
		exit 1
	fi
else
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

if [ "$(printf '%s\n' "$CURRENTVERSION" "$RELEASE" | sort -V | head -n1)" = "$RELEASE" ]; then
	echo "Error: New version $RELEASE is not greater than current version $CURRENTVERSION" >&2
	exit 1
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

echo '#define PROGRAM_VERSION "'"${RELEASE}"'"' | tee version.h

# Update DEB changelog
LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
if [ -n "$LAST_TAG" ]; then
	echo "Extracting changes since $LAST_TAG..."

	mapfile -t COMMITS < <(git log ${LAST_TAG}..HEAD --pretty=format:"%s" --no-merges | grep -v "^Release version ")

	if [ ${#COMMITS[@]} -eq 0 ]; then
		dch -v ${RELEASE}-1 --distribution unstable "No changes found." || exit 1
	else
		dch -v ${RELEASE}-1 --distribution unstable "${COMMITS[-1]}" || exit 1
		for (( i=${#COMMITS[@]}-2; i>=0; i-- )); do
			[ -n "${COMMITS[$i]}" ] && { dch --append "${COMMITS[$i]}" || exit 1; }
		done
	fi
else
	echo "Initial release."
	dch -v ${RELEASE}-1 --distribution unstable "Initial release" || exit 1
fi
dch --release "" || exit 1

# Update RPM changelog
if [ -f nflog_dns.spec ]; then
	LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
	CHANGELOG_DATE=$(date '+%a %b %d %Y')

	# Create new entry header
	NEW_ENTRY="* ${CHANGELOG_DATE} ${DEBFULLNAME} <${DEBEMAIL}> - ${RELEASE}-1"

	# Get commits or use default
	if [ -n "$LAST_TAG" ] && git log ${LAST_TAG}..HEAD --oneline --no-merges | grep -q .; then
		CHANGES=$(git log ${LAST_TAG}..HEAD --pretty=format:"- %s" --no-merges)
	else
		CHANGES="- Release version ${RELEASE}"
	fi

	# Insert into spec file
	awk -v entry="$NEW_ENTRY" -v changes="$CHANGES" '
	/^%changelog/ {
		print
		print entry
		print changes
		print ""
		next
	}
	{ print }
	' nflog_dns.spec > nflog_dns.spec.new && mv nflog_dns.spec.new nflog_dns.spec
fi

# Commit changes
git add version.h debian/changelog nflog_dns.spec
git commit -m "Release version ${RELEASE}"

# Create and push tag
git tag v${RELEASE}
git push origin master
git push origin v${RELEASE}
