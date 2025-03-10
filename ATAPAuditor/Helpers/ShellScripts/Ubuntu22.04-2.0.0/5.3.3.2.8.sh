#!/usr/bin/env bash

# File configuration
FILE="/etc/security/pwquality.conf"
# what we look for
PATTERN="enforce_for_root"

# Check if the file exists
if [ ! -f "$FILE" ]; then
	echo "File $FILE wa not found."
	exit 1
fi

# Search for the pattern, regardless of its case, even if it is commented out
grep -Ei "^[[:space:]]*#?[[:space:]]*$PATTERN" "$FILE" >/dev/null
FOUND=$?

# if the pattern is found
if [ $FOUND -eq 0 ]; then
	# check if it is commented
	grep -Ei "^[[:space:]]*#[[:space:]]*$PATTERN" "$FILE" >/dev/null
	COMMENTED=$?

	if [ $COMMENTED -eq 0 ]; then
		exit 1
	fi
	exit 0
else
	exit 1
fi
