#!/usr/bin/env bash

directory="/var/tmp"
flag="nodev"
FSTAB_FILE="/etc/fstab"

if [[ ! -f "$FSTAB_FILE" ]]; then
	echo "Error: $FSTAB_FILE does not exist."
	exit 0
fi

if grep -q -E "^[^#]*[[:space:]]+$directory[[:space:]]+" "$FSTAB_FILE"; then
	if grep -E "^[^#]*[[:space:]]+$directory[[:space:]]+" "$FSTAB_FILE" | grep -vq "$flag"; then
		exit 1
	fi
fi

exit 0
