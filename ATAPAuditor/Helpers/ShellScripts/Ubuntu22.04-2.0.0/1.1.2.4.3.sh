#!/usr/bin/env bash

if grep -q -E '^[^#]*\s/var\s' /etc/fstab; then
	# If such a line exists, check if it contains the nosuid  flag
	if grep -E '^[^#]*\s/var\s' /etc/fstab | grep -vq 'nosuid'; then
		# If /var exists and does NOT contain nosuid, exit with 1 (error)
		exit 1
	fi
fi

exit 0
