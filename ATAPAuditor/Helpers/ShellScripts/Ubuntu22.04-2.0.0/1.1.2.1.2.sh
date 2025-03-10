#!/usr/bin/env bash

if grep -q -E '^[^#]*\s/tmp\s' /etc/fstab; then
	if grep -E '^[^#]*\s/tmp\s' /etc/fstab | grep -vq 'nodev'; then
		exit 1
	fi
fi

exit 0
