#!/usr/bin/env bash

if grep -q -E '^[^#]*\s/home\s' /etc/fstab; then
	if grep -E '^[^#]*\s/home\s' /etc/fstab | grep -vq 'nosuid'; then
		exit 1
	fi
fi

exit 0
