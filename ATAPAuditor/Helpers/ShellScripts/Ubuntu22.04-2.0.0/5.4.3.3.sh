#!/usr/bin/env bash

for file in /etc/profile.d/*.sh; do
	if grep -P '^\s*umask\s+0027' "$file" &>/dev/null; then
		exit 0
	fi
done

exit 1
