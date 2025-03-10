#!/usr/bin/env bash

result=$(find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root)
if [ -z "$result" ]; then
	exit 0
else
	echo "Files found that do not belong to the root user:"
	echo "$result"
	exit 1
fi
