#!/usr/bin/env bash
TEST_FILE="/etc/motd"
if [ -e "$TEST_FILE" ]; then
	DESIRED_PERM="644"
	ACTUAL_PERM=$(stat -c "%a" "$TEST_FILE")
	if [[ "$ACTUAL_PERM" == "$DESIRED_PERM" ]]; then
		exit 0
	else
		exit 1
	fi
fi
