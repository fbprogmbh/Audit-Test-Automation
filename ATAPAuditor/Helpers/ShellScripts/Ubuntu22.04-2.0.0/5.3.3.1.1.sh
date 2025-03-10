#!/usr/bin/env bash

faillock_conf="/etc/security/faillock.conf"
expected_value=5
if grep -Pq '^\s*#?\s*deny\s*=\s*([0-9]+)' "$faillock_conf"; then
	current_value=$(grep -Eo '^\s*#?\s*deny\s*=\s*([0-9]+)' "$faillock_conf" | awk -F'=' '{print $2}' | tr -d ' ')
else
	echo "ERROR: deny is not set in $faillock_conf."
	exit 1
fi
if ((current_value <= expected_value)); then
	exit 0
else
	echo "ERROR: deny=$current_value is higher than $expected_value"
	exit 1
fi
