#!/usr/bin/env bash

faillock_conf="/etc/security/faillock.conf"
expected_value=900
value="unlock_time"
regex_pattern="^\s*#*\s*${value}\s*=\s*[0-9]+"

if grep -Eq "$regex_pattern" "$faillock_conf"; then
	current_value=$(grep -E "$regex_pattern" "$faillock_conf" | head -n 1 | sed -E "s/.*=\s*([0-9]+)/\1/" | tr -d ' ')
	if [[ $current_value =~ ^# ]]; then
		echo "ERROR: The line is commented out"
		exit 1
	fi
	if ((current_value < expected_value)); then
		echo "ERROR: unlock_time = $current_value < $expected_value"
		exit 1
	else
		exit 0
	fi
else
	echo "ERROR: No such line found for unlock_time in $faillock_conf"
	exit 1
fi
