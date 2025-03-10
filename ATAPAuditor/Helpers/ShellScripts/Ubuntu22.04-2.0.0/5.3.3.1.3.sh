#!/usr/bin/env bash

faillock_conf="/etc/security/faillock.conf"
limit_value=60

if grep -Eq "^\s*even_deny_root\s*" "$faillock_conf"; then
	echo "Test passed: even_deny_root is correctly enabled."
else
	echo "ERROR: even_deny_root is missing or commented out."
	exit 1
fi

if grep -Eq "^\s*root_unlock_time\s*=\s*[0-9]+\s*" "$faillock_conf"; then
	current_value=$(grep -Eo "^\s*root_unlock_time\s*=\s*[0-9]+" "$faillock_conf" | awk -F'=' '{print $2}' | tr -d ' ')
	if ((current_value >= limit_value)); then
		echo "Test passed: root_unlock_time=$current_value is correctly set."
	else
		echo "ERROR: root_unlock_time=$current_value is less than $limit_value."
		exit 1
	fi
else
	echo "ERROR: root_unlock_time is missing or commented out."
	exit 1
fi
