#!/usr/bin/env bash

SUDO_LOG_FILE=$(grep -r logfile /etc/sudoers* | grep -v "/etc/sudoers.bak" | sed -e 's/.*logfile=//;s/,? .*//' -e 's/"//g')

if [ -n "$SUDO_LOG_FILE" ]; then
	on_disk=$(grep -E "^\s*-w\s+$SUDO_LOG_FILE\s+-p\s+wa" /etc/audit/rules.d/*.rules)
	loaded=$(auditctl -l | grep -E "^\s*-w\s+$SUDO_LOG_FILE\s+-p\s+wa")
	if [[ -n "$on_disk" && -n "$loaded" ]]; then
		echo "Audit rules are correctly set."
		exit 0
	else
		echo "ERROR: Audit rules are NOT correctly set or loaded."
		exit 1
	fi
else
	echo "ERROR: Variable 'SUDO_LOG_FILE' is unset or empty."
	exit 1
fi
