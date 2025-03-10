#!/usr/bin/env bash

# Path to the auditd configuration file
AUDITD_CONF="/etc/audit/auditd.conf"

# Check if the file exists
if [[ -f "$AUDITD_CONF" ]]; then
	# Use grep to search for the exact line
	if grep -q "^max_log_file_action[[:space:]]*=[[:space:]]*keep_logs" "$AUDITD_CONF"; then
		exit 0
	else
		exit 1
	fi
else
	echo "File $AUDITD_CONF does not exist."
	exit 1
fi
