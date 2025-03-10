#!/usr/bin/env bash

config_file="/etc/aide/aide.conf"
pattern=("/sbin/auditctl" "/sbin/auditd" "/sbin/ausearch" "/sbin/aureport" "/sbin/autrace" "/sbin/augenrules")
if [ ! -f "$config_file" ]; then
	exit 0
fi

for line in "${pattern[@]}"; do
	regex_pattern="^\s*#*\s*${line}\b"
	if ! grep -Eq "$regex_pattern" "$config_file"; then
		exit 1
	fi
done
exit 0
