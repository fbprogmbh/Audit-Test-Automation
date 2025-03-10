#!/usr/bin/env bash

audit_conf="/etc/audit/auditd.conf"
perm_mask="0177"
if [ ! -f "$audit_conf" ]; then
	exit 1
fi
audit_log_dir=$(grep -E '^\s*log_file\s*=' "$audit_conf" | cut -d= -f2 | xargs dirname 2>/dev/null)
if [ -z "$audit_log_dir" ]; then
	exit 1
fi
audit_log_group=$(grep -E '^\s*log_group\s*=' "$audit_conf" | cut -d= -f2 | xargs)
if [ -z "$audit_log_group" ]; then
	exit 1
fi
if [ ! -d "$audit_log_dir" ]; then
	exit 1
fi
for file in "$audit_log_dir"/*; do
	if [ -f "$file" ]; then
		group=$(ls -l "$file" | awk '{print $4}')
		if [[ "$group" != "root" && "$group" != "adm" ]]; then
			exit 1
		fi
	fi
done
exit 0
