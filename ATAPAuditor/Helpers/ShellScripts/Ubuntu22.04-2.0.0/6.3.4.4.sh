#!/usr/bin/env bash
perm_mask="0027"
if [ -e "/etc/audit/auditd.conf" ]; then
	log_dir="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
	if [ -d "$log_dir" ]; then
		maxperm="$(printf '%o' $((0777 & ~$perm_mask)))"
		log_dir_mode="$(stat -Lc '%#a' "$log_dir")"
		if [ $(($log_dir_mode & $perm_mask)) -gt 0 ]; then
			exit 1
		fi
	else
		exit 1
	fi
else
	exit 1
fi
exit 0
