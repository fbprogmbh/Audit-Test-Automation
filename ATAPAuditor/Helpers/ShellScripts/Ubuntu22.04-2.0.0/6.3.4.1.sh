#!/usr/bin/env bash

l_perm_mask="0137"
if [ -e "/etc/audit/auditd.conf" ]; then
	# Extract the log directory from the configuration file
	l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"

	if [ -d "$l_audit_log_directory" ]; then
		l_maxperm="$(printf '%o' $((0777 & ~$l_perm_mask)))"

		# Find files matching the permission mask and process them line by line
		while IFS= read -r l_file; do
			# Ensure the file exists and get its mode
			if [ -e "$l_file" ]; then
				l_file_mode="$(stat -Lc '%#a' "$l_file")"
				exit 1
			fi
		done < <(find "$l_audit_log_directory" -maxdepth 1 -type f -perm /"$l_perm_mask")

		# Check if any files were processed
		if [ $? -eq 0 ]; then
			exit 0
		fi
	else
		exit 0
	fi
else
	exit 0
fi
