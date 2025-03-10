#!/usr/bin/env bash

l_output="" l_output2=""
if [ -e "/etc/audit/auditd.conf" ]; then
	l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
	if [ -d "$l_audit_log_directory" ]; then
		while IFS= read -r l_file; do
			l_output2="$l_output2\n - File: \"$l_file\" is owned by user: \"$(stat -Lc '%U' "$l_file")\"\n (should be owned by user: \"root\")\n"
		done < <(find "$l_audit_log_directory" -maxdepth 1 -type f ! -user root)
	else
		l_output2="$l_output2\n - Log file directory not set in \"/etc/audit/auditd.conf\" please set log file directory"
	fi
else
	l_output2="$l_output2\n - File: \"/etc/audit/auditd.conf\" not found.\n - ** Verify auditd is installed **"
fi
if [ -z "$l_output2" ]; then
	l_output="$l_output\n - All files in \"$l_audit_log_directory\" are owned by user: \"root\"\n"
	echo -e "\n- Audit Result:\n ** PASS **\n - * Correctly configured * :$l_output"
	exit 0
else
	echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for auditgfailure * :$l_output2\n"
	exit 1
fi
