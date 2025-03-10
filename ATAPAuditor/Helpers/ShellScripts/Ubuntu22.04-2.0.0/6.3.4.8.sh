#!/usr/bin/env bash

perm_mask="0022"
maxperm="$(printf '%o' $((0777 & ~$perm_mask)))"
audit_tools=("/sbin/auditctl" "/sbin/aureport" "/sbin/ausearch" "/sbin/autrace" "/sbin/auditd" "/sbin/augenrules")

for a_tool in "${audit_tools[@]}"; do
	if [ -e "$a_tool" ]; then
		mode="$(stat -c '%#a' "$a_tool")"
		if ((mode & perm_mask)); then
			echo "Error: $a_tool has permissions that are too permissive."
			exit 1
		fi
	else
		echo "Warning: $a_tool does not exist."
	fi
done

unset audit_tools
exit 0
