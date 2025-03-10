#!/usr/bin/env bash

rules_file="/etc/audit/rules.d/50-fbPro-hardening.rules"

if grep -qE -- '^\s*-w\s+(\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd|\/etc\/nsswitch\.conf|\/etc\/pam\.conf|\/etc\/pam\.d)' $rules_file &&
	grep -qE -- '-p\s+wa' $rules_file &&
	grep -qE -- '(\s*key=\s*[!-~]*\s*|-\s*k\s*[!-~]*\s*)' $rules_file; then
	exit 0
else
	echo "ERROR: Audit rules are NOT correctly set."
	exit 1
fi
