#!/usr/bin/env bash

l_valid_shells=$(grep -v "nologin" /etc/shells | sed -r '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|')

if grep -qE '^\s*UID_MIN\s+([0-9]+)' /etc/login.defs; then
	uid_min=$(grep -oP '^\s*UID_MIN\s+\K[0-9]+' /etc/login.defs)
else
	printf "ERROR: UID_MIN not found in /etc/login.defs.\n"
	exit 1
fi
while IFS=: read -r username _ uid _ _ _ shell; do
	if [[ -n "$uid" && "$uid" =~ ^[0-9]+$ ]]; then
		if echo "$username" | grep -qE "^(root|halt|sync|shutdown|nfsnobody)$" &&
			{ [ "$uid" -lt "$uid_min" ] || [ "$uid" -eq 65534 ]; } &&
			echo "$shell" | grep -qE "^($l_valid_shells)$"; then
			exit 1
		fi
	fi
done </etc/passwd
exit 0
