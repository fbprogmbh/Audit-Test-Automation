#!/usr/bin/env bash

expected_inactive_days=45

if useradd -D | grep -Eq '^\s*INACTIVE\s*=\s*'$expected_inactive_days'\b'; then
	echo "Default inactivity period is correct."
else
	echo "Default inactivity period is incorrect."
	exit 1
fi

while IFS=: read -r username password lastchg min max warn inactive_days expire; do
	if [[ -z "$inactive_days" || "$inactive_days" == " " ]]; then
		continue
	fi

	if [[ "$inactive_days" -gt $expected_inactive_days ]]; then
		echo "User $username exceeds policy."
		exit 1
	fi
done </etc/shadow
exit 0
