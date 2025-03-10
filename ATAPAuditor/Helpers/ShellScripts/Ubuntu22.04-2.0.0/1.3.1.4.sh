#!/usr/bin/env bash

unconfined_lines=$(apparmor_status | grep unconfined)

while IFS= read -r line; do
	if [[ ! "$line" =~ ^0 ]]; then
		exit 1
	fi
done <<<"$unconfined_lines"
exit 0
