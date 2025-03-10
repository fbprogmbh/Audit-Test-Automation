#!/usr/bin/env bash

output=$(sshd -T -C user=root -C host="$(hostname)" -C addr="$(hostname -I | cut -d ' ' -f1)" | grep -Ei "kexalgorithms\s+([^#\n\r]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b")

if [[ -n "$output" ]]; then
	exit 1
else
	exit 0
fi
