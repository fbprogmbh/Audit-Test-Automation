#!/usr/bin/env bash

if [[ -f /etc/sysconfig/sshd ]]; then
	if grep -Pi '^\s*CRYPTO_POLICY\s*=' /etc/sysconfig/sshd; then
		echo "CRYPTO_POLICY ist set"
		exit 1
	else
		echo "CRYPTO_POLICY is not set"
	fi
else
	echo "file /etc/sysconfig/sshd does not exist"
fi
exit 0
