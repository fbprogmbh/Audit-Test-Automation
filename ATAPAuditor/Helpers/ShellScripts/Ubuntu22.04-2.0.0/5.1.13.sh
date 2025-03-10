#!/usr/bin/env bash

#test
parameter_sshd_t=logingracetime
parameter_sshd_config=LoginGraceTime
desired_value=60

if ! command -v sshd &>/dev/null; then
	echo "sshd command could not be found"
	exit 0
fi

# Check using sshd -T output
actual_value=$(sshd -T | grep -i "$parameter_sshd_t" | awk '{print $2}')

if [ -z "$actual_value" ]; then
	if grep -iq '^$parameter_sshd_config' /etc/ssh/sshd_config; then
		actual_value=$(grep -i '^$parameter_sshd_config' /etc/ssh/sshd_config | awk '{print $2}')
	else
		echo "$parameter_sshd_config not set in sshd_config, using default"
		actual_value=120
	fi
fi

if [ "$actual_value" -le "$desired_value" ]; then
	exit 0
else
	exit 1
fi
