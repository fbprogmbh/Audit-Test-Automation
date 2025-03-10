#!/usr/bin/env bash
parameter_sshd_t=loglevel
parameter_sshd_config=LogLevel
desired_value=INFO
desired_value1=VERBOSE

if ! command -v sshd &>/dev/null; then
	echo "sshd command could not be found"
	exit 0
fi

# Check using sshd -T output
actual_value=$(sshd -T | grep -i "$parameter_sshd_t" | awk '{print $2}')

if [ -z "$actual_value" ]; then
	if grep -iq "^$parameter_sshd_config" /etc/ssh/sshd_config; then
		actual_value=$(grep "^$parameter_sshd_config" /etc/ssh/sshd_config | awk '{print $2}')
	else
		echo "$parameter_sshd_config not set in sshd_config, using default"
		actual_value=INFO
	fi
fi

if [ "$actual_value" = "$desired_value" ] || [ "$actual_value" = "$desired_value1" ]; then
	exit 0
else
	exit 1
fi
