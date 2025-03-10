#!/usr/bin/env bash
parameter_sshd_t=clientaliveinterval
parameter_sshd_config=ClientAliveInterval
desired_value=15

parameter_sshd_t1=clientalivecountmax
parameter_sshd_config1=ClientAliveCountMax
desired_value1=3

if ! command -v sshd &>/dev/null; then
	echo "sshd command could not be found"
	exit 0
fi

# Check using sshd -T output
actual_value=$(sshd -T | grep -i "$parameter_sshd_t" | awk '{print $2}')
actual_value1=$(sshd -T | grep -i "$parameter_sshd_t1" | awk '{print $2}')

if [ -z "$actual_value" ] && [ -z "$actual_value1" ]; then
	if (grep -iq '^$parameter_sshd_config' /etc/ssh/sshd_config) && (grep -iq '^$parameter_sshd_config1' /etc/ssh/sshd_config); then
		actual_value=$(grep -i '^$parameter_sshd_config' /etc/ssh/sshd_config | awk '{print $2}')
		actual_value1=$(grep -i '^$parameter_sshd_config1' /etc/ssh/sshd_config | awk '{print $2}')

	else
		echo "$parameter_sshd_config not set in sshd_config, using default"
		exit 1
	fi
fi

if [ "$actual_value" -eq "$desired_value" ] && [ "$actual_value1" -eq "$desired_value1" ]; then
	exit 0
else
	exit 1
fi
