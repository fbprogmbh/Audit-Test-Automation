#!/usr/bin/env bash

kernel_parameter="net.ipv4.icmp_ignore_bogus_error_responses"
kernel_value="1"
current_value=$(sysctl -n "$kernel_parameter" 2>/dev/null)

if [ $? -ne 0 ]; then
	echo "Error: Kernel parameter $kernel_parameter does not exist or could not be retrieved."
	exit 1
fi

if [ "$current_value" == "$kernel_value" ]; then
	echo "Kernel parameter $kernel_parameter is set to $kernel_value"
	exit 0
else
	echo "Kernel parameter $kernel_parameter is not set to $kernel_value (current value: $current_value)"
	exit 1
fi
