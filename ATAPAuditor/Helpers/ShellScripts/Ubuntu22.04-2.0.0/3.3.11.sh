#!/usr/bin/env bash

kernel_parameters=("net.ipv6.conf.all.accept_ra" "net.ipv6.conf.default.accept_ra")
kernel_values=("0" "0")
len=${#kernel_parameters[@]}
for ((i = 0; i < len; i++)); do
	param=${kernel_parameters[$i]}
	value=${kernel_values[$i]}
	current_value=$(sysctl -n "$param" 2>/dev/null)

	# Check if sysctl command was successful
	if [ $? -ne 0 ]; then
		echo "Error: Kernel parameter $param does not exist or could not be retrieved."
		exit 1
	fi

	# Check if the current value matches the expected value
	if [ "$current_value" == "$value" ]; then
		echo "Kernel parameter $param is set correctly to $value."
	else
		echo "Kernel parameter $param is not set to $value (current value: $current_value)."
		exit 1
	fi
done
