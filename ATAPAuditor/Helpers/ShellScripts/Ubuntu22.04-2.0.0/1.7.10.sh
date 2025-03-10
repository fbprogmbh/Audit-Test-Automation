#!/usr/bin/env bash

config_file="/etc/gdm/custom.conf"

if [[ ! -f "$config_file" || ! -r "$config_file" ]]; then
	exit 0
fi

value="Enable"

if grep -Eq "^\s*$value\s*=\s*true\s*$" "$config_file"; then
	echo -e " \"$value\" in $config_file is true"
	exit 1
else
	echo -e "\"$value\" not found or not set "
fi
exit 0
