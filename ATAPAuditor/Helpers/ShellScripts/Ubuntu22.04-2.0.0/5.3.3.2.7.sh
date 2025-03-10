#!/usr/bin/env bash
# Parameter to search for
parameter_config="enforcing"
unwanted_value=0
file="/etc/security/pwquality.conf"

# Search for the line containing the parameter with '=' and the unwanted value, even if commented
line=$(grep -E "^\s*$parameter_config\s*=\s*$unwanted_value\s*$" "$file")

# Check if the unwanted line exists
if [ -n "$line" ]; then
	echo "Error: The line '$parameter_config=$unwanted_value' exists in $file (even if commented)."
	exit 1
else
	echo "No unwanted or commented line '$parameter_config=$unwanted_value' found in $file."
	exit 0
fi
