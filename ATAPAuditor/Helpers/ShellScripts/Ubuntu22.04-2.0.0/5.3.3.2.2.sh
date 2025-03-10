#!/usr/bin/env bash

# Configuration file to check
FILE="/etc/security/pwquality.conf"
# Pattern to search for
PATTERN="minlen"

# Check if the configuration file exists
if [ ! -f "$FILE" ]; then
	echo "File $FILE not found."
	exit 1
fi

# Search for the pattern, whether it's commented or not
grep -E "^[[:space:]]*#?[[:space:]]*$PATTERN\b" "$FILE" >/dev/null
FOUND=$?

# If the pattern is found
if [ $FOUND -eq 0 ]; then
	# Check if the pattern is commented
	grep -E "^[[:space:]]*#[[:space:]]*$PATTERN\b" "$FILE" >/dev/null
	COMMENTED=$?

	if [ $COMMENTED -eq 0 ]; then
		echo "Pattern $PATTERN is commented."
		exit 1
	fi

	# Extract the value of minlen using grep and sed
	VALUE=$(grep -E "^[[:space:]]*$PATTERN\s*=\s*[0-9]+" "$FILE" | sed -E 's/.*=\s*([0-9]+).*/\1/')

	# If the value was found and it's a valid number
	if [[ -n "$VALUE" ]]; then
		# Compare the extracted value with 14
		if [ "$VALUE" -lt 14 ]; then
			echo "The value of $PATTERN ($VALUE) is less than 14."
			exit 1
		else
			echo "The value of $PATTERN ($VALUE) is valid (>= 14)."
			exit 0
		fi
	else
		echo "No valid value for $PATTERN found."
		exit 1
	fi
else
	echo "Pattern $PATTERN not found."
	exit 1
fi
