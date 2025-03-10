#!/usr/bin/env bash
# Configuration file to check
FILE="/etc/login.defs"
# Pattern to search for
PATTERN="PASS_MIN_DAYS"

# Check if the configuration file exists
if [ ! -f "$FILE" ]; then
	echo "File $FILE not found."
	exit 1
fi

# Search for the pattern, whether it's commented or not
grep -E "^\s*#?\s*$PATTERN\b" "$FILE" >/dev/null
FOUND=$?

# If the pattern is found
if [ $FOUND -eq 0 ]; then
	# Check if the pattern is commented
	grep -E "^#\s*$PATTERN\s+[0-9]+" "$FILE" >/dev/null
	COMMENTED=$?

	if [ $COMMENTED -eq 0 ]; then
		echo "Pattern $PATTERN is commented."
		exit 1
	fi

	# Extract the value of PASS_MIN_DAYS using grep and sed
	VALUE=$(grep -E "^[[:space:]]*$PATTERN\s*=?\s*[0-9]+" "$FILE" | sed -E 's/[^0-9]*([0-9]+).*/\1/')

	# If the value was found and it's a valid number
	if [[ -n "$VALUE" ]]; then
		# Compare the extracted value with 0
		if [ "$VALUE" -le 0 ]; then
			echo "The value of $PATTERN ($VALUE) is less than 0 or egal to 0."
			exit 1
		else
			echo "The value of $PATTERN ($VALUE) is valid (>=0)."
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
