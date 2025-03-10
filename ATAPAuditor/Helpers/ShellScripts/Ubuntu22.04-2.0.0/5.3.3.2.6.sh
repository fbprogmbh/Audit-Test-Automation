#!/usr/bin/env bash
# Configuration file to check
FILE="/etc/security/pwquality.conf"
# Pattern to search for
PATTERN="dictcheck"

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
	grep -E "^\s*#\s*$PATTERN\b" "$FILE" >/dev/null
	COMMENTED=$?

	if [ $COMMENTED -eq 0 ]; then
		echo "Pattern $PATTERN is commented."
		exit 1
	fi

	# Extract the value of dictcheck using grep and sed
	VALUE=$(grep -E "^\s*$PATTERN\s*=\s*[0-9]+" "$FILE" | sed -E 's/.*=\s*([0-9]+).*/\1/')

	# If the value was found and it's a valid number
	if [[ -n "$VALUE" ]]; then
		# Compare the extracted value with 1
		if [ "$VALUE" -ne 1 ] || [ "$VALUE" -eq 0 ]; then
			echo "The value of $PATTERN ($VALUE) is not the best or egal to 0. Updating to $R_VALUE."
			exit 1
		else
			echo "The value of $PATTERN ($VALUE) is valid (dictcheck = 1)."
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
