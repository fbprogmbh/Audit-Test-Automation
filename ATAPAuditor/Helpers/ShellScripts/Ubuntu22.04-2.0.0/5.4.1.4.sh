#!/usr/bin/env bash
# Configuration file to check
FILE="/etc/login.defs"
# Pattern to search for
PATTERN="ENCRYPT_METHOD"

# Check if the configuration file exists
if [ ! -f "$FILE" ]; then
	echo "File $FILE not found."
	exit 1
fi

# Search for the pattern, whether it's commented or not
grep -Eq "^#?\s*$PATTERN\s+\S+$" "$FILE"
FOUND=$?

# If the pattern is found
if [ $FOUND -eq 0 ]; then
	# Check if the pattern is commented

	grep -Eq "^#\s*$PATTERN\s+\S+$" "$FILE"
	COMMENTED=$?

	if [ $COMMENTED -eq 0 ]; then
		echo "Pattern $PATTERN is commented."
		exit 1
	fi

	line=$(grep -E "^\s*$PATTERN\s+\S+$" "$FILE")
	if [ -n "$line" ]; then
		word=$(echo "$line" | awk '{print $2}')
	fi

	if [[ -n "$word" ]]; then
		# Compare the extracted word with SHA512 UND YESCRYPT
		VALUE1="SHA512"
		VALUE2="YESCRYPT"

		if [ "$word" != "$VALUE1" ] && [ "$word" != "$VALUE2" ]; then
			echo "The value of $PATTERN ($word) is not good."
			exit 1
		else
			echo "The value of $PATTERN ($word) is valid (equal to SHA512 or YESCRYPT). No changes needed."
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
