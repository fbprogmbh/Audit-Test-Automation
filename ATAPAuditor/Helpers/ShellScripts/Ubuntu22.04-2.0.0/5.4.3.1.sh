#!/usr/bin/env bash
# Define the word to search for
PATTERN="nologin"
FILE="/etc/shells"

# Check if the configuration file exists
if [ ! -f "$FILE" ]; then
	echo "File $FILE not found."
	exit 1
fi

grep -q -E "$PATTERN" "$FILE" >/dev/null
FOUND=$?

if [ $FOUND -eq 0 ]; then

	echo "The line containing '$PATTERN' is in the File $FILE."
	exit 1
else
	echo "$PATTERN is not in the File or not Found"
	exit 0

fi
