#!/usr/bin/env bash

# Define the files to check
FILES=("/etc/at.allow" "/etc/at.deny")

check_file() {
	local file=$1

	# Check if the file exists
	if [ ! -e "$file" ]; then
		echo "File $file does not exist. Ignoring."
		return 0
	fi

	# Get the file permissions in numeric format
	local permissions=$(stat -c "%a" "$file")
	local owner=$(stat -c "%U" "$file")
	local group=$(stat -c "%G" "$file")

	# Check if the file permissions are 0640 or more restrictive
	if [ "$permissions" -gt 640 ]; then
		echo "File $file permissions are not 0640 or more restrictive."
		return 1
	fi

	# Check if the owner is root and group is root
	if [ "$owner" != "root" ] || [ "$group" != "root" ]; then
		echo "File $file owner or group is not root."
		return 1
	fi

	return 0
}

# Check each file
for file in "${FILES[@]}"; do
	if ! check_file "$file"; then
		exit 1
	fi
done

# If all checks pass, exit with status 0
exit 0
