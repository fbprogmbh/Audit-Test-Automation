#!/usr/bin/env bash
# List of files to check
files=(/sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules)

# Go through each file in the list and check if it exists,if a file does not exist print error
for file in "${files[@]}"; do
	if [ ! -e "$file" ]; then
		echo "Error: at least one file does not exist  "
		exit 1
	fi
done

# Loop to check the owner of each file
for file in "${files[@]}"; do
	# Check if the file is owned by root
	owner=$(stat -c "%U" "$file")
	if [ "$owner" != "root" ]; then
		echo "Error : $file not owned by root (current owner : $owner)"
		exit 1
	fi
done

echo "All files are owned by root."
exit 0
