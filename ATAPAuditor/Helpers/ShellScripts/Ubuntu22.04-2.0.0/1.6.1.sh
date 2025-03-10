#!/usr/bin/env bash
# Extract the OS ID from /etc/os-release
OS_ID=$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g')

# Run the grep command with the OS ID incorporated
grep -Eis "(\\v|\\r|\\m|\\s|$OS_ID)" /etc/motd

# Check the exit code of the grep command
if [ $? -ne 0 ]; then
	# Grep did not find any matches, return 0
	exit 0
else
	# Grep found matches, return 1
	exit 1
fi
