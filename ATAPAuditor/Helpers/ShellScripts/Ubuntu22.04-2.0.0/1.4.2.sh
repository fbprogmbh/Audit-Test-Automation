#!/usr/bin/env bash

# Define the paths to check for grub.cfg
UBUNTU_GRUB_PATH="/boot/grub/grub.cfg"
REDHAT_GRUB_PATH="/boot/grub2/grub.cfg"

# Function to check permissions
check_permissions() {
	local file_path="$1"
	if [ -f "$file_path" ]; then
		# Get the file's permissions in octal format
		permissions=$(stat -c "%a" "$file_path")
		if [ "$permissions" -eq 600 ]; then
			echo "Permissions for $file_path are correct (600)."
			exit 0
		else
			echo "Permissions for $file_path are incorrect ($permissions)."
			exit 1
		fi
	fi
}

# Check for Ubuntu path
check_permissions "$UBUNTU_GRUB_PATH"

# Check for Red Hat path
check_permissions "$REDHAT_GRUB_PATH"

# If neither file is found, exit with an error
echo "grub.cfg file not found in the expected locations."
exit 1
