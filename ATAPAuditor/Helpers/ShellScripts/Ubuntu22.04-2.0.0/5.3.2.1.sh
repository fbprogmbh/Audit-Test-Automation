#!/usr/bin/env bash

pam_files=("/etc/pam.d/common-account" "/etc/pam.d/common-session" "/etc/pam.d/common-auth" "/etc/pam.d/common-password")
pam_module="pam_unix.so"
error_found=false

for file in "${pam_files[@]}"; do
	echo "Checking $file..."
	if grep -q "$pam_module" "$file"; then
		echo "OK: $pam_module is enabled in $file"
	else
		echo "Error: $pam_module is NOT enabled in $file"
		error_found=true
	fi
done

if [ "$error_found" = true ]; then
	echo "Test Failed: pam_unix.so is NOT enabled in all PAM configuration files."
	exit 1
else
	echo "Test Passed: pam_unix.so is enabled in all PAM configuration files."
	exit 0
fi
