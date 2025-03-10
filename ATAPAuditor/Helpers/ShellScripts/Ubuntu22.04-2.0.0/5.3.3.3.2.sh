#!/usr/bin/env bash

files_to_check=$(awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if (/pam_pwhistory\.so/) print FILENAME}' /usr/share/pam-configs/*)
if [[ -z $files_to_check ]]; then
	echo "file was not  found"
else
	for file in "$files_to_check"; do
		if grep -Eq "pam_pwhistory\.so.*enforce_for_root" "$file"; then
			exit 0
		else
			exit 1
		fi
	done
	exit 1
fi
