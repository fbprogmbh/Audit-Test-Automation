#!/usr/bin/env bash

files_to_check=$(grep -Elz "Password-Type:.*\n.*pam_unix\.so" /usr/share/pam-configs/*)
if [ -z "$files_to_check" ]; then
        echo "No relevant files found."
        exit 0
fi

for file in $files_to_check; do
        if ! grep -Eq "pam_unix\.so.*use_authtok" "$file"; then
                exit 1
        fi
done
exit 0

