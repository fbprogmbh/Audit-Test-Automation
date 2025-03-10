#!/usr/bin/env bash

pam_path="/usr/share/pam-configs"
profile_name="pwquality"

expected_content=(
	'Name: Pwquality password strength checking'
	'Default: yes'
	'Priority: 1024'
	'Conflicts: cracklib'
	'Password-Type: Primary'
	'Password:' 'requisite pam_pwquality.so retry=3'
	'Password-Initial:'
	'requisite'
)
# check if the pwquality exists
if [[ -f "$pam_path/$profile_name" ]]; then
	echo "$profile_name profile found in $pam_path:"
else
	echo "ERROR: $profile_name profile not found in $pam_path."
	exit 1
fi

# check content of pwquality
for line in "${expected_pwquality[@]}"; do
	if ! grep -Fxq "$line" "$pam_path/$profile_name"; then
		echo "ERROR: Expected line not found in $profile_name: $line"
		exit 1
	fi
done
echo "pwquality profile content in $pam_path/$profile_name is correct."
exit 0
