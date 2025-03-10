#!/usr/bin/env bash

pam_path="/usr/share/pam-configs"
profile_name="pwhistory"

expected_content=(
	'Name: pwhistory password history checking'
	'Default: yes'
	'Priority: 1024'
	'Password-Type: Primary' 'Password:'
	'requisite pam_pwhistory.so remember=24 enforce_for_root try_first_pass use_authtok'
)

# check content of pwhistory
if [[ -f "$pam_path/$profile_name" ]]; then
	echo "$profile_name profile found in $pam_path:"
else
	echo "ERROR: $profile_name profile not found in $pam_path."
	exit 1
fi

# check content of pwhistory
for line in "${expected_pwquality[@]}"; do
	if ! grep -Fxq "$line" "$pam_path/$profile_name"; then
		echo "ERROR: Expected line not found in $profile_name: $line"
		exit 1
	fi
done
echo "$profile_name profile content in $pam_path/$profile_name is correct."
exit 0
