#!/usr/bin/env bash

pam_path="/usr/share/pam-configs"
pam_files=("faillock" "faillock_notify")

expected_faillock=(
	'Name: Enable pam_faillock to deny access'
	'Default: yes'
	'Priority: 0'
	'Auth-Type: Primary'
	'Auth:        [default=die] pam_faillock.so authfail'
)
expected_faillock_notify=(
	'Name: Notify of failed login attempts and reset count upon success'
	'Default: yes'
	'Priority: 1024'
	'Auth-Type: Primary'
	'Auth:        requisite pam_faillock.so preauth'
	'Account-Type: Primary'
	'Account:     required pam_faillock.so'
)
check_profile() {
	local profile_path="$pam_path/$1"
	local expected_content=("${!2}")

	if [[ ! -f "$profile_path" ]]; then
		echo "ERROR: Profile $profile_path does not exist."
		exit 1
	fi
	echo "Checking profile: $profile_path"
	# Read the actual content of the profile file
	for line in "${expected_content[@]}"; do
		if ! grep -Fxq "$line" "$profile_path"; then
			echo "ERROR: Expected line not found in $profile_path: $line"
			exit 1
		fi
	done
}
check_profile "faillock" expected_faillock[@]
check_profile "faillock_notify" expected_faillock_notify[@]
