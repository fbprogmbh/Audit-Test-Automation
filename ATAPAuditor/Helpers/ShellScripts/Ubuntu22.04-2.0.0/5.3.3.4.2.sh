#!/usr/bin/env bash

files_to_check=$(grep -El 'pam_unix\.so.*remember=' /usr/share/pam-configs/*)
if [[ -z "$files_to_check" ]]; then
	exit 0
else
	exit 1
fi
