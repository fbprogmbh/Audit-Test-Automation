#!/usr/bin/env bash

l_output="" l_output2="" l_perm_mask="0137"
l_maxperm="$(printf '%o' $((0777 & ~$l_perm_mask)))"

# Capture the output of find into a variable
l_files=$(find /etc/audit/ -type f \( -name "*.conf" -o -name '*.rules' \))

# Loop through each file in the list
while IFS= read -r l_fname; do
	# Skip empty lines (in case of any)
	[ -z "$l_fname" ] && continue

	# Get the file mode
	l_mode=$(stat -Lc '%#a' "$l_fname")

	# Check if the file mode matches the permission mask
	if [ $((l_mode & l_perm_mask)) -gt 0 ]; then
		l_output2="$l_output2\n - file: \"$l_fname\" is mode: \"$l_mode\" (should be mode: \"$l_maxperm\" or more restrictive)"
	fi
done <<<"$l_files"

# Output the results
if [ -z "$l_output2" ]; then
	exit 0
else
	exit 1
fi
