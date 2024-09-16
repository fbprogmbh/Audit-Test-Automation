#!/usr/bin/env bash
{
    output="" output2="" perm_mask='0177'
    maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | (while read -r user home; do
        if [ -f "$home/.netrc" ]; then mode="$( stat -L -c '%#a' "$home/.netrc" )"
            if [ $(( $mode & $perm_mask )) -gt 0 ]; then
                output="$output\n - User \"$user\" file: \"$home/.netrc\" is too permissive: \"$mode\" (should be: \"$maxperm\" or more restrictive)"
            else
                output2="$output2\n - User \"$user\" file: \"$home/.netrc\" exists and has file mode: \"$mode\" (should be: \"$maxperm\" or more restrictive)"
            fi
        fi
    done
    if [ -z "$output" ]; then
        if [ -z "$output2" ]; then
            echo -e "\n-PASSED: - No local interactive users have \".netrc\" files in their home directory\n"
        else
            echo -e "\n- WARNING:\n$output2\n"
        fi
    else
        echo -e "\n- FAILED:\n$output\n" [ -n "$output2" ] && echo -e "\n- WARNING:\n$output2\n"
    fi
    )
}