#!/usr/bin/env bash
{
    output=""
    perm_mask='0027'
    maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )" valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | (while read -r user home; do
        mode=$( stat -L -c '%#a' "$home" )
        [ $(( $mode & $perm_mask )) -gt 0 ] && output="$output\n- User $user home directory: \"$home\" is too permissive: \"$mode\" (should be: \"$maxperm\" or more restrictive)"
    done
    if [ -n "$output" ]; then
        echo -e "\n- Failed:$output"
    else
        echo -e "\n- Passed:\n- All user home directories are mode: \"$maxperm\" or more restrictive"
    fi
    )
}