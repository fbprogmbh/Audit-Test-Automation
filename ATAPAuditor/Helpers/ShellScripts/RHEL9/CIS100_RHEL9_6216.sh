#!/usr/bin/env bash
{
    output=""
    perm_mask='0022'
    maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | (while read -r user home; do
        for dfile in $(find "$home" -type f -name '.*'); do
            mode=$( stat -L -c '%#a' "$dfile" )
            [ $(( $mode & $perm_mask )) -gt 0 ] && output="$output\n- User $user file: \"$dfile\" is too permissive: \"$mode\" (should be: \"$maxperm\" or more restrictive)"
        done
    done
    if [ -n "$output" ]; then
        echo -e "\n- Failed:$output"
    else
        echo -e "\n- Passed:\n- All user home dot files are mode: \"$maxperm\" or more restrictive"
    fi
    )
}