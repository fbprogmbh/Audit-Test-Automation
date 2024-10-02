#!/usr/bin/env bash
{
    output=""
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | (while read -r user home; do
        [ ! -d "$home" ] && output="$output\n - User \"$user\" home directory \"$home\" doesn't exist"
    done
    if [ -z "$output" ]; then
        echo -e "\n-PASSED: - All local interactive users have a home directory\n"
    else
        echo -e "\n- FAILED:\n$output\n"
    fi
    )
}