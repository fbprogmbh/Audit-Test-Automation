#!/usr/bin/env bash
{
    output=""
    fname=".forward"
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | (while read -r user home; do
        [ -f "$home/$fname" ] && output="$output\n - User \"$user\" file: \"$home/$fname\" exists"
    done
    if [ -z "$output" ]; then
        echo -e "\n-PASSED: - No local interactive users have \"$fname\" files in their home directory\n"
    else
        echo -e "\n- FAILED:\n$output\n"
    fi
    )
}