#!/usr/bin/env bash
{
    awk -F: '/^[^:]+:[^!*]/{print $1}' /etc/shadow | while read -r usr; do
        change=$(date -d "$(chage --list $usr | grep '^Last password change' | cut -d: -f2 | grep -v 'never$')" +%s);
        if [[ "$change" -gt "$(date +%s)" ]]; then 
            echo "User: \"$usr\" last password change was \"$(chage --list $usr | grep '^Last password change' | cut -d: -f2)\"";
        fi;
    done
}