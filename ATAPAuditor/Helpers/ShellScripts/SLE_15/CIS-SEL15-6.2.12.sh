#!/bin/bash
awk -F: '($1 !~ /^(root|halt|sync|shutdown)$/ && $7 != "'"$(which nologin)"'" && $7 != "/bin/false" && $7 != "/usr/bin/false") { print $1 " " $6 }' /etc/passwd | while read user dir; do
    if [ ! -d "$dir" ]; then
        echo "The home directory ($dir) of user $user does not exist."
    else
        for file in $dir/.rhosts; do
            if [ ! -h "$file" -a -e "$file" ]; then
                echo ".rhosts file in $dir"
            fi
        done
    fi
done