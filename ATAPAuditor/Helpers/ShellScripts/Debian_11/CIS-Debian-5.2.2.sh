#!/usr/bin/env bash

{
    l_output=""
    l_skgn="ssh_keys" # Group designated to own openSSH keys
    l_skgid="$(awk -F: '($1 == "'"$l_skgn"'"){print $3}' /etc/group)"
    awk '{print}' <<<"$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat -L -c "%n %#a %U %G %g" {} +)" | (
        while read -r l_file l_mode l_owner l_group l_gid; do
            [ -n "$l_skgid" ] && l_cga="$l_skgn" || l_cga="root"
            [ "$l_gid" = "$l_skgid" ] && l_pmask="0137" || l_pmask="0177"
            l_maxperm="$(printf '%o' $((0777 & ~$l_pmask)))"
            [ $(($l_mode & $l_pmask)) -gt 0 ] && l_output="$l_output\n - File: \"$l_file\" is mode \"$l_mode\" should be mode: \"$l_maxperm\" or more restrictive"
            [ "$l_owner" != "root" ] && l_output="$l_output\n - File: \"$l_file\" is owned by: \"$l_owner\" should be owned by \"root\""
            if [ "$l_group" != "root" ] && [ "$l_gid" != "$l_skgid" ]; then
                l_output="$l_output\n - File: \"$l_file\" is owned by group \"$l_group\" should belong to group \"$l_cga\""
            fi
        done
        if [ -z "$l_output" ]; then
            echo -e "\n- Audit Result:\n *** PASS ***\n"
        else
            echo -e "\n- Audit Result:\n *** FAIL ***$l_output\n"
        fi
    )
}
