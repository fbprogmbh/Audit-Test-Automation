#!/usr/bin/env bash
{
    # Check if GNOME Desktop Manager is installed. If package isn't installed, recommendation is Not Applicable\n
    # determine system's package manager
    l_pkgoutput=""
    if command -v dpkg-query >/dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm >/dev/null 2>&1; then
        l_pq="rpm -q"
    fi
    # Check if GDM is installed
    l_pcl="gdm gdm3" # Space seporated list of packages to check
    for l_pn in $l_pcl; do
        $l_pq "$l_pn" >/dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n -Package: \"$l_pn\" exists on the system\n - checking configuration"
    done
    # Check configuration (If applicable)
    if [ -n "$l_pkgoutput" ]; then
        l_output="" l_output2=""
        # Look for idle-delay to determine profile in use, needed for remaining    tests
        l_kfd="/etc/dconf/db/$(grep -Psril '^\h*idle-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d" #set directory of key file to be locked
        l_kfd2="/etc/dconf/db/$(grep -Psril '^\h*lock-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d"       #set directory of key file to be locked
        if [ -d "$l_kfd" ]; then # If key file directory doesn't exist, options can't be locked
            if
                grep -Prilq '\/org\/gnome\/desktop\/session\/idle-delay\b'
                "$l_kfd"
            then
                l_output="$l_output\n - \"idle-delay\" is locked in \"$(
                    grep -Pril '\/org\/gnome\/desktop\/session\/idle-delay\b' "$l_kfd"
                )\""
            else
                l_output2="$l_output2\n - \"idle-delay\" is not locked"
            fi
        else
            l_output2="$l_output2\n - \"idle-delay\" is not set so it can not be locked"
        fi
        if [ -d "$l_kfd2" ]; then # If key file directory doesn't exist, options can't be locked
            if
                grep -Prilq '\/org\/gnome\/desktop\/screensaver\/lock-delay\b'
                "$l_kfd2"
            then
                l_output="$l_output\n - \"lock-delay\" is locked in \"$(
                    grep -
                    Pril '\/org\/gnome\/desktop\/screensaver\/lock-delay\b' "$l_kfd2"
                )\""
            else
                l_output2="$l_output2\n - \"lock-delay\" is not locked"
            fi
        else
            l_output2="$l_output2\n - \"lock-delay\" is not set so it can not be
locked"
        fi
    else
        l_output="$l_output\n - GNOME Desktop Manager package is not installed
on the system\n - Recommendation is not applicable"
    fi
    # Report results. If no failures output in l_output2, we pass
    [ -n "$l_pkgoutput" ] && echo -e "\n$l_pkgoutput"
    if [ -z "$l_output2" ]; then
        echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
    else
        echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit
failure:\n$l_output2\n"
        [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
    fi
}
