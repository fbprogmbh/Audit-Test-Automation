#!/usr/bin/env bash
{
    # Check if GNMOE Desktop Manager is installed. If package isn't installed, recommendation is Not Applicable\n
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
        l_idmv="900" # Set for max value for idle-delay in seconds
        l_ldmv="5"   # Set for max value for lock-delay in seconds
        # Look for idle-delay to determine profile in use, needed for remaining tests
        l_kfile="$(grep -Psril '^\h*idle-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/ )" # Determine file containing idle-delay key
        if [ -n "$l_kfile" ]; then
            # set profile name (This is the name of a dconf database)
            l_profile="$(awk -F'/' '{split($(NF-1),a,".");print a[1]}' <<<"$l_kfile")" #Set the key profile name
            l_pdbdir="/etc/dconf/db/$l_profile.d"                                      # Set the key file dconf db directory
            # Confirm that idle-delay exists, includes unit32, and value is   between 1 and max value for idle-delay
            l_idv="$(awk -F 'uint32' '/idle-delay/{print $2}' "$l_kfile" |     xargs)"
            if [ -n "$l_idv" ]; then
                [ "$l_idv" -gt "0" -a "$l_idv" -le "$l_idmv" ] && l_output="$l_output\n - The \"idle-delay\" option is set to \"$l_idv\" seconds in \"$l_kfile\""
                [ "$l_idv" = "0" ] && l_output2="$l_output2\n - The \"idle-delay\" option is set to \"$l_idv\" (disabled) in \"$l_kfile\""
                [ "$l_idv" -gt "$l_idmv" ] && l_output2="$l_output2\n - The \"idle-delay\" option is set to \"$l_idv\" seconds (greater than $l_idmv) in \"$l_kfile\""
            else
                l_output2="$l_output2\n - The \"idle-delay\" option is not set in \"$l_kfile\""
            fi
            # Confirm that lock-delay exists, includes unit32, and value is between 0 and max value for lock-delay
            l_ldv="$(awk -F 'uint32' '/lock-delay/{print $2}' "$l_kfile" |xargs)"
            if [ -n "$l_ldv" ]; then
                [ "$l_ldv" -ge "0" -a "$l_ldv" -le "$l_ldmv" ] && l_output="$l_output\n - The \"lock-delay\" option is set to \"$l_ldv\" seconds in \"$l_kfile\""
                [ "$l_ldv" -gt "$l_ldmv" ] && l_output2="$l_output2\n - The \"lock-delay\" option is set to \"$l_ldv\" seconds (greater than $l_ldmv) in \"$l_kfile\""
            else
                l_output2="$l_output2\n - The \"lock-delay\" option is not set in \"$l_kfile\""
            fi
            # Confirm that dconf profile exists
            if grep -Psq "^\h*system-db:$l_profile" /etc/dconf/profile/*; then 
		l_output="$l_output\n - The \"$l_profile\" profile exists"
            else
                l_output2="$l_output2\n - The \"$l_profile\" doesn't exist"
            fi
            # Confirm that dconf profile database file exists
            if [ -f "/etc/dconf/db/$l_profile" ]; then
                l_output="$l_output\n - The \"$l_profile\" profile exists in the dconf database"
            else
                l_output2="$l_output2\n - The \"$l_profile\" profile doesn't exist in the dconf database"
            fi
        else
            l_output2="$l_output2\n - The \"idle-delay\" option doesn't exist, remaining tests skipped"
        fi
    else
        l_output="$l_output\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
    fi
    # Report results. If no failures output in l_output2, we pass
    [ -n "$l_pkgoutput" ] && echo -e "\n$l_pkgoutput"
    if [ -z "$l_output2" ]; then
        echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
    else
        echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
        [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
    fi
}
