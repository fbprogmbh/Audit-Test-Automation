#!/usr/bin/env bash
{
    output="" l_tsd="" l_sdtd="" chrony="" l_ntp=""
    dpkg-query -W chrony >/dev/null 2>&1 && l_chrony="y"
    dpkg-query -W ntp >/dev/null 2>&1 && l_ntp="y" || l_ntp=""
    systemctl list-units --all --type=service | grep -q 'systemd-
timesyncd.service' && systemctl is-enabled systemd-timesyncd.service | grep -q 'enabled' && l_sdtd="y"
    # ! systemctl is-enabled systemd-timesyncd.service | grep -q 'enabled' &&
    l_nsdtd="y" || l_nsdtd=""
    if [[ "$l_chrony" = "y" && "$l_ntp" != "y" && "$l_sdtd" != "y" ]]; then
        l_tsd="chrony"
        output="$output\n- chrony is in use on the system"
    elif [[ "$l_chrony" != "y" && "$l_ntp" = "y" && "$l_sdtd" != "y" ]]; then
        l_tsd="ntp"
        output="$output\n- ntp is in use on the system"
    elif [[ "$l_chrony" != "y" && "$l_ntp" != "y" ]]; then
        if
            systemctl list-units --all --type=service | grep -q 'systemd-
timesyncd.service' && systemctl is-enabled systemd-timesyncd.service | grep -Eq '(enabled|disabled|masked)'
        then
            l_tsd="sdtd"
            output="$output\n- systemd-timesyncd is in use on the system"
        fi
    else
        [[ "$l_chrony" = "y" && "$l_ntp" = "y" ]] && output="$output\n- both
chrony and ntp are in use on the system"
        [[ "$l_chrony" = "y" && "$l_sdtd" = "y" ]] && output="$output\n- both
chrony and systemd-timesyncd are in use on the system"
        [[ "$l_ntp" = "y" && "$l_sdtd" = "y" ]] && output="$output\n- both ntp
and systemd-timesyncd are in use on the system"
    fi
    if [ -n "$l_tsd" ]; then
        echo -e "\n- PASS:\n$output\n"
    else
        echo -e "\n- FAIL:\n$output\n"
    fi
}
