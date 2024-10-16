#!/usr/bin/env bash
{
    l_output="" l_output2="" l_zone=""
    if systemctl is-enabled firewalld.service | grep -q 'enabled'; then
        l_zone="$(firewall-cmd --get-default-zone)"
        if [ -n "$l_zone" ]; then
            l_output=" - The default zone is set to: \"$l_zone\""
        else
            l_output2=" - The default zone is not set"
        fi
    else
        l_output=" - FirewallD is not in use on the system"
    fi
    if [ -z "$l_output2" ]; then
        echo -e "\n- Audit Results:\n PASS\n$l_output\n"
    else
        echo -e "\n- Audit Results:\n FAIL\n$l_output2\n"
    fi
}