#!/usr/bin/env bash
{
        l_output="" l_output2="" l_kparameters="net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0"
        searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"
        kernel_par_chk()
        {
            krp="" pafile="" fafile=""
            krp="$(sysctl "$kpname" | awk -F= '{print $2}' | xargs)"
            pafile="$(grep -Psl -- "^\h*$kpname\h*=\h*$kpvalue\b\h*(#.*)?$" $searchloc)"
            fafile="$(grep -s -- "^\s*$kpname" $searchloc | grep -Pv -- "\h*=\h*$kpvalue\b\h*" | awk -F: '{print $1}')" [ "$krp" = "$kpvalue" ] && l_output="$l_output\n - \"$kpname\" is set to \"$kpvalue\" in the running configuration"
            [ -n "$pafile" ] && l_output="$l_output\n - \"$kpname\" is set to \"$kpvalue\" in \"$pafile\""
            [ -z "$fafile" ] && l_output="$l_output\n - \"$kpname\" is not set incorectly in a kernel parameter configuration file" [ "$krp" != "$kpvalue" ] && l_output2="$l_output2\n - \"$kpname\" is incorrectly set to \"$krp\" in the running configuration"
            [ -n "$fafile" ] && l_output2="$l_output2\n - \"$kpname\" is set incorrectly in \"$fafile\""
            [ -z "$pafile" ] && l_output2="$l_output2\n - \"$kpname = $kpvalue\" is not set in a kernel parameter configuration file"
        }
        for l_kpar in $l_kparameters; do
            kpname="$(awk -F"=" '{print $1}' <<< "$l_kpar" | xargs)" kpvalue="$(awk -F"=" '{print $2}' <<< "$l_kpar" | xargs)"
            if grep -Pq '^\h*net\.ipv6\.' <<< "$l_kpname"; then
                if grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable; then
                    kernel_par_chk
                else
                    l_output="$l_output\n - IPv6 is not enabled, check for: \"$l_kpar\" is not applicable"
                fi
            else
                kernel_par_chk
            fi
        done
        if [ -z "$l_output2" ]; then
            echo -e "\n- Audit Result:\n PASS\n$l_output\n"
        else
            echo -e "\n- Audit Result:\n FAIL\n - Reason(s) for audit failure:\n$l_output2\n"
            [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
        fi
}