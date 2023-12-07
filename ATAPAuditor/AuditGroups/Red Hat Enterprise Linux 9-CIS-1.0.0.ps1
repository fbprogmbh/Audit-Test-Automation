$parentPath = Split-Path -Parent -Path $PSScriptRoot
$rcTrue = "True"
$rcCompliant = "Compliant"
$rcFalse = "False"
$rcNonCompliant = "Non-Compliant"
$rcNonCompliantManualReviewRequired = "Manual review required"
$rcCompliantIPv6isDisabled = "IPv6 is disabled"

$retCompliant = @{
    Message = $rcCompliant
    Status = $rcTrue
}
$retNonCompliant = @{
    Message = $rcNonCompliant
    Status = $rcFalse
}
$retCompliantIPv6Disabled = @{
    Message = $rcCompliantIPv6isDisabled
    Status = $rcTrue
}
$retNonCompliantManualReviewRequired = @{
    Message = $rcNonCompliantManualReviewRequired
    Status = $rcFalse
}

$IPv6Status_script = @'
#!/bin/bash
[ -n "$passing" ] && passing=""
[ -z "$(grep "^\s*linux" /boot/grub2/grub.cfg | grep -v ipv6.disabled=1)" ] && passing="true"
grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" /etc/sysctl.conf /etc/sysctl.d/*.conf && grep -Eq "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" /etc/sysctl.conf /etc/sysctl.d/*.conf && sysctl net.ipv6.conf.all.disable_ipv6 | grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" && sysctl net.ipv6.conf.default.disable_ipv6 | grep -Eq "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" && passing="true"
if [ "$passing" = true ] ; then
    echo "IPv6 is disabled on the system"
else
    echo "IPv6 is enabled on the system"
fi
'@
$IPv6Status = bash -c $IPv6Status_script
if ($IPv6Status -match "enabled") {
    $IPv6Status = "enabled"
} else {
    $IPv6Status = "disabled"
}

### Chapter 1 - Initial Setup


[AuditTest] @{
    Id = "1.1.1.1"
    Task = "Ensure mounting of squashfs filesystems is disabled"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    l_output="" l_output2=""
    l_mname="squashfs"
    if [ -z "$(modprobe -n -v "$l_mname" 2>&1 | grep -Pi -- "\h*modprobe:\h+FATAL:\h+Module\h+$l_mname\h+not\h+found\h+in\h+directory")" ]; then
        l_loadable="$(modprobe -n -v "$l_mname")"
        [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P -- "(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
        if grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
            l_output="$l_output\n - module: \"$l_mname\" is not loadable: \"$l_loadable\""
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is loadable: \"$l_loadable\""
        fi
        if ! lsmod | grep "$l_mname" > /dev/null 2>&1; then
            l_output="$l_output\n - module: \"$l_mname\" is not loaded"
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is loaded"
        fi
        if modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mname\b"; then
            l_output="$l_output\n - module: \"$l_mname\" is deny listed in: \"$(grep -Pl -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*)\""
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is not deny listed"
        fi
    else
        l_output="$l_output\n - Module \"$l_mname\" doesn't exist on the system"
    fi
    if [ -z "$l_output2" ]; then
        echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
    else
        echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
    fi
}
'@
        $script = bash -c $script_string
        if ($script -match "** PASS **") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.1.2"
    Task = "Ensure mounting of udf filesystems is disabled"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    l_output="" l_output2=""
    l_mname="udf"
    if [ -z "$(modprobe -n -v "$l_mname" 2>&1 | grep -Pi -- "\h*modprobe:\h+FATAL:\h+Module\h+$l_mname\h+not\h+found\h+in\h+directory")" ]; then
        l_loadable="$(modprobe -n -v "$l_mname")"
        [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P -- "(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
        if grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
            l_output="$l_output\n - module: \"$l_mname\" is not loadable: \"$l_loadable\""
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is loadable: \"$l_loadable\""
        fi
        if ! lsmod | grep "$l_mname" > /dev/null 2>&1; then
            l_output="$l_output\n - module: \"$l_mname\" is not loaded"
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is loaded"
        fi
        if modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mname\b"; then
            l_output="$l_output\n - module: \"$l_mname\" is deny listed in: \"$(grep -Pl -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*)\""
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is not deny listed"
        fi
    else
        l_output="$l_output\n - Module \"$l_mname\" doesn't exist on the system"
    fi
    if [ -z "$l_output2" ]; then
        echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
    else
        echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
    fi
}
'@
        $script = bash -c $script_string
        if ($script -match "** PASS **") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.2.1"
    Task = "Ensure /tmp is a separate partition"
    Test = {
        $result = findmnt --kernel /tmp | grep -E '\s/tmp\s'
        if ($result -match "/tmp") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.2.2"
    Task = "Ensure nodev option set on /tmp partition"
    Test = {
        $result = findmnt --kernel /tmp | grep nodev
        if ($result -match "/tmp") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.2.3"
    Task = "Ensure noexec option set on /tmp partition"
    Test = {
        $result = findmnt --kernel /tmp | grep noexec
        if ($result -match "/tmp") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.2.4"
    Task = "Ensure nosuid option set on /tmp partition"
    Test = {
        $result = findmnt --kernel /tmp | grep nosuid
        if ($result -match "/tmp") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.3.1"
    Task = "Ensure separate partition exists for /var"
    Test = {
        $result = findmnt --kernel /var
        if ($result -match "/var") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id = "1.1.3.2"
    Task = "Ensure nodev option set on /var partition"
    Test = {
        $result = findmnt --kernel /var | grep nodev
        if ($result -match "/var") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.3.3"
    Task = "Ensure nosuid option set on /var partition"
    Test = {
        $result = findmnt --kernel /var | grep nosuid
        if ($result -match "/var") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.4.1"
    Task = "Ensure separate partition exists for /var/tmp"
    Test = {
        $result = findmnt --kernel /var/tmp
        if ($result -match "/var/tmp") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.4.2"
    Task = "Ensure noexec option set on /var/tmp partition"
    Test = {
        $result = findmnt --kernel /var/tmp | grep noexec
        if ($result -match "/var/tmp") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.4.3"
    Task = "Ensure nosuid option set on /var/tmp partition"
    Test = {
        $result = findmnt --kernel /var/tmp | grep nosuid
        if ($result -match "/var/tmp") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.4.4"
    Task = "Ensure nodev option set on /var/tmp partition"
    Test = {
        $result = findmnt --kernel /var/tmp | grep nodev
        if ($result -match "/tmp") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.5.1"
    Task = "Ensure separate partition exists for /var/log"
    Test = {
        $result = findmnt --kernel /var/log
        if ($result -match "/var/log") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.5.2"
    Task = "Ensure nodev option set on /var/log"
    Test = {
        $result = findmnt --kernel /var/log | grep nodev
        if ($result -match "/var/log") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.5.3"
    Task = "Ensure noexec option set on /var/log"
    Test = {
        $result = findmnt --kernel /var/log | grep noexec
        if ($result -match "/var/log") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.5.4"
    Task = "Ensure nosuid option set on /var/log"
    Test = {
        $result = findmnt --kernel /var/log | grep nosuid
        if ($result -match "/var/log") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.6.1"
    Task = "Ensure separate partition exists for /var/log/audit"
    Test = {
        $result = findmnt --kernel /var/log/audit
        if ($result -match "/var/log/audit") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.6.2"
    Task = "Ensure noexec option set on /var/log/audit"
    Test = {
        $result = findmnt --kernel /var/log/audit | grep noexec
        if ($result -match "/var/log/audit") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.6.3"
    Task = "Ensure nodev option set on /var/log/audit"
    Test = {
        $result = findmnt --kernel /var/log/audit | grep nodev
        if ($result -match "/var/log/audit") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.6.4"
    Task = "Ensure nosuid option set on /var/log/audit"
    Test = {
        $result = findmnt --kernel /var/log/audit | grep nosuid
        if ($result -match "/var/log/audit") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.7.1"
    Task = "Ensure separate partition exists for /home"
    Test = {
        $result = findmnt --kernel /home
        if ($result -match "/home") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.7.2"
    Task = "Ensure nodev option set on /home"
    Test = {
        $result = findmnt --kernel /home | grep nodev
        if ($result -match "/home") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.7.3"
    Task = "Ensure nosuid option set on /home"
    Test = {
        $result = findmnt --kernel /home | grep nosuid
        if ($result -match "/home") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.8.1"
    Task = "Ensure /dev/shm is a separate partition"
    Test = {
        $result = findmnt --kernel /dev/shm
        if ($result -match "/dev/shm") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.8.2"
    Task = "Ensure nodev option set on /dev/shm partition"
    Test = {
        $result = mount | grep -E '\s/dev/shm\s' | grep nodev
        if ($result -match "/dev/shm") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.8.3"
    Task = "Ensure noexec option set on /dev/shm partition"
    Test = {
        $result = findmnt --kernel /dev/shm | grep noexec
        if ($result -match "/dev/shm") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.8.4"
    Task = "Ensure nosuid option set on /dev/shm partition"
    Test = {
        $result = findmnt --kernel /dev/shm | grep nosuid
        if ($result -match "/dev/shm") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.9"
    Task = "Disable USB Storage"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    l_output="" l_output2=""
    l_mname="usb-storage" # set module name
    # Check if the module exists on the system
    if [ -z "$(modprobe -n -v "$l_mname" 2>&1 | grep -Pi -- "\h*modprobe:\h+FATAL:\h+Module\h+$l_mname\h+not\h+found\h+in\h+directory")" ]; then
        l_loadable="$(modprobe -n -v "$l_mname")"
        [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P -- "(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
        if grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
            l_output="$l_output\n - module: \"$l_mname\" is not loadable: \"$l_loadable\""
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is loadable: \"$l_loadable\""
        fi
        # Check is the module currently loaded
        if ! lsmod | grep "$l_mname" > /dev/null 2>&1; then
            l_output="$l_output\n - module: \"$l_mname\" is not loaded"
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is loaded"
        fi
        # Check if the module is deny listed
        if modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$(tr '-' '_' <<< "$l_mname")\b"; then
            l_output="$l_output\n - module: \"$l_mname\" is deny listed in: \"$(grep -Pl -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*)\""
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is not deny listed"
        fi
    else
        l_output="$l_output\n - Module \"$l_mname\" doesn't exist on the system"
    fi
    # Report results. If no failures output in l_output2, we pass
    if [ -z "$l_output2" ]; then
        echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
    else
        echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
    fi
}
'@
        $script = bash -c $script_string
        if ($script -match "** PASS **") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.2.1"
    Task = "Ensure GPG keys are configured"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "1.2.2"
    Task = "Ensure gpgcheck is globally activated"
    Test = {
        $result = grep ^gpgcheck /etc/dnf/dnf.conf
        if ($result -match "gpgcheck=1") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.2.3"
    Task = "Ensure package manager repositories are configured"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

# TODO
[AuditTest] @{
    Id = "1.2.4"
    Task = "Ensure repo_gpgcheck is globally activated"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "1.3.1"
    Task = "Ensure aide is installed"
    Test = {
        $result = rpm -q aide
        if ($result -match "aide-") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.3.2"
    Task = "Ensure filesystem integrity is regularly checked"
    Test = {
        $result1 = systemctl is-enabled aidecheck.service
        $result2 = systemctl is-enabled aidecheck.timer
        $result3 = systemctl status aidecheck.service
        if ($result1 -match "enabled" -and $result2 -match "enabled" -and $result3 -match "Active:") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.3.3"
    Task = "Ensure filesystem integrity is regularly checked"
    Test = {
        $result = grep -Ps -- '(\/sbin\/(audit|au)\H*\b)' /etc/aide.conf.d/*.conf /etc/aide.conf
        if ($result -match "/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" -and
        $result -match "/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512" -and
        $result -match "/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512" -and
        $result -match "/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512" -and
        $result -match "/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512" -and
        $result -match "/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.4.1"
    Task = "Ensure bootloader password is set"
    Test = {
        $result = awk -F. '/^\s*GRUB2_PASSWORD/ {print $1"."$2"."$3}' /boot/grub2/user.cfg
        if ($result -match "GRUB2_PASSWORD=grub.pbkdf2.sha512") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.4.2"
    Task = "Ensure permissions on bootloader config are configured"
    Test = {
        $result1 = stat -Lc "%n %#a %u/%U %g/%G" /boot/grub2/grub.cfg | grep '/boot/grub2/grub.cfg\s*0700\s*0/root\s*0/root'
        $result2 = stat -Lc "%n %#a %u/%U %g/%G" /boot/grub2/grubenv | grep '/boot/grub2/grubenv\s*0600\s*0/root\s*0/root'
        $result3 = stat -Lc "%n %#a %u/%U %g/%G" /boot/grub2/user.cfg | grep '/boot/grub2/user.cfg\s*0600\s*0/root\s*0/root'
        if ($result1 -ne $null -and $result2 -ne $null -and $result3 -ne $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.5.1"
    Task = "Ensure core dump storage is disabled"
    Test = {
        $result = grep -i '^\s*storage\s*=\s*none' /etc/systemd/coredump.conf
        if ($result -match "Storage=none") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

#TODO
[AuditTest] @{
    Id = "1.5.2"
    Task = "Ensure core dump backtraces are disabled"
    Test = {
        $result = grep -Pi '^\h*ProcessSizeMax\h*=\h*0\b' /etc/systemd/coredump.conf || echo -e "\n- Audit results:\n ** Fail **\n - \"ProcessSizeMax\" is: \"$(grep -i 'ProcessSizeMax' /etc/systemd/coredump.conf)\""
        if ($result -match "ProcessSizeMax=0") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.5.3"
    Task = "Ensure address space layout randomization (ASLR) is enabled"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    l_output="" l_output2=""
    l_parlist="kernel.randomize_va_space=2"
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"
    KPC()
    {
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        l_pafile="$(grep -Psl -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc)"
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        if [ "$l_krp" = "$l_kpvalue" ]; then
            l_output="$l_output\n - \"$l_kpname\" is set to \"$l_kpvalue\" in the running configuration"
        else
            l_output2="$l_output2\n - \"$l_kpname\" is set to \"$l_krp\" in the running configuration"
        fi
        if [ -n "$l_pafile" ]; then
            l_output="$l_output\n - \"$l_kpname\" is set to \"$l_kpvalue\" in \"$l_pafile\""
        else
            l_output2="$l_output2\n - \"$l_kpname = $l_kpvalue\" is not set in a kernel parameter configuration file"
        fi
        [ -n "$l_fafile" ] && l_output2="$l_output2\n - \"$l_kpname\" is set incorrectly in \"$l_fafile\""
    }
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        KPC
    done
    if [ -z "$l_output2" ]; then
        echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
    else
        echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
    fi
}
'@
        $script = bash -c $script_string
        if ($script -match "** PASS **") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.6.1.1"
    Task = "Ensure SELinux is installed"
    Test = {
        $result = rpm -q libselinux
        if ($result -match "libselinux-") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.6.1.2"
    Task = "Ensure SELinux is not disabled in bootloader configuration"
    Test = {
        $result = grubby --info=ALL | grep -Po '(selinux|enforcing)=0\b'
        if ($result -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.6.1.3"
    Task = "Ensure SELinux policy is configured"
    Test = {
        $result1 = grep -E '^\s*SELINUXTYPE=(targeted|mls)\b' /etc/selinux/config
        $result2 = sestatus | grep Loaded
        if (($result1 -match "targeted" -or $result1 -match "mls") -and ($result2 -match "targeted" -or $result2 -match "mls")) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.6.1.4"
    Task = "Ensure the SELinux mode is not disabled"
    Test = {
        $result1 = getenforce
        $result2 = grep -Ei '^\s*SELINUX=(enforcing|permissive)' /etc/selinux/config
        if (($result1 -match "Enforcing" -or $result1 -match "Permissive") -and ($result2 -match "SELINUX=enforcing" -or $result2 -match "SELINUX=permissive")) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.6.1.5"
    Task = "Ensure the SELinux mode is enforcing"
    Test = {
        $result1 = getenforce
        $result2 = grep -i SELINUX=enforcing /etc/selinux/config
        if ($result1 -match "Enforcing" -and $result2 -match "SELINUX=enforcing") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.6.1.6"
    Task = "Ensure no uncofined services exist"
    Test = {
        $result = ps -eZ | grep unconfined_service_t
        if ($result -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.6.1.7"
    Task = "Ensure SETroubleshoot is not installed"
    Test = {
        $result = rpm -q setroubleshoot
        if ($result -match "is not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.6.1.8"
    Task = "Ensure the MCS Translation Service (mcstrans) is not installed"
    Test = {
        $result = rpm -q mcstrans
        if ($result -match "is not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.7.1"
    Task = "Ensure the MCS Translation Service (mcstrans) is not installed"
    Test = {
        $result = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/motd
        if ($result -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.7.2"
    Task = "Ensure local login warning banner is configured properly"
    Test = {
        $result = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue
        if ($result -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.7.3"
    Task = "Ensure remote login warning banner is configured properly"
    Test = {
        $result = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net
        if ($result -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.7.4"
    Task = "Ensure permissions on /etc/motd are configured"
    Test = {
        $result = stat -L /etc/motd | grep 'Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)'
        if ($result -match "0644") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.7.5"
    Task = "Ensure permissions on /etc/motd are configured"
    Test = {
        $result = stat -L /etc/issue | grep 'Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)'
        if ($result -match "0644") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.7.6"
    Task = "Ensure permissions on /etc/motd are configured"
    Test = {
        $result = stat -L /etc/issue.net | grep 'Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)'
        if ($result -match "0644") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.1"
    Task = "Ensure GNOME Display Manager is removed"
    Test = {
        $result = rpm -q gdm
        if ($result -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.2"
    Task = "Ensure GDM login banner is configured"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    l_pkgoutput=""
    if command -v dpkg-query > /dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm > /dev/null 2>&1; then
        l_pq="rpm -q"
    fi
    l_pcl="gdm gdm3"
    for l_pn in $l_pcl; do
        $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration"
    done
    if [ -n "$l_pkgoutput" ]; then
        l_output="" l_output2=""
        echo -e "$l_pkgoutput" # Look for existing settings and set variables if they exist
        l_gdmfile="$(grep -Prils '^\h*banner-message-enable\b' /etc/dconf/db/*.d)"
        if [ -n "$l_gdmfile" ]; then
            # Set profile name based on dconf db directory ({PROFILE_NAME}.d)
            l_gdmprofile="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_gdmfile")" # Check if banner message is enabled
            if grep -Pisq '^\h*banner-message-enable=true\b' "$l_gdmfile"; then
                l_output="$l_output\n - The \"banner-message-enable\" option is enabled in \"$l_gdmfile\""
            else
                l_output2="$l_output2\n - The \"banner-message-enable\" option is not enabled"
            fi
            l_lsbt="$(grep -Pios '^\h*banner-message-text=.*$' "$l_gdmfile")"
            if [ -n "$l_lsbt" ]; then
                l_output="$l_output\n - The \"banner-message-text\" option is set in \"$l_gdmfile\"\n - banner-message-text is set to:\n - \"$l_lsbt\""
            else
                l_output2="$l_output2\n - The \"banner-message-text\" option is not set"
            fi
            if grep -Pq "^\h*system-db:$l_gdmprofile" /etc/dconf/profile/"$l_gdmprofile"; then
                l_output="$l_output\n - The \"$l_gdmprofile\" profile exists"
            else
                l_output2="$l_output2\n - The \"$l_gdmprofile\" profile doesn't exist"
            fi
            if [ -f "/etc/dconf/db/$l_gdmprofile" ]; then
                l_output="$l_output\n - The \"$l_gdmprofile\" profile exists in the dconf database"
            else
                l_output2="$l_output2\n - The \"$l_gdmprofile\" profile doesn't exist in the dconf database"
            fi
        else
            l_output2="$l_output2\n - The \"banner-message-enable\" option isn't configured"
        fi
    else
        echo -e "\n\n - GNOME Desktop Manager isn't installed\n - Recommendation is Not Applicable\n- Audit result:\n *** PASS ***\n"
    fi # Report results. If no failures output in l_output2, we pass
    if [ -z "$l_output2" ]; then
        echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
    else
        echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
    fi
}
'@
        $script = bash -c $script_string
        if ($script -match "** PASS **") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.3"
    Task = "Ensure GDM disable-user-list option is enabled"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    l_pkgoutput=""
    if command -v dpkg-query > /dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm > /dev/null 2>&1; then
        l_pq="rpm -q" fi l_pcl="gdm gdm3"
        for l_pn in $l_pcl; do
            $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration"
        done
        if [ -n "$l_pkgoutput" ]; then
            output="" output2=""
            l_gdmfile="$(grep -Pril '^\h*disable-user-list\h*=\h*true\b' /etc/dconf/db)"
            if [ -n "$l_gdmfile" ]; then
                output="$output\n - The \"disable-user-list\" option is enabled in \"$l_gdmfile\""
                l_gdmprofile="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_gdmfile")"
                if grep -Pq "^\h*system-db:$l_gdmprofile" /etc/dconf/profile/"$l_gdmprofile"; then
                    output="$output\n - The \"$l_gdmprofile\" exists"
                else
                    output2="$output2\n - The \"$l_gdmprofile\" doesn't exist"
                fi
                if [ -f "/etc/dconf/db/$l_gdmprofile" ]; then
                    output="$output\n - The \"$l_gdmprofile\" profile exists in the dconf database"
                else
                    output2="$output2\n - The \"$l_gdmprofile\" profile doesn't exist in the dconf database"
                fi
            else
                output2="$output2\n - The \"disable-user-list\" option is not enabled"
            fi
            if [ -z "$output2" ]; then
                echo -e "$l_pkgoutput\n- Audit result:\n *** PASS: ***\n$output\n"
            else
                echo -e "$l_pkgoutput\n- Audit Result:\n *** FAIL: ***\n$output2\n" [ -n "$output" ] && echo -e "$output\n"
            fi
        else
        echo -e "\n\n - GNOME Desktop Manager isn't installed\n - Recommendation is Not Applicable\n- Audit result:\n *** PASS ***\n"
    fi
}
'@
        $script = bash -c $script_string
        if ($script -match "** PASS **") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.4"
    Task = "Ensure GDM screen locks then the user is idle"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    l_pkgoutput=""
    if command -v dpkg-query > /dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm > /dev/null 2>&1; then
        l_pq="rpm -q"
    fi
    l_pcl="gdm gdm3"
    for l_pn in $l_pcl; do
        $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration"
    done
    if [ -n "$l_pkgoutput" ]; then
        l_output="" l_output2="" l_idmv="900"
        l_ldmv="5"
        l_kfile="$(grep -Psril '^\h*idle-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/)"
        if [ -n "$l_kfile" ]; then
            l_profile="$(awk -F'/' '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile")"
            l_pdbdir="/etc/dconf/db/$l_profile.d"
            l_idv="$(awk -F 'uint32' '/idle-delay/{print $2}' "$l_kfile" | xargs)"
            if [ -n "$l_idv" ]; then
                [ "$l_idv" -gt "0" -a "$l_idv" -le "$l_idmv" ] && l_output="$l_output\n - The \"idle-delay\" option is set to \"$l_idv\" seconds in \"$l_kfile\"" [ "$l_idv" = "0" ] && l_output2="$l_output2\n - The \"idle-delay\" option is set to \"$l_idv\" (disabled) in \"$l_kfile\"" [ "$l_idv" -gt "$l_idmv" ] && l_output2="$l_output2\n - The \"idle-delay\" option is set to \"$l_idv\" seconds (greater than $l_idmv) in \"$l_kfile\""
            else
                l_output2="$l_output2\n - The \"idle-delay\" option is not set in \"$l_kfile\""
            fi
            l_ldv="$(awk -F 'uint32' '/lock-delay/{print $2}' "$l_kfile" | xargs)"
            if [ -n "$l_ldv" ]; then
                [ "$l_ldv" -ge "0" -a "$l_ldv" -le "$l_ldmv" ] && l_output="$l_output\n - The \"lock-delay\" option is set to \"$l_ldv\"seconds in \"$l_kfile\"" [ "$l_ldv" -gt "$l_ldmv" ] && l_output2="$l_output2\n - The \"lock-delay\" option is set to \"$l_ldv\" seconds (greater than $l_ldmv) in \"$l_kfile\""
            else
                l_output2="$l_output2\n - The \"lock-delay\" option is not set in \"$l_kfile\""
            fi
            if grep -Psq "^\h*system-db:$l_profile" /etc/dconf/profile/*; then
                l_output="$l_output\n - The \"$l_profile\" profile exists"
            else
                l_output2="$l_output2\n - The \"$l_profile\" doesn't exist"
            fi
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
    [ -n "$l_pkgoutput" ] && echo -e "\n$l_pkgoutput"
    if [ -z "$l_output2" ]; then
        echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
    else
        echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
    fi
}
'@
        $script = bash -c $script_string
        if ($script -match "** PASS **") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.5"
    Task = "Ensure GDM screen locks cannot be overridden"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    l_pkgoutput=""
    if command -v dpkg-query > /dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm > /dev/null 2>&1; then
        l_pq="rpm -q"
    fi
    l_pcl="gdm gdm3"
    for l_pn in $l_pcl; do
        $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration"
    done
    if [ -n "$l_pkgoutput" ]; then
        l_output="" l_output2=""
        l_kfd="/etc/dconf/db/$(grep -Psril '^\h*idle-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d"
        l_kfd2="/etc/dconf/db/$(grep -Psril '^\h*lock-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d"
        if [ -d "$l_kfd" ]; then
            if grep -Prilq '\/org\/gnome\/desktop\/session\/idle-delay\b' "$l_kfd"; then
                l_output="$l_output\n - \"idle-delay\" is locked in \"$(grep -Pril '\/org\/gnome\/desktop\/session\/idle-delay\b' "$l_kfd")\""
            else
                l_output2="$l_output2\n - \"idle-delay\" is not locked"
            fi
        else
            l_output2="$l_output2\n - \"idle-delay\" is not set so it can not be locked"
        fi
        if [ -d "$l_kfd2" ]; then
            if grep -Prilq '\/org\/gnome\/desktop\/screensaver\/lock-delay\b' "$l_kfd2"; then
                l_output="$l_output\n - \"lock-delay\" is locked in \"$(grep -Pril '\/org\/gnome\/desktop\/screensaver\/lock-delay\b' "$l_kfd2")\""
            else
                l_output2="$l_output2\n - \"lock-delay\" is not locked"
            fi
        else
            l_output2="$l_output2\n - \"lock-delay\" is not set so it can not be locked"
        fi
    else
        l_output="$l_output\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
    fi
    [ -n "$l_pkgoutput" ] && echo -e "\n$l_pkgoutput"
    if [ -z "$l_output2" ]; then
        echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
    else
        echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
    fi
}
'@
        $script = bash -c $script_string
        if ($script -match "** PASS **") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}