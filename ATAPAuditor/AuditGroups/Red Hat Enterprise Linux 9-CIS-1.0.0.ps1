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

$IPv6Status_script = grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable && echo -e "\n - IPv6 is enabled\n" || echo -e "\n - IPv6 is not enabled\n"
$IPv6Status = bash -c $IPv6Status_script
if ($IPv6Status -match "is enabled") {
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

[AuditTest] @{
    Id = "1.8.6"
    Task = "Ensure GDM automatic mounting of removable media is disabled"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    l_pkgoutput="" l_output="" l_output2=""
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
        echo -e "$l_pkgoutput"
        l_kfile="$(grep -Prils -- '^\h*automount\b' /etc/dconf/db/*.d)"
        l_kfile2="$(grep -Prils -- '^\h*automount-open\b' /etc/dconf/db/*.d)"
        if [ -f "$l_kfile" ]; then
            l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile")"
        elif [ -f "$l_kfile2" ]; then
            l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile2")"
        fi
        if [ -n "$l_gpname" ]; then
            l_gpdir="/etc/dconf/db/$l_gpname.d"
            if grep -Pq -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*; then
                l_output="$l_output\n - dconf database profile file \"$(grep -Pl -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*)\" exists"
            else
                l_output2="$l_output2\n - dconf database profile isn't set"
            fi
            if [ -f "/etc/dconf/db/$l_gpname" ]; then
                l_output="$l_output\n - The dconf database \"$l_gpname\" exists"
            else
                l_output2="$l_output2\n - The dconf database \"$l_gpname\" doesn't exist"
            fi
            if [ -d "$l_gpdir" ]; then
                l_output="$l_output\n - The dconf directory \"$l_gpdir\" exitst"
            else
                l_output2="$l_output2\n - The dconf directory \"$l_gpdir\" doesn't exist"
            fi
            if grep -Pqrs -- '^\h*automount\h*=\h*false\b' "$l_kfile"; then
                l_output="$l_output\n - \"automount\" is set to false in: \"$l_kfile\""
            else
                l_output2="$l_output2\n - \"automount\" is not set correctly"
            fi
            if grep -Pqs -- '^\h*automount-open\h*=\h*false\b' "$l_kfile2"; then
                l_output="$l_output\n - \"automount-open\" is set to false in: \"$l_kfile2\""
            else
                l_output2="$l_output2\n - \"automount-open\" is not set correctly"
            fi
        else
            l_output2="$l_output2\n - neither \"automount\" or \"automount-open\" is set"
        fi
    else
        l_output="$l_output\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
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
    Id = "1.8.7"
    Task = "Ensure GDM disabling automatic mounting of removable media is not overridden"
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
        l_kfd="/etc/dconf/db/$(grep -Psril '^\h*automount\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d"
        l_kfd2="/etc/dconf/db/$(grep -Psril '^\h*automount-open\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d"
        if [ -d "$l_kfd" ]; then
            if grep -Piq '^\h*\/org/gnome\/desktop\/media-handling\/automount\b' "$l_kfd"; then
                l_output="$l_output\n - \"automount\" is locked in \"$(grep -Pil '^\h*\/org/gnome\/desktop\/media-handling\/automount\b' "$l_kfd")\""
            else
                l_output2="$l_output2\n - \"automount\" is not locked"
            fi
        else
            l_output2="$l_output2\n - \"automount\" is not set so it can not be locked"
        fi
        if [ -d "$l_kfd2" ]; then
            if grep -Piq '^\h*\/org/gnome\/desktop\/media-handling\/automount-open\b' "$l_kfd2"; then
                l_output="$l_output\n - \"lautomount-open\" is locked in \"$(grep -Pril '^\h*\/org/gnome\/desktop\/media-handling\/automount-open\b' "$l_kfd2")\""
            else
                l_output2="$l_output2\n - \"automount-open\" is not locked"
            fi
        else
            l_output2="$l_output2\n - \"automount-open\" is not set so it can not be locked"
        fi
    else
        l_output="$l_output\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
    fi
    [ -n "$l_pkgoutput" ] && echo -e "\n$l_pkgoutput"
    if [ -z "$l_output2" ]; then
        echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
    else
        echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
        [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
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
    Id = "1.8.8"
    Task = "Ensure GDM autorun-never is enabled"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    l_pkgoutput="" l_output="" l_output2=""
    if command -v dpkg-query > /dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm > /dev/null 2>&1; then
        l_pq="rpm -q"
    fi
    l_pcl="gdm gdm3"
    for l_pn in $l_pcl; do
        $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration" echo -e "$l_pkgoutput"
    done
    if [ -n "$l_pkgoutput" ]; then
        echo -e "$l_pkgoutput"
        l_kfile="$(grep -Prils -- '^\h*autorun-never\b' /etc/dconf/db/*.d)"
        if [ -f "$l_kfile" ]; then
            l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile")"
        fi
        if [ -n "$l_gpname" ]; then
            l_gpdir="/etc/dconf/db/$l_gpname.d"
            if grep -Pq -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*; then
                l_output="$l_output\n - dconf database profile file \"$(grep -Pl -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*)\" exists"
            else
                l_output2="$l_output2\n - dconf database profile isn't set"
            fi
            if [ -f "/etc/dconf/db/$l_gpname" ]; then
                l_output="$l_output\n - The dconf database \"$l_gpname\" exists"
            else
                l_output2="$l_output2\n - The dconf database \"$l_gpname\" doesn't exist"
            fi
            if [ -d "$l_gpdir" ]; then
                l_output="$l_output\n - The dconf directory \"$l_gpdir\" exitst"
            else
                l_output2="$l_output2\n - The dconf directory \"$l_gpdir\" doesn't exist"
            fi
            if grep -Pqrs -- '^\h*autorun-never\h*=\h*true\b' "$l_kfile"; then
                l_output="$l_output\n - \"autorun-never\" is set to true in: \"$l_kfile\""
            else
                l_output2="$l_output2\n - \"autorun-never\" is not set correctly"
            fi
        else
            l_output2="$l_output2\n - \"autorun-never\" is not set"
        fi
    else
        l_output="$l_output\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
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
    Id = "1.8.10"
    Task = "Ensure XDCMP is not enabled"
    Test = {
        $test = grep -Eis '^\s*Enable\s*=\s*true' /etc/gdm/custom.conf
        if ($test -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.9"
    Task = "Ensure updates, patches, and additional security software are installed"
    Test = {
        return $rcNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "1.10"
    Task = "Ensure system-wide crypto policy is not legacy"
    Test = {
        $test = grep -E -i '^\s*LEGACY\s*(\s+#.*)?$' /etc/crypto-policies/config
        if ($test -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}


### Chapter 2 - Services


[AuditTest] @{
    Id = "2.1.1"
    Task = "Ensure time synchronization is in use"
    Test = {
        $test = rpm -q chrony
        if ($test -match "chrony-") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.1.2"
    Task = "Ensure time synchronization is in use"
    Test = {
        $test = grep -E "^(server|pool)" /etc/chrony.conf | grep OPTIONS\s*-u\s*chrony
        if ($test -match "OPTIONS") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.1"
    Task = "Ensure xorg-x11-server-common is not installed"
    Test = {
        $test = rpm -q xorg-x11-server-common
        if ($test -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.2"
    Task = "Ensure Avahi Server is not installed"
    Test = {
        $test = rpm -q avahi
        if ($test -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.3"
    Task = "Ensure CUPS is not installed"
    Test = {
        $test = rpm -q cups
        if ($test -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.4"
    Task = "Ensure DHCP Server is not installed"
    Test = {
        $test = rpm -q dhcp-server
        if ($test -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.5"
    Task = "Ensure DNS Server is not installed"
    Test = {
        $test = rpm -q bind
        if ($test -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.6"
    Task = "Ensure VSFTP Server is not installed"
    Test = {
        $test = rpm -q vsftpd
        if ($test -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.7"
    Task = "Ensure VSFTP Server is not installed"
    Test = {
        $test = rpm -q vsftpd
        if ($test -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.8"
    Task = "Ensure a web server is not installed"
    Test = {
        $test = rpm -q httpd nginx
        if ($test -match "httpd is not installed" -and $test -match "nginx is not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.9"
    Task = "Ensure IMAP and POP3 server is not installed"
    Test = {
        $test = rpm -q dovecot cyrus-imapd
        if ($test -match "dovecot is not installed" -and $test -match "cyrus-imapd is not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.10"
    Task = "Ensure Samba is not installed"
    Test = {
        $test = rpm -q samba
        if ($test -match "samba is not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.11"
    Task = "Ensure HTTP Proxy Server is not installed"
    Test = {
        $test = rpm -q squid
        if ($test -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.12"
    Task = "Ensure net-snmp is not installed"
    Test = {
        $test = rpm -q net-snmp
        if ($test -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.13"
    Task = "Ensure telnet-server is not installed"
    Test = {
        $test = rpm -q telnet-server
        if ($test -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.14"
    Task = "Ensure dnsmasq is not installed"
    Test = {
        $test = rpm -q dnsmasq
        if ($test -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.15"
    Task = "Ensure mail transfer agent is configured for local-only mode"
    Test = {
        $test = ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|\[?::1\]?):25\s'
        if ($test -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.16"
    Task = "Ensure nfs-utils is not installed or the nfs-server service is masked"
    Test = {
        $test = rpm -q nfs-utils
        if ($test -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.17"
    Task = "Ensure rpcbind is not installed or the rpcbind services are masked"
    Test = {
        $test1 = rpm -q rpcbind
        $test21 = systemctl is-enabled rpcbind
        $test22 = systemctl is-enabled rpcbind.socket
        if ($test1 -match "not installed" -or ($test21 -match "masked" -and $test22 -match "masked")) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.18"
    Task = "Ensure rsync-daemon is not installed or the rsyncd service is masked"
    Test = {
        $test1 = rpm -q rsync-daemon
        $test2 = systemctl is-enabled rsync-daemon
        if ($test1 -match "not installed" -or $test2 -match "masked") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.3.1"
    Task = "Ensure telnet client is not installed"
    Test = {
        $test = rpm -q telnet
        if ($test -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.3.2"
    Task = "Ensure LDAP client is not installed"
    Test = {
        $test = rpm -q openldap-clients
        if ($test -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.3.3"
    Task = "Ensure TFTP client is not installed"
    Test = {
        $test = rpm -q tftp
        if ($test -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.3.4"
    Task = "Ensure FTP client is not installed"
    Test = {
        $test = rpm -q ftp
        if ($test -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.4"
    Task = "Ensure nonessential services listening on the system are removed or masked"
    Test = {
        return $rcNonCompliantManualReviewRequired
    }
}


### Chapter 3 - Network Configuration


[AuditTest] @{
    Id = "3.1.1"
    Task = "Ensure IPv6 status is identified"
    Test = {
        return $rcNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "3.1.3"
    Task = "Ensure TIPC is disabled"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    l_output="" l_output2="" l_mname="tipc"
    if [ -z "$(modprobe -n -v "$l_mname" 2>&1 | grep -Pi -- "\h*modprobe:\h+FATAL:\h+Module\h+$l_mname\h+not\h+found\h+in\h+directory")" ]; then
        l_loadable="$(modprobe -n -v "$l_mname")"
        [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P -- "(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
        if grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
            l_output="$l_output\n - module: \"$l_mname\" is not loadable: \"$l_loadable\""
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is loadable: \"$l_loadable\""
        fi
        if ! lsmod | grep "$l_mname" > /dev/null 2>&1; then
            l_output="$l_output\n - module: \"$l_mname\" is not loaded" else l_output2="$l_output2\n - module: \"$l_mname\" is loaded"
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
    Id = "3.2.1"
    Task = "Ensure IP forwarding is disabled"
    Test = {
        $script_string = @'
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
    Id = "3.2.2"
    Task = "Ensure packet redirect sending is disabled"
    Test = {
        $script_string1 = @'
#!/usr/bin/env bash
{
    krp="" pafile="" fafile=""
    kpname="net.ipv4.conf.all.send_redirects" kpvalue="0"
    searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf"
    krp="$(sysctl "$kpname" | awk -F= '{print $2}' | xargs)"
    pafile="$(grep -Psl -- "^\h*$kpname\h*=\h*$kpvalue\b\h*(#.*)?$" $searchloc)" fafile="$(grep -s -- "^\s*$kpname" $searchloc | grep -Pv -- "\h*=\h*$kpvalue\b\h*" | awk -F: '{print $1}')"
    if [ "$krp" = "$kpvalue" ] && [ -n "$pafile" ] && [ -z "$fafile" ]; then
        echo -e "\nPASS:\n\"$kpname\" is set to \"$kpvalue\" in the running configuration and in \"$pafile\""
    else
        echo -e "\nFAIL: "
        [ "$krp" != "$kpvalue" ] && echo -e "\"$kpname\" is set to \"$krp\" in the running configuration\n"
        [ -n "$fafile" ] && echo -e "\n\"$kpname\" is set incorrectly in \"$fafile\""
        [ -z "$pafile" ] && echo -e "\n\"$kpname = $kpvalue\" is not set in a kernel parameter configuration file\n"
    fi
}
'@
$script_string2 = @'
#!/usr/bin/env bash
{
    krp="" pafile="" fafile="" kpname="net.ipv4.conf.default.send_redirects" kpvalue="0"
    searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf"
    krp="$(sysctl "$kpname" | awk -F= '{print $2}' | xargs)"
    pafile="$(grep -Psl -- "^\h*$kpname\h*=\h*$kpvalue\b\h*(#.*)?$" $searchloc)"
    fafile="$(grep -s -- "^\s*$kpname" $searchloc | grep -Pv -- "\h*=\h*$kpvalue\b\h*" | awk -F: '{print $1}')"
    if [ "$krp" = "$kpvalue" ] && [ -n "$pafile" ] && [ -z "$fafile" ]; then
        echo -e "\nPASS:\n\"$kpname\" is set to \"$kpvalue\" in the running configuration and in \"$pafile\""
    else
        echo -e "\nFAIL: " [ "$krp" != "$kpvalue" ] && echo -e "\"$kpname\" is set to \"$krp\" in the running configuration\n"
        [ -n "$fafile" ] && echo -e "\n\"$kpname\" is set incorrectly in \"$fafile\""
        [ -z "$pafile" ] && echo -e "\n\"$kpname = $kpvalue\" is not set in a kernel parameter configuration file\n"
    fi
}
'@
        $script1 = bash -c $script_string1
        $script2 = bash -c $script_string2
        if ($script1 -match "** PASS **" -and $script2 -match "** PASS **") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}