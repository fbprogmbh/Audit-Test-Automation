function Get-IPv6Disabled{
    $test1 = sysctl net.ipv6.conf.all.disable_ipv6
    $test2 = sysctl net.ipv6.conf.default.disable_ipv6
    $grep = grep -E '^\s*net\.ipv6\.conf\.(all|default)\.disable_ipv6\s*=\s*1\b(\s+#.*)?$'/etc/sysctl.conf /etc/sysctl.d/*.conf | cut -d: -f2
    if($test1 -match "net.ipv6.conf.all.disable_ipv6 = 1" -and $test2 -match "net.ipv6.conf.default.disable_ipv6 = 1" -and $grep -match "net.ipv6.conf.all.disable_ipv6 = 1" -and $grep -match "net.ipv6.conf.default.disable_ipv6 = 1"){
        return $true
    }
    return $false
}
$isIPv6Disabled = Get-IPv6Disabled

[AuditTest] @{
    Id = "1.1.1.1"
    Task = "Ensure mounting of cramfs filesystems is disabled"
    Test = {
        $result1 = modprobe -n -v cramfs | grep -E '(cramfs|install)'
        $result2 = lsmod | grep cramfs
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.2"
    Task = "Ensure mounting of freevxfs filesystems is disabled"
    Test = {
        $result1 = modprobe -n -v freevxfs | grep -E '(freevxfs|install)'
        $result2 = lsmod | grep freevxfs
        
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.3"
    Task = "Ensure mounting of jffs2 filesystetms is disabled"
    Test = {
        $result1 = modprobe -n -v jffs2 | grep -E '(jffs2|install)'
        $result2 = lsmod | grep jffs2
        
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.4"
    Task = "Ensure mounting of hfs filesystetms is disabled"
    Test = {
        $result1 = modprobe -n -v hfs | grep -E '(hfs|install)'
        $result2 = lsmod | grep hfs
        
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.5"
    Task = "Ensure mounting of hfsplus filesystetms is disabled"
    Test = {
        $result1 = modprobe -n -v hfsplus | grep -E '(hfsplus|install)'
        $result2 = lsmod | grep hfsplus
        
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.6"
    Task = "Ensure mounting of squashfs filesystems is disabled"
    Test = {
        $result1 = modprobe -n -v squashfs | grep -E '(squashfs|install)'
        $result2 = lsmod | grep squashfs
        
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.7"
    Task = "Ensure mounting of udf filesystetms is disabled"
    Test = {
        $result1 = modprobe -n -v udf | grep -E '(udf|install)'
        $result2 = lsmod | grep udf
        
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.2"
    Task = "Ensure /tmp is configured"
    Test = {
        $result = findmnt -n /tmp
        if($result -match "/tmp"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.3"
    Task = "Ensure nodev option set on /tmp partition"
    Test = {
        $result = findmnt -n /tmp
        if($result -match "nodev"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.4"
    Task = "Ensure nosuid option set on /tmp partition"
    Test = {
        $result = findmnt -n /tmp
        if($result -match "nosuid"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.5"
    Task = "Ensure noexec option set on /tmp partition"
    Test = {
        $result = findmnt -n /tmp
        if($result -match "noexec"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.6"
    Task = "Ensure /dev/shm is configured"
    Test = {
        $result = findmnt -n /dev/shm
        if($result -match "/dev/shm"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.7"
    Task = "Ensure nodev option set on /dev/shm partition"
    Test = {
        $result = findmnt -n /dev/shm
        if($result -match "nodev"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.8"
    Task = "Ensure nosuid option set on /dev/shm partition"
    Test = {
        $result = findmnt -n /dev/shm
        if($result -match "nosuid"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.9"
    Task = "Ensure nosuid option set on /dev/shm partition"
    Test = {
        $result = findmnt -n /dev/shm | grep -v noexec
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.10"
    Task = "Ensure separate partition exists for /var"
    Test = {
        $result = findmnt /var
        if($result -match "/var"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.11"
    Task = "Ensure separate partition exists for /var/tmp"
    Test = {
        $result = findmnt /var/tmp
        if($result -match "/var/tmp"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.12"
    Task = "Ensure /var/tmp partition includes the nodev option"
    Test = {
        $result = findmnt /var/tmp
        if($result -match "nodev"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.13"
    Task = "Ensure /var/tmp partition includes the nosuid option"
    Test = {
        $result = findmnt /var/tmp
        if($result -match "nosuid"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.14"
    Task = "Ensure /var/tmp partition includes the noexec option"
    Test = {
        $result = findmnt /var/tmp
        if($result -match "noexec"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.15"
    Task = "Ensure separate partition exists for /var/log"
    Test = {
        $result = findmnt /var/log
        if($result -match "/var/log"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.16"
    Task = "Ensure separate partition exists for /var/log/audit"
    Test = {
        $result = findmnt /var/log/audit
        if($result -match "/var/log/audit"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.17"
    Task = "Ensure separate partition exists for /home"
    Test = {
        $result = findmnt /home
        if($result -match "/home"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.18"
    Task = "Ensure /home partition includes the nodev option"
    Test = {
        $result = findmnt /home
        if($result -match "nodev"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.19"
    Task = "Ensure nodev option set on removable media partitions"
    Test = {
        $result = mount
        foreach($line in $result){
            if(!($line -match "nodev")){
                return @{
                    Message = "Not-Compliant"
                    Status = "False"
                }
            }
        }
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.1.20"
    Task = "Ensure nosuid option set on removable media partitions"
    Test = {
        $result = mount
        foreach($line in $result){
            if(!($line -match "nosuid")){
                return @{
                    Message = "Not-Compliant"
                    Status = "False"
                }
            }
        }
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.1.21"
    Task = "Ensure noexec option set on removable media partitions"
    Test = {
        $result = mount
        foreach($line in $result){
            if(!($line -match "noexec")){
                return @{
                    Message = "Not-Compliant"
                    Status = "False"
                }
            }
        }
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.1.22"
    Task = "Ensure sticky bit is set on all world-writable directories"
    Test = {
        try{
            $result = bash -c "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2> /dev/null"
            if($result -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "1.1.23"
    Task = "Disable Automounting"
    Test = {
        $result = dpkg -l | grep -o autofs
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        else{
            $result = systemctl is-enabled autofs
            if($result -match "No such file or directory"){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.1.24"
    Task = "Disable USB Storage"
    Test = {
        $result1 = modprobe -n -v usb-storage
        $result2 = lsmod | grep usb-storage
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.2.1"
    Task = "Ensure package manager repositories are configured"
    Test = {
        $result = apt-cache policy
        if($result -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.2.2"
    Task = "Ensure GPG keys are configured"
    Test = {
        $result = apt-key list
        if($result -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.3.1"
    Task = "Ensure AIDE is installed"
    Test = {
        $result1 = dpkg -l aide | grep '^ii'
        $result2 = dpkg -l aide-common | grep '^ii'
        if($result1 -eq $null -or $result2 -eq $null){
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.3.2"
    Task = "Ensure filesystem integrity is regularly checked"
    Test = {
        $result = grep -Ers '^([^#]+\s+)?(\/usr\/s?bin\/|^\s*)aide(\.wrapper)?\s(--check|\$AIDEARGS)\b' /etc/cron.* /etc/crontab /var/spool/cron/
        if($result -eq $null){
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "1.4.1"
    Task = "Ensure permissions on bootloader config are not overridden"
    Test = {
        $output = grep -E '^\s*chmod\s+[0-7][0-7][0-7]\s+\$\{grub_cfg\}\.new' -A 1 -B1 /usr/sbin/grub-mkconfig
        if($output -match 'hmod 400 ${grub_cfg}.new || true'){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.4.2"
    Task = "Ensure bootloader password is set"
    Test = {
        $result1 = grep "^set superusers" /boot/grub/grub.cfg
        $result2 = grep "^password" /boot/grub/grub.cfg
        if($result1 -match "set superusers=" -and $result2 -match "password_pbkdf2"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.4.3"
    Task = "Ensure permissions on bootloader config are configured"
    Test = {
        $result = stat /boot/grub/grub.cfg | grep "Uid: (    0/    root)   Gid: (    0/    root)"
        $result = $result | cut -d '(' -f 2
        $result = $result | cut -d '/' -f 1

        if($result -eq "0400" -or $result[1] -le 4){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.4.4"
    Task = "Ensure authentication required for single user mode"
    Test = {
        $result = grep -Eq '^root:\$[0-9]' /etc/shadow || echo "root is locked"
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.5.1"
    Task = "Ensure XD/NX support is enabled"
    Test = {
        $result = bash -c '[[ -n $(grep noexec[0-9]*=off /proc/cmdline) || -z $(grep -E -i " (pae|nx)" /proc/cpuinfo) || -n $(grep "\\sNX\\s.*\\sprotection:\\s" /var/log/dmesg | grep -v active) ]] && echo "NX Protection is not active"'
        
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.5.2"
    Task = "Ensure address space layout randomization (ASLR) is enabled"
    Test = {
        $result1 = sysctl kernel.randomize_va_space
        $result2 = grep -Es "^\s*kernel\.randomize_va_space\s*=\s*([0-1]|[3-9]|[1-9][0-9]+)" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
        if($result1 -match "kernel.randomize_va_space = 2" -and $result2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.5.3"
    Task = "Ensure prelink is not installed"
    Test = {
        $result = dpkg -l | grep -o prelink
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.5.4"
    Task = "Ensure core dumps are restricted"
    Test = {
        try{
            $result1 = grep -Es '^(\*|\s).*hard.*core.*(\s+#.*)?$' /etc/security/limits.conf /etc/security/limits.d/*
            $result2 = sysctl fs.suid_dumpable
            $result3 = grep "fs.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*
            try{
                $result4 = systemctl is-enabled coredump.service
                $message = "Compliant"
                if($result4 -match "enabled" -or $result4 -match "masked" -or $result4 -match "disabled"){
                    $message = "systemd-coredump is installed"
                }
            }
            catch{
                $message = "systemd-coredump not installed"
            }
            if($result1 -match ".*\s*hard\s*core\s*0{1}?\s*" -and $result2 -match "fs.suid_dumpable = 0" -and $result3 -match "fs.suid_dumpable = 0"){
                return @{
                    Message = $message
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "1.6.1.1"
    Task = "Ensure AppArmor is installed"
    Test = {
        $result = dpkg -s apparmor | grep -E '(Status:|not installed)'
        
        if($result -match "Status: install ok installed"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.6.1.2"
    Task = "Ensure AppArmor is enabled in the bootloader configuration"
    Test = {
        $result1 = grep "^\s*linux" /boot/grub/grub.cfg | grep -v "apparmor=1"
        $result2 = grep "^\s*linux" /boot/grub/grub.cfg | grep -v "security=apparmor"
        if($result1 -eq $null -and $result2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.6.1.3"
    Task = "Ensure all AppArmor Profiles are in enforce or complain mode"
    Test = {
        $profileMode1 = apparmor_status | grep profiles | sed '1!d' | cut -d ' ' -f 1
        $profileMode2 = apparmor_status | grep profiles | sed '2!d' | cut -d ' ' -f 1
        $profileMode3 = apparmor_status | grep profiles | sed '3!d' | cut -d ' ' -f 1
        $result = expr $profileMode3 + $profileMode2
        
        $unconfinedProcesses = apparmor_status | grep processes | sed '4!d' | cut -d ' ' -f 1

        if($result -eq $profileMode1 -and $unconfinedProcesses -eq 0){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.6.1.4"
    Task = "Ensure all AppArmor Profiles are enforcing"
    Test = {
        $profileMode1 = apparmor_status | grep profiles | sed '1!d' | cut -d ' ' -f 1
        $profileMode2 = apparmor_status | grep profiles | sed '2!d' | cut -d ' ' -f 1
        
        $unconfinedProcesses = apparmor_status | grep processes | sed '4!d' | cut -d ' ' -f 1

        if($profileMode1 -eq $profileMode2 -and $unconfinedProcesses -eq 0){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.7.1"
    Task = "Ensure message of the day is configured properly"
    Test = {
        $output = grep -Eis "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/motd

        if($output -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.7.2"
    Task = "Ensure local login warning banner is configured properly"
    Test = {
        $output1 = cat /etc/issue
        $output2 = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue
        
        if($output1 -ne $null -and $output2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.7.3"
    Task = "Ensure remote login warning banner is configured properly"
    Test = {
        $output1 = cat /etc/issue.net
        $output2 = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net
        
        if($output1 -ne $null -and $output2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.7.4"
    Task = "Ensure permissions on /etc/motd are configured"
    Test = {
        $output = stat -L /etc/motd | grep "Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)"
        
        if($output -eq $null -or $output -match "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.7.5"
    Task = "Ensure permissions on /etc/issue are configured"
    Test = {
        $output = stat -L /etc/issue | grep "Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)"
        
        if($output -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.7.6"
    Task = "Ensure permissions on /etc/issue.net are configured"
    Test = {
        $output = stat -L /etc/issue.net | grep "Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)"
        
        if($output -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.8.2"
    Task = "Ensure GNOME Display Manager is removed"
    Test = {
        if(Test-Path "/etc/gdm3/greeter.dconf-defaults"){
            $content = cat /etc/gdm3/greeter.dconf-defaults
            $line1 = $content | grep "banner-message-enable=true"
            $line2 = $content | grep "banner-message-text="
            if($line1 -ne $null -and $line1[0] -ne '#' -and $line2 -ne $null -and $line2[0] -ne '#'){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.8.3"
    Task = "Ensure disable-user-list is enabled"
    Test = {
        if(Test-Path "/etc/gdm3/greeter.dconf-defaults"){
            $content = cat /etc/gdm3/greeter.dconf-defaults
            $line = $content | grep "disable-user-list=true"
            if($line -ne $null -and $line[0] -ne '#'){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.8.4"
    Task = "Ensure XDCMP is not enabled"
    Test = {
        $output = grep -Eis '^\s*Enable\s*=\s*true' /etc/gdm3/custom.conf
        if($output -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.9"
    Task = "Ensure updates, patches, and additional security software are installed"
    Test = {
        $output = apt -s upgrade
        $output = $?
        if($output -match "True"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}

[AuditTest] @{
    Id = "2.1.1.1"
    Task = "Ensure time synchronization is in use"
    Test = {
        $test1 = systemctl is-enabled systemd-timesyncd    
        $test2 = dpkg -s ntp
        $test3 = dpkg -s chrony
        if($test1 -match "enabled" -or $test2 -match "Status: install ok installed" -or $test3 -match "Status: install ok installed"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
$ntp = dpkg -s ntp
$ntp = $?
$chrony = dpkg -s chrony
$chrony = $?
$timesyncd = systemctl is-enabled systemd-timesyncd

if($ntp -match "False" -and $chrony -match "False"){
    [AuditTest] @{
        Id = "2.1.1.2"
        Task = "Ensure systemd-timesyncd is configured"
        Test = {
            $test1 = systemctl is-enabled systemd-timesyncd.service
            $time = timedatectl status
            if($test1 -match "enabled" -and $time -ne $null){    
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
    }
}
elseif($ntp -match "False" -and $timesyncd -notmatch "enabled"){
    [AuditTest] @{
        Id = "2.1.1.3"
        Task = "Ensure chrony is configured"
        Test = {
            $test1 = dpkg -s ntp | grep -E '(Status:|not installed)'
            $test2 = systemctl is-enabled systemd-timesyncd
            $test3 = grep -E "^(server|pool)" /etc/chrony/chrony.conf
            $test4 = ps -ef | grep chronyd | grep "_chrony"
            if($test1 -match "package 'ntp' is not installed" -and $test2 -match "masked" -and $test3 -ne $null -and $test4 -ne $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
    }
}
elseif($chrony -match "False" -and $timesyncd -notmatch "enabled"){
    [AuditTest] @{
        Id = "2.1.1.4"
        Task = "Ensure ntp is configured"
        Test = {
            $test1 = grep "^restrict" /etc/ntp.conf
            $test2 = grep -E "^(server|pool)" /etc/ntp.conf
            $test3 = grep "RUNASUSER=ntp" /etc/init.d/ntp
            if($test1 -match "restrict -4 default kod notrap nomodify nopeer noquery limited" -and $test1 -match "restrict -6 default kod notrap nomodify nopeer noquery limited" -and $test2 -ne $null -and $test3 -match "RUNASUSER=ntp"){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "2.1.2"
    Task = "Ensure X Window System is not installed"
    Test = {
        $test1 = dpkg -l | grep -o xserver-xorg*
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.1.3"
    Task = "Ensure Avahi Server is not installed"
    Test = {
        $status = dpkg -l | grep -o avahi-daemon
        if($status -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.1.4"
    Task = "Ensure CUPS is not installed"
    Test = {
        $test1 = dpkg -s cups
        $test1 = $?
        if($test1 -match "False"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.1.5"
    Task = "Ensure DHCP Server is not installed"
    Test = {
        $test1 = dpkg -l | grep -o isc-dhcp-server
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.1.6"
    Task = "Ensure LDAP server is not installed"
    Test = {
        $test1 = dpkg -l | grep -o slapd
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.1.7"
    Task = "Ensure NFS is not installed"
    Test = {
        $test1 = dpkg -l | grep -o nfs-kernel-server
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.1.8"
    Task = "Ensure DNS Server is not installed"
    Test = {
        $test1 = dpkg -l | grep -o bind9
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.1.9"
    Task = "Ensure FTP Server is not installed"
    Test = {
        $test1 = dpkg -l | grep -o vsftpd
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.1.10"
    Task = "Ensure HTTP server is not installed"
    Test = {
        $test1 = dpkg -l | grep -o apache2
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.1.11"
    Task = "Ensure IMAP and POP3 server are not installed"
    Test = {
        $test1 =  dpkg -l | grep -o dovecot-imapd
        $test2 = dpkg -l | grep -o dovecot-pop3d
        if($test1 -eq $null -and $test2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.1.12"
    Task = "Ensure Samba is not installed"
    Test = {
        dpkg -s samba | grep -E '(Status:|not installed)'
        $test1 = $?
        if($test1 -match "False"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.1.13"
    Task = "Ensure HTTP Proxy Server is not installed"
    Test = {
        $test1 = dpkg -l | grep -o squid
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.1.14"
    Task = "Ensure SNMP Server is not installed"
    Test = {
        $test1 = dpkg -l | grep -o snmpd
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.1.15"
    Task = "Ensure mail transfer agent is configured for local-only mode"
    Test = {
        $test1 = ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s'
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.1.16"
    Task = "Ensure rsync service is not installed"
    Test = {
        dpkg -s rsync | grep -E '(Status:|not installed)'
        $test1 = $?
        if($test1 -match "False"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.1.17"
    Task = "Ensure NIS Server is not installed"
    Test = {
        $test1 = dpkg -s nis
        $test1 = $?
        if($test1 -match "False"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.2.1"
    Task = "Ensure NIS Client is not installed"
    Test = {
        $test1 = dpkg -s nis
        $test1 = $?
        if($test1 -match "False"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.2.2"
    Task = "Ensure rsh client is not installed"
    Test = {
        $test1 = dpkg -s rsh-client
        $test1 = $?
        if($test1 -match "False"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.2.3"
    Task = "Ensure talk client is not installed"
    Test = {
        $test1 = dpkg -s talk
        $test1 = $?
        if($test1 -match "False"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.2.4"
    Task = "Ensure telnet client is not installed"
    Test = {
        $test1 = dpkg -l | grep -o telnet
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.2.5"
    Task = "Ensure LDAP client is not installed"
    Test = {
        $test1 = dpkg -l | grep -o ldap-utils
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.2.6"
    Task = "Ensure RPC is not installed"
    Test = {
        $test1 = dpkg -l | grep -o rpcbind
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "2.3"
    Task = "Ensure nonessential services are removed or masked"
    Test = {
        $test1 = lsof -i -P -n | grep -v "(ESTABLISHED)"
        if($test1 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.1.1"
    Task = "Disable IPv6"
    Test = {
        if($isIPv6Disabled -eq $true){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.1.2"
    Task = "Ensure wireless interfaces are disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu-3.1.2.sh"
        $result=bash $path
        if($result -match "Wireless is not enabled"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Wireless interfaces are active"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.2.1"
    Task = "Ensure packet redirect sending is disabled"
    Test = {
        $test1 = sysctl net.ipv4.conf.all.send_redirects
        $test2 = sysctl net.ipv4.conf.default.send_redirects
        $test3 = grep -E "^\s*net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        $test4 = grep -E "^\s*net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        if($test1 -match "net.ipv4.conf.all.send_redirects = 0" -and $test2 -match "net.ipv4.conf.default.send_redirects = 0" -and $test3 -match "net.ipv4.conf.all.send_redirects = 0" -and $test4 -match "net.ipv4.conf.default.send_redirects = 0"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.2.2"
    Task = "Ensure IP forwarding is disabled"
    Test = {
        $test1 = sysctl net.ipv4.ip_forward
        $test2 = grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
        if($test1 -match "net.ipv4.ip_forward = 0" -and $test2 -eq $null){
            if($isIPv6Disabled -ne $true){
                $test1 = sysctl net.ipv6.conf.all.forwarding
                $test2 = grep -E -s "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
                if($test1 -match "net.ipv6.conf.all.forwarding = 0" -and $test2 -eq $null){
                    return @{
                        Message = "Compliant"
                        Status = "True"
                    }
                }
            }
            else{
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.3.1"
    Task = "Ensure source routed packets are not accepted"
    Test = {
        $test1 = sysctl net.ipv4.conf.all.accept_source_route
        $test2 = sysctl net.ipv4.conf.default.accept_source_route
        $test3 = grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
        $test4 = grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
        if($test1 -match "net.ipv4.conf.all.accept_source_route = 0" -and $test2 -match "net.ipv4.conf.default.accept_source_route = 0" -and $test3 -match "net.ipv4.conf.all.accept_source_route = 0" -and $test4 -match "net.ipv4.conf.default.accept_source_route = 0"){
            if($isIPv6Disabled -eq $false){
                $test1 = sysctl net.ipv6.conf.all.accept_source_route
                $test2 = sysctl net.ipv6.conf.default.accept_source_route
                $test3 = grep "net\.ipv6\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
                $test4 = grep "net\.ipv6\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
                if($test1 -match "net.ipv6.conf.all.accept_source_route = 0" -and $test2 -match "net.ipv6.conf.default.accept_source_route = 0" -and $test3 -match "net.ipv4.conf.all.accept_source_route = 0" -and $test4 -match "net.ipv6.conf.default.accept_source_route = 0"){
                    return @{
                        Message = "Compliant"
                        Status = "True"
                    }
                }
            }
            else{
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.3.2"
    Task = "Ensure ICMP redirects are not accepted"
    Test = {
        $test1 = sysctl net.ipv4.conf.all.accept_redirects
        $test2 = sysctl net.ipv4.conf.default.accept_redirects
        $test3 = grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        $test4 = grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        if($test1 -match "net.ipv4.conf.all.accept_redirects = 0" -and $test2 -match "net.ipv4.conf.default.accept_redirects = 0" -and $test3 -match "net.ipv4.conf.all.accept_redirects = 0" -and $test4 -match "net.ipv4.conf.default.accept_redirects = 0"){
            if($isIPv6Disabled -eq $false){
                $test1 = sysctl net.ipv6.conf.all.accept_redirects
                $test2 = sysctl net.ipv6.conf.default.accept_redirects
                $test3 = grep "net\.ipv6\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
                $test4 = grep "net\.ipv6\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
                if($test1 -match "net.ipv6.conf.all.accept_redirects = 0" -and $test2 -match "net.ipv6.conf.default.accept_redirects = 0" -and $test3 -match "net.ipv6.conf.all.accept_redirects = 0" -and $test4 -match "net.ipv6.conf.default.accept_redirects = 0"){
                    return @{
                        Message = "Compliant"
                        Status = "True"
                    }
                }
            }
            else{
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.3.3"
    Task = "Ensure secure ICMP redirects are not accepted"
    Test = {
        $test1 = sysctl net.ipv4.conf.all.secure_redirects
        $test2 = sysctl net.ipv4.conf.default.secure_redirects
        $test3 = grep "net\.ipv4\.conf\.all\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        $test4 = grep "net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        if($test1 -match "net.ipv4.conf.all.secure_redirects = 0" -and $test2 -match "net.ipv4.conf.default.secure_redirects = 0" -and $test3 -match "net.ipv4.conf.all.secure_redirects = 0" -and $test4 -match "net.ipv4.conf.default.secure_redirects = 0"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.3.4"
    Task = "Ensure suspicious packets are logged"
    Test = {
        $test1 = sysctl net.ipv4.conf.all.log_martians
        $test2 = sysctl net.ipv4.conf.default.log_martians
        $test3 = grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*
        $test4 = grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*
        if($test1 -match "net.ipv4.conf.all.log_martians = 1" -and $test2 -match "net.ipv4.conf.default.log_martians = 1" -and $test3 -match "net.ipv4.conf.all.log_martians = 1" -and $test4 -match "net.ipv4.conf.default.log_martians = 1"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}

[AuditTest] @{
    Id = "3.3.5"
    Task = "Ensure broadcast ICMP requests are ignored"
    Test = {
        $test1 = sysctl net.ipv4.icmp_echo_ignore_broadcasts
        $test2 = grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/*
        if($test1 -match "net.ipv4.icmp_echo_ignore_broadcasts = 1" -and $test2 -match "net.ipv4.icmp_echo_ignore_broadcasts = 1"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.3.6"
    Task = "Ensure bogus ICMP responses are ignored"
    Test = {
        $test1 = sysctl net.ipv4.icmp_ignore_bogus_error_responses
        $test2 = grep "net.ipv4.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/*
        if($test1 -match "net.ipv4.icmp_ignore_bogus_error_responses = 1" -and $test2 -match "net.ipv4.icmp_ignore_bogus_error_responses = 1"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.3.7"
    Task = "Ensure Reverse Path Filtering is enabled"
    Test = {
        $test1 = sysctl net.ipv4.conf.all.rp_filter
        $test2 = sysctl net.ipv4.conf.default.rp_filter
        $test3 = grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*
        $test4 = grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*
        if($test1 -match "net.ipv4.conf.all.rp_filter = 1" -and $test2 -match "net.ipv4.conf.default.rp_filter = 1" -and $test3 -match "net.ipv4.conf.all.rp_filter=1" -and $test4 -match "net.ipv4.conf.default.rp_filter=1"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.3.8"
    Task = "Ensure TCP SYN Cookies is enabled"
    Test = {
        $test1 = sysctl net.ipv4.tcp_syncookies
        $test2 = grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/*
        if($test1 -match "net.ipv4.tcp_syncookies = 1" -and $test2 -match "net.ipv4.tcp_syncookies = 1"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.3.9"
    Task = "Ensure IPv6 router advertisements are not accepted"
    Test = {
        $test1 = sysctl net.ipv6.conf.all.accept_ra
        $test2 = sysctl net.ipv6.conf.default.accept_ra
        $test3 = grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*
        $test4 = grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*
        if($test1 -match "net.ipv6.conf.all.accept_ra = 0" -and $test2 -match "net.ipv6.conf.default.accept_ra = 0" -and $test3 -match "net.ipv6.conf.all.accept_ra = 0" -and $test4 -match "net.ipv6.conf.default.accept_ra = 0"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.4.1"
    Task = "Ensure DCCP is disabled"
    Test = {
        $test1 = modprobe -n -v dccp
        $test2 = lsmod | grep dccp
        if($test1 -match "install /bin/true" -and $test2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.4.2"
    Task = "Ensure SCTP is disabled"
    Test = {
        $test1 = modprobe -n -v sctp | grep -E '(sctp|install)'
        $test2 = lsmod | grep sctp
        if($test1 -match "install /bin/true" -and $test2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.4.3"
    Task = "Ensure RDS is disabled"
    Test = {
        $test1 = modprobe -n -v rds
        $test2 = lsmod | grep rds
        if($test1 -match "install /bin/true" -and $test2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.4.4"
    Task = "Ensure TIPC is disabled"
    Test = {
        $test1 = modprobe -n -v tipc | grep -E '(tipc|install)'
        $test2 = lsmod | grep tipc
        if($test1 -match "install /bin/true" -and $test2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.5.1.1"
    Task = "Ensure ufw is installed"
    Test = {
        $test1 = dpkg -s ufw | grep 'Status: install'
        if($test1 -match "Status: install ok installed"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.5.1.2"
    Task = "Ensure iptables-persistent is not installed with ufw"
    Test = {
        $test1 = dpkg -l | grep -o iptables-persistent
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.5.1.3"
    Task = "Ensure ufw service is enabled"
    Test = {
        $test1 = systemctl is-enabled ufw
        $test1 = $?
        $test2 = ufw status | grep Status
        if($test1 -match "True" -and $test2 -match "Status: active"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.5.1.4"
    Task = "Ensure ufw loopback traffic is configured"
    Test = {
        $test1 = ufw status verbose
        if($test1 -notmatch "Status: inactive"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.5.1.5"
    Task = "Ensure ufw outbound connections are configured"
    Test = {
        $test1 = ufw status numbered
        if($test1 -notmatch "Status: inactive"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.5.1.7"
    Task = "Ensure ufw default deny firewall policy"
    Test = {
        $test1 = ufw status verbose
        if($test1 -match "deny" -or $test1 -match "reject"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.5.2.1"
    Task = "Ensure nftables is installed"
    Test = {
        $test1 = dpkg -l | grep -o nftables
        if($test1 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.5.2.2"
    Task = "Ensure ufw is uninstalled or disabled with nftables"
    Test = {
        $test1 = dpkg-query -s ufw
        $test1 = $?
        $test2 = dpkg-query -s nftables
        $test2 = $?
        if($test1 -match "True" -and $test2 -match "True"){
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        return @{
            Message = "Compliant"
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "3.5.2.3"
    Task = "Ensure iptables are flushed with nftables"
    Test = {
        $test1 = iptables -L
        $test2 = ip6tables -L
        if($test1 -notmatch "target" -and $test2 -notmatch "target"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.5.2.4"
    Task = "Ensure a nftables table exists"
    Test = {
        try{
            $test1 = nft list tables
            if($test1 -match "table"){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "3.5.2.5"
    Task = "Ensure nftables base chains exist"
    Test = {
        try{
            $test1 = nft list ruleset | grep 'hook input'
            $test2 = nft list ruleset | grep 'hook forward'
            $test3 = nft list ruleset | grep 'hook output'
            if($test1 -match "type filter hook input" -and $test2 -match "type filter hook forward" -and $test3 -match "type filter hook output"){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "3.5.2.6"
    Task = "Ensure nftables loopback traffic is configured"
    Test = {
        try{
            if($isIPv6Disabled -ne $true){
                $test1 = nft list ruleset | awk '/hook input/,/}/' | grep 'iif "lo" accept'
                $test2 = nft list ruleset | awk '/hook input/,/}/' | grep 'ip saddr'
                if($test1 -match 'iif "lo" accept' -and $test2 -match "ip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop"){
                    return @{
                        Message = "Compliant"
                        Status = "True"
                    }
                }
            }
            else{
                $test = nft list ruleset | awk '/hook input/,/}/' | grep 'ip6 saddr'
                if($test -match 'ip6 saddr ::1 counter packets 0 bytes 0 drop'){
                    return @{
                        Message = "Compliant"
                        Status = "True"
                    }
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "3.5.2.7"
    Task = "Ensure nftables outbound and established connections are configured"
    Test = {
        try{
            $test1 = nft list ruleset | awk '/hook input/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'
            $test2 = nft list ruleset | awk '/hook output/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'
            if($test1 -match "ip protocol tcp ct state established accept" -and $test1 -match "p protocol udp ct state established accept" -and $test1 -match "ip protocol icmp ct state established accept" -and $test2 -match "ip protocol tcp ct state established,related,new accep" -and $test2 -match "ip protocol udp ct state established,related,new accept" -and $test2 -match "ip protocol icmp ct state established,related,new accept"){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "3.5.2.8"
    Task = "Ensure nftables default deny firewall policy"
    Test = {
        try{
            $test1 = nft list ruleset | grep 'hook input'
            $test2 = nft list ruleset | grep 'hook forward'
            $test3 = nft list ruleset | grep 'hook output'
            if($test1 -match "policy drop" -and $test2 -match "policy drop" -and $test3 -match "policy drop"){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "3.5.2.9"
    Task = "Ensure nftables service is enabled"
    Test = {
        $test1 = systemctl is-enabled nftables
        if($test1 -match "enabled"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.5.3.1.1"
    Task = "Ensure iptables packages are installed"
    Test = {
        $test1 = apt list iptables iptables-persistent
        $test1 = $?
        if($test1 -match "True"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.5.3.1.2"
    Task = "Ensure nftables is not installed with iptables"
    Test = {
        $test1 = dpkg -s nftables
        if($test1 -match "package 'nftables' is not installed"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.5.3.1.3"
    Task = "Ensure ufw is uninstalled or disabled with iptables"
    Test = {
        $test1 = dpkg -l | grep -o ufw
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.5.3.2.1"
    Task = "Ensure iptables loopback traffic is configured"
    Test = {
        $test1 = iptables -L INPUT -v -n | grep "Chain\s*INPUT\s*(policy\s*DROP"
        $test2 = iptables -L OUTPUT -v -n | grep "Chain\s*OUTPUT\s*(policy\s*DROP"
        if($test1 -ne $null -and $test2 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.5.3.2.2"
    Task = "Ensure iptables outbound and established connections are configured"
    Test = {
        $test1 = iptables -L -v -n
        if($test1 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.5.3.2.3"
    Task = "Ensure iptables default deny firewall policy"
    Test = {
        $output = iptables -L
        $test1 = $output -match "DROP" | grep "Chain INPUT (policy DROP)"
        $res1 = $?
        $test2 = $output -match "DROP" | grep "Chain FORWARD (policy DROP)"
        $res2 = $?
        $test3 = $output -match "DROP" | grep "Chain OUTPUT (policy DROP)"
        $res3 = $?
        if($res1 -match "True" -and $res2 -match "True" -and $res3 -match "True"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.5.3.3.3"
    Task = "Ensure ip6tables default deny firewall policy"
    Test = {
        $output = ip6tables -L
        $test1 = $output -match "DROP" | grep "Chain INPUT (policy DROP)"
        $res1 = $?
        $test2 = $output -match "DROP" | grep "Chain FORWARD (policy DROP)"
        $res2 = $?
        $test3 = $output -match "DROP" | grep "Chain OUTPUT (policy DROP)"
        $res3 = $?
        if($isIPv6Disabled -eq $true){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        if($res1 -match "True" -and $res2 -match "True" -and $res3 -match "True"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.1.1"
    Task = "Ensure auditd is installed"
    Test = {
        $test1 = dpkg -l | grep -o auditd
        $test2 = dpkg -l | grep -o audispd-plugins
        if($test1 -ne $null -and $test2 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.1.2"
    Task = "Ensure auditd service is enabled"
    Test = {
        $test1 = systemctl is-enabled auditd
        if($test1 -match "enabled"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.1.3"
    Task = "Ensure auditing for processes that start prior to auditd is enabled"
    Test = {
        $test1 = grep "^\s*linux" /boot/grub/grub.cfg | grep -v "audit=1"
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.1.4"
    Task = "Ensure audit_backlog_limit is sufficient"
    Test = {
        $test1 = grep "^\s*linux" /boot/grub/grub.cfg | grep -v "audit_backlog_limit="
        $test2 = grep "audit_backlog_limit=" /boot/grub/grub.cfg | grep "audit_backlog_limit=8192"
        if($test1 -eq $null -and $test2 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.2.1"
    Task = "Ensure audit log storage size is configured"
    Test = {
        $test1 = grep max_log_file /etc/audit/auditd.conf
        if($test1 -match "max_log_file"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.2.2"
    Task = "Ensure audit logs are not automatically deleted"
    Test = {
        $test1 = grep max_log_file_action /etc/audit/auditd.conf
        if($test1 -match "max_log_file_action = keep_logs"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.2.3"
    Task = "Ensure system is disabled when audit logs are full"
    Test = {
        $test1 = grep space_left_action /etc/audit/auditd.conf
        $test2 = grep action_mail_acct /etc/audit/auditd.conf
        $test3 = grep admin_space_left_action /etc/audit/auditd.conf
        if($test1 -match "space_left_action = email" -and $test2 -match "action_mail_acct = root" -and $test3 -match "admin_space_left_action = halt"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.3"
    Task = "Ensure events that modify date and time information are collected"
    Test = {
        try{
            $bitVersion = uname -a
            #if 32 bit
            if($bitVersion -match "i386"){
                $output = grep time-change /etc/audit/rules.d/*.rules
                $test1 = $output -match "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change"
                $test2 = $output -match "-a always,exit -F arch=b32 -S clock_settime -k time-change"
                $test3 = $output -match "-w /etc/localtime -p wa -k time-change"
                
                $output2 = auditctl -l | grep time-change
                $test4 = $output2 -match "-a always,exit -F arch=b32 -S stime,settimeofday,adjtimex -F key=time-change"
                $test5 = $output2 -match "-a always,exit -F arch=b32 -S clock_settime -F key=time-change"
                $test6 = $output2 -match "-w /etc/localtime -p wa -k time-change"
               
                if($test1 -ne $null -and $test2 -ne $null -and $test3 -ne $null -and $test4 -ne $null -and $test5 -ne $null -and $test6 -ne $null){
                    return @{
                        Message = "Compliant"
                        Status = "True"
                    }
                }
            }
            #64 bit
            elseif($bitVersion -match "x86_64"){
                $output = grep time-change /etc/audit/rules.d/*.rules
                $test1 = $output -match "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change"
                $test2 = $output -match "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change"
                $test3 = $output -match "-a always,exit -F arch=b64 -S clock_settime -k time-change"
                $test4 = $output -match "-a always,exit -F arch=b32 -S clock_settime -k time-change"
                $test5 = $output -match "-w /etc/localtime -p wa -k time-change"
                $output2 = auditctl -l | grep time-change
                $test6 = $output2 -match "-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change"
                $test7 = $output2 -match "-a always,exit -F arch=b32 -S stime,settimeofday,adjtimex -F key=time-change"
                $test8 = $output2 -match "-a always,exit -F arch=b64 -S clock_settime -F key=time-change"
                $test9 = $output2 -match "-a always,exit -F arch=b32 -S clock_settime -F key=time-change"
                $test10 = $output2 -match "-w /etc/localtime -p wa -k time-change"
                if($test1 -ne $null -and $test2 -ne $null -and $test3 -ne $null -and $test4 -ne $null -and $test5 -ne $null -and $test6 -ne $null -and $test7 -ne $null -and $test8 -ne $null -and $test9 -ne $null -and $test10 -ne $null){
                    return @{
                        Message = "Compliant"
                        Status = "True"
                    }
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.1.4"
    Task = "Ensure events that modify user/group information are collected"
    Test = {
        try{
            $output = grep identity /etc/audit/rules.d/*.rules
            $test1 = $output -match "-w /etc/group -p wa -k identity"
            $test2 = $output -match "-w /etc/passwd -p wa -k identity"
            $test3 = $output -match "-w /etc/gshadow -p wa -k identity"
            $test4 = $output -match "-w /etc/shadow -p wa -k identity"
            $test5 = $output -match "-w /etc/security/opasswd -p wa -k identity"
            $output2 = auditctl -l | grep identity
            $test6 = $output2 -match "-w /etc/group -p wa -k identity"
            $test7 = $output2 -match "-w /etc/passwd -p wa -k identity"
            $test8 = $output2 -match "-w /etc/gshadow -p wa -k identity"
            $test9 = $output2 -match "-w /etc/shadow -p wa -k identity"
            $test10 = $output2 -match "-w /etc/security/opasswd -p wa -k identity"
            if($test1 -ne $null -and $test2 -ne $null -and $test3 -ne $null -and $test4 -ne $null -and $test5 -ne $null -and $test6 -ne $null -and $test7 -ne $null -and $test8 -ne $null -and $test9 -ne $null -and $test10 -ne $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.1.5"
    Task = "Ensure events that modify the system's network environment are collected"
    Test = {
        try{
            $bitVersion = uname -a
            #if 32 bit
            if($bitVersion -match "i386"){
                $output = grep system-locale /etc/audit/rules.d/*.rules
                $test1 = $output -match "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale"
                $test2 = $output -match "-w /etc/issue -p wa -k system-locale"
                $test3 = $output -match "-w /etc/issue.net -p wa -k system-locale"
                $test4 = $output -match "-w /etc/hosts -p wa -k system-locale"
                $test5 = $output -match "-w /etc/network -p wa -k system-locale"
                $output2 = auditctl -l | grep system-locale
                $test6 = $output2 -match "-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale"
                $test7 = $output2 -match "-w /etc/issue -p wa -k system-locale"
                $test8 = $output2 -match "-w /etc/issue.net -p wa -k system-locale"
                $test9 = $output2 -match "-w /etc/hosts -p wa -k system-locale"
                $test10 = $output2 -match "-w /etc/network -p wa -k system-locale"
                if($test1 -ne $null -and $test2 -ne $null -and $test3 -ne $null -and $test4 -ne $null -and $test5 -ne $null -and $test6 -ne $null -and $test7 -ne $null -and $test8 -ne $null -and $test9 -ne $null -and $test10 -ne $null){
                    return @{
                        Message = "Compliant"
                        Status = "True"
                    }
                }
            }
            #64 bit
            elseif($bitVersion -match "x86_64"){
                $output = grep system-locale /etc/audit/rules.d/*.rules
                $test1 = $output -match "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale"
                $test1_2 = $output -match "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale"
                $test2 = $output -match "-w /etc/issue -p wa -k system-locale"
                $test3 = $output -match "-w /etc/issue.net -p wa -k system-locale"
                $test4 = $output -match "-w /etc/hosts -p wa -k system-locale"
                $test5 = $output -match "-w /etc/network -p wa -k system-locale"
                $output2 = auditctl -l | grep system-locale
                $test6 = $output2 -match "-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale"
                $test6_2 = $output2 -match "-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale"
                $test7 = $output2 -match "-w /etc/issue -p wa -k system-locale"
                $test8 = $output2 -match "-w /etc/issue.net -p wa -k system-locale"
                $test9 = $output2 -match "-w /etc/hosts -p wa -k system-locale"
                $test10 = $output2 -match "-w /etc/network -p wa -k system-locale"
                if($test1 -ne $null -and $test1_2 -ne $null -and $test2 -ne $null -and $test3 -ne $null -and $test4 -ne $null -and $test5 -ne $null -and $test6 -ne $null -and $test6_2 -ne $null -and $test7 -ne $null -and $test8 -ne $null -and $test9 -ne $null -and $test10 -ne $null){
                    return @{
                        Message = "Compliant"
                        Status = "True"
                    }
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.1.6"
    Task = "Ensure events that modify the system's Mandatory Access Controls are collected"
    Test = {
        try{
            $output = grep MAC-policy /etc/audit/rules.d/*.rules
            $test1 = $output -match "-w /etc/apparmor/ -p wa -k MAC-policy"
            $test2 = $output -match "-w /etc/apparmor.d/ -p wa -k MAC-policy"
            $output2 = auditctl -l | grep MAC-policy
            $test3 = $output2 -match "-w /etc/apparmor -p wa -k MAC-policy"
            $test4 = $output2 -match "-w /etc/apparmor.d -p wa -k MAC-policy"
            if($test1 -ne $null -and $test2 -ne $null -and $test3 -ne $null -and $test4 -ne $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.1.7"
    Task = "Ensure login and logout events are collected"
    Test = {
        try{
            $output = grep logins /etc/audit/rules.d/*.rules
            $test1 = $output -match "-w /var/log/faillog -p wa -k logins"
            $test2 = $output -match "-w /var/log/lastlog -p wa -k logins"
            $test3 = $output -match "-w /var/log/tallylog -p wa -k logins"
            $output2 = auditctl -l | grep logins
            $test4 = $output2 -match "-w /var/log/faillog -p wa -k logins"
            $test5 = $output2 -match "-w /var/log/lastlog -p wa -k logins"
            $test6 = $output2 -match "-w /var/log/tallylog -p wa -k logins"
            if($test1 -ne $null -and $test2 -ne $null -and $test3 -ne $null -and $test4 -ne $null -and $test5 -ne $null -and $test6 -ne $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.1.8"
    Task = "Ensure session initiation information is collected"
    Test = {
        try{
            $output = grep -E '(session|logins)' /etc/audit/rules.d/*.rules
            $test1 = $output -match "-w /var/run/utmp -p wa -k session"
            $test2 = $output -match "-w /var/log/wtmp -p wa -k logins"
            $test3 = $output -match "-w /var/log/btmp -p wa -k logins"
            $output2 = auditctl -l | grep -E '(session|logins)'
            $test4 = $output2 -match "-w /var/run/utmp -p wa -k session"
            $test5 = $output2 -match "-w /var/log/wtmp -p wa -k logins"
            $test6 = $output2 -match "-w /var/log/btmp -p wa -k logins"
            if($test1 -ne $null -and $test2 -ne $null -and $test3 -ne $null -and $test4 -ne $null -and $test5 -ne $null -and $test6 -ne $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.1.9"
    Task = "Ensure discretionary access control permission modification events are collected"
    Test = {
        try{
            $bitVersion = uname -a
            #if 32 bit
            if($bitVersion -match "i386"){
                $output = grep perm_mod /etc/audit/rules.d/*.rules
                $test1 = $output -match "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
                $test2 = $output -match "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
                $test3 = $output -match "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295"
                $test4 = $output -match "-k perm_mod"
                $output2 = auditctl -l | grep perm_mod
                $test5 = $output2 -match "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1"
                $test6 = $output2 -match "-F key=perm_mod"
                $test7 = $output2 -match "-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod"
                $test8 = $output2 -match "-a always,exit -F arch=b32 -S"
                $test9 = $output2 -match "setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod"
                if($test1 -ne $null -and $test1_2 -ne $null -and $test2 -ne $null -and $test3 -ne $null -and $test4 -ne $null -and $test5 -ne $null -and $test6 -ne $null -and $test6_2 -ne $null -and $test7 -ne $null -and $test8 -ne $null -and $test9 -ne $null){
                    
                    return @{
                        Message = "Compliant"
                        Status = "True"
                    }
                }
            }
            #64 Bit
            elseif($bitVersion -match "x86_64"){
                $output = grep perm_mod /etc/audit/rules.d/*.rules
                $test1 = $output -match "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
                $test2 = $output -match "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
                $test3 = $output -match "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
                $test4 = $output -match "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
                $test5 = $output -match "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295"
                $test6 = $output -match "-k perm_mod"
                $test7 = $output -match "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295"
                $test8 = $output -match "-k perm_mod"
                $output2 = auditctl -l | grep perm_mod
                $test9 = $output2 -match "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod"
                $test10 = $output2 -match "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod"
                $test11 = $output2 -match "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod"
                $test12 = $output2 -match "-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod"
                $test13 = $output2 -match "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod"
                $test14 = $output2 -match "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod"
                if($test1 -ne $null  -and $test2 -ne $null -and $test3 -ne $null -and $test4 -ne $null -and $test5 -ne $null -and $test6 -ne $null  -and $test7 -ne $null -and $test8 -ne $null -and $test9 -ne $null -and $test10 -ne $null -and $test11 -ne $null -and $test12 -ne $null -and $test13 -ne $null -and $test14 -ne $null){
                    return @{
                        Message = "Compliant"
                        Status = "True"
                    }
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.1.10"
    Task = "Ensure unsuccessful unauthorized file access attempts are collected"
    Test = {
        try{
            $bitVersion = uname -a
            if($bitVersion -match "i386"){
                $output = grep access /etc/audit/rules.d/*.rules
                $test1 = $output -match "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access"
                $test2 = $output -match "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"
                $output2 = auditctl -l | grep access
                $test3 = $output2 -match "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access"
                $test4 = $output2 -match "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access"
                if($test1 -ne $null -and $test2 -ne $null -and $test3 -ne $null -and $test4 -ne $null){
                    return @{
                        Message = "Compliant"
                        Status = "True"
                    }
                }
            }
            elseif($bitVersion -match "x86_64"){
                $output = grep access /etc/audit/rules.d/*.rules
                $test1 = $output -match "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access"
                $test2 = $output -match "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access"
                $test3 = $output -match "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"
                $test4 = $output -match "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"
                $output2 = auditctl -l | grep access
                $test5 = $output2 -match "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access"
                $test6 = $output2 -match "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access"
                $test7 = $output2 -match "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access"
                $test8 = $output2 -match "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access"
                if($test1 -ne $null -and $test2 -ne $null -and $test3 -ne $null -and $test4 -ne $null -and $test5 -ne $null -and $test6 -ne $null -and $test7 -ne $null -and $test8 -ne $null){
                    return @{
                        Message = "Compliant"
                        Status = "True"
                    }
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.1.11"
    Task = "Ensure use of privileged commands is collected"
    Test = {
        $mountPoints = mount | grep -v "/var/lib/snapd" | grep -v "cgroup on " | grep -v "noexec" | grep -v " fuse" | cut -f 3 -d ' '
        #$filesPerMountPoint = bash -c "find /home -xdev \( -perm -4000 -o -perm -2000 \) -type f
        #auditctl -l in array 
        return @{
            Message = "Not Implemented!"
            Status = "Error"
        }
    }
}
[AuditTest] @{
    Id = "4.1.12"
    Task = "Ensure successful file system mounts are collected"
    Test = {
        try{
            $bitVersion = uname -a
            if($bitVersion -match "i386"){
                $output = grep mounts /etc/audit/rules.d/*.rules
                $test1 = $output -match "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts"
                $output2 = auditctl -l | grep mounts
                $test2 = $output2 -match "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts"
                if($test1 -ne $null -and $test2 -ne $null){
                    return @{
                        Message = "Compliant"
                        Status = "True"
                    }
                }
            }
            elseif($bitVersion -match "x86_64"){
                $output = grep mounts /etc/audit/rules.d/*.rules
                $test1 = $output -match "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts"
                $test2 = $output -match "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts"
                $output2 = auditctl -l | grep mounts
                $test3 = $output2 -match "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts"
                $test4 = $output2 -match "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts"
                if($test1 -ne $null -and $test2 -ne $null -and $test3 -ne $null -and $test4 -ne $null){
                    return @{
                        Message = "Compliant"
                        Status = "True"
                    }
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.1.13"
    Task = "Ensure file deletion events by users are collected"
    Test = {
        try{
            $test1 = grep delete /etc/audit/rules.d/*.rules
            $test2 = auditctl -l | grep delete
            if($test1 -match "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" -and $test2 -match "-a always,exit -F arch=b32 -S unlink,rename,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete"){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.1.14"
    Task = "Ensure changes to system administration scope (sudoers) is collected"
    Test = {
        try{
            $test1 = grep scope /etc/audit/rules.d/*.rules
            $test2 = auditctl -l | grep scope
            if($test1 -match "-w /etc/sudoers -p wa -k scope" -and $test1 -match "-w /etc/sudoers.d/ -p wa -k scope" -and $test2 -match "-w /etc/sudoers -p wa -k scope" -and $test2 -match "-w /etc/sudoers.d -p wa -k scope" ){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.1.15"
    Task = "Ensure system administrator command executions (sudo) are collected"
    Test = {
        try{
            $test1 = grep actions /etc/audit/rules.d/*.rules
            $test2 = auditctl -l | grep actions
            $res1 = "-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions"
            $res2 = "-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions"
            $res3 = "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F auid>=1000 -F auid!=-1 -F key=actions"
            $res4 = "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F auid>=1000 -F auid!=-1 -F key=actions"
            if($test1 -match $res1 -and $test1 -match $res2 -and $test2 -match $res3 -and $test2 -match $res4){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.1.16"
    Task = "Ensure kernel module loading and unloading is collected"
    Test = {
        $test1 = grep modules /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | grep modules
        $res1 = "-w /sbin/insmod -p x -k modules"
        $res2 = "-w /sbin/rmmod -p x -k modules"
        $res3 = "-w /sbin/modprobe -p x -k modules"
        $res4 = "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules"
        $res5 = "-w /sbin/insmod -p x -k modules"
        $res6 = "-w /sbin/rmmod -p x -k modules"
        $res7 = "-w /sbin/modprobe -p x -k modules"
        $res8 = "-a always,exit -F arch=b64 -S init_module,delete_module -F key=modules"

        if($test1 -match $res1 -and $test1 -match $res2 -and $test1 -match $res3 -and $test1 -match $res4 -and $test2 -match $res5 -and $test2 -match $res6 -and $test2 -match $res7 -and $test2 -match $res8){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        else{
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.1.17"
    Task = "Ensure the audit configuration is immutable"
    Test = {
        $test1 = grep "^\s*[^#]" /etc/audit/rules.d/*.rules | tail -l
        if($test1 -match "-e 2"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.2.1.1"
    Task = "Ensure rsyslog is installed"
    Test = {
        $test1 = dpkg -s rsyslog
        if($test1 -match "Status: install ok installed"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.2.1.2"
    Task = "Ensure rsyslog Service is enabled"
    Test = {
        $test1 = systemctl is-enabled rsyslog
        if($test1 -match "enabled"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.2.1.3"
    Task = "Ensure logging is configured"
    Test = {
        $logginTypes = 0
        $fileContent = cat /etc/rsyslog.conf /etc/rsyslog.d/*.conf
        if($fileContent -match "^*.emerg\s*:omusrmsg:*") {$logginTypes++}
        if($fileContent -match "^auth,authpriv.*\s*/var/log/auth.log") {$logginTypes++}
        if($fileContent -match "^mail.*\s*-/var/log/mail") {$logginTypes++}
        if($fileContent -match "^mail.info\s*-/var/log/mail.info") {$logginTypes++}
        if($fileContent -match "^mail.warning\s*-/var/log/mail.warn") {$logginTypes++}
        if($fileContent -match "^mail.err\s*/var/log/mail.err") {$logginTypes++}
        if($fileContent -match "^news.crit\s*-/var/log/news/news.crit") {$logginTypes++}
        if($fileContent -match "^news.err\s*-/var/log/news/news.err") {$logginTypes++}
        if($fileContent -match "^news.notice\s*-/var/log/news/news.notice") {$logginTypes++}
        if($fileContent -match "^*.=warning;*.=err\s*-/var/log/warn") {$logginTypes++}
        if($fileContent -match "^*.crit\s*/var/log/warn") {$logginTypes++}
        if($fileContent -match "^*.*;mail.none;news.none\s*-/var/log/messages") {$logginTypes++}
        if($fileContent -match "^local0,local1.*\s*-/var/log/localmessages") {$logginTypes++}
        if($fileContent -match "^local2,local3.*\s*-/var/log/localmessages") {$logginTypes++}
        if($fileContent -match "^local4,local5.*\s*-/var/log/localmessages") {$logginTypes++}
        if($fileContent -match "^local6,local7.*\s*-/var/log/localmessages") {$logginTypes++}

        if($logginTypes -le 5){
            return @{
                Message = "Not enough logging types supported! Currently: " + $logginTypes
                Status = "False"
            }
        }
        if($logginTypes -le 12){
            return @{
                Message = "Currently configured: " + $logginTypes
                Status = "Warning"
            }
        }
        return @{
            Message = "Compliant. Currently: " + $logginTypes
            Status = "True"
        }
    }
}
[AuditTest] @{
    Id = "4.2.1.4"
    Task = "Ensure rsyslog default file permissions configured"
    Test = {
        $test1 = cat /etc/rsyslog.conf /etc/rsyslog.d/*.conf | grep "^\s*\`$FileCreateMode"
        if($test1 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.2.1.5"
    Task = "Ensure rsyslog is configured to send logs to a remote log host"
    Test = {
        $test1 = grep -E '^\s*([^#]+\s+)?action\(([^#]+\s+)?\btarget=\"?[^#"]+\"?\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
        if($test1 -match "target"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.2.2.1"
    Task = "Ensure journald is configured to send logs to rsyslog"
    Test = {
        $test1 = grep -e ForwardToSyslog /etc/systemd/journald.conf
        if($test1 -match "ForwardToSyslog=yes"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.2.2.2"
    Task = "Ensure journald is configured to compress large log files"
    Test = {
        $test1 = grep -e Compress /etc/systemd/journald.conf
        if($test1 -match "Compress=yes"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.2.2.3"
    Task = "Ensure journald is configured to write logfiles to persistent disk"
    Test = {
        $test1 = grep -e Storage /etc/systemd/journald.conf
        if($test1 -match "Storage=persistent"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.2.3"
    Task = "Ensure permissions on all logfiles are configured"
    Test = {
        $fileListAll = find /var/log -type f -ls
        $fileListFiltered = find /var/log -type f -ls | grep "\-....\-\-\-\-\-"
        if($fileListAll.Count -eq $fileListFiltered.Count){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "$($fileListAll.Count - $fileListFiltered.Count) files grant too many permissions"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.3"
    Task = "Ensure logrotate is configured"
    Test = {
        return @{
            Message = "Review /etc/logrotate.conf and /etc/logrotate.d/rsyslog and verify logs are rotated according to site policy."
            Status = "None"
        }
    }
}
[AuditTest] @{
    Id = "4.4"
    Task = "Ensure logrotate assigns appropriate permissions"
    Test = {
        $test1 = grep -Es "^\s*create\s+\S+" /etc/logrotate.conf /etc/logrotate.d/* | grep -E -v "\s(0)?[0-6][04]0\s"
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.1.1"
    Task = "Ensure cron daemon is enabled and running"
    Test = {
        $test1 = systemctl is-enabled cron
        $test2 = systemctl status cron | grep 'Active: active (running) '
        if($test1 -eq "enabled" -and $test2 -match "running"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.1.2"
    Task = "Ensure permissions on /etc/crontab are configured"
    Test = {
        $test1 = stat /etc/crontab
        if($test1 -eq "Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.1.3"
    Task = "Ensure permissions on /etc/cron.hourly are configured"
    Test = {
        $test1 = stat /etc/cron.hourly/
        if($test1 -eq "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.1.4"
    Task = "Ensure permissions on /etc/cron.daily are configured"
    Test = {
        $test1 = stat /etc/cron.daily/
        if($test1 -eq "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.1.5"
    Task = "Ensure permissions on /etc/cron.weekly are configured"
    Test = {
        $test1 = stat /etc/cron.weekly/
        if($test1 -eq "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.1.6"
    Task = "Ensure permissions on /etc/cron.monthly are configured"
    Test = {
        $test1 = stat /etc/cron.monthly/
        if($test1 -eq "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.1.7"
    Task = "Ensure permissions on /etc/cron.d are configured"
    Test = {
        $test1 = stat /etc/cron.d/
        if($test1 -eq "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.1.8"
    Task = "Ensure cron is restricted to authorized users"
    Test = {
        $test1 = stat /etc/cron.deny
        $test1 = $?
        $test2 = stat /etc/cron.allow
        if($test1 -match "False" -and $test2 -match "0640\s*.*Uid.*root.*Gid.*root"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.1.9"
    Task = "Ensure at is restricted to authorized users"
    Test = {
        $test1 = stat /etc/at.deny
        $test1 = $?
        $test2 = stat /etc/at.allow | grep 0640
        if($test1 -match "False" -and $test2 -eq "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (    0/    root)"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.2.1"
    Task = "Ensure sudo is installed"
    Test = {
        $test1 = dpkg -s sudo
        if($test1 -match "Status: install ok installed"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.2.2"
    Task = "Ensure sudo commands use pty"
    Test = {
        $test1 = grep -Ei '^\s*Defaults\s+([^#]+,\s*)?use_pty(,\s+\S+\s*)*(\s+#.*)?$' /etc/sudoers /etc/sudoers.d/*
        if($test1 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.2.3"
    Task = "Ensure sudo log file exists"
    Test = {
        $test1 = grep -Ei '^\s*Defaults\s+logfile=\S+' /etc/sudoers /etc/sudoers.d/*
        if($test1 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.3.1"
    Task = "Ensure permissions on /etc/ssh/sshd_config are configured"
    Test = {
        try{
            try{
                $test1 = stat /etc/ssh/sshd_config | grep 0600
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }

            if($test1 -eq "Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)"){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Path not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.2"
    Task = "Ensure permissions on SSH private host key files are configured"
    Test = {
        $test1 = find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \;
        if($test1 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.3.3"
    Task = "Ensure permissions on SSH public host key files are configured"
    Test = {
        $test1 = find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;
        if($test1 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.3.4"
    Task = "Ensure SSH access is limited"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -Ei '^\s*(allow|deny)(users|groups)\s+\S+'
            if($test1 -match "allowusers" -or $test1 -match "allowgroups" -or $test1 -match "denyusers" -or $test1 -match "denygroups"){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.5"
    Task = "Ensure SSH LogLevel is appropriate"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep loglevel
            try{
                $test2 = grep -is 'loglevel' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Evi '(VERBOSE|INFO)'
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if(($test1 -match "loglevel VERBOSE" -or $test1 -match "loglevel INFO") -and $test2 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.6"
    Task = "Ensure SSH X11 forwarding is disabled"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep -i x11forwarding
            try{
                $test2 = grep -Eis '^\s*x11forwarding\s+yes' /etc/ssh/sshd_config/etc/ssh/sshd_config.d/*.conf
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if($test1 -match "x11forwarding no" -and $test2 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.7"
    Task = "Ensure SSH MaxAuthTries is set to 4 or less"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep maxauthtries | cut -d ' ' -f 2
            try{
                $test2 = grep -Eis '^\s*maxauthtries\s+([5-9]|[1-9][0-9]+)' /etc/ssh/sshd_config/etc/ssh/sshd_config.d/*.conf
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if($test1 -le 4 -and $test2 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.8"
    Task = "Ensure SSH IgnoreRhosts is enabled"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep ignorerhosts
            try{
                $test2 = grep -Eis '^\s*ignorerhosts\s+no\b' /etc/ssh/sshd_config/etc/ssh/sshd_config.d/*.conf
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if($test1 -match "ignorerhosts yes" -and $test2 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.10"
    Task = "Ensure SSH root login is disabled"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep permitrootlogin
            try{
                $test2 = grep -Eis '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config/etc/ssh/sshd_config.d/*.conf
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if($test1 -match "permitrootlogin no" -and $test2 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.11"
    Task = "Ensure SSH PermitEmptyPasswords is disabled"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep permitemptypasswords
            try{
                $test2 = grep -Eis '^\s*PermitEmptyPasswords\s+yes' /etc/ssh/sshd_config/etc/ssh/sshd_config.d/*.conf
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if($test1 -match "permitemptypasswords no" -and $test2 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.12"
    Task = "Ensure SSH PermitUserEnvironment is disabled"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep permituserenvironment
            try{
                $test2 = grep -Eis '^\s*PermitUserEnvironment\s+yes' /etc/ssh/sshd_config/etc/ssh/sshd_config.d/*.conf
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if($test1 -match "permituserenvironment no" -and $test2 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.13"
    Task = "Ensure only strong Ciphers are used"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep -Ei '^\s*ciphers\s+([^#]+,)?(3des-cbc|aes128-cbc|aes192-cbc|aes256-cbc|arcfour|arcfour128|arcfour256|blowfish-cbc|cast128-cbc|rijndael-cbc@lysator.liu.se)\b'
            try{
                $test2 = grep -Eis '^\s*ciphers\s+([^#]+,)?(3des-cbc|aes128-cbc|aes192-cbc|aes256-cbc|arcfour|arcfour128|arcfour256|blowfish-cbc|cast128-cbc|rijndael-cbc@lysator.liu.se)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if($test1 -eq $null -and $test2 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.14"
    Task = "Ensure only strong MAC algorithms are used"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep -Ei '^\s*macs\s+([^#]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b'
            try{
                $test2 = grep -Eis '^\s*macs\s+([^#]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if($test1 -eq $null -and $test2 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.15"
    Task = "Ensure only strong Key Exchange algorithms are used"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep -Ei'^\s*kexalgorithms\s+([^#]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b'
            try{
                $test2 = grep -Ei '^\s*kexalgorithms\s+([^#]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b'/etc/ssh/sshd_config
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if($test1 -eq $null -and $test2 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.16"
    Task = "Ensure SSH Idle Timeout Interval is configured"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep clientaliveinterval | cut -d ' ' -f 2
            $test2 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep clientalivecountmax | cut -d ' ' -f 2
            try{
                $test3 = grep -Eis '^\s*clientaliveinterval\s+(0|3[0-9][1-9]|[4-9][0-9][0-9]|[1-9][0-9][0-9][0-9]+|[6-9]m|[1-9][0-9]+m)\b' /etc/ssh/sshd_config/etc/ssh/sshd_config.d/*.conf
                $test4 = grep -Eis '^\s*ClientAliveCountMax\s+(0|[4-9]|[1-9][0-9]+)\b'/etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if(($test1 -ge 1 -and $test1 -le 300) -and ($test2 -ge 1 -and $test2 -le 3) -and $test3 -eq $null -and $test4 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.17"
    Task = "Ensure SSH LoginGraceTime is set to one minute or less"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep logingracetime | cut -d ' ' -f 2
            try{
                $test2 = grep -Eis '^\s*LoginGraceTime\s+(0|6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+|[^1]m)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if(($test1 -ge 1 -and $test1 -le 60) -and $test2 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.18"
    Task = "Ensure SSH warning banner is configured"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep banner
            try{
                $test2 = grep -Eis '^\s*Banner\s+"?none\b' /etc/ssh/sshd_config/etc/ssh/sshd_config.d/*.conf
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if($test1 -match "banner /etc/issue.net" -and $test2 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.19"
    Task = "Ensure SSH PAM is enabled"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep -i usepam
            try{
                $test2 = grep -Eis '^\s*UsePAM\s+no' /etc/ssh/sshd_config/etc/ssh/sshd_config.d/*.conf
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if($test1 -match "usepam yes" -and $test2 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.20"
    Task = "Ensure SSH AllowTcpForwarding is disabled"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep -i allowtcpforwarding
            try{
                $test2 = grep -Eis '^\s*AllowTcpForwarding\s+yes\b' /etc/ssh/sshd_config/etc/ssh/sshd_config.d/*.conf
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if($test1 -match "allowtcpforwarding no" -and $test2 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.21"
    Task = "Ensure SSH MaxStartups is configured"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep -i maxstartups
            try{
                $test2 = grep -Eis '^\s*maxstartups\s+(((1[1-9]|[1-9][0-9][0-9]+):([0-9]+):([0-9]+))|(([0-9]+):(3[1-9]|[4-9][0-9]|[1-9][0-9][0-9]+):([0-9]+))|(([0-9]+):([0-9]+):(6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+)))' /etc/ssh/sshd_config/etc/ssh/sshd_config.d/*.conf
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            $value1 = $test1 | cut -d ':' -f 1
            $value2 = $test1 | cut -d ':' -f 2
            $value3 = $test1 | cut -d ':' -f 3
            if($value1 -ge 10 -and $value2 -ge 30 -and $value3 -ge 60 -and $test2 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.3.22"
    Task = "Ensure SSH MaxSessions is limited"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep -i maxsessions | cut -d ' ' -f 2
            
            try{
                $test2 = grep -Eis '^\s*MaxSessions\s+(1[1-9]|[2-9][0-9]|[1-9][0-9][0-9]+)'/etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if($test1 -le 10 -and $test2 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command doesn't exist"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.4.1"
    Task = "Ensure password creation requirements are configured"
    Test = {
        $test1 = grep '^\s*minlen\s*' /etc/security/pwquality.conf | cut -d ' ' -f 3
        $test2 = grep '^\s*minclass\s*' /etc/security/pwquality.conf | cut -d ' ' -f 3
        $test3 = grep -E '^\s*password\s+(requisite|required)\s+pam_pwquality\.so\s+(\S+\s+)*retry=[1-3]\s*(\s+\S+\s*)*(\s+#.*)?$' /etc/pam.d/common-password | cut -d '=' -f 2
        if($test1 -ge 14 -and $test2 -eq 4 -and $test3 -le 3){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.4.2"
    Task = "Ensure lockout for failed password attempts is configured"
    Test = {
        $test1 = grep "pam_tally2" /etc/pam.d/common-auth
        $test2 = grep -E "pam_(tally2|deny)\.so" /etc/pam.d/common-account
        if($test1 -ne $null -and $test2 -match "pam_deny.so" -and $test2 -match "pam_tally2.so"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.4.3"
    Task = "Ensure password reuse is limited"
    Test = {
        $test1 = grep -E '^\s*password\s+required\s+pam_pwhistory\.so\s+([^#]+\s+)?remember=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/common-password | cut -d '=' -f 2
        if($test1 -ge 5){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.4.4"
    Task = "Ensure password hashing algorithm is SHA-512"
    Test = {
        $test1 = grep -E '^\s*password\s+(\[success=1\s+default=ignore\]|required)\s+pam_unix\.so\s+([^#]+\s+)?sha512\b' /etc/pam.d/common-password
        if($test1 -match "password" -and $test1 -match "success=1" -and $test1 -match "default=ignore" -and $test1 -match "sha512"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.5.1.1"
    Task = "Ensure minimum days between password changes is configured"
    Test = {
        $test1 = grep PASS_MIN_DAYS /etc/login.defs | cut -d ' ' -f 2
        if($test1 -ge 1){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.5.1.2"
    Task = "Ensure password expiration is 365 days or less"
    Test = {
        try{
            $res=grep PASS_MAX_DAYS /etc/login.defs | tail -1 | cut -d ' ' -f 1
            $res=$res.substring($res.Length -3)

            $min=grep PASS_MIN_DAYS /etc/login.defs | tail -1 | cut -d ' ' -f 2
            $min=$min.substring($min.Length -1)
            if($res -le 365 -and $res -gt $min){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "5.5.1.3"
    Task = "Ensure password expiration warning days is 7 or more"
    Test = {
        $test1 = grep PASS_WARN_AGE /etc/login.defs | cut -d ' ' -f 2
        if($test1 -ge 7){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.5.1.4"
    Task = "Ensure inactive password lock is 30 days or less"
    Test = {
        $test1 = useradd -D | grep INACTIVE | cut -d '=' -2
        if($test1 -le 30){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.5.1.5"
    Task = "Ensure all users last password change date is in the past"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu-5.5.1.5.sh"
        $result=bash $path
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.5.2"
    Task = "Ensure system accounts are secured"
    Test = {
        $test1 = awk -F: '$1!~/(root|sync|shutdown|halt|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!~/((\/usr)?\/sbin\/nologin)/ && $7!~/(\/bin)?\/false/ {print}' /etc/passwd
        $test2 = awk -F: '($1!~/(root|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}'/etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!~/LK?/) {print $1}'
        if($test1 -eq $null -and $test2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.5.3"
    Task = "Ensure default group for the root account is GID 0"
    Test = {
        $test1 = grep "^root:" /etc/passwd | cut -f4 -d ':'
        if($test1 -eq 0){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.7"
    Task = "Ensure access to the su command is restricted"
    Test = {
        $test1 = grep pam_wheel.so /etc/pam.d/su

        if($test1 -match "auth required pam_wheel.so use_uid group="){
            $test2 = $test1 | cut -d '=' -f 2
            $test3 = grep $test2 /etc/group | cut -d ':' -f 4
            if($test3 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.1.1"
    Task = "Audit system file permissions"
    Test = {
        $test1 = dpkg --verify $(dpkg --get-selections | awk '{print $1}')
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.1.2"
    Task = "Ensure permissions on /etc/passwd are configured"
    Test = {
        $test1 = stat /etc/passwd
        if($test1 -eq "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.1.3"
    Task = "Ensure permissions on /etc/passwd- are configured"
    Test = {
        $test1 = stat /etc/passwd-
        if($test1 -eq "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.1.4"
    Task = "Ensure permissions on /etc/group are configured"
    Test = {
        $test1 = stat /etc/group
        if($test1 -eq "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.1.5"
    Task = "Ensure permissions on /etc/group- are configured"
    Test = {
        $test1 = stat /etc/group- | grep 0644
        if($test1 -eq "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.1.6"
    Task = "Ensure permissions on /etc/shadow are configured"
    Test = {
        $test1 = stat /etc/shadow | grep 0640
        if($test1 -eq "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (    0/    root)"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.1.7"
    Task = "Ensure permissions on /etc/shadow- are configured"
    Test = {
        $test1 = stat /etc/shadow- | grep 0640
        if($test1 -eq "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (   42/  shadow)"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.1.8"
    Task = "Ensure permissions on /etc/gshadow are configured"
    Test = {
        $test1 = stat /etc/gshadow | grep 0640
        if($test1 -eq "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (   42/  shadow)"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.1.9"
    Task = "Ensure permissions on /etc/gshadow- are configured"
    Test = {
        $test1 = stat /etc/gshadow- | grep 0640
        if($test1 -eq "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (   42/  shadow)"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.1.10"
    Task = "Ensure no world writable files exist"
    Test = {
        # $partitions = mapfile -t partitions < (sudo fdisk -l | grep -o '/dev/[^ ]*')
        $test1 = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.1.11"
    Task = "Ensure no unowned files or directories exist"
    Test = {
        try{
            $test1 = df --local -P | awk "{if (NR -ne 1) { print `$6 }}" | xargs -I '{}' find '{}' -xdev -nouser
            if($test1 -eq $null){
                return @{
                    Message = "Compliant"
                    Status = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status = "False"
            }
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }  
        }
    }
}
[AuditTest] @{
    Id = "6.1.12"
    Task = "Ensure no ungrouped files or directories exist"
    Test = {
        $test1 = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.1.13"
    Task = "Audit SUID executables"
    Test = {
        $test1 = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000
        $message = ""
        foreach($line in $test1){
            $message += "<br>$line"
        }
        return @{
            Message = "Please review following list of files: $($message)"
            Status = "None"
        }
    }
}
[AuditTest] @{
    Id = "6.1.14"
    Task = "Audit SGID executables"
    Test = {
        $test1 = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000
        $message = ""
        foreach($line in $test1){
            $message += "<br>$line"
        }
        return @{
            Message = "Please review following list of files: $($message)"
            Status = "None"
        }
    }
}
[AuditTest] @{
    Id = "6.2.1"
    Task = "Ensure accounts in /etc/passwd use shadowed passwords"
    Test = {
        $test1 = awk -F: '($2 != "x" ) { print $1 " is not set to shadowed passwords "}'/etc/passwd
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.2"
    Task = "Ensure password fields are not empty"
    Test = {
        $test1 = awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow
        if($test1 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.3"
    Task = "Ensure all groups in /etc/passwd exist in /etc/group"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu-6.2.3.sh"
        $result=bash $path
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.4"
    Task = "Ensure all users' home directories exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu-6.2.4.sh"
        $result=bash $path
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.5"
    Task = "Ensure users own their home directories"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu-6.2.5.sh"
        $result=bash $path
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.6"
    Task = "Ensure users' home directories permissions are 750 or more restrictive"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu-6.2.6.sh"
        $result=bash $path
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.7"
    Task = "Ensure users' dot files are not group or world writable"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu-6.2.7.sh"
        $result=bash $path
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.8"
    Task = "Ensure no users have .netrc files"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu-6.2.8.sh"
        $result=bash $path
        if($result -match "FAILED"){
            return @{
                Message = "Not-Compliant. Permissions need to get updated."
                Status = "False"
            }
        }
        if($result -match "WARNING" -and $result -notmatch "FAILED"){
            return @{
                Message = "Some changed should be made."
                Status = "Warning"
            }
        }
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.9"
    Task = "Ensure no users have .forward files"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu-6.2.9.sh"
        $result=bash $path
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.10"
    Task = "Ensure no users have .rhosts files"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu-6.2.10.sh"
        $result=bash $path
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.11"
    Task = "Ensure root is the only UID 0 account"
    Test = {
        $test1 = awk -F: '($3 == 0) { print $1 }' /etc/passwd
        if($test1 -match "root"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.12"
    Task = "Ensure root PATH Integrity"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu-6.2.12.sh"
        $result=bash $path
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.13"
    Task = "Ensure no duplicate UIDs exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu-6.2.13.sh"
        $result=bash $path
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.14"
    Task = "Ensure no duplicate GIDs exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu-6.2.14.sh"
        $result=bash $path
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.15"
    Task = "Ensure no duplicate user names exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu-6.2.15.sh"
        $result=bash $path
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.16"
    Task = "Ensure no duplicate group names exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu-6.2.16.sh"
        $result=bash $path
        if($result -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.17"
    Task = "Ensure shadow group is empty"
    Test = {
        $test1 = awk -F: '($1=="shadow") {print $NF}' /etc/group
        $test2 = awk -F: -v GID="$(awk -F: '($1=="shadow") {print $3}' /etc/group)" '($4==GID) {print $1}' /etc/passwd
        if($test1.Length -eq 0 -and $test2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}