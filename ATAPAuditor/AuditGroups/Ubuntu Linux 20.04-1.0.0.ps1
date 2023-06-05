[AuditTest] @{
    Id = "1.1.1.1"
    Task = "Ensure mounting of cramfs filesystetms is disabled"
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
    Task = "Ensure mounting of freevxfs filesystetms is disabled"
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
    Task = "Ensure mounting of squashfs filesystetms is disabled"
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
        $result = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
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
    Id = "1.1.23"
    Task = "Disable Automounting"
    Test = {
        $result = dpkg -s autofs
        if($result -match "package 'autofs' is not installed"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        else{
            $result = systemctl is-enabled autofs
            if($result -match "disabled"){
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
        $result1 = dpkg -s aide | grep -E 'Status:|not installed)'
        $result2 = dpkg -s aide-common | grep -E 'Status:|not installed)'
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
        $response = 'if [ "x${grub_cfg}" != "x" ] && ! grep "^password" ${grub_cfg}.new >/dev/null; then
        chmod 444 ${grub_cfg}.new || true
      fi
      ' 
        if($output -ne $response){
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
        $result = $result | cut '/'
        $result = $result | cut -d '/' -f 1
        if($result -ge 0400){
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
        $result = journalctl | grep 'protection: active'
        if($result -match "kernel: NX (Execute Disable) protection: active"){
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
        $result = dpkg -s prelink | grep -E '(Status:|not installed)'
        if($result -match "package 'prelink' is not installed"){
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
        $result1 = grep -Es '^(\*|\s).*hard.*core.*(\s+#.*)?$' /etc/security/limits.conf /etc/security/limits.d/*
        $result2 = sysctl fs.suid_dumpable
        $result3 = grep "fs.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*
        $result4 = systemctl is-enabled coredump.service
        $message = "Compliant"
        if($result4 -match "enabled" -or $result4 -match "masked" -or $result4 -match "disabled"){
            $message = "systemd-coredump is installed"
        }
        if($result1 -match "* hard core 0" -and $result2 -match "fs.suid_dumpable = 0" -and $result3 -match "fs.suid_dumpable = 0"){
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