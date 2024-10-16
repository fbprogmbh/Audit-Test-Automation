[AuditTest] @{
    Id   = "1.1.1.1"
    Task = "Ensure mounting of cramfs filesystems is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-1.1.1.1.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.1.2"
    Task = "Ensure mounting of squashfs filesystems is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-1.1.1.2.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.1.3"
    Task = "Ensure mounting of udf filesystems is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-1.1.1.3.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.1"
    Task = "Ensure /tmp is a separate partition"
    Test = {
        $result = findmnt --kernel /tmp
        if ($result -match "/tmp") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.2"
    Task = "Ensure nodev option set on /tmp partition"
    Test = {
        $result = findmnt --kernel /tmp | grep nodev
        if ($result -match "nodev") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.3"
    Task = "Ensure noexec option set on /tmp partition"
    Test = {
        $result = findmnt --kernel /tmp | grep noexec
        if ($result -match "noexec") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.4"
    Task = "Ensure nosuid option set on /tmp partition"
    Test = {
        $result = findmnt --kernel /tmp | grep nosuid
        if ($result -match "nosuid") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.3.1"
    Task = "Ensure separate partition exists for /var"
    Test = {
        $result = findmnt --kernel /var
        if ($result -match "/var") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.3.2"
    Task = "Ensure nodev option set on /var partition"
    Test = {
        $result = findmnt --kernel /var
        if ($result -match "nodev") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.3.3"
    Task = "Ensure nosuid option set on /var partition"
    Test = {
        $result = findmnt --kernel /var
        if ($result -match "nosuid") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.4.1"
    Task = "Ensure separate partition exists for /var/tmp"
    Test = {
        $result = findmnt --kernel /var/tmp
        if ($result -match "/var/tmp") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.4.2"
    Task = "Ensure noexec option set on /var/tmp partition"
    Test = {
        $result = findmnt --kernel /var/tmp
        
        # if no separate partition, at least the flag is set
        if ($result -eq $null) {
            $result = findmnt --kernel /var
        }

        if ($result -match "noexec") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.4.3"
    Task = "Ensure nosuid option set on /var/tmp partition"
    Test = {
        $result = findmnt --kernel /var/tmp

        # if no separate partition, at least the flag is set
        if ($result -eq $null) {
            $result = findmnt --kernel /var
        }

        if ($result -match "nosuid") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.4.4"
    Task = "Ensure nodev option set on /var/tmp partition"
    Test = {
        $result = findmnt --kernel /var/tmp

        # if no separate partition, at least the flag is set
        if ($result -eq $null) {
            $result = findmnt --kernel /var
        }

        if ($result -match "nodev") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.5.1"
    Task = "Ensure separate partition exists for /var/log"
    Test = {
        $result = findmnt --kernel /var/log

        # if no separate partition, at least the flag is set
        if ($result -eq $null) {
            $result = findmnt --kernel /var
        }

        if ($result -match "/var/log") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.5.2"
    Task = "Ensure nodev option set on /var/log partition"
    Test = {
        $result = findmnt --kernel /var/log

        # if no separate partition, at least the flag is set
        if ($result -eq $null) {
            $result = findmnt --kernel /var
        }

        if ($result -match "nodev") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.5.3"
    Task = "Ensure noexec option set on /var/log partition"
    Test = {
        $result = findmnt --kernel /var/log

        # if no separate partition, at least the flag is set
        if ($result -eq $null) {
            $result = findmnt --kernel /var
        }

        if ($result -match "noexec") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.5.4"
    Task = "Ensure nosuid option set on /var/log partition"
    Test = {
        $result = findmnt --kernel /var/log

        # if no separate partition, at least the flag is set
        if ($result -eq $null) {
            $result = findmnt --kernel /var
        }

        if ($result -match "nosuid") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.6.1"
    Task = "Ensure separate partition exists for /var/log/audit"
    Test = {
        $result = findmnt --kernel /var/log/audit
        if ($result -match "/var/log/audit") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.6.2"
    Task = "Ensure noexec option set on /var/log/audit partition"
    Test = {
        $result = findmnt --kernel /var/log/audit

        # if no separate partition, at least the flag is set
        if ($result -eq $null) {
            $result = findmnt --kernel /var
        }

        if ($result -match "noexec") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.6.3"
    Task = "Ensure nodev option set on /var/log/audit partition"
    Test = {
        $result = findmnt --kernel /var/log/audit

        # if no separate partition, at least the flag is set
        if ($result -eq $null) {
            $result = findmnt --kernel /var
        }

        if ($result -match "nodev") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.6.4"
    Task = "Ensure nosuid option set on /var/log/audit partition"
    Test = {
        $result = findmnt --kernel /var/log/audit

        # if no separate partition, at least the flag is set
        if ($result -eq $null) {
            $result = findmnt --kernel /var
        }
        
        if ($result -match "nosuid") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.7.1"
    Task = "Ensure separate partition exists for /home"
    Test = {
        $result = findmnt --kernel /home
        if ($result -match "/home") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.7.2"
    Task = "Ensure nodev option set on /home partition"
    Test = {
        $result = findmnt --kernel /home
        if ($result -match "nodev") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.7.3"
    Task = "Ensure nosuid option set on /home partition"
    Test = {
        $result = findmnt --kernel /home
        if ($result -match "nosuid") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.8.1"
    Task = "Ensure nodev option set on /dev/shm partition"
    Test = {
        $result = findmnt --kernel /dev/shm | grep nodev
        if ($result -match "nodev") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.8.2"
    Task = "Ensure noexec option set on /dev/shm partition"
    Test = {
        $result = findmnt --kernel /dev/shm | grep noexec
        if ($result -match "noexec") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.8.3"
    Task = "Ensure nosuid option set on /dev/shm partition"
    Test = {
        $result = findmnt --kernel /dev/shm | grep nosuid
        if ($result -match "nosuid") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.9"
    Task = "Disable Automounting"
    Test = {
        $result1 = systemctl is-enabled autofs
        $status = $?
        # error occurs when autofs is not installed, that is compliant, too
        if ($status -match "False") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        if ($result1 -match "Failed" -and ($result1 -match "Failed" -or $result1 -match "disabled")) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.1.10"
    Task = "Disable USB Storage"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-1.1.10.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.2.1"
    Task = "Ensure package manager repositories are configured"
    Test = {
        $result = apt-cache policy
        if ($result -ne $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.2.2"
    Task = "Ensure GPG keys are configured"
    Test = {
        $result = apt-key list
        if ($result -ne $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.3.1"
    Task = "Ensure AIDE is installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' aide aide-common
        if ($result -match "install ok installed") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.3.2"
    Task = "Ensure filesystem integrity is regularly checked"
    Test = {
        $result = grep -Prs '^([^#\n\r]+\h+)?(\/usr\/s?bin\/|^\h*)aide(\.wrapper)?\h+(--check|([^#\n\r]+\h+)?\$AIDEARGS)\b' /etc/cron.* /etc/crontab /var/spool/cron/
        if ($result -match "install ok installed") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.4.1"
    Task = "Ensure bootloader password is set"
    Test = {
        $result1 = grep "^set superusers" /boot/grub/grub.cfg
        $result2 = grep "^password" /boot/grub/grub.cfg

        if ($result1 -match "set superusers=" -and $result2 -match "password_pbkdf2") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.4.2"
    Task = "Ensure permissions on bootloader config are configured"
    Test = {
        $test1 = stat /boot/grub/grub.cfg | grep 0400
        if ($test1 -ne $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.4.3"
    Task = "Ensure authentication required for single user mode"
    Test = {
        $command = @'
grep -Eq '^root:\$(y|[0-9])' /etc/shadow || echo 'root is locked'
'@
        $result = bash -c $command
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.5.1"
    Task = "Ensure address space layout randomization (ASLR) is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-1.5.1.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.5.2"
    Task = "Ensure prelink is not installed"
    Test = {
        $result = dpkg -l | grep -o prelink
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.5.3"
    Task = "Ensure Automatic Error Reporting is not enabled"
    Test = {
        $command = "dpkg-query -s apport > /dev/null 2>&1 && grep -Psi --'^\h*enabled\h*=\h*[^0]\b' /etc/default/apport"
        $result1 = bash -c $command
        $result2 = systemctl is-active apport.service | grep '^active'
        if ($result1 -eq $null -and $result2 -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.5.4"
    Task = "Ensure core dumps are restricted"
    Test = {
        try {
            $result1 = grep -Es '^(\*|\s).*hard.*core.*(\s+#.*)?$' /etc/security/limits.conf /etc/security/limits.d/*
            $result2 = sysctl fs.suid_dumpable
            $result3 = grep "fs.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*
            try {
                $result4 = systemctl is-enabled coredump.service
                $message = "Compliant"
                if ($result4 -match "enabled" -or $result4 -match "masked" -or $result4 -match "disabled") {
                    $message = "systemd-coredump is installed"
                }
            }
            catch {
                $message = "systemd-coredump not installed"
            }
            if ($result1 -match ".*\s*hard\s*core\s*0{1}?\s*" -and $result2 -match "fs.suid_dumpable = 0" -and $result3 -match "fs.suid_dumpable = 0") {
                return @{
                    Message = $message
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        catch {
            return @{
                Message = "Command not found!"
                Status  = "False"
            }
        }
    }
}
[AuditTest] @{
    Id   = "1.6.1.1"
    Task = "Ensure AppArmor is installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' apparmor apparmor-utils
        if ($result -match "apparmor\s+install ok installed\s+installed" -and $result -match "apparmor-utils\s+install ok installed\s+installed") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.6.1.2"
    Task = "Ensure AppArmor is enabled in the bootloader configuration"
    Test = {
        $result1 = grep "^\s*linux" /boot/grub/grub.cfg | grep -v "apparmor=1"
        $result2 = grep "^\s*linux" /boot/grub/grub.cfg | grep -v "security=apparmor"
        if ($result1 -eq $null -and $result2 -eq $null ) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.6.1.3"
    Task = "Ensure all AppArmor Profiles are in enforce or complain mode"
    Test = {
        $profileMode1 = apparmor_status | grep profiles | sed '1!d' | cut -d ' ' -f 1
        $profileMode2 = apparmor_status | grep profiles | sed '2!d' | cut -d ' ' -f 1
        $profileMode3 = apparmor_status | grep profiles | sed '3!d' | cut -d ' ' -f 1
        $result = expr $profileMode3 + $profileMode2
        
        $unconfinedProcesses = apparmor_status | grep processes | sed '4!d' | cut -d ' ' -f 1

        if ($result -eq $profileMode1 -and $unconfinedProcesses -eq 0) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.6.1.4"
    Task = "Ensure all AppArmor Profiles are enforcing"
    Test = {
        $profileMode1 = apparmor_status | grep profiles | sed '1!d' | cut -d ' ' -f 1
        $profileMode2 = apparmor_status | grep profiles | sed '2!d' | cut -d ' ' -f 1
        
        $unconfinedProcesses = apparmor_status | grep processes | sed '4!d' | cut -d ' ' -f 1

        if ($profileMode1 -eq $profileMode2 -and $unconfinedProcesses -eq 0) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.7.1"
    Task = "Ensure message of the day is configured properly"
    Test = {
        $output = grep -Eis "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/motd

        if ($output -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.7.2"
    Task = "Ensure local login warning banner is configured properly"
    Test = {
        $output1 = cat /etc/issue
        $output2 = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue
        
        if ($output1 -ne $null -and $output2 -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.7.3"
    Task = "Ensure remote login warning banner is configured properly"
    Test = {
        $output1 = cat /etc/issue.net
        $output2 = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net
        
        if ($output1 -ne $null -and $output2 -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.7.4"
    Task = "Ensure permissions on /etc/motd are configured"
    Test = {
        if (Test-Path /etc/motd) {
            $test1 = stat /etc/motd | grep 0644
            if ($test1 -ne $null) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        else {
            return @{
                Message = "motd not present"
                Status  = "None"
            }
        }
    }
}
[AuditTest] @{
    Id   = "1.7.5"
    Task = "Ensure permissions on /etc/issue are configured"
    Test = {
        $output = stat -L /etc/issue | grep "Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)"
        
        if ($output -ne $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.8.1"
    Task = "Ensure GNOME Display Manager is removed"
    Test = {
        $test = dpkg -l | grep "^ii" | grep -q "gdm3"
        $output = $?
        if ($output -match "False") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.8.2"
    Task = "Ensure GDM login banner is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-1.8.2.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.8.3"
    Task = "Ensure GDM disable-user-list option is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-1.8.3.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.8.4"
    Task = "Ensure GDM screen locks when the user is idle"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-1.8.4.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.8.5"
    Task = "Ensure GDM screen locks cannot be overridden"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-1.8.5.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.8.6"
    Task = "Ensure GDM automatic mounting of removable media is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-1.8.6.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.8.7"
    Task = "Ensure GDM disabling automatic mounting of removable media is not overridden"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-1.8.7.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.8.8"
    Task = "Ensure GDM autorun-never is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-1.8.8.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.8.9"
    Task = "Ensure GDM autorun-never is not overridden"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-1.8.9.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.8.10"
    Task = "Ensure XDCMP is not enabled"
    Test = {
        $output = grep -Eis '^\s*Enable\s*=\s*true' /etc/gdm3/custom.conf
        if ($output -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "1.9"
    Task = "Ensure updates, patches, and additional security software are installed"
    Test = {
        $output = apt -s upgrade
        $output = $?
        if ($output -match "True") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.1.1.1"
    Task = "Ensure a single time synchronization daemon is in use"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-2.1.1.1.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.1.2.1"
    Task = "Ensure chrony is configured with authorized timeserver"
    Test = {
        $output = apt -s upgrade
        $output = $?
        if ($output -match "True") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.1.2.2"
    Task = "Ensure chrony is running as user _chrony"
    Test = {
        $testchr = dpkg-query -s chrony 
        $statuschr = $?
        if ($statuschr -match "True") {
            $result = ps -ef | awk '(/[c]hronyd/ && $1!="_chrony") { print $1 }'
            if ($result -eq $null) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        return @{
            Message = "chrony not installed"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "2.1.2.3"
    Task = "Ensure chrony is enabled and running"
    Test = {
        $testchr = dpkg-query -s chrony 
        $statuschr = $?
        if ($statuschr -match "True") {
            $result1 = systemctl is-enabled chrony.service
            $result2 = systemctl is-active chrony.service
            if ($result1 -match "enabled" -and $result2 -match "active") {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        return @{
            Message = "chrony not installed"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "2.1.3.1"
    Task = "Ensure systemd-timesyncd configured with authorized timeserver"
    Test = {

        $testtime = dpkg-query -s systemd-timesyncd 
        $statustime = $?
        if ($statustime -match "True") {
            $command = @'
find /etc/systemd -type f -name '*timesyncd*' -exec grep -Ehl '^NTP=|^FallbackNTP=' {} +
'@
            $test = bash -c $command
            $status = $?

            if ($status -match "True") {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        return @{
            Message = "systemd-timesyncd not installed"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "2.1.3.2"
    Task = "Ensure systemd-timesyncd is enabled and running"
    Test = {
        $result1 = systemctl is-enabled systemd-timesyncd.service
        $result2 = systemctl is-active systemd-timesyncd.service
        if ($result1 -match "enabled" -and $result2 -match "active") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.1.4.1"
    Task = "Ensure ntp access control is configured"
    Test = {
        $testntp = dpkg-query -s ntp 
        $statusntp = $?

        if ($statusntp -match "True") {
            $result = grep -P -- '^\h*restrict\h+((-4\h+)?|-6\h+)default\h+(?:[^#\n\r]+\h+)*(?!(?:\2|\3|\4|\5))(\h*\bkod\b\h*|\h*\bnomodify\b\h*|\h*\bnotrap\b\h*|\h*\bnopeer\b\h*|\h*\bnoquery\b\h*)\h+(?:[^#\n\r]+\h+)*(?!(?:\1|\3|\4|\5))(\h*\bkod\b\h*|\h*\bnomodify\b\h*|\h*\bnotrap\b\h*|\h*\bnopeer\b\h*|\h*\bnoquery\b\h*)\h+(?:[^#\n\r]+\h+)*(?!(?:\1|\2|\4|\5))(\h*\bkod\b\h*|\h*\bnomodify\b\h*|\h*\bnotrap\b\h*|\h*\bnopeer\b\h*|\h*\bnoquery\b\h*)\h+(?:[^#\n\r]+\h+)*(?!(?:\1|\2|\3|\5))(\h*\bkod\b\h*|\h*\bnomodify\b\h*|\h*\bnotrap\b\h*|\h*\bnopeer\b\h*|\h*\bnoquery\b\h*)\h+(?:[^#\n\r]+\h+)*(?!(?:\1|\2|\3|\4))(\h*\bkod\b\h*|\h*\bnomodify\b\h*|\h*\bnotrap\b\h*|\h*\bnopeer\b\h*|\h*\bnoquery\b\h*)\h*(?:\h+\H+\h*)*(?:\h+#.*)?$' /etc/ntp.conf
            $wordsToCheck = "default", "kod", "nomodify", "notrap", "nopeer", "noquery"
            $pattern = "\b(" + ($wordsToCheck -join "|") + ")\b"
            if ($result.Count -eq 2 -and $result[0] -match $pattern -and $result[1] -match $pattern) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        return @{
            Message = "ntp not installed"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "2.1.4.2"
    Task = "Ensure ntp is configured with authorized timeserver"
    Test = {
        $testntp = dpkg-query -s ntp 
        $statusntp = $?
        if ($statusntp -match "True") {
            $result = grep -P -- '^\h*(server|pool)\h+\H+' /etc/ntp.conf
            $wordsToCheck = "default", "kod", "nomodify", "notrap", "nopeer", "noquery"
            $pattern = "\b(" + ($wordsToCheck -join "|") + ")\b"
            if ($result.Count -eq 2 -and $result[0] -match $pattern -and $result[1] -match $pattern) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        return @{
            Message = "ntp not installed"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "2.1.4.3"
    Task = "Ensure ntp is running as user ntp"
    Test = {
        $testntp = dpkg-query -s ntp 
        $statusntp = $?
        if ($statusntp -match "True") {
            $result1 = ps -ef | awk '(/[n]tpd/ && $1!="ntp") { print $1 }'
            $result2 = grep -P -- '^\h*RUNASUSER=' /etc/init.d/ntp
            if ($result1 -eq $null -and $result2 -eq "RUNASUSER=ntp") {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        return @{
            Message = "ntp not installed"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "2.1.4.4"
    Task = "Ensure ntp is enabled and running"
    Test = {
        $testntp = dpkg-query -s ntp 
        $statusntp = $?
        if ($statusntp -match "True") {
            $result1 = systemctl is-enabled ntp.service
            $result2 = systemctl is-active ntp.service
            if ($result1 -match "enabled" -and $result2 -match "active") {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }  
        }
        return @{
            Message = "ntp not installed"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.1"
    Task = "Ensure X Window System is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' xserver-xorg* | grep -Pi '\h+installed\b'
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.2"
    Task = "Ensure Avahi Server is not installed"
    Test = {
        $test1 = dpkg -l | grep "^ii" | grep -q "avahi-daemon"
        $test1 = $?
        if ($test1 -match "False") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.3"
    Task = "Ensure CUPS is not installed"
    Test = {
        $result = dpkg-query -s cups 
        $status = $?
        if ($status -match "False") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.4"
    Task = "Ensure DHCP Server is not installed"
    Test = {
        $result = dpkg -l | grep -o isc-dhcp-server
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.5"
    Task = "Ensure LDAP server is not installed"
    Test = {
        $result = dpkg -l | grep -o slapd
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.6"
    Task = "Ensure NFS is not installed"
    Test = {
        $result = dpkg -l | grep -o  nfs-kernel-server
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.7"
    Task = "Ensure DNS Server is not installed"
    Test = {
        $result = dpkg -l | grep -E -w "^ii\s+bind9\s"
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.8"
    Task = "Ensure FTP Server is not installed"
    Test = {
        $result = dpkg -l | grep -o vsftpd
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.9"
    Task = "Ensure HTTP server is not installed"
    Test = {
        $result = dpkg -l | grep -E 'apache2\s'
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.10"
    Task = "Ensure IMAP and POP3 server are not installed"
    Test = {
        $result = dpkg -l | grep -o dovecot-
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.11"
    Task = "Ensure Samba is not installed"
    Test = {
        $result = dpkg-query -s samba 
        $status = $?
        if ($status -match "False") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.12"
    Task = "Ensure HTTP Proxy Server is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' squid
        if ($result -match "squid\s+unknown ok not-installed\s+not-installed") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.13"
    Task = "Ensure SNMP Server is not installed"
    Test = {
        $result = dpkg -l | grep -E 'snmpd\s'
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.14"
    Task = "Ensure NIS Server is not installed"
    Test = {
        $result = dpkg-query -s nis 
        $status = $?
        if ($status -match "False") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.15"
    Task = "Ensure mail transfer agent is configured for local-only mode"
    Test = {
        $result = ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s'
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.2.16"
    Task = "Ensure rsync service is either not installed or masked"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' rsync
        if ($result -match "rsync\s+unknown ok not-installed\s+not-installed") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.3.1"
    Task = "Ensure NIS Client is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' nis
        if ($result -match "nis\s+unknown ok not-installed\s+not-installed") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.3.2"
    Task = "Ensure rsh client is not installed"
    Test = {
        $result = dpkg-query -s rsh-client 
        $status = $?
        if ($status -match "False") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.3.3"
    Task = "Ensure talk client is not installed"
    Test = {
        $test1 = dpkg -l | grep "^ii" | grep -q "talk"
        $test1 = $?
        if ($test1 -match "False") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.3.4"
    Task = "Ensure telnet client is not installed"
    Test = {
        $test1 = dpkg -l | grep -o telnet
        if ($test1 -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.3.5"
    Task = "Ensure LDAP client is not installed"
    Test = {
        $test1 = dpkg -l | grep -o ldap-utils
        if ($test1 -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.3.6"
    Task = "Ensure RPC is not installed"
    Test = {
        $test1 = dpkg -l | grep -o rpcbind
        if ($test1 -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "2.4"
    Task = "Ensure nonessential services are removed or masked"
    Test = {
        $test1 = lsof -i -P -n | grep -v "(ESTABLISHED)"
        if ($test1 -ne $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.1.1"
    Task = "Ensure system is checked to determine if IPv6 is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.1.1.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.1.2"
    Task = "Ensure wireless interfaces are disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.1.2.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.1.3"
    Task = "Ensure DCCP is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.1.3.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.1.4"
    Task = "Ensure SCTP is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.1.4.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.1.5"
    Task = "Ensure RDS is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.1.5.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.1.6"
    Task = "Ensure TIPC is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.1.6.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.2.1"
    Task = "Ensure packet redirect sending is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.2.1.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.2.2"
    Task = "Ensure IP forwarding is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.2.2.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.3.1"
    Task = "Ensure source routed packets are not accepted"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.1.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.3.2"
    Task = "Ensure ICMP redirects are not accepted"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.2.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.3.3"
    Task = "Ensure secure ICMP redirects are not accepted"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.3.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.3.4"
    Task = "Ensure suspicious packets are logged"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.4.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.3.5"
    Task = "Ensure broadcast ICMP requests are ignored"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.5.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.3.6"
    Task = "Ensure bogus ICMP responses are ignored"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.6.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.3.7"
    Task = "Ensure Reverse Path Filtering is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.7.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.3.8"
    Task = "Ensure TCP SYN Cookies is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.8.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.3.9"
    Task = "Ensure IPv6 router advertisements are not accepted"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.9.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.1.1"
    Task = "Ensure ufw is installed"
    Test = {
        $testnft = dpkg-query -s nftables 
        $statusnft = $?
        if ($statusnft -match "False") {
            $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' ufw
            if ($result -match "ufw\s+install ok installeds\+installed") {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        return @{
            Message = "nftables installed instead "
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.1.2"
    Task = "Ensure iptables-persistent is not installed with ufw"
    Test = {
        $testufw = dpkg-query -s ufw 
        $statusufw = $?
        if ($statusufw -match "True") {
            $test1 = dpkg -l | grep -o iptables-persistent
            if ($test1 -eq $null) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.1.3"
    Task = "Ensure ufw service is enabled"
    Test = {
        $testnft = dpkg-query -s nftables 
        $statusnft = $?
        if ($statusnft -match "True") {
            return @{
                Message = "nftables installed instead "
                Status  = "None"
            }
        }
        $result1 = systemctl is-enabled ufw.service
        $result2 = systemctl is-active ufw
        $result3 = ufw status

        if ($result1 -match "enabled" -and $result2 -match "active" -and $result3 -match "Status: active") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.1.4"
    Task = "Ensure ufw loopback traffic is configured"
    Test = {
        $testnft = dpkg-query -s nftables 
        $statusnft = $?
        if ($statusnft -match "True") {
            return @{
                Message = "nftables installed instead "
                Status  = "None"
            }
        }
        $test1 = ufw status verbose
        $result1 = $test1 -match "^Anywhere on lo\s+ALLOW IN\s+Anywhere$"
        $result2 = $test1 -match "^Anywhere\s+DENY IN\s+127.0.0.0/8$"
        $result3 = $test1 -match "^Anywhere (v6) on lo\s+ALLOW IN\s+Anywhere (v6)$"
        $result4 = $test1 -match "^Anywhere (v6)\s+DENY IN\s+::1$"
        $result5 = $test1 -match "^Anywhere\s+ALLOW OUT\s+Anywhere on lo$"
        $result6 = $test1 -match "^Anywhere (v6)\s+ALLOW OUT\s+Anywhere (v6) on lo$"
        if ($result1 -ne $null -and $result2 -ne $null -and $result3 -ne $null -and $result4 -ne $null -and $result5 -ne $null -and $result6 -ne $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.1.5"
    Task = "Ensure ufw outbound connections are configured"
    Test = {
        $testnft = dpkg-query -s nftables 
        $statusnft = $?
        if ($statusnft -match "True") {
            return @{
                Message = "nftables installed instead "
                Status  = "None"
            }
        }
        return @{
            Message = "Run the following command and verify all rules for new outbound connections match site policy: ufw status numbered"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.1.6"
    Task = "Ensure ufw firewall rules exist for all open ports"
    Test = {
        $testnft = dpkg-query -s nftables 
        $statusnft = $?
        if ($statusnft -match "True") {
            return @{
                Message = "nftables installed instead "
                Status  = "None"
            }
        }
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.5.1.6.sh"
        $result = bash $path
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.1.7"
    Task = "Ensure ufw default deny firewall policy"
    Test = {

        $testnft = dpkg-query -s nftables 
        $statusnft = $?
        if ($statusnft -match "True") {
            return @{
                Message = "nftables installed instead "
                Status  = "None"
            }
        }

        $result = ufw status verbose | grep Default:

        if ($result -match "Default: (deny|reject|disabled) (incoming), (deny|reject|disabled) (outgoing), (deny|reject|disabled) (routed)") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.2.1"
    Task = "Ensure nftables is installed"
    Test = {
        $test = dpkg-query -s nftables | grep 'Status: install ok installed'
        if ($test -match "Status: install ok installed") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.2.2"
    Task = "Ensure ufw is uninstalled or disabled with nftables"
    Test = {
        $testnft = dpkg-query -s nftables 
        $statusnft = $?
        if ($statusnft -match "True") {
            $testufw = dpkg-query -s ufw | grep 'Status: install ok installed'
            $statusufw = $?

            if ($statusufw -match "True") {
                $test2 = ufw status
                if ($test2 -match "inactive") {
                    return @{
                        Message = "Compliant"
                        Status  = "True"
                    }
                }
                return @{
                    Message = "Not-Compliant"
                    Status  = "False"
                }
            }
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "nftables not installed"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.2.3"
    Task = "Ensure iptables are flushed with nftables"
    Test = {
        return @{
            Message = "Run the following commands to ensure no iptables rules exist for iptables: iptables -L \nNo rules should be returned for ip6tables: ip6tables -L \nNo rules should be returned"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.2.4"
    Task = "Ensure a nftables table exists"
    Test = {
        $testnft = dpkg-query -s nftables 
        $statusnft = $?
        if ($statusnft -match "True") {
            $test = nft list tables
            if ($test -match "table") {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        return @{
            Message = "nftables not installed"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.2.5"
    Task = "Ensure nftables base chains exist"
    Test = {
        try {
            $test1 = nft list ruleset | grep 'hook input'
            $test2 = nft list ruleset | grep 'hook forward'
            $test3 = nft list ruleset | grep 'hook output'
            if ($test1 -match "type filter hook input" -and $test2 -match "type filter hook forward" -and $test3 -match "type filter hook output") {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        catch {
            return @{
                Message = "nft not installed!"
                Status  = "None"
            }
        }
    }
}
[AuditTest] @{
    Id   = "3.5.2.6"
    Task = "Ensure nftables loopback traffic is configured"
    Test = {
        try {
            if ($isIPv6Disabled -ne $true) {
                $test1 = nft list ruleset | awk '/hook input/,/}/' | grep 'iif "lo" accept'
                $test2 = nft list ruleset | awk '/hook input/,/}/' | grep 'ip saddr'
                if ($test1 -match 'iif "lo" accept' -and $test2 -match "ip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop") {
                    return @{
                        Message = "Compliant"
                        Status  = "True"
                    }
                }
            }
            else {
                $test = nft list ruleset | awk '/hook input/,/}/' | grep 'ip6 saddr'
                if ($test -match 'ip6 saddr ::1 counter packets 0 bytes 0 drop') {
                    return @{
                        Message = "Compliant"
                        Status  = "True"
                    }
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        catch {
            return @{
                Message = "nft not installed!"
                Status  = "None"
            }
        }
    }
}
[AuditTest] @{
    Id   = "3.5.2.7"
    Task = "Ensure nftables outbound and established connections are configured"
    Test = {
        try {
            $test1 = nft list ruleset | awk '/hook input/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'
            $test2 = nft list ruleset | awk '/hook output/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'
            if ($test1 -match "ip protocol tcp ct state established accept" -and $test1 -match "p protocol udp ct state established accept" -and $test1 -match "ip protocol icmp ct state established accept" -and $test2 -match "ip protocol tcp ct state established,related,new accep" -and $test2 -match "ip protocol udp ct state established,related,new accept" -and $test2 -match "ip protocol icmp ct state established,related,new accept") {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        catch {
            return @{
                Message = "nft not installed!"
                Status  = "None"
            }
        }
    }
}
[AuditTest] @{
    Id   = "3.5.2.8"
    Task = "Ensure nftables default deny firewall policy"
    Test = {
        try {
            $test1 = nft list ruleset | grep 'hook input'
            $test2 = nft list ruleset | grep 'hook forward'
            $test3 = nft list ruleset | grep 'hook output'
            if ($test1 -match "policy drop" -and $test2 -match "policy drop" -and $test3 -match "policy drop") {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        catch {
            return @{
                Message = "nft not installed!"
                Status  = "None"
            }
        }
    }
}
[AuditTest] @{
    Id   = "3.5.2.9"
    Task = "Ensure nftables service is enabled"
    Test = {
        $testnft = dpkg-query -s nftables 
        $statusnft = $?
        if ($statusnft -match "True") {
            $test1 = systemctl is-enabled nftables
            if ($test1 -match "enabled") {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        return @{
            Message = "nftables not installed"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.3.1.1"
    Task = "Ensure iptables packages are installed"
    Test = {
        $testnft = dpkg-query -s nftables 
        $statusnft = $?
        if ($statusnft -match "False") {
            $test1 = apt list iptables iptables-persistent
            $test1 = $?
            if ($test1 -match "True") {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        return @{
            Message = "nftables installed instead"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.3.1.2"
    Task = "Ensure nftables is not installed with iptables"
    Test = {

        $testipt = dpkg-query -s iptables | grep 'Status: install ok installed'
        $statusipt = $?
        $testnft = dpkg-query -s nftables | grep 'Status: install ok installed'
        $statusnft = $?

        if ($statusipt -match "True") {
            if ($statusnft -match "True") {
                $test1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' nftables
                if ($test1 -match "nftables\s+unknown ok not-installed\s+not-installed") {
                    return @{
                        Message = "Compliant"
                        Status  = "True"
                    }
                }
                return @{
                    Message = "Not-Compliant"
                    Status  = "False"
                }
            } return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "iptables not installed "
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.3.1.3"

    Task = "Ensure ufw is uninstalled or disabled with iptables"
    Test = {

        $testipt = dpkg-query -s iptables | grep 'Status: install ok installed'
        $statusipt = $?
        $testufw = dpkg-query -s ufw | grep 'Status: install ok installed'
        $statusufw = $?

        if ($statusipt -match "True") {
            if ($statusufw -match "True") {
                $test1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' ufw
                $test2 = ufw status
                $test3 = systemctl is-enabled ufw
                if ($test1 -match "ufw\s+unknown ok not-installed\s+not-installed" -and $test2 -match "Status: inactive" -and $test3 -match "masked") {
                    return @{
                        Message = "Compliant"
                        Status  = "True"
                    }
                }
                return @{
                    Message = "Not-Compliant"
                    Status  = "False"
                }
            } return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "iptables not installed "
            Status  = "None"
        }

    }
}
[AuditTest] @{
    Id   = "3.5.3.2.1"
    Task = "Ensure iptables default deny firewall policy"
    Test = {
        $test1 = iptables -L
        if ($test1 -match "Chain INPUT (policy (DROP|REJCET))" -and $test1 -match "Chain FORWARD (policy (DROP|REJCET))" -and $test1 -match "Chain OUTPUT (policy (DROP|REJCET))") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.3.2.2"
    Task = "Ensure iptables loopback traffic is configured"
    Test = {
        $test1 = iptables -L INPUT -v -n | grep "Chain\s*INPUT\s*(policy\s*DROP"
        $test2 = iptables -L OUTPUT -v -n | grep "Chain\s*OUTPUT\s*(policy\s*DROP"
        if ($test1 -ne $null -and $test2 -ne $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.3.2.4"
    Task = "Ensure iptables firewall rules exist for all open ports"
    Test = {
        $test1 = ss -4tuln
        if ($test1 -ne $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.3.3.1"
    Task = "Ensure ip6tables default deny firewall policy"
    Test = {
        $test1 = ip6tables -L
        if ($test1 -match "Chain INPUT (policy (DROP|REJCET))" -and $test1 -match "Chain FORWARD (policy (DROP|REJCET))" -and $test1 -match "Chain OUTPUT (policy (DROP|REJCET))") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "3.5.3.3.3"
    Task = "Ensure ip6tables outbound and established connections are configured"
    Test = {
        return @{
            Message = "Run the following command and verify all rules for new outbound, and established connections match site policy: ip6tables -L -v -n"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.1.1"
    Task = "Ensure auditd is installed"
    Test = {
        $test = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' auditd audispd-plugins
        if ($test -match "audispd-plugins\s+install ok installed\s+installed" -and $test -match "auditd\s+install ok installed\s+installed") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.1.2"
    Task = "Ensure auditd service is enabled and active"
    Test = {
        $test1 = systemctl is-enabled auditd
        $test2 = systemctl is-active auditd
        if ($test1 -match "enabled" -and $test2 -match "active") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.1.3"
    Task = "Ensure auditing for processes that start prior to auditd is enabled"
    Test = {
        $command = @'
        find /boot -type f -name 'grub.cfg' -exec grep -Ph -- '^\h*linux' {} + | grep -v 'audit=1'
'@
        $test = bash -c $command
        if ($test -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.1.4"
    Task = "Ensure audit_backlog_limit is sufficient"
    Test = {
        $command = @'
        find /boot -type f -name 'grub.cfg' -exec grep -Ph -- '^\h*linux' {} + | grep -Pv 'audit_backlog_limit=\d+\b'
'@
        $test = bash -c $command
        if ($test -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.2.1"
    Task = "Ensure audit log storage size is configured"
    Test = {
        $test = grep -Po -- '^\h*max_log_file\h*=\h*\d+\b' /etc/audit/auditd.conf
        if ($test -match "max_log_file =") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.2.2"
    Task = "Ensure audit logs are not automatically deleted"
    Test = {
        $test = grep max_log_file_action /etc/audit/auditd.conf
        if ($test -match "max_log_file_action = keep_logs") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.2.3"
    Task = "Ensure system is disabled when audit logs are full"
    Test = {
        $test1 = grep space_left_action /etc/audit/auditd.conf
        $test2 = grep action_mail_acct /etc/audit/auditd.conf
        $test3 = grep -E 'admin_space_left_action\s*=\s*(halt|single)' /etc/audit/auditd.conf
        if ($test1 -match "space_left_action = email" -and $test2 -match "action_mail_acct = root" -and $test3 -match "admin_space_left_action = (halt|single)") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.3.1"
    Task = "Ensure changes to system administration scope (sudoers) is collected"
    Test = {
        try {
            $res1 = awk '/^ *-w/ &&/\/etc\/sudoers/ &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | grep -- "-w /etc/sudoers -p wa -k scope"
            $res2 = awk '/^ *-w/ &&/\/etc\/sudoers/ &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | grep -- "-w /etc/sudoers.d -p wa -k scope"
            $res3 = auditctl -l | awk '/^ *-w/ &&/\/etc\/sudoers/ &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' | grep -- "-w /etc/sudoers -p wa -k scope"
            $res4 = auditctl -l | awk '/^ *-w/ &&/\/etc\/sudoers/ &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' | grep -- "-w /etc/sudoers.d -p wa -k scope"
            if ($res1 -ne $null -and $res2 -ne $null -and $res3 -ne $null -and $res4 -ne $null) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        catch {
            return @{
                Message = "Command not found!"
                Status  = "False"
            }
        }
    }
}
[AuditTest] @{
    Id   = "4.1.3.2"
    Task = "Ensure actions as another user are always logged"
    Test = {
        $test1 = awk '/^ *-a *always,exit/  &&/ -F *arch=b[2346]{2}/  &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/)  &&(/ -C *euid!=uid/||/ -C *uid!=euid/)  &&/ -S *execve/  &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 
        try {
            $test2 = auditctl -l | awk '/^ *-a *always,exit/  &&/ -F *arch=b[2346]{2}/  &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/)  &&(/ -C *euid!=uid/||/ -C *uid!=euid/)  &&/ -S *execve/  &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
        }
        catch {
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        if ($test1 -match "-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation" -and $test1 -match "-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation" -and $test2 -match "-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation" -and $test2 -match "-a always,exit -F arch=b32 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.3.3"
    Task = "Ensure events that modify the sudo log file are collected"
    Test = {
        $command1 = @'
SUDO_LOG_FILE_ESCAPED=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//' -e 's/"//g' -e 's|/|\\/|g') [ -n "${SUDO_LOG_FILE_ESCAPED}" ] && awk "/^ *-w/ \ &&/"${SUDO_LOG_FILE_ESCAPED}"/ \ &&/ +-p *wa/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \ || printf "ERROR: Variable 'SUDO_LOG_FILE_ESCAPED' is unset.\n"
'@
        $command2 = @'
SUDO_LOG_FILE_ESCAPED=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//' -e 's/"//g' -e 's|/|\\/|g') [ -n "${SUDO_LOG_FILE_ESCAPED}" ] && auditctl -l | awk "/^ *-w/ \ &&/"${SUDO_LOG_FILE_ESCAPED}"/ \ &&/ +-p *wa/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" \ || printf "ERROR: Variable 'SUDO_LOG_FILE_ESCAPED' is unset.\n"
'@
        $test1 = bash -c $command1
        $test2 = bash -c $command2
        if ($test1 -match "-w /var/log/sudo.log -p wa -k sudo_log_file" -and $test2 -match "-w /var/log/sudo.log -p wa -k sudo_log_file") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.3.4"
    Task = "Ensure events that modify date and time information are collected"
    Test = {
        $test1 = { awk '/^ *-a *always,exit/ \ &&/ -F *arch=b[2346]{2}/ \ &&/ -S/ \ &&(/adjtimex/ \ ||/settimeofday/ \ ||/clock_settime/ ) \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules awk '/^ *-w/ \ &&/\/etc\/localtime/ \ &&/ +-p *wa/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules }
        $test2 = { auditctl -l | awk '/^ *-a *always,exit/ \ &&/ -F *arch=b[2346]{2}/ \ &&/ -S/ \ &&(/adjtimex/ \ ||/settimeofday/ \ ||/clock_settime/ ) \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' auditctl -l | awk '/^ *-w/ \ &&/\/etc\/localtime/ \ &&/ +-p *wa/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' }
        if ($test1 -match "-a always,exit -F arch=b64 -S adjtimex,settimeofday clock_settime -k time-change" -and $test1 -match "-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change" -and $test1 -match "-w /etc/localtime -p wa -k time-change" -and $test2 -match "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -F key=time-change" -and $test2 -match "-a always,exit -F arch=b32 -S adjtimex,settimeofday clock_settime -F key=time-change" -and $test3 -match "-w /etc/localtime -p wa -k time-change") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.3.5"
    Task = "Ensure events that modify the system's network environment are collected"
    Test = {
        $test1 = awk '/^ *-a *always,exit/  &&/ -F *arch=b(32|64)/  &&/ -S/  &&(/sethostname/  ||/setdomainname/)  &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
        $test2 = awk "/^ *-w/  &&(/\/etc\/issue/ ||/\/etc\/issue.net/  ||/\/etc\/hosts/  ||/\/etc\/network/)  &&/ +-p *wa/  &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules
        try {
            $test3 = auditctl -l | awk '/^ *-a *always,exit/  &&/ -F *arch=b(32|64)/  &&/ -S/  &&(/sethostname/  ||/setdomainname/)  &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
            $test4 = auditctl -l | awk '/^ *-w/ &&(/\/etc\/issue/ ||/\/etc\/issue.net/ ||/\/etc\/hosts/ ||/\/etc\/network/) &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'        
        }
        catch {
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        if ($test1 -match "-a always,exit -F arch=b64 -S adjtimex,settimeofday clock_settime -k time-change" -and $test1 -match "-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change" -and $test1 -match "-w /etc/localtime -p wa -k time-change" -and $test2 -match "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -F key=time-change" -and $test2 -match "-a always,exit -F arch=b32 -S adjtimex,settimeofday clock_settime -F key=time-change" -and $test3 -match "-w /etc/localtime -p wa -k time-change") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.3.6"
    Task = "Ensure use of privileged commands are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-4.1.3.6-A.sh"
        $result1 = bash $path1 | grep "Warning"
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path2 = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-4.1.3.6-B.sh"
        $result2 = bash $path2 | grep "Warning"
        if ($result1 -eq $null -and $result2 -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.3.8"
    Task = "Ensure events that modify user/group information are collected"
    Test = {

        try {
            $dummy = auditctl -l 
        }
        catch {
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }

        $output1 = awk '/^ *-w/ \
        &&(/\/etc\/group/ \
         ||/\/etc\/passwd/ \
         ||/\/etc\/gshadow/ \
         ||/\/etc\/shadow/ \
         ||/\/etc\/security\/opasswd/) \
        &&/ +-p *wa/ \
        &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
        $result11 = $output1 | grep "\-w /etc/group -p wa -k identity"
        $result12 = $output1 | grep "\-w /etc/passwd -p wa -k identity"
        $result13 = $output1 | grep "\-w /etc/gshadow -p wa -k identity"
        $result14 = $output1 | grep "\-w /etc/shadow -p wa -k identity"
        $result15 = $output1 | grep "\-w /etc/security/opasswd -p wa -k identity"
        $output2 = auditctl -l | awk '/^ *-w/ \
        &&(/\/etc\/group/ \
         ||/\/etc\/passwd/ \
         ||/\/etc\/gshadow/ \
         ||/\/etc\/shadow/ \
         ||/\/etc\/security\/opasswd/) \
        &&/ +-p *wa/ \
        &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
        $result21 = $output2 | grep "\-w /etc/group -p wa -k identity"
        $result22 = $output2 | grep "\-w /etc/passwd -p wa -k identity"
        $result23 = $output2 | grep "\-w /etc/gshadow -p wa -k identity"
        $result24 = $output2 | grep "\-w /etc/shadow -p wa -k identity"
        $result25 = $output2 | grep "\-w /etc/security/opasswd -p wa -k identity"
        if ($result11 -ne $null -and $result12 -ne $null -and $result13 -ne $null -and $result14 -and $result15 -ne $null -and $result21 -ne $null -and $result22 -ne $null -and $result23 -ne $null -and $result24 -ne $null -and $result25 -ne $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.3.11"
    Task = "Ensure session initiation information is collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath + "/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.11_1.sh"
        $result11 = bash $path1 | grep "\-w /var/run/utmp -p wa -k session"
        $result12 = bash $path1 | grep "\-w /var/log/wtmp -p wa -k session"
        $result13 = bash $path1 | grep "\-w /var/log/btmp -p wa -k session"
        $path2 = $parentPath + "/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.11_2.sh"
        $result21 = bash $path2 | grep "\-w /var/run/utmp -p wa -k session"
        $result22 = bash $path2 | grep "\-w /var/log/wtmp -p wa -k session"
        $result23 = bash $path2 | grep "\-w /var/log/btmp -p wa -k session"
        if ($result11 -ne $null -and $result12 -ne $null -and $result13 -ne $null -and $result21 -ne $null -and $result22 -ne $null -and $result23 -ne $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.3.12"
    Task = "Ensure login and logout events are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath + "/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.12_1.sh"
        $result11 = bash $path1 | grep "\-w /var/log/lastlog -p wa -k logins"
        $result12 = bash $path1 | grep "\-w /var/run/faillock -p wa -k logins"
        $path2 = $parentPath + "/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.12_2.sh"
        $result21 = bash $path2 | grep "\-w /var/log/lastlog -p wa -k logins"
        $result22 = bash $path2 | grep "\-w /var/run/faillock -p wa -k logins"
        if ($result11 -ne $null -and $result12 -ne $null -and $result21 -ne $null -and $result22 -ne $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.3.14"
    Task = "Ensure events that modify the system's Mandatory Access Controls are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath + "/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.14_1.sh"
        $result11 = bash $path1 | grep "\-w /etc/apparmor/ -p wa -k MAC-policy"
        $result12 = bash $path1 | grep "\-w /etc/apparmor.d/ -p wa -k MAC-policy"
        $path2 = $parentPath + "/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.14_2.sh"
        $result21 = bash $path2 | grep "\-w /etc/apparmor/ -p wa -k MAC-policy"
        $result22 = bash $path2 | grep "\-w /etc/apparmor.d/ -p wa -k MAC-policy"
        if ($result11 -ne $null -and $result12 -ne $null -and $result21 -ne $null -and $result22 -ne $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.3.20"
    Task = "Ensure events that modify the system's Mandatory Access Controls are collected"
    Test = {
        $test = grep -Ph -- '^\h*-e\h+2\b' /etc/audit/rules.d/*.rules | tail -1
        if ($test -match "-e 2") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.3.21"
    Task = "Ensure the running and on disk configuration is the same"
    Test = {
        return @{
            Message = "Ensure that all rules in /etc/audit/rules.d have been merged into /etc/audit/audit.rules: augenrules --check \n/usr/sbin/augenrules: No change \nShould there be any drift, run augenrules --load to merge and load all rules."
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.4.1"
    Task = "Ensure audit log files are mode 0640 or less permissive"
    Test = {
        $command = @'
dir=$(awk -F= '/^log_file/ {print $2}' /etc/audit/auditd.conf | xargs dirname) && [ $(stat -c "%a" "$dir") -le 640 ] && echo "PASS: Directory permissions are 0640 or less permissive" || echo "FAIL: Directory permissions are more permissive"
'@
        $result = bash -c $command
        if ($result -match " PASS ") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.4.2"
    Task = "Ensure only authorized users own audit log files"
    Test = {
        $test1 = stat -Lc "%n %U" "$(dirname $(awk -F"=" '/^\s*log_file\s*=\s*/ {print $2}' /etc/audit/auditd.conf | xargs))"/* | grep -Pv -- '^\H+\h+root\b'
        if ($test1 -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.4.3"
    Task = "Ensure only authorized groups are assigned ownership of audit log files"
    Test = {
        $test1 = grep -Piw -- '^\h*log_group\h*=\h*(adm|root)\b' /etc/audit/auditd.conf
        $test2 = stat -c "%n %G" "$(dirname $(awk -F"=" '/^\s*log_file\s*=\s*/ {print $2}' /etc/audit/auditd.conf | xargs))"/* | grep -Pv '^\h*\H+\h+(adm|root)\b'
        if ($test1 -match "(log_group = adm)|(log_group = root)" -and $test2 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.4.4"
    Task = "Ensure the audit log directory is 0750 or more restrictive"
    Test = {
        $test1 = stat -Lc "%n %a" "$(dirname $( awk -F"=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf))" | grep -Pv -- '^\h*\H+\h+([0,5,7][0,5]0)'
        if ($test1 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.4.5"
    Task = "Ensure audit configuration files are 640 or more restrictive"
    Test = {
        $command = @'
        find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec stat -Lc "%n %a" {} + | grep -Pv -- '^\h*\H+\h*([0,2,4,6][0,4]0)\h*$'
'@
        $test1 = bash -c $command
        if ($test1 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.4.6"
    Task = "Ensure audit configuration files are owned by root"
    Test = {
        $command = @'
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root
'@
        $test1 = bash -c $command
        if ($test1 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.4.7"
    Task = "Ensure audit configuration files belong to group root"
    Test = {
        $command = @'
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root
'@
        $test1 = bash -c $command
        if ($test1 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.4.8"
    Task = "Ensure audit tools are 755 or more restrictive"
    Test = {
        $test1 = stat -c "%n %a" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h*$'
        if ($test1 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.4.9"
    Task = "Ensure audit tools are owned by root"
    Test = {
        $test1 = stat -c "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | grep -Pv -- '^\h*\H+\h+root\h*$'
        if ($test1 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.4.10"
    Task = "Ensure audit tools belong to group root"
    Test = {
        $test1 = stat -c "%n %a %U %G" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h+root\h+root\h*$'
        if ($test1 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.1.4.11"
    Task = "Ensure cryptographic mechanisms are used to protect the integrity of audit tools"
    Test = {
        $test1 = grep -Ps -- '(\/sbin\/(audit|au)\H*\b)' /etc/aide/aide.conf.d/*.conf /etc/aide/aide.conf
        if ($test1 -match "/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" -and
            $test1 -match "/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512" -and
            $test1 -match "/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512" -and
            $test1 -match "/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512" -and
            $test1 -match "/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512" -and
            $test1 -match "/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.1.1.1"
    Task = "Ensure systemd-journal-remote is installed"
    Test = {
        $test1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' systemd-journal-remote
        if ($test1 -match "systemd-journal-remote\s+install ok installed\s+installed") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.1.1.2"
    Task = "Ensure systemd-journal-remote is configured"
    Test = {
        return @{
            Message = 'Verify systemd-journal-remote is configured. Run the following command: grep -P "^ *URL=|^ *ServerKeyFile=|^ *ServerCertificateFile=|^ *TrustedCertificateFile=" /etc/systemd journal-upload.conf'
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.1.1.3"
    Task = "Ensure systemd-journal-remote is enabled"
    Test = {
        $test1 = systemctl is-enabled systemd-journal-upload.service
        if ($test1 -match "enabled") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.1.1.4"
    Task = "Ensure journald is not configured to recieve logs from a remote client"
    Test = {
        $test1 = systemctl is-enabled systemd-journal-remote.socket
        if ($test1 -match "disabled") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.1.2"
    Task = "Ensure journald service is enabled"
    Test = {
        $test1 = systemctl is-enabled systemd-journald.service
        if ($test1 -match "static") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.1.3"
    Task = "Ensure journald is configured to compress large log files"
    Test = {
        $test1 = grep ^\s*Compress /etc/systemd/journald.conf
        if ($test1 -match "Compress=yes") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.1.4"
    Task = "Ensure journald is configured to write logfiles to persistent disk"
    Test = {
        $test1 = grep ^\s*Storage /etc/systemd/journald.conf
        if ($test1 -match "Storage=persistent") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.1.5"
    Task = "Ensure journald is not configured to send logs to rsyslog"
    Test = {
        $test1 = grep ^\s*ForwardToSyslog /etc/systemd/journald.conf
        if ($test1 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.1.6"
    Task = "Ensure journald log rotation is configured per site policy"
    Test = {
        return @{
            Message = "Review /etc/systemd/journald.conf and verify logs are rotated according to site policy. The specific parameters for log rotation are:\n
            SystemMaxUse=\n
            SystemKeepFree=\n
            RuntimeMaxUse=\n
            RuntimeKeepFree=\n
            MaxFileSec="
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.1.7"
    Task = "Ensure journald default file permissions configured"
    Test = {
        return @{
            Message = "First see if there is an override file /etc/tmpfiles.d/systemd.conf. If so, this file will override all default settings as defined in /usr/lib/tmpfiles.d/systemd.conf and should be inspected. If there is no override file, inspect the default /usr/lib/tmpfiles.d/systemd.conf against the site specific requirements. Ensure that file permissions are 0640. Should a site policy dictate less restrictive permissions, ensure to follow said policy. NOTE: More restrictive permissions such as 0600 is implicitly sufficient."
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.2.1"
    Task = "Ensure rsyslog is installed"
    Test = {
        $test1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' rsyslog
        if ($test1 -match "rsyslog\s+install ok installed\s+installed") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.2.2"
    Task = "Ensure rsyslog service is enabled"
    Test = {
        $test1 = systemctl is-enabled rsyslog
        if ($test1 -match "enabled") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.2.3"
    Task = "Ensure journald is configured to send logs to rsyslog"
    Test = {
        $test1 = grep ^\s*ForwardToSyslog /etc/systemd/journald.conf
        if ($test1 -match "ForwardToSyslog=yes") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.2.4"
    Task = "Ensure rsyslog default file permissions are configured"
    Test = {
        $test1 = grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf
        if ($test1 -match "$FileCreateMode 0640") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.2.6"
    Task = "Ensure rsyslog is configured to send logs to a remote log host"
    Test = {
        return @{
            Message = "Review the /etc/rsyslog.conf and /etc/rsyslog.d/*.conf files and verify that logs are sent to a central host (where loghost.example.com is the name of your central log host):"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.2.7"
    Task = "Ensure rsyslog is not configured to receive logs from a remote client"
    Test = {
        $test1 = grep -s '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
        $test2 = grep -s '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
        if ($test1 -eq $null -and $test2 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.3"
    Task = "Ensure all logfiles have appropriate permissions and ownership"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-4.2.3.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "4.2.2.7"
    Task = "Ensure rsyslog is not configured to receive logs from a remote client"
    Test = {
        $test1 = grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
        $test2 = grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
        if ($test1 -eq $null -and $test2 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.1"
    Task = "Ensure cron daemon is enabled and running"
    Test = {
        $test1 = systemctl is-enabled cron
        $test2 = systemctl status cron | grep 'Active: active (running) '
        if ($test1 -eq "enabled" -and $test2 -match "running") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.2"
    Task = "Ensure permissions on /etc/crontab are configured"
    Test = {
        $test1 = stat /etc/crontab | grep 0600
        if ($test1 -ne $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.3"
    Task = "Ensure permissions on /etc/cron.hourly are configured"
    Test = {
        $test1 = stat /etc/cron.hourly/
        if ($test1 -eq "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.4"
    Task = "Ensure permissions on /etc/cron.daily are configured"
    Test = {
        $test1 = stat /etc/cron.daily/
        if ($test1 -eq "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.5"
    Task = "Ensure permissions on /etc/cron.weekly are configured"
    Test = {
        $test1 = stat /etc/cron.weekly/
        if ($test1 -eq "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.6"
    Task = "Ensure permissions on /etc/cron.monthly are configured"
    Test = {
        $test1 = stat /etc/cron.monthly/
        if ($test1 -eq "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.7"
    Task = "Ensure permissions on /etc/cron.d are configured"
    Test = {
        $test1 = stat /etc/cron.d/
        if ($test1 -eq "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.8"
    Task = "Ensure cron is restricted to authorized users"
    Test = {
        $test1 = stat /etc/cron.deny
        $test1 = $?
        $test2 = stat /etc/cron.allow
        if ($test1 -match "False" -and $test2 -match "0640\s*.*Uid.*root.*Gid.*root") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.1.9"
    Task = "Ensure at is restricted to authorized users"
    Test = {
        $test1 = stat /etc/at.deny
        $test1 = $?
        $test2 = stat /etc/at.allow | grep 0640
        if ($test1 -match "False" -and $test2 -eq "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (    0/    root)") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.2.1"
    Task = "Ensure permissions on /etc/ssh/sshd_config are configured"
    Test = {
        try {
            try {
                $test1 = stat /etc/ssh/sshd_config | grep 0600
            }
            catch {
                return @{
                    Message = "Path not found!"
                    Status  = "False"
                }
            }

            if ($test1 -eq "Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)") {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        catch {
            return @{
                Message = "Path not found!"
                Status  = "False"
            }
        }
    }
}
[AuditTest] @{
    Id   = "5.2.2"
    Task = "Ensure permissions on SSH private host key files are configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-5.2.2.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.2.3"
    Task = "Ensure permissions on SSH public host key files are configured"
    Test = {
        $res = bash -c "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;" | grep "Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)\s*"
        if ($res.count -eq 3) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.2.4"
    Task = "Ensure SSH access is limited"
    Test = {
        try {
            $result = bash -c "sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -Ei '^\s*(allow|deny)(users|groups)\s+\S+'"
            if ($result -match "allowusers" -or $result -match "allowgroups" -or $result -match "denyusers" -or $result -match "denygroups") {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        catch {
            return @{
                Message = "Command doesn't exist"
                Status  = "False"
            }
        }
    }
}
[AuditTest] @{
    Id   = "5.2.5"
    Task = "Ensure SSH LogLevel is appropriate"
    Test = {
        try {
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep loglevel
            try {
                $test2 = grep -is 'loglevel' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Evi '(VERBOSE|INFO)'
            }
            catch {
                return @{
                    Message = "Path not found!"
                    Status  = "False"
                }
            }
            if (($test1 -match "loglevel VERBOSE" -or $test1 -match "loglevel INFO") -and $test2 -eq $null) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        catch {
            return @{
                Message = "Command doesn't exist"
                Status  = "False"
            }
        }
    }
}
[AuditTest] @{
    Id   = "5.2.6"
    Task = "Ensure SSH PAM is enabled"
    Test = {
        $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i usepam
        $test2 = grep -Ei '^\s*UsePAM\s+no' /etc/ssh/sshd_config
        if ($test1 -match "usepam yes" -and $test2 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.2.7"
    Task = "Ensure SSH root login is disabled"
    Test = {
        $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permitrootlogin
        $test2 = grep -Ei '^\s*PermitRootLogin\s+no' /etc/ssh/sshd_config
        if ($test1 -match "permitrootlogin no" -and $test2 -match "PermitRootLogin no") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.2.8"
    Task = "Ensure SSH HostbasedAuthentication is disabled"
    Test = {
        $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep hostbasedauthentication
        $test2 = grep -Ei '^\s*HostbasedAuthentication\s+yes' /etc/ssh/sshd_config
        if ($test1 -match "hostbasedauthentication no" -and $test2 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.2.9"
    Task = "Ensure SSH PermitEmptyPasswords is disabled"
    Test = {
        $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permitemptypasswords
        $test2 = grep -Ei '^\s*PermitEmptyPasswords\s+yes' /etc/ssh/sshd_config
        if ($test1 -match "permitemptypasswords no" -and $test2 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.2.10"
    Task = "Ensure SSH PermitUserEnvironment is disabled"
    Test = {
        $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permituserenvironment
        $test2 = grep -Ei '^\s*PermitUserEnvironment\s+yes' /etc/ssh/sshd_config
        if ($test1 -match "permituserenvironment no" -and $test2 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.2.11"
    Task = "Ensure SSH IgnoreRhosts is enabled"
    Test = {
        $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep ignorerhosts
        $test2 = grep -Ei '^\s*ignorerhosts\s+no\b' /etc/ssh/sshd_config
        if ($test1 -match "ignorerhosts yes" -and $test2 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.2.12"
    Task = "Ensure SSH X11 forwarding is disabled"
    Test = {
        try {
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i x11forwarding
            try {
                $test2 = grep -Eis '^\s*x11forwarding\s+yes' /etc/ssh/sshd_config/etc/ssh/sshd_config.d/*.conf
            }
            catch {
                return @{
                    Message = "Path not found!"
                    Status  = "False"
                }
            }
            if ($test1 -match "x11forwarding no" -and $test2 -eq $null) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        catch {
            return @{
                Message = "Command doesn't exist"
                Status  = "False"
            }
        }
    }
}
[AuditTest] @{
    Id   = "5.2.13"
    Task = "Ensure only strong Ciphers are used"
    Test = {
        $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep ciphers
        if ($test1 -notmatch "(3des-cbc|aes128-cbc|aes192-cbc|aes256-cbc)") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.2.14"
    Task = "Ensure only strong MAC algorithms are used"
    Test = {
        $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i "MACs"
        if ($test1 -notmatch "(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1|hmac-sha1-96|umac-64@openssh.com|umac-128@openssh.com|hmac-md5-etm@openssh.com|hmac-md5-96-etm@openssh.com|hmac-ripemd160-etm@openssh.com|hmac-sha1-etm@openssh.com|hmac-sha1-96-etm@openssh.com|umac-64-etm@openssh.com|umac-128-etm@openssh.com)") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.2.15"
    Task = "Ensure only strong Key Exchange algorithms are used"
    Test = {
        $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep kexalgorithms
        if ($test1 -notmatch "(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.2.16"
    Task = "Ensure SSH AllowTcpForwarding is disabled"
    Test = {
        $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i allowtcpforwarding
        $test2 = grep -Ei '^\s*AllowTcpForwarding\s+yes' /etc/ssh/sshd_config
        if ($test1 -match "allowtcpforwarding no" -and $test2 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.2.17"
    Task = "Ensure SSH warning banner is configured"
    Test = {
        $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep banner
        if ($test1 -match "banner /etc/issue.net") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.2.18"
    Task = "Ensure SSH MaxAuthTries is set to 4 or less"
    Test = {
        $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep maxauthtries
        $test2 = grep -Ei '^\s*maxauthtries\s+([5-9]|[1-9][0-9]+)' /etc/ssh/sshd_config
        if ($test1 -match "maxauthtries 4" -and $test2 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.2.19"
    Task = "Ensure SSH MaxStartups is configured"
    Test = {
        $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i maxstartups
        $test2 = grep -Ei '^\s*maxstartups\s+(((1[1-9]|[1-9][0-9][0-9]+):([0-9]+):([0-9]+))|(([0-9]+):(3[1-9]|[4-9][0-9]|[1-9][0-9][0-9]+):([0-9]+))|(([0-9]+):([0-9]+):(6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+)))' /etc/ssh/sshd_config
        if ($test1 -match "maxstartups 10:30:60" -and $test2 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.2.20"
    Task = "Ensure SSH MaxSessions is set to 10 or less"
    Test = {
        try {
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i maxsessions | cut -d ' ' -f 2
            
            try {
                $test2 = grep -Eis '^\s*MaxSessions\s+(1[1-9]|[2-9][0-9]|[1-9][0-9][0-9]+)'/etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
            }
            catch {
                return @{
                    Message = "Path not found!"
                    Status  = "False"
                }
            }
            if ($test1 -le 10 -and $test2 -eq $null) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        catch {
            return @{
                Message = "Command doesn't exist"
                Status  = "False"
            }
        }
    }
}
[AuditTest] @{
    Id   = "5.2.21"
    Task = "Ensure SSH LoginGraceTime is set to one minute or less"
    Test = {
        try {
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep logingracetime | cut -d ' ' -f 2
            try {
                $test2 = grep -Eis '^\s*LoginGraceTime\s+(0|6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+|[^1]m)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
            }
            catch {
                return @{
                    Message = "Path not found!"
                    Status  = "False"
                }
            }
            if (($test1 -ge 1 -and $test1 -le 60) -and $test2 -eq $null) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        catch {
            return @{
                Message = "Command doesn't exist"
                Status  = "False"
            }
        }
    }
}
[AuditTest] @{
    Id   = "5.2.22"
    Task = "Ensure SSH Idle Timeout Interval is configured"
    Test = {
        $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep clientaliveinterval
        $test2 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep clientalivecountmax
        if ($test1 -match "clientaliveinterval 15" -and $test2 -match "clientalivecountmax 3") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.3.1"
    Task = "Ensure sudo is installed"
    Test = {
        $command = @'
dpkg-query -W sudo sudo-ldap > /dev/null 2>&1 && dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' sudo sudo-ldap | awk '($4=="installed" && $NF=="installed") {print "\n""PASS:""\n""Package ""\""$1"\""" is installed""\n"}' || echo -e "\nFAIL:\nneither \"sudo\" or \"sudo-ldap\" package is installed\n"
'@
        $test1 = bash -c $command
        if ($test1 -match "PASS:") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.3.2"
    Task = "Ensure sudo commands use pty"
    Test = {
        $test1 = grep -rPi '^\h*Defaults\h+([^#\n\r]+,)?use_pty(,\h*\h+\h*)*\h*(#.*)?$' /etc/sudoers*
        if ($test1 -match "/etc/sudoers:Defaults use_pty") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.3.3"
    Task = "Ensure sudo log file exists"
    Test = {
        $command = @'
        grep -rPsi "^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\')?\H+(\"|\')?(,\h*\H+\h*)*\h* (#.*)?$" /etc/sudoers*
'@
        $test1 = bash -c $command

        if ($test1 -eq $null) { 
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        return @{
            Message = "Compliant"
            Status  = "True"
        }

       
    }
}
[AuditTest] @{
    Id   = "5.3.4"
    Task = "Ensure users must provide password for privilege escalation"
    Test = {
        $test1 = grep -r "^[^#].*NOPASSWD" /etc/sudoers*
        if ($test1 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.3.5"
    Task = "Ensure re-authentication for privilege escalation is not disabled globally"
    Test = {
        $test1 = grep -r "^[^#].*\!authenticate" /etc/sudoers*
        if ($test1 -match '!authenticate') { 
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        return @{
            Message = "Compliant"
            Status  = "True"
        }
    }
}
[AuditTest] @{
    Id   = "5.3.6"
    Task = "Ensure sudo authentication timeout is configured correctly"
    Test = {
        #todo
        $test1 = grep -roP "timestamp_timeout=\K[0-9]*" /etc/sudoers*
        if ($test1 -match 'auth required pam_wheel.so use_uid group=') { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.3.7"
    Task = "Ensure access to the su command is restricted"
    Test = {
        #todo
        $test1 = grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su
        if ($test1 -match 'auth required pam_wheel.so use_uid group=') { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.4.1"
    Task = "Ensure password creation requirements are configured"
    Test = {
        $test1 = grep '^\s*minlen\s*' /etc/security/pwquality.confsu
        if ($test1 -match 'minlen = 14') { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.4.4"
    Task = "Ensure password hashing algorithm is up to date with the latest standards"
    Test = {
        $test1 = grep -i "^\s*ENCRYPT_METHOD\s*yescrypt\s*$" /etc/login.defs
        if ($test1 -match 'ENCRYPT_METHOD yescrypt') { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.4.5"
    Task = "Ensure all current passwords uses the configured hashing algorithm"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-5.4.5.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.5.1.1"
    Task = "Ensure minimum days between password changes is configured"
    Test = {
        $test1 = grep -E '^[[:space:]]*PASS_MIN_DAYS[[:space:]]+' /etc/login.defs | grep -v '^#'
        if ($test1 -ge 1) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.5.1.2"
    Task = "Ensure password expiration is 365 days or less"
    Test = {
        $test1 = awk '/^PASS_MAX_DAYS/ && $2 <= 365 {print "true"; exit}' /etc/login.defs
        $test2 = awk -F: '(/^[^:]+:[^!*]/ && ($5>365 || $5~/([0-1]|-1|\s*)/)){print $1 " " $5}' /etc/shadow
        if ($test1 -match 'true' -and $test2 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.5.1.3"
    Task = "Ensure password expiration warning days is 7 or more"
    Test = {
        $test1 = grep PASS_WARN_AGE /etc/login.defs | cut -d ' ' -f2
        if ($test1 -ge 7) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.5.1.4"
    Task = "Ensure inactive password lock is 30 days or less"
    Test = {
        $test1 = useradd -D | grep INACTIVE | cut -d '=' -f2
        if ($test1 -le 30) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.5.1.5"
    Task = "Ensure all users last password change date is in the past"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-5.5.1.5.sh"
        $result = bash $path
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.5.2"
    Task = "Ensure system accounts are secured"
    Test = {
        $test1 = awk -F: '$1!~/(root|sync|shutdown|halt|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!~/((\/usr)?\/sbin\/nologin)/ && $7!~/(\/bin)?\/false/ {print}' /etc/passwd
        $test2 = awk -F: '($1!~/(root|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!~/LK?/) {print $1}'
        if ($test1 -eq $null -and $test2 -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.5.3"
    Task = "Ensure default group for the root account is GID 0"
    Test = {
        $test1 = grep "^root:" /etc/passwd | cut -f4 -d ':'
        if ($test1 -eq 0) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.5.4"
    Task = "Ensure default user umask is 027 or more restrictive"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-5.5.4.sh"
        $result = bash $path
        $test2 = grep -RPi '(^|^[^#]*)\s*umask\s+([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b|[0-7][01][0-7]\b|[0-7][0-7][0-6]\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}(,o=[rwx]{0,3})?\b)' /etc/login.defs /etc/profile* /etc/bash.bashrc*
        if ($result -match "Default user umask is set" -and $test2 -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "5.5.5"
    Task = "Ensure default user shell timeout is 900 seconds or less"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-5.5.5.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.1"
    Task = "Ensure permissions on /etc/passwd are configured"
    Test = {
        $test1 = stat -Lc "%n %a %u/%U %g/%G" /etc/passwd
        if ($test1 -match "/etc/passwd\s+644\s+0/root\s+0/root") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.2"
    Task = "Ensure permissions on /etc/passwd- are configured"
    Test = {
        $test1 = stat /etc/passwd-
        if ($test1 -eq "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.3"
    Task = "Ensure permissions on /etc/group are configured"
    Test = {
        $test1 = stat /etc/group
        if ($test1 -eq "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.4"
    Task = "Ensure permissions on /etc/group- are configured"
    Test = {
        $test1 = stat /etc/group- | grep 0644
        if ($test1 -eq "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.5"
    Task = "Ensure permissions on /etc/shadow are configured"
    Test = {
        $test1 = stat /etc/shadow | grep 0640
        if ($test1 -eq "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (    0/    root)") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.6"
    Task = "Ensure permissions on /etc/shadow- are configured"
    Test = {
        $test1 = stat /etc/shadow- | grep 0640
        if ($test1 -eq "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (   42/  shadow)") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.7"
    Task = "Ensure permissions on /etc/gshadow are configured"
    Test = {
        $test1 = stat /etc/gshadow | grep 0640
        if ($test1 -eq "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (   42/  shadow)") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.8"
    Task = "Ensure permissions on /etc/gshadow- are configured"
    Test = {
        $test1 = stat /etc/gshadow- | grep 0640
        if ($test1 -eq "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (   42/  shadow)") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.9"
    Task = "Ensure no world writable files exist"
    Test = {
        #$partitions = mapfile -t partitions < (sudo fdisk -l | grep -o '/dev/[^ ]*')
        $test1 = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002
        if ($test1 -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.10"
    Task = "Ensure no unowned files or directories exist"
    Test = {
        $command = @'
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser
'@
        $test1 = bash -c $command
            
        if ($test1 -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.11"
    Task = "Ensure no ungrouped files or directories exist"
    Test = {
        $test1 = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup
        if ($test1 -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.12"
    Task = "Audit SUID executables"
    Test = {
        $test1 = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000
        $message = ""
        foreach ($line in $test1) {
            $message += "<br>$line"
        }
        return @{
            Message = "Please review following list of files: $($message)"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "6.1.13"
    Task = "Audit SGID executables"
    Test = {
        $test1 = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000
        $message = ""
        foreach ($line in $test1) {
            $message += "<br>$line"
        }
        return @{
            Message = "Please review following list of files: $($message)"
            Status  = "None"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.1"
    Task = "Ensure accounts in /etc/passwd use shadowed passwords"
    Test = {
        $test1 = awk -F: '($2 != "x" ) { print $1 " is not set to shadowed passwords "}' /etc/passwd
        if ($test1 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.2"
    Task = "Ensure /etc/shadow password fields are not empty"
    Test = {
        $test1 = awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow
        if ($test1 -eq $null) { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.3"
    Task = "Ensure all groups in /etc/passwd exist in /etc/group"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-6.2.3.sh"
        $result = bash $path
        $status = $?
        
        if ($status -match "True") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.4"
    Task = "Ensure shadow group is empty"
    Test = {
        $test1 = awk -F: '($1=="shadow") {print $NF}' /etc/group
        $test2 = awk -F: -v GID="$(awk -F: '($1=="shadow") {print $3}' /etc/group)" '($4==GID) {print $1}' /etc/passwd
        if ($test1.Length -eq 0 -and $test2 -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.5"
    Task = "Ensure no duplicate UIDs exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-6.2.5.sh"
        $result = bash $path
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.6"
    Task = "Ensure no duplicate GIDs exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-6.2.6.sh"
        $result = bash $path
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.7"
    Task = "Ensure no duplicate user names exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-6.2.7.sh"
        $result = bash $path
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.8"
    Task = "Ensure no duplicate group names exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-6.2.8.sh"
        $result = bash $path
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.9"
    Task = "Ensure root PATH Integrity"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-6.2.9.sh"
        $result = bash $path
        if ($result -eq $null) {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.10"
    Task = "Ensure root is the only UID 0 account"
    Test = {
        $test1 = awk -F: '($3 == 0) { print $1 }' /etc/passwd
        if ($test1 -eq "root") { 
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.11"
    Task = "Ensure local interactive user home directories exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-6.2.11.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.12"
    Task = "Ensure local interactive users own their home directories"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-6.2.12.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.13"
    Task = "Ensure local interactive user home directories are mode 750 or more restrictive"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-6.2.13.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.14"
    Task = "Ensure no local interactive user has .netrc files"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-6.2.14.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.15"
    Task = "Ensure no local interactive user has .forward files"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-6.2.15.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.16"
    Task = "Ensure no local interactive user has .rhosts files"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-6.2.16.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}
[AuditTest] @{
    Id   = "6.2.17"
    Task = "Ensure local interactive user dot files are not group or world writable"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath + "/Helpers/ShellScripts/Debian_11/CIS-Debian-6.2.17.sh"
        $result = bash $path
        foreach ($line in $result) {
            if (!($line -match "PASS")) {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}