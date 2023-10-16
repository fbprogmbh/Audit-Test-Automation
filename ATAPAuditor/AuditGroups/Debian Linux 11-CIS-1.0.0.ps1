[AuditTest] @{
    Id = "1.1.1.1"
    Task = "Ensure mounting of cramfs filesystems is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-1.1.1.1.sh"
        $result=bash $path
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
    Id = "1.1.1.2"
    Task = "Ensure mounting of squashfs filesystems is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-1.1.1.2.sh"
        $result=bash $path
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
    Id = "1.1.1.3"
    Task = "Ensure mounting of udf filesystems is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-1.1.1.3.sh"
        $result=bash $path
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
    Id = "1.1.2.1"
    Task = "Ensure /tmp is a separate partition"
    Test = {
        $result1 = findmnt --kernel /tmp
        $result2 = systemctl is-enabled tmp.mount
        if($result1 -match "/tmp" -and $result2 -match "enabled"){
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
    Id = "1.1.2.2"
    Task = "Ensure nodev option set on /tmp partition"
    Test = {
        $result = findmnt --kernel /tmp | grep nodev
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
    Id = "1.1.2.3"
    Task = "Ensure noexec option set on /tmp partition"
    Test = {
        $result = findmnt --kernel /tmp | grep noexec
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
    Id = "1.1.2.4"
    Task = "Ensure nosuid option set on /tmp partition"
    Test = {
        $result = findmnt --kernel /tmp | grep nosuid
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
    Id = "1.1.3.1"
    Task = "Ensure separate partition exists for /var"
    Test = {
        $result = findmnt --kernel /var
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
    Id = "1.1.3.2"
    Task = "Ensure nodev option set on /var partition"
    Test = {
        $result = findmnt --kernel /var
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
    Id = "1.1.3.3"
    Task = "Ensure nosuid option set on /var partition"
    Test = {
        $result = findmnt --kernel /var
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
    Id = "1.1.4.1"
    Task = "Ensure separate partition exists for /var/tmp"
    Test = {
        $result = findmnt --kernel /var/tmp
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
    Id = "1.1.4.2"
    Task = "Ensure noexec option set on /var/tmp partition"
    Test = {
        $result = findmnt --kernel /var/tmp
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
    Id = "1.1.4.3"
    Task = "Ensure nosuid option set on /var/tmp partition"
    Test = {
        $result = findmnt --kernel /var/tmp
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
    Id = "1.1.4.4"
    Task = "Ensure nodev option set on /var/tmp partition"
    Test = {
        $result = findmnt --kernel /var/tmp
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
    Id = "1.1.5.1"
    Task = "Ensure separate partition exists for /var/log"
    Test = {
        $result = findmnt --kernel /var/log
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
    Id = "1.1.5.2"
    Task = "Ensure nodev option set on /var/log partition"
    Test = {
        $result = findmnt --kernel /var/log
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
    Id = "1.1.5.3"
    Task = "Ensure noexec option set on /var/log partition"
    Test = {
        $result = findmnt --kernel /var/log
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
    Id = "1.1.5.4"
    Task = "Ensure nosuid option set on /var/log partition"
    Test = {
        $result = findmnt --kernel /var/log
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
    Id = "1.1.6.1"
    Task = "Ensure separate partition exists for /var/log/audit"
    Test = {
        $result = findmnt --kernel /var/log/audit
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
    Id = "1.1.6.2"
    Task = "Ensure noexec option set on /var/log/audit partition"
    Test = {
        $result = findmnt --kernel /var/log/audit
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
    Id = "1.1.6.3"
    Task = "Ensure nodev option set on /var/log/audit partition"
    Test = {
        $result = findmnt --kernel /var/log/audit
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
    Id = "1.1.6.4"
    Task = "Ensure nosuid option set on /var/log/audit partition"
    Test = {
        $result = findmnt --kernel /var/log/audit
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
    Id = "1.1.7.1"
    Task = "Ensure separate partition exists for /home"
    Test = {
        $result = findmnt --kernel /home
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
    Id = "1.1.7.2"
    Task = "Ensure nodev option set on /home partition"
    Test = {
        $result = findmnt --kernel /home
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
    Id = "1.1.7.3"
    Task = "Ensure nosuid option set on /home partition"
    Test = {
        $result = findmnt --kernel /home
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
    Id = "1.1.8.1"
    Task = "Ensure nodev option set on /dev/shm partition"
    Test = {
        $result = findmnt --kernel /dev/shm | grep nodev
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
    Id = "1.1.8.2"
    Task = "Ensure noexec option set on /dev/shm partition"
    Test = {
        $result = findmnt --kernel /dev/shm | grep noexec
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
    Id = "1.1.8.3"
    Task = "Ensure nosuid option set on /dev/shm partition"
    Test = {
        $result = findmnt --kernel /dev/shm | grep nosuid
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
    Task = "Disable Automounting"
    Test = {
        $result1 = systemctl is-enabled autofs
        $result2 = systemctl is-enabled autofs
        if($result1 -match "Failed" -and ($result2 -match "Failed" -or $result2 -match "disabled")){
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
    Task = "Disable USB Storage"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-1.1.10.sh"
        $result=bash $path
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
    Id = "1.2.1"
    Task = "Ensure package manager repositories are configured"
    Test = {
        return @{
            Message = "Run the following command and verify package repositories are configured correctly: apt-cache policy"
            Status = "None"
        }
    }
}
[AuditTest] @{
    Id = "1.2.2"
    Task = "Ensure GPG keys are configured"
    Test = {
        return @{
            Message = "Verify GPG keys are configured correctly for your package manager: apt-key list"
            Status = "None"
        }
    }
}
[AuditTest] @{
    Id = "1.3.1"
    Task = "Ensure AIDE is installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' aide aide-common
        if($result -match "install ok installed"){
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
    Id = "1.3.2"
    Task = "Ensure filesystem integrity is regularly checked"
    Test = {
        $result = grep -Prs '^([^#\n\r]+\h+)?(\/usr\/s?bin\/|^\h*)aide(\.wrapper)?\h+(--check|([^#\n\r]+\h+)?\$AIDEARGS)\b' /etc/cron.* /etc/crontab /var/spool/cron/
        if($result -match "install ok installed"){
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
    Id = "1.4.1"
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
    Id = "1.4.2"
    Task = "Ensure permissions on bootloader config are configured"
    Test = {
        $result = stat /boot/grub/grub.cfg
        if($result -match "Access:\s*(0400/-r--------)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)"){
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
    Task = "Ensure address space layout randomization (ASLR) is enabled"
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
    Id = "1.5.2"
    Task = "Ensure prelink is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' prelink
        if($result -match "not-installed"){
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
    Task = "Ensure Automatic Error Reporting is not enabled"
    Test = {
        $result1 = dpkg-query -s apport > /dev/null 2>&1 && grep -Psi --'^\h*enabled\h*=\h*[^0]\b' /etc/default/apport
        $result2 = systemctl is-active apport.service | grep '^active'
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
    Id = "1.5.4"
    Task = "Ensure core dumps are restricted"
    Test = {
        $result1 = grep -Es '^(\*|\s).*hard.*core.*(\s+#.*)?$' /etc/security/limits.conf /etc/security/limits.d/*
        $result2 = sysctl fs.suid_dumpable
        $result3 = grep "fs.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*
        $result4 = systemctl is-enabled coredump.service
        if($result1 -match "* hard core 0" -and $result2 -match "fs.suid_dumpable = 0" -and $result3 -match "fs.suid_dumpable = 0" -and $result4 -match "enabled|masked|disabled"){
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
    Id = "1.6.1.1"
    Task = "Ensure AppArmor is installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' apparmor apparmor-utils
        if($result -match "apparmor\s+install ok installed\s+installed" -and $result -match "apparmor-utils\s+install ok installed\s+installed"){
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
        if($result1 -eq $null -and $result2 -eq $null ){
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
    Id = "1.8.1"
    Task = "Ensure GNOME Display Manager is removed"
    Test = {
        $test = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' gdm3
        if($test -match "gdm3\s+unknown ok not-installed\s*not-installed"){
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
    Task = "Ensure GDM login banner is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-1.8.2.sh"
        $result=bash $path
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
    Id = "1.8.3"
    Task = "Ensure GDM disable-user-list option is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-1.8.3.sh"
        $result=bash $path
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
    Id = "1.8.4"
    Task = "Ensure GDM screen locks when the user is idle"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-1.8.4.sh"
        $result=bash $path
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
    Id = "1.8.5"
    Task = "Ensure GDM screen locks cannot be overridden"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-1.8.5.sh"
        $result=bash $path
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
    Id = "1.8.6"
    Task = "Ensure GDM automatic mounting of removable media is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-1.8.6.sh"
        $result=bash $path
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
    Id = "1.8.7"
    Task = "Ensure GDM disabling automatic mounting of removable media is not overridden"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-1.8.7.sh"
        $result=bash $path
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
    Id = "1.8.8"
    Task = "Ensure GDM autorun-never is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-1.8.8.sh"
        $result=bash $path
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
    Id = "1.8.9"
    Task = "Ensure GDM autorun-never is not overridden"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-1.8.9.sh"
        $result=bash $path
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
    Id = "1.8.10"
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
    Task = "Ensure a single time synchronization daemon is in use"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-2.1.1.1.sh"
        $result=bash $path
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
    Id = "2.1.2.1"
    Task = "Ensure chrony is configured with authorized timeserver"
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
    Id = "2.1.2.2"
    Task = "Ensure chrony is running as user _chrony"
    Test = {
        $result = ps -ef | awk '(/[c]hronyd/ && $1!="_chrony") { print $1 }'
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
    Id = "2.1.2.3"
    Task = "Ensure chrony is enabled and running"
    Test = {
        $result1 = systemctl is-enabled chrony.service
        $result2 = systemctl is-active chrony.service
        if($result1 -match "enabled" -and $result2 -match "active"){
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
    Id = "2.1.3.1"
    Task = "Ensure systemd-timesyncd configured with authorized timeserver"
    Test = {
        $result1 = systemctl is-enabled chrony.service
        $result2 = systemctl is-active chrony.service
        if($result1 -match "enabled" -and $result2 -match "active"){
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
    Id = "2.1.3.2"
    Task = "Ensure systemd-timesyncd is enabled and running"
    Test = {
        $result1 = systemctl is-enabled systemd-timesyncd.service
        $result2 = systemctl is-active systemd-timesyncd.service
        if($result1 -match "enabled" -and $result2 -match "active"){
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
    Id = "2.1.4.1"
    Task = "Ensure ntp access control is configured"
    Test = {
        $result = grep -P -- '^\h*restrict\h+((-4\h+)?|-6\h+)default\h+(?:[^#\n\r]+\h+)*(?!(?:\2|\3|\4|\5))(\h*\bkod\b\h*|\h*\bnomodify\b\h*|\h*\bnotrap\b\h*|\h*\bnopeer\b\h*|\h*\bnoquery\b\h*)\h+(?:[^#\n\r]+\h+)*(?!(?:\1|\3|\4|\5))(\h*\bkod\b\h*|\h*\bnomodify\b\h*|\h*\bnotrap\b\h*|\h*\bnopeer\b\h*|\h*\bnoquery\b\h*)\h+(?:[^#\n\r]+\h+)*(?!(?:\1|\2|\4|\5))(\h*\bkod\b\h*|\h*\bnomodify\b\h*|\h*\bnotrap\b\h*|\h*\bnopeer\b\h*|\h*\bnoquery\b\h*)\h+(?:[^#\n\r]+\h+)*(?!(?:\1|\2|\3|\5))(\h*\bkod\b\h*|\h*\bnomodify\b\h*|\h*\bnotrap\b\h*|\h*\bnopeer\b\h*|\h*\bnoquery\b\h*)\h+(?:[^#\n\r]+\h+)*(?!(?:\1|\2|\3|\4))(\h*\bkod\b\h*|\h*\bnomodify\b\h*|\h*\bnotrap\b\h*|\h*\bnopeer\b\h*|\h*\bnoquery\b\h*)\h*(?:\h+\H+\h*)*(?:\h+#.*)?$' /etc/ntp.conf
        $wordsToCheck = "default", "kod", "nomodify", "notrap", "nopeer", "noquery"
        $pattern = "\b(" + ($wordsToCheck -join "|") + ")\b"
        if($result.Count -eq 2 -and $result[0] -match $pattern -and $result[1] -match $pattern){
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
    Id = "2.1.4.2"
    Task = "Ensure ntp is configured with authorized timeserver"
    Test = {
        $result = grep -P -- '^\h*restrict\h+((-4\h+)?|-6\h+)default\h+(?:[^#\n\r]+\h+)*(?!(?:\2|\3|\4|\5))(\h*\bkod\b\h*|\h*\bnomodify\b\h*|\h*\bnotrap\b\h*|\h*\bnopeer\b\h*|\h*\bnoquery\b\h*)\h+(?:[^#\n\r]+\h+)*(?!(?:\1|\3|\4|\5))(\h*\bkod\b\h*|\h*\bnomodify\b\h*|\h*\bnotrap\b\h*|\h*\bnopeer\b\h*|\h*\bnoquery\b\h*)\h+(?:[^#\n\r]+\h+)*(?!(?:\1|\2|\4|\5))(\h*\bkod\b\h*|\h*\bnomodify\b\h*|\h*\bnotrap\b\h*|\h*\bnopeer\b\h*|\h*\bnoquery\b\h*)\h+(?:[^#\n\r]+\h+)*(?!(?:\1|\2|\3|\5))(\h*\bkod\b\h*|\h*\bnomodify\b\h*|\h*\bnotrap\b\h*|\h*\bnopeer\b\h*|\h*\bnoquery\b\h*)\h+(?:[^#\n\r]+\h+)*(?!(?:\1|\2|\3|\4))(\h*\bkod\b\h*|\h*\bnomodify\b\h*|\h*\bnotrap\b\h*|\h*\bnopeer\b\h*|\h*\bnoquery\b\h*)\h*(?:\h+\H+\h*)*(?:\h+#.*)?$' /etc/ntp.conf
        $wordsToCheck = "default", "kod", "nomodify", "notrap", "nopeer", "noquery"
        $pattern = "\b(" + ($wordsToCheck -join "|") + ")\b"
        if($result.Count -eq 2 -and $result[0] -match $pattern -and $result[1] -match $pattern){
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
    Id = "2.1.4.3"
    Task = "Ensure ntp is running as user ntp"
    Test = {
        $result1 = ps -ef | awk '(/[n]tpd/ && $1!="ntp") { print $1 }'
        $result2 = grep -P -- '^\h*RUNASUSER=' /etc/init.d/ntp
        if($result1 -eq $null -and $result2 -eq "RUNASUSER=ntp"){
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
    Id = "2.1.4.4"
    Task = "Ensure ntp is enabled and running"
    Test = {
        $result1 = systemctl is-enabled ntp.service
        $result2 = systemctl is-active ntp.service
        if($result1 -match "enabled" -and $result2 -match "active"){
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
    Task = "Ensure X Window System is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' xserver-xorg* | grep -Pi '\h+installed\b'
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
    Id = "2.2.2"
    Task = "Ensure Avahi Server is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' avahi-daemon
        if($result -match "avahi-daemon\s+unknown ok not-installed\s+not-installed"){
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
    Task = "Ensure CUPS is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' cups
        if($result -match "cups\s+unknown ok not-installed\s+not-installed"){
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
    Task = "Ensure DHCP Server is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' isc-dhcp-server
        if($result -match "isc-dhcp-server\s+unknown ok not-installed\s+not-installed"){
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
    Task = "Ensure LDAP server is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' slapd
        if($result -match "slapd\s+unknown ok not-installed\s+not-installed"){
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
    Task = "Ensure NFS is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' nfs-kernel-server
        if($result -match "nfs-kernel-server\s+unknown ok not-installed\s+not-installed"){
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
    Id = "2.2.7"
    Task = "Ensure DNS Server is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' bind9
        if($result -match "bind9\s+unknown ok not-installed\s+not-installed"){
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
    Id = "2.2.8"
    Task = "Ensure FTP Server is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' vsftpd
        if($result -match "vsftpd\s+unknown ok not-installed\s+not-installed"){
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
    Id = "2.2.9"
    Task = "Ensure HTTP server is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' apache2
        if($result -match "apache2\s+unknown ok not-installed\s+not-installed"){
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
    Id = "2.2.10"
    Task = "Ensure IMAP and POP3 server are not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' dovecot-imapd dovecot-pop3d
        if($result -match "dovecot-imapd\s+unknown ok not-installed\s+not-installed" -and $result -match "dovecot-pop3d\s+unknown ok not-installed\s+not-installed"){
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
    Id = "2.2.11"
    Task = "Ensure Samba is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' samba
        if($result -match "samba\s+unknown ok not-installed\s+not-installed"){
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
    Id = "2.2.12"
    Task = "Ensure HTTP Proxy Server is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' squid
        if($result -match "squid\s+unknown ok not-installed\s+not-installed"){
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
    Id = "2.2.13"
    Task = "Ensure SNMP Server is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' snmp
        if($result -match "snmp\s+unknown ok not-installed\s+not-installed"){
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
    Id = "2.2.14"
    Task = "Ensure NIS Server is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' nis
        if($result -match "nis\s+unknown ok not-installed\s+not-installed"){
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
    Id = "2.2.15"
    Task = "Ensure mail transfer agent is configured for local-only mode"
    Test = {
        $result = ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s'
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
    Id = "2.2.16"
    Task = "Ensure rsync service is either not installed or masked"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' rsync
        if($result -match "rsync\s+unknown ok not-installed\s+not-installed"){
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
    Id = "2.3.1"
    Task = "Ensure NIS Client is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' nis
        if($result -match "nis\s+unknown ok not-installed\s+not-installed"){
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
    Id = "2.3.2"
    Task = "Ensure rsh client is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' rsh-client
        if($result -match "rsh-client\s+unknown ok not-installed\s+not-installed"){
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
    Id = "2.3.3"
    Task = "Ensure talk client is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' talk
        if($result -match "talk\s+unknown ok not-installed\s+not-installed"){
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
    Id = "2.3.4"
    Task = "Ensure telnet client is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' telnet
        if($result -match "telnet\s+unknown ok not-installed\s+not-installed"){
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
    Id = "2.3.5"
    Task = "Ensure LDAP client is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' ldap-utils
        if($result -match "ldap-utils\s+unknown ok not-installed\s+not-installed"){
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
    Id = "2.3.6"
    Task = "Ensure RPC is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' rpcbind
        if($result -match "rpcbind\s+unknown ok not-installed\s+not-installed"){
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
    Id = "2.4"
    Task = "Ensure nonessential services are removed or masked"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' rpcbind
        if($result -match "rpcbind\s+unknown ok not-installed\s+not-installed"){
            return @{
                Message = "Run the following command: 'ss -plntu'\nReview the output to ensure that all services listed are required on the system. If a listed service is not required, remove the package containing the service. If the package containing the service is required, stop and mask the service."
                Status = "None"
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
    Task = "Ensure system is checked to determine if IPv6 is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.1.1.sh"
        $result=bash $path
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
    Id = "3.1.2"
    Task = "Ensure wireless interfaces are disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.1.2.sh"
        $result=bash $path
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
    Id = "3.1.3"
    Task = "Ensure DCCP is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.1.3.sh"
        $result=bash $path
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
    Id = "3.1.4"
    Task = "Ensure SCTP is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.1.4.sh"
        $result=bash $path
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
    Id = "3.1.5"
    Task = "Ensure RDS is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.1.5.sh"
        $result=bash $path
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
    Id = "3.1.6"
    Task = "Ensure TIPC is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.1.6.sh"
        $result=bash $path
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
    Id = "3.2.1"
    Task = "Ensure packet redirect sending is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.2.1.sh"
        $result=bash $path
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
    Id = "3.2.2"
    Task = "Ensure IP forwarding is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.2.2.sh"
        $result=bash $path
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
    Id = "3.3.1"
    Task = "Ensure source routed packets are not accepted"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.1.sh"
        $result=bash $path
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
    Id = "3.3.2"
    Task = "Ensure ICMP redirects are not accepted"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.2.sh"
        $result=bash $path
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
    Id = "3.3.3"
    Task = "Ensure secure ICMP redirects are not accepted"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.3.sh"
        $result=bash $path
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
    Id = "3.3.4"
    Task = "Ensure suspicious packets are logged"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.4.sh"
        $result=bash $path
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
    Id = "3.3.5"
    Task = "Ensure broadcast ICMP requests are ignored"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.5.sh"
        $result=bash $path
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
    Id = "3.3.6"
    Task = "Ensure bogus ICMP responses are ignored"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.6.sh"
        $result=bash $path
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
    Id = "3.3.7"
    Task = "Ensure Reverse Path Filtering is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.7.sh"
        $result=bash $path
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
    Id = "3.3.8"
    Task = "Ensure TCP SYN Cookies is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.8.sh"
        $result=bash $path
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
    Id = "3.3.9"
    Task = "Ensure IPv6 router advertisements are not accepted"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.3.9.sh"
        $result=bash $path
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
    Id = "3.5.1.1"
    Task = "Ensure ufw is installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' ufw
        if($result -match "ufw\s+install ok installeds\+installed"){
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
        $result = dpkg-query -s iptables-persistent
        if($result -match "package 'iptables-persistent' is not installed and no information is available"){
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
        $result1 = systemctl is-enabled ufw.service
        $result2 = systemctl is-active ufw
        $result3 = ufw status

        if($result1 -match "enabled" -and $result2 -match "active" -and $result3 -match "Status: active"){
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
        $result1 = ufw status verbose

        if($result1 -match "enabled" -and $result2 -match "active" -and $result3 -match "Status: active"){
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
        return @{
            Message = "Run the following command and verify all rules for new outbound connections match site policy: ufw status numbered"
            Status = "None"
        }
    }
}
[AuditTest] @{
    Id = "3.5.1.6"
    Task = "Ensure ufw firewall rules exist for all open ports"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-3.5.1.6.sh"
        $result=bash $path
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
    Id = "3.5.1.7"
    Task = "Ensure ufw default deny firewall policy"
    Test = {
        $result = ufw status verbose | grep Default:

        if($result -match "Default: (deny|reject|disabled) (incoming), (deny|reject|disabled) (outgoing), (deny|reject|disabled) (routed)"){
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
        $test = dpkg-query -s nftables | grep 'Status: install ok installed'
        if($test -match "Status: install ok installed"){
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
        $test1 = dpkg-query -s ufw | grep 'Status: install ok installed'
        $test2 = ufw status
        if($test1 -match "package 'ufw' is not installed and no information is available" -and $test2 -match "ufw status"){
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
    Id = "3.5.2.3"
    Task = "Ensure iptables are flushed with nftables"
    Test = {
        return @{
            Message = "Run the following commands to ensure no iptables rules exist for iptables: iptables -L \nNo rules should be returned for ip6tables: ip6tables -L \nNo rules should be returned"
            Status = "None"
        }
    }
}
[AuditTest] @{
    Id = "3.5.2.4"
    Task = "Ensure a nftables table exists"
    Test = {
        $test = nft list tables
        if($test -match "table"){
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
        $test1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' nftables
        if($test1 -match "nftables\s+unknown ok not-installed\s+not-installed"){
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
        $test1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' ufw
        $test2 = ufw status
        $test3 = systemctl is-enabled ufw
        if($test1 -match "ufw\s+unknown ok not-installed\s+not-installed" -and $test2 -match "Status: inactive" -ant $test3 -match "masked"){
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
    Task = "Ensure iptables default deny firewall policy"
    Test = {
        $test1 = iptables -L
        if($test1 -match "Chain INPUT (policy (DROP|REJCET))" -and $test1 -match "Chain FORWARD (policy (DROP|REJCET))" -and $test1 -match "Chain OUTPUT (policy (DROP|REJCET))"){
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
    Id = "3.5.3.2.4"
    Task = "Ensure iptables firewall rules exist for all open ports"
    Test = {
        $test1 = ss -4tuln
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
    Id = "3.5.3.3.1"
    Task = "Ensure ip6tables default deny firewall policy"
    Test = {
        $test1 = ip6tables -L
        if($test1 -match "Chain INPUT (policy (DROP|REJCET))" -and $test1 -match "Chain FORWARD (policy (DROP|REJCET))" -and $test1 -match "Chain OUTPUT (policy (DROP|REJCET))"){
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
    Task = "Ensure ip6tables outbound and established connections are configured"
    Test = {
        return @{
            Message = "Run the following command and verify all rules for new outbound, and established connections match site policy: ip6tables -L -v -n"
            Status = "None"
        }
    }
}
[AuditTest] @{
    Id = "4.1.1.1"
    Task = "Ensure auditd is installed"
    Test = {
        $test = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' auditd audispd-plugins
        if($test -match "audispd-plugins\s+install ok installed\s+installed" -and $test -match "auditd\s+install ok installed\s+installed"){
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
    Task = "Ensure auditd service is enabled and active"
    Test = {
        $test1 = systemctl is-enabled auditd
        $test2 = systemctl is-active auditd
        if($test1 -match "enabled" -and $test2 -match "active"){
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
        $test = find /boot -type f -name 'grub.cfg' -exec grep -Ph -- '^\h*linux' {} + | grep -v 'audit=1'
        if($test -eq $null){
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
        $test = find /boot -type f -name 'grub.cfg' -exec grep -Ph -- '^\h*linux' {} + | grep -Pv 'audit_backlog_limit=\d+\b'
        if($test -eq $null){
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
        $test = grep -Po -- '^\h*max_log_file\h*=\h*\d+\b' /etc/audit/auditd.conf
        if($test -match "max_log_file ="){
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
        $test = grep max_log_file_action /etc/audit/auditd.conf
        if($test -match "max_log_file_action = keep_logs"){
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
        $test3 = grep -E 'admin_space_left_action\s*=\s*(halt|single)' /etc/audit/auditd.conf
        if($test1 -match "space_left_action = email" -and $test2 -match "action_mail_acct = root" -and $test3 -match "admin_space_left_action = (halt|single)"){
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
    Id = "4.1.3.1"
    Task = "Ensure changes to system administration scope (sudoers) is collected"
    Test = {
        $test1 = awk '/^ *-w/ \ &&/\/etc\/sudoers/ \ &&/ +-p *wa/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | awk '/^ *-w/ \ &&/\/etc\/sudoers/ \ &&/ +-p *wa/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
        if($test1 -match "-w /etc/sudoers -p wa -k scope" -and $test1 -match "-w /etc/sudoers.d -p wa -k scope" -and $test2 -match "-w /etc/sudoers -p wa -k scope" -and $test2 -match "-w /etc/sudoers.d -p wa -k scope"){
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
    Id = "4.1.3.2"
    Task = "Ensure actions as another user are always logged"
    Test = {
        $test1 = awk '/^ *-a *always,exit/ \ &&/ -F *arch=b[2346]{2}/ \ &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \ &&(/ -C *euid!=uid/||/ -C *uid!=euid/) \ &&/ -S *execve/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | awk '/^ *-a *always,exit/ \ &&/ -F *arch=b[2346]{2}/ \ &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \ &&(/ -C *euid!=uid/||/ -C *uid!=euid/) \ &&/ -S *execve/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
        if($test1 -match "-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation" -and $test1 -match "-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation" -and $test2 -match "-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation" -and $test2 -match "-a always,exit -F arch=b32 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation"){
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
    Id = "4.1.3.3"
    Task = "Ensure events that modify the sudo log file are collected"
    Test = {
        $test1 = { SUDO_LOG_FILE_ESCAPED=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//' -e 's/"//g' -e 's|/|\\/|g') [ -n "${SUDO_LOG_FILE_ESCAPED}" ] && awk "/^ *-w/ \ &&/"${SUDO_LOG_FILE_ESCAPED}"/ \ &&/ +-p *wa/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \ || printf "ERROR: Variable 'SUDO_LOG_FILE_ESCAPED' is unset.\n" }
        $test2 = {
SUDO_LOG_FILE_ESCAPED=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//' -e 's/"//g' -e 's|/|\\/|g') [ -n "${SUDO_LOG_FILE_ESCAPED}" ] && auditctl -l | awk "/^ *-w/ \ &&/"${SUDO_LOG_FILE_ESCAPED}"/ \ &&/ +-p *wa/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" \ || printf "ERROR: Variable 'SUDO_LOG_FILE_ESCAPED' is unset.\n" }
        if($test1 -match "-w /var/log/sudo.log -p wa -k sudo_log_file" -and $test2 -match "-w /var/log/sudo.log -p wa -k sudo_log_file"){
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
    Id = "4.1.3.4"
    Task = "Ensure events that modify date and time information are collected"
    Test = {
        $test1 = { awk '/^ *-a *always,exit/ \ &&/ -F *arch=b[2346]{2}/ \ &&/ -S/ \ &&(/adjtimex/ \ ||/settimeofday/ \ ||/clock_settime/ ) \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules awk '/^ *-w/ \ &&/\/etc\/localtime/ \ &&/ +-p *wa/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules }
        $test2 = { auditctl -l | awk '/^ *-a *always,exit/ \ &&/ -F *arch=b[2346]{2}/ \ &&/ -S/ \ &&(/adjtimex/ \ ||/settimeofday/ \ ||/clock_settime/ ) \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' auditctl -l | awk '/^ *-w/ \ &&/\/etc\/localtime/ \ &&/ +-p *wa/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'}
        if($test1 -match "-a always,exit -F arch=b64 -S adjtimex,settimeofday clock_settime -k time-change" -and $test1 -match "-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change" -and $test1 -match "-w /etc/localtime -p wa -k time-change" -and $test2 -match "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -F key=time-change" -and $test2 -match "-a always,exit -F arch=b32 -S adjtimex,settimeofday clock_settime -F key=time-change" -and $test3 -match "-w /etc/localtime -p wa -k time-change"){
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
    Id = "4.1.3.5"
    Task = "Ensure events that modify the system's network environment are collected"
    Test = {
        $test1 = awk '/^ *-a *always,exit/ \ &&/ -F *arch=b(32|64)/ \ &&/ -S/ \ &&(/sethostname/ \ ||/setdomainname/) \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
        $test2 = awk '/^ *-w/ \ &&(/\/etc\/issue/ \ ||/\/etc\/issue.net/ \ ||/\/etc\/hosts/ \ ||/\/etc\/network/) \ &&/ +-p *wa/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
        $test3 = auditctl -l | awk '/^ *-a *always,exit/ \ &&/ -F *arch=b(32|64)/ \ &&/ -S/ \ &&(/sethostname/ \ ||/setdomainname/) \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
        $test4 = auditctl -l | awk '/^ *-w/ \ &&(/\/etc\/issue/ \ ||/\/etc\/issue.net/ \ ||/\/etc\/hosts/ \ ||/\/etc\/network/) \ &&/ +-p *wa/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
        if($test1 -match "-a always,exit -F arch=b64 -S adjtimex,settimeofday clock_settime -k time-change" -and $test1 -match "-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change" -and $test1 -match "-w /etc/localtime -p wa -k time-change" -and $test2 -match "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -F key=time-change" -and $test2 -match "-a always,exit -F arch=b32 -S adjtimex,settimeofday clock_settime -F key=time-change" -and $test3 -match "-w /etc/localtime -p wa -k time-change"){
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
    Id = "4.1.3.6"
    Task = "Ensure use of privileged commands are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-4.1.3.6-A.sh"
        $result1=bash $path
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Debian_11/CIS-Debian-4.1.3.6-B.sh"
        $result2=bash $path
        if(!($line -match "nodev")){
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
    Id = "4.1.3.8"
    Task = "Ensure events that modify user/group information are collected"
    Test = {
        $test1 = awk '/^ *-w/ \ &&(/\/etc\/group/ \ ||/\/etc\/passwd/ \ ||/\/etc\/gshadow/ \ ||/\/etc\/shadow/ \ ||/\/etc\/security\/opasswd/) \ &&/ +-p *wa/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | awk '/^ *-w/ \ &&(/\/etc\/group/ \ ||/\/etc\/passwd/ \ ||/\/etc\/gshadow/ \ ||/\/etc\/shadow/ \ ||/\/etc\/security\/opasswd/) \ &&/ +-p *wa/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
        if($test1 -match "-w /etc/group -p wa -k identity" -and $test1 -match "-w /etc/passwd -p wa -k identity" -and $test1 -match "-w /etc/gshadow -p wa -k identity" -and $test1 -match "-w /etc/shadow -p wa -k identity" -and $test1 -match "-w /etc/security/opasswd -p wa -k identity" -and $test2 -match "-w /etc/group -p wa -k identity" -and $test2 -match "-w /etc/passwd -p wa -k identity" -and $test2 -match "-w /etc/gshadow -p wa -k identity" -and $test2 -match "-w /etc/shadow -p wa -k identity" -and $test2 -match "-w /etc/security/opasswd -p wa -k identity"){
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