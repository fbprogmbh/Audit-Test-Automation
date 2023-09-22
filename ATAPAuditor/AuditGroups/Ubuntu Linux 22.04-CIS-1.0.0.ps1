function Get-IPv6-Status {
    $parentPath = Split-Path -Parent -Path $PSScriptRoot
    $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-IP6Status.sh"
    $result=bash $path | grep "enabled"
    if($result -match "*** IPv6 is enabled on the system ***") {
        return $true
    }
    return $false
}
$IPv6Status = Get-IPv6-Status
$ntp = dpkg -s ntp
$ntp = $?
$chrony = dpkg -s chrony
$chrony = $?
$timesyncd = systemctl is-enabled systemd-timesyncd

[AuditTest] @{
    Id = "1.1.1.1"
    Task = "Ensure mounting of cramfs filesystems is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-1.1.1.1.sh"
        $result=bash $path | grep "** PASS **"
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
    Id = "1.1.1.2"
    Task = "Ensure mounting of squashfs filesystems is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-1.1.1.2.sh"
        $result=bash $path | grep "** PASS **"
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
    Id = "1.1.1.3"
    Task = "Ensure mounting of udf filesystetms is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-1.1.1.3.sh"
        $result=bash $path | grep "** PASS **"
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
    Id = "1.1.2.1"
    Task = "Ensure /tmp is a separate partition"
    Test = {
        $result = findmnt --kernel /tmp
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
    Id = "1.1.2.2"
    Task = "Ensure nodev option set on /tmp partition"
    Test = {
        $result =  findmnt --kernel /tmp | grep nodev
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
        $result =  findmnt --kernel /tmp | grep noexec
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
        if($result -match !$null){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure nodev option is set on /var partition"
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
    Task = "Ensure nosuid option is set on /var partition"
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
    Task = "Ensure noexec option is set on /var/tmp partition"
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
    Task = "Ensure nosuid option is set /var/tmp partition"
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
    Task = "Ensure nodev option is set /var/tmp partition"
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
        if($result -match !$null){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure nodev option is set /var/log partition"
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
    Task = "Ensure noexec option is set on /var/log partition"
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
    Task = "Ensure nosuid option is set /var/log partition"
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
    Task = "Ensure noexec option is set on /var/log/audit partition"
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
    Task = "Ensure nodev option is set /var/log/audit partition"
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
    Task = "Ensure nosuid option is set /var/log/audit partition"
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
    Task = "Ensure nodev option is set /home partition"
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
    Task = "Ensure nosuid option is set /home partition"
    Test = {
        $result = findmnt --kernel /home | grep nosuid
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
        $result = findmnt --kernel -n /dev/shm | grep nodev
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
        $result = findmnt --kernel -n /dev/shm | grep noexec
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
        $result = findmnt --kernel -n /dev/shm | grep nosuid
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
        $result = systemctl is-enabled autofs
        if($result -match "Failed to get unit file state for autofs.service: No such file or directory" -or $result -match "Disabled") {
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
     Id = "1.1.10"
     Task = "Disable USB Storage"
     Test = {
         $parentPath = Split-Path -Parent -Path $PSScriptRoot
         $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-1.1.10.sh"
         $result=bash $path | grep "** PASS **"
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
        $result1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' aide
        $result2 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' aide-common
        if($result1 -match "aide\s*install\s*ok\s*installed\s*installed" -and $result2 -match "aide-commons\s*install\s*ok\s*installed\s*installed"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure permissions on bootloader config are not overridden"
    Test = {
        $output = stat /boot/grub/grub.cfg
        if($output -match "Access: (0400/-r--------) Uid: ( 0/ root) Gid: ( 0/ root)"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-1.5.1.sh"
        $result=bash $path | grep "PASS:"
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
    Id = "1.5.2"
    Task = "Ensure prelink is not installed"
    Test = {
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' prelink
        if($result -eq "prelink unknown ok not-installed not-installed"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure automatic error reporting is not enabled"
    Test = {
        $result1 = dpkg-query -s apport > /dev/null 2>&1 && grep -Psi -- '^\h*enabled\h*=\h*[^0]\b' /etc/default/apport
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
        $result = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' apparmor
        
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
    Task = "Ensure GDM login banner is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-1.8.2.sh"
        $result=bash $path
        if($result -match "##TEST"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure GDM disable-user-list option is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-1.8.3.sh"
        $result=bash $path
        if($result -match "##TEST"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure GDM screen locks when the user is idle"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-1.8.4.sh"
        $result=bash $path
        if($result -match "##TEST"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.8.5"
    Task = "Ensure GDM screen locks cannot be overridden"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-1.8.5.sh"
        $result=bash $path
        if($result -match "##TEST"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.8.6"
    Task = "Ensure GDM automatic mounting of removable media is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-1.8.6.sh"
        $result=bash $path | grep "** PASS **"
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
    Id = "1.8.7"
    Task = "Ensure GDM disabling automatic mounting of removable media is not overridden"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-1.8.7.sh"
        $result=bash $path | grep "** PASS **"
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
    Id = "1.8.8"
    Task = "Ensure GDM autorun-never is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-1.8.8.sh"
        $result=bash $path
        if($result -match "##TEST"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.8.9"
    Task = "Ensure GDM autorun-never is not overridden"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-1.8.9.sh"
        $result=bash $path
        if($result -match "##TEST"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "1.8.10"
    Task = "Ensure XDCMP is not enabled"
    Test = {
        $result = grep -Eis '^\s*Enable\s*=\s*true' /etc/gdm3/custom.conf
        if($result -match $null){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-2.1.1.1.sh"
        $result=bash $path
        if($result -match "##TEST"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Id = "2.2.2"
    Task = "Ensure Avahi Server is not installed"
    Test = {
        $status = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' avahi-daemon
        if($status -match "avahi-daemon unknown ok not-installed not-installed"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $test1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' cups
        if($test1 -match "cups unknown ok not-installed not-installed"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $test1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' isc-dhcp-server
        if($test1 -match "isc-dhcp-server unknown ok not-installed not-installed"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $test1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' slapd
        if($test1 -match "slapd unknown ok not-installed not-installed"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $test1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' nfs-kernel-server
        if($test1 -match "nfs-kernel-server unknown ok not-installed not-installed"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $test1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' bind9
        if($test1 -match "bind9 unknown ok not-installed not-installed"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $test1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' vsftpd
        if($test1 -match "vsftpd unknown ok not-installed not-installed"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $test1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' apache2
        if($test1 -match "apache2 unknown ok not-installed not-installed"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Id = "2.2.11"
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
    Id = "2.2.12"
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
    Id = "2.2.13"
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
    Id = "2.2.14"
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
    Id = "2.2.15"
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
    Id = "2.2.16"
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
    Id = "2.3.1"
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
    Id = "2.3.2"
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
    Id = "2.3.3"
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
    Id = "2.3.4"
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
    Id = "2.3.5"
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
    Id = "2.3.6"
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
    Id = "3.1.1"
    Task = "Ensure system is checked to determine if IPv6 is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.1.1.sh"
        $result=bash $path
        if($result -match "IPv6 is enabled on the system"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.1.2.sh"
        $result=bash $path | grep "Wireless is not enabled"
        if($result -ne $null){
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
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.2.1.sh"
        $result=bash $path
        if($result -match "** PASS **"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.2.2.sh"
        $result=bash $path
        if($result -match "** PASS **") {
            return @{
                Message = "Compliant"
                Status = "True"
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
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.3.1.sh"
        $result=bash $path
        if($result -match "** PASS **"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.3.2.sh"
        $result=bash $path
        if($result -match "** PASS **"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.3.3.sh"
        $result=bash $path
        if($result -match "** PASS **"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.3.4"
    Task = "Ensure suspicious packets are logged"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.3.4.sh"
        $result=bash $path
        if($result -match "** PASS **"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.3.5.sh"
        $result=bash $path
        if($result -match "##TEST"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.3.6.sh"
        $result=bash $path
        if($result -match "** PASS **"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.3.7.sh"
        $result=bash $path
        if($result -match "** PASS **"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.3.8.sh"
        $result=bash $path
        if($result -match "** PASS **"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.3.9.sh"
        $result=bash $path
        if($result -match "** PASS **"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.4.1.sh"
        $result=bash $path | grep "** PASS **"
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
    Id = "3.4.2"
    Task = "Ensure SCTP is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.4.2.sh"
        $result=bash $path | grep "** PASS **"
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
    Id = "3.4.3"
    Task = "Ensure RDS is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.4.3.sh"
        $result=bash $path | grep "** PASS **"
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
    Id = "3.4.4"
    Task = "Ensure TIPC is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.4.4.sh"
        $result=bash $path | grep "** PASS **"
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
        $test2 = systemctl is-active ufw
        $test3 = ufw status | grep Status
        if($test1 -match "enabled" -and $test2 -match "active" -and $test3 -match "Status: aktiv"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Id = "3.5.1.6"
    Task = "Ensure ufw firewall rules exist for all open ports"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.5.1.6.sh"
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
    Id = "3.5.1.7"
    Task = "Ensure ufw default deny firewall policy"
    Test = {
        $test1 = ufw status verbose
        if($test1 -match "deny" -or $test1 -match "reject" -or $test1 -match "disabled"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $test1 = dpkg-query -s nftables | grep 'Status: install ok installed'
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
        $test1 = dpkg-query -s ufw | grep 'Status: install ok installed'
        $test2 = ufw status | grep 'Status: Inaktiv'
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
    Id = "3.5.2.10"
    Task = "Ensure nftables rules are permanent"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.5.2.10_1.sh"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.5.2.10_2.sh"
        $path3 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-3.5.2.10_3.sh"
        if($path1 -ne $null -and $path2 -ne $null -and $path3 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $test1 = apt list iptables iptables-persistent | grep installed
        if($test1 -match "iptables-persistent"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        if($test1 -match "install ok installed"){
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
    Id = "3.5.3.1.3"
    Task = "Ensure ufw is uninstalled or disabled with iptables"
    Test = {
        $test1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' ufw
        $test2 = ufw status
        $test3 = systemctl is-enabled ufw
        if($test1 -match "not-installed" -and $test2 -match "Status: Inaktiv" -and $test3 -match "masked"){
            return @{
                Message = "Compliant"
                Status = "True"
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
        $output = iptables -L
        $test1 = $output -match "DROP" | grep "Chain INPUT (policy DROP)"
        $test2 = $output -match "DROP" | grep "Chain FORWARD (policy DROP)"
        $test3 = $output -match "DROP" | grep "Chain OUTPUT (policy DROP)"
        if($test1 -ne $null -and $test2 -ne $null -and $test3 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Id = "3.5.3.2.3"
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
    Id = "3.5.3.2.4"
    Task = "Ensure iptables firewall rules exist for all open ports"
    Test = {
        $test1 =  nix
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
        $output = ip6tables -L
        $test11 = $output -match "DROP" | grep "Chain INPUT (policy DROP)"
        $test12 = $output -match "REJECT" | grep "Chain INPUT (policy REJECT)"
        $test21 = $output -match "DROP" | grep "Chain OUTPUT (policy DROP)"
        $test22 = $output -match "REJECT" | grep "Chain OUTPUT (policy REJECT)"
        $test31 = $output -match "DROP" | grep "Chain FORWARD (policy DROP)"
        $test32 = $output -match "REJECT" | grep "Chain FORWARD (policy REJECT)"

        if ($IPv6Status -eq $false) {
            return @{
                Message = "IPv6 is disabled"
                Status = "True"
            }
        }
        if(($test11 -ne $null -or $test12 -ne $null) -and ($test21 -ne $null -or $test22 -ne $null) -and ($test31 -ne $null -or $test32 -ne $null)){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
# 3.5.3.3.2 ...
# 3.5.3.3.3 ...
# 3.5.3.3.4 ...

[AuditTest] @{
    Id = "4.1.3.1"
    Task = "Ensure changes to system administration scope (sudoers) is collected"
    Test = {
        try{
            $res1 = awk '/^ *-w/ &&/\/etc\/sudoers/ &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | grep "-w /etc/sudoers -p wa -k scope"
            $res2 = awk '/^ *-w/ &&/\/etc\/sudoers/ &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | grep "-w /etc/sudoers.d -p wa -k scope"
            $res3 = auditctl -l | awk '/^ *-w/ &&/\/etc\/sudoers/ &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' | grep "-w /etc/sudoers -p wa -k scope"
            $res4 = auditctl -l | awk '/^ *-w/ &&/\/etc\/sudoers/ &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' | grep "-w /etc/sudoers.d -p wa -k scope"
            if($res1 -ne $null -and $res2 -ne $null -and $res3 -ne $null -and $res4 -ne $null) {
                return @{
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
    Id = "4.1.3.2"
    Task = "Ensure actions as another user are always logged"
    Test = {
        try{
            $res1 = awk '/^ *-a *always,exit/ &&/ -F *arch=b[2346]{2}/ &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) &&(/ -C *euid!=uid/||/ -C *uid!=euid/) &&/ -S *execve/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | grep "-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation "
            $res2 = awk '/^ *-a *always,exit/ &&/ -F *arch=b[2346]{2}/ &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) &&(/ -C *euid!=uid/||/ -C *uid!=euid/) &&/ -S *execve/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | grep "-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation"
            $res3 = auditctl -l | awk '/^ *-a *always,exit/ &&/ -F *arch=b[2346]{2}/ &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) &&(/ -C *euid!=uid/||/ -C *uid!=euid/) &&/ -S *execve/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' | grep "-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation"
            $res4 = auditctl -l | awk '/^ *-a *always,exit/ &&/ -F *arch=b[2346]{2}/ &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) &&(/ -C *euid!=uid/||/ -C *uid!=euid/) &&/ -S *execve/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' | grep "-a always,exit -F arch=b32 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation"
             if($res1 -ne $null -and $res2 -ne $null -and $res3 -ne $null -and $res4 -ne $null) {
                return @{
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
    Id = "4.1.3.3"
    Task = "Ensure events that modify the sudo log file are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.3_1.sh"
        $result1 = bash $path1 | grep "-w /var/log/sudo.log -p wa -k sudo_log_file"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.3_2.sh"
        $result2 = bash $path2 | grep "-w /var/log/sudo.log -p wa -k sudo_log_file"
        if($result1 -ne $null -and $result2 -ne $null) {
            return @{
                Message = "Compliant"
                Status = "True"    
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
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.4_1.sh"
        $result11 = bash $path1 | grep "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change"
        $result12 = bash $path1 | grep "-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change"
        $result13 = bash $path1 | grep "-w /etc/localtime -p wa -k time-change"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.4_2.sh"
        $result21 = bash $path2 | grep "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -F key=time-change"
        $result22 = bash $path2 | grep "-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -F key=time-change"
        $result23 = bash $path2 | grep "-w /etc/localtime -p wa -k time-change"
        if($result11 -ne $null -and $result12 -ne $null -and $result13 -ne $null -and $result21 -ne $null -and $result22 -ne $null -and $result23 -ne $null) {
            return @{
                Message = "Compliant"
                Status = "True"    
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
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.5_1.sh"
        $result11 = bash $path1 | grep "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale"
        $result12 = bash $path1 | grep "-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale"
        $result13 = bash $path1 | grep "-w /etc/issue -p wa -k system-locale"
        $result14 = bash $path1 | grep "-w /etc/issue.net -p wa -k system-locale"
        $result15 = bash $path1 | grep "-w /etc/hosts -p wa -k system-locale"
        $result16 = bash $path1 | grep "-w /etc/networks -p wa -k system-locale"
        $result17 = bash $path1 | grep "-w /etc/network/ -p wa -k system-locale"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.5_2.sh"
        $result21 = bash $path2 | grep "-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale"
        $result22 = bash $path2 | grep "-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale"
        $result23 = bash $path2 | grep "-w /etc/issue -p wa -k system-locale"
        $result24 = bash $path2 | grep "-w /etc/issue.net -p wa -k system-locale"
        $result25 = bash $path2 | grep "-w /etc/hosts -p wa -k system-locale"
        $result26 = bash $path2 | grep "-w /etc/networks -p wa -k system-locale"
        $result27 = bash $path2 | grep "-w /etc/network/ -p wa -k system-locale"
        if($result11 -ne $null -and $result12 -ne $null -and $result13 -ne $null -and $result14 -ne $null -and $result15 -ne $null -and $result16 -ne $null -and $result17 -ne $null -and $result21 -ne $null -and $result22 -ne $null -and $result23 -ne $null -and $result24 -ne $null -and $result25 -ne $null -and $result26 -ne $null -and $result27 -ne $null) {
            return @{
                    Message = "Compliant"
                    Status = "True"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.1.3.6"
    Task = "Ensure use of privileged commands is collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.6_1.sh"
        $result1 = bash $path1 | grep "Warning"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.6_2.sh"
        $result2 = bash $path2 | grep "Warning"
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
    Id = "4.1.3.7"
    Task = "Ensure unsuccessful file access attempts are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.7_1.sh"
        $result11 = bash $path1 | grep "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
        $result12 = bash $path1 | grep "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
        $result13 = bash $path1 | grep "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
        $result14 = bash $path1 | grep "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.7_2.sh"
        $result21 = bash $path2 | grep "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access"
        $result22 = bash $path2 | grep "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access"
        $result23 = bash $path2 | grep "-a always,exit -F arch=b32 -S open,truncate,ftruncate,creat,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access"
        $result24 = bash $path2 | grep "-a always,exit -F arch=b32 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access"
        if($result11 -ne $null -and $result12 -ne $null -and $result13 -ne $null -and $result14 -ne $null -and $result21 -ne $null -and $result22 -ne $null -and $result23 -ne $null-and $result24 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.3.8"
    Task = "Ensure events that modify user/group information are collected"
    Test = {
        $output1 = awk '/^ *-w/ \
        &&(/\/etc\/group/ \
         ||/\/etc\/passwd/ \
         ||/\/etc\/gshadow/ \
         ||/\/etc\/shadow/ \
         ||/\/etc\/security\/opasswd/) \
        &&/ +-p *wa/ \
        &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
        $result11 = $output1 | grep "-w /etc/group -p wa -k identity"
        $result12 = $output1 | grep "-w /etc/passwd -p wa -k identity"
        $result13 = $output1 | grep "-w /etc/gshadow -p wa -k identity"
        $result14 = $output1 | grep "-w /etc/shadow -p wa -k identity"
        $result15 = $output1 | grep "-w /etc/security/opasswd -p wa -k identity"
        $output2 = auditctl -l | awk '/^ *-w/ \
        &&(/\/etc\/group/ \
         ||/\/etc\/passwd/ \
         ||/\/etc\/gshadow/ \
         ||/\/etc\/shadow/ \
         ||/\/etc\/security\/opasswd/) \
        &&/ +-p *wa/ \
        &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
        $result21 = $output2 | grep "-w /etc/group -p wa -k identity"
        $result22 = $output2 | grep "-w /etc/passwd -p wa -k identity"
        $result23 = $output2 | grep "-w /etc/gshadow -p wa -k identity"
        $result24 = $output2 | grep "-w /etc/shadow -p wa -k identity"
        $result25 = $output2 | grep "-w /etc/security/opasswd -p wa -k identity"
        if($result11 -ne $null -and $result12 -ne $null -and $result13 -ne $null -and $result14 -and $result15 -ne $null -and $result21 -ne $null -and $result22 -ne $null -and $result23 -ne $null-and $result24 -ne $null -and $result25 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.3.9"
    Task = "Ensure discretionary access control permission modification events are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.9_1.sh"
        $result11 = bash $path1 | grep "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod"
        $result12 = bash $path1 | grep "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod"
        $result13 = bash $path1 | grep "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod"
        $result14 = bash $path1 | grep "-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod"
        $result15 = bash $path1 | grep "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod"
        $result16 = bash $path1 | grep "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.9_2.sh"
        $result21 = bash $path2 | grep "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod"
        $result22 = bash $path2 | grep "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod"
        $result23 = bash $path2 | grep "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod"
        $result24 = bash $path2 | grep "-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod"
        $result25 = bash $path2 | grep "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod"
        $result26 = bash $path2 | grep "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod"
        if($result11 -ne $null -and $result12 -ne $null -and $result13 -ne $null -and $result14 -ne $null -and $result15 -ne $null-and $result16 -ne $null -and $result21 -ne $null -and $result22 -ne $null -and $result23 -ne $null-and $result24 -ne $null-and $result25 -ne $null-and $result26 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.3.10"
    Task = "Ensure successful file system mounts are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.10_1.sh"
        $result11 = bash $path1 | grep "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts"
        $result12 = bash $path1 | grep "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.10_2.sh"
        $result21 = bash $path2 | grep "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts"
        $result22 = bash $path2 | grep "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts"
        if($result11 -ne $null -and $result12 -ne $null -and $result21 -ne $null -and $result22 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.3.11"
    Task = "Ensure session initiation information is collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.11_1.sh"
        $result11 = bash $path1 | grep "-w /var/run/utmp -p wa -k session"
        $result12 = bash $path1 | grep "-w /var/log/wtmp -p wa -k session"
        $result13 = bash $path1 | grep "-w /var/log/btmp -p wa -k session"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.11_2.sh"
        $result21 = bash $path2 | grep "-w /var/run/utmp -p wa -k session"
        $result22 = bash $path2 | grep "-w /var/log/wtmp -p wa -k session"
        $result23 = bash $path2 | grep "-w /var/log/btmp -p wa -k session"
        if($result11 -ne $null -and $result12 -ne $null -and $result13 -ne $null -and $result21 -ne $null -and $result22 -ne $null -and $result23 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.3.12"
    Task = "Ensure login and logout events are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.12_1.sh"
        $result11 = bash $path1 | grep "-w /var/log/lastlog -p wa -k logins"
        $result12 = bash $path1 | grep "-w /var/run/faillock -p wa -k logins"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.12_2.sh"
        $result21 = bash $path2 | grep "-w /var/log/lastlog -p wa -k logins"
        $result22 = bash $path2 | grep "-w /var/run/faillock -p wa -k logins"
        if($result11 -ne $null -and $result12 -ne $null -and $result21 -ne $null -and $result22 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.3.13"
    Task = "Ensure file deletion events by users are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.13_1.sh"
        $result11 = bash $path1 | grep "a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete"
        $result12 = bash $path1 | grep "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.13_2.sh"
        $result21 = bash $path2 | grep "-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete"
        $result22 = bash $path2 | grep "-a always,exit -F arch=b32 -S unlink,rename,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete"
        if($result11 -ne $null -and $result12 -ne $null -and $result21 -ne $null -and $result22 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.3.14"
    Task = "Ensure events that modify the system's Mandatory Access Controls are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.14_1.sh"
        $result11 = bash $path1 | grep "-w /etc/apparmor/ -p wa -k MAC-policy"
        $result12 = bash $path1 | grep "-w /etc/apparmor.d/ -p wa -k MAC-policy"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.14_2.sh"
        $result21 = bash $path2 | grep "-w /etc/apparmor/ -p wa -k MAC-policy"
        $result22 = bash $path2 | grep "-w /etc/apparmor.d/ -p wa -k MAC-policy"
        if($result11 -ne $null -and $result12 -ne $null -and $result21 -ne $null -and $result22 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.3.15"
    Task = "Ensure successful and unsuccessful attempts to use the chcon command are recorded"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.15_1.sh"
        $result1 = bash $path1 | grep "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.15_2.sh"
        $result2 = bash $path2 | grep "-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng"
        if($result1 -ne $null -and $result2 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.3.16"
    Task = "Ensure events that modify the system's Mandatory Access Controls are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.16_1.sh"
        $result1 = bash $path1 | grep "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.16_2.sh"
        $result2 = bash $path2 | grep "-a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng"
        if($result1 -ne $null -and $result2 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.3.17"
    Task = "Ensure successful and unsuccessful attempts to use the chacl command are recorded"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.17_1.sh"
        $result1 = bash $path1 | grep "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.17_2.sh"
        $result2 = bash $path2 | grep "-a always,exit -S all -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd"
        if($result1 -ne $null -and $result2 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.3.18"
    Task = "Ensure successful and unsuccessful attempts to use the usermod command are recorded"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.18_1.sh"
        $result1 = bash $path1 | grep "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.18_2.sh"
        $result2 = bash $path2 | grep "-a always,exit -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -F key=usermod"
        if($result1 -ne $null -and $result2 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.3.19"
    Task = "Ensure kernel module loading unloading and modification is collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.19_1.sh"
        $result11 = bash $path1 | grep "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules"
        $result12 = bash $path1 | grep "-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules"
        $path2 = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.1.3.19_2.sh"
        $result21 = bash $path2 | grep "-a always,exit -F arch=b64 -S create_module,init_module,delete_module,query_module,finit_module -F auid>=1000 -F auid!=-1 -F key=kernel_modules"
        $result22 = bash $path1 | grep "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=kernel_modules"
        if($result11 -ne $null -and $result12 -ne $null -and $result21 -ne $null -and $result22 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.3.20"
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
    Id = "4.1.3.21"
    Task = "Ensure the running and on disk configuration is the same"
    Test = {
        $test1 = augenrules --check
        if($test1 -match "/usr/sbin/augenrules: No change"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.4.1"
    Task = "Ensure audit log files are mode 0640 or less permissive"
    Test = {
        $test = stat -Lc "%n %a" "$(dirname $( awk -F"=" '/^\s*log_file\s*=\s*/ {print $2}' /etc/audit/auditd.conf | xargs))"/* | grep -v '[0,2,4,6][0,4]0'
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
    Id = "4.1.4.2"
    Task = "Ensure only authorized users own audit log files"
    Test = {
        $test1 = stat -Lc "%n %U" "$(dirname $(awk -F"=" '/^\s*log_file\s*=\s*/ {print $2}' /etc/audit/auditd.conf | xargs))"/* | grep -Pv -- '^\H+\h+root\b'
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
    Id = "4.1.4.3"
    Task = "Ensure only authorized groups are assigned ownership of audit log files"
    Test = {
        $test1 = grep -Piw -- '^\h*log_group\h*=\h*(adm|root)\b' /etc/audit/auditd.conf
        $output1 = $test1 | grep "log_group = adm"
        $output2 = $test1 | grep "log_group = root"
        $test2 = stat -c "%n %G" "$(dirname $(awk -F"=" '/^\s*log_file\s*=\s*/ {print $2}' /etc/audit/auditd.conf | xargs))"/* | grep -Pv '^\h*\H+\h+(adm|root)\b'
        if(($output1 -ne $null -or $output2 -ne $null) -and $test2 -eq $null) {
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.4.4"
    Task = "Ensure the audit log directory is 0750 or more restrictive"
    Test = {
        $test1 = stat -Lc "%n %a" "$(dirname $( awk -F"=" '/^\s*log_file\s*=\s*/ {print $2}' /etc/audit/auditd.conf))" | grep -Pv -- '^\h*\H+\h+([0,5,7][0,5]0)'
        if($test1 -eq $null) {
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.4.5"
    Task = "Ensure audit configuration files are 640 or more restrictive"
    Test = {
        $test1 = find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec stat -Lc "%n %a" {} + | grep -Pv -- '^\h*\H+\h*([0,2,4,6][0,4]0)\h*$'
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
    Id = "4.1.4.6"
    Task = "Ensure audit configuration files are owned by root"
    Test = {
        $test1 = find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root
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
    Id = "4.1.4.7"
    Task = "Ensure audit configuration files belong to group root"
    Test = {
        $test1 = find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root
        if($test1 -eq $null) {
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.4.8"
    Task = "Ensure audit tools are 755 or more restrictive"
    Test = {
        $test1 = stat -c "%n %a" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h*$'
        if($test1 -eq $null) {
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.4.9"
    Task = "Ensure audit tools are owned by root"
    Test = {
        $test1 = stat -c "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | grep -Pv -- '^\h*\H+\h+root\h*$'
        if($test1 -eq $null) {
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.4.10"
    Task = "Ensure audit tools are owned by root"
    Test = {
        $test1 = stat -c "%n %a %U %G" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h+root\h+root\h*$'
        if($test1 -eq $null) {
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.1.4.11"
    Task = "Ensure cryptographic mechanisms are used to protect the integrity of audit tools"
    Test = {
        $test1 = grep -P -- '(\/sbin\/(audit|au)\H*\b)' /etc/aide/aide.conf
        $output1 = $test1 | grep "/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512"
        $output2 = $test1 | grep "/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512 "
        $output3 = $test1 | grep "/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512"
        $output4 = $test1 | grep "/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512"
        $output5 = $test1 | grep "/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512"
        $output6 = $test1 | grep "/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512"
        if($output1 -ne $null -and $output2 -ne $null -and $output3 -ne $null -and $output4 -ne $null -and $output5 -ne $null -and $output6 -ne $null) {
            return @{
                Message = "Compliant"
                Status = "True"
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
        Task = "Ensure all logfiles have appropriate permissions and ownership"
        Test = {
            $parentPath = Split-Path -Parent -Path $PSScriptRoot
            $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-4.2.3.sh"
            $result = $path | grep "PASS"
            if($result -match "PASS"){
                return @{
                    Message = "Compliant"
                    Status = "True"
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
    Task = "Ensure journald service is enabled"
    Test = {
        $test1 =  systemctl is-enabled systemd-journald.service
        if($test1 -match "static"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure journald is configured to compress large log files"
    Test = {
        $test1 = grep ^\s*Compress /etc/systemd/journald.conf
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
    Id = "4.2.1.4"
    Task = "Ensure journald is configured to write logfiles to persistent disk"
    Test = {
        $test1 = grep ^\s*Storage /etc/systemd/journald.conf
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
    Id = "4.2.1.5"
    Task = "Ensure journald is not configured to send logs to rsyslog"
    Test = {
        $test1 = grep ^\s*ForwardToSyslog /etc/systemd/journald.conf
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
    Id = "4.2.1.6"
    Task = "Ensure journald log rotation is configured per site policy"
    Test = {
        $test1 = nix
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
#4.2.1.7 ...
[AuditTest] @{
    Id = "4.2.1.1.1"
    Task = "Ensure systemd-journal-remote is installed"
    Test = {
        $test1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' systemd-journal-remote
        if($test1 -match "systemd-journal-remote install ok installed installed"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.2.1.1.2"
    Task = "Ensure systemd-journal-remote is configured"
    Test = {
        $test1 = grep -P "^ *URL=|^ *ServerKeyFile=|^ *ServerCertificateFile=|^ *TrustedCertificateFile=" /etc/systemd/journal-upload.conf
        $output1 = $test1 | grep "URL=*"
        $output2 = $test1 | grep "ServerKeyFile=*"
        $output3 = $test1 | grep "ServerCertificateFile=*"
        $output4 = $test1 | grep "TrustedCertificateFile=*"
        if($output1 -ne $null -and $output2 -ne $null -and $output3 -ne $null -and $output4 -ne $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.2.1.1.3"
    Task = "Ensure systemd-journal-remote is enabled"
    Test = {
        $test = systemctl is-enabled systemd-journal-upload.service
        $output = $test | grep "enabled"
        if($output -match "enabled"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.2.1.1.4"
    Task = "Ensure journald is not configured to recieve logs from a remote client"
    Test = {
        $test = systemctl is-enabled systemd-journal-remote.socket
        $output = $test | grep "disabled"
        if($output -match "disabled"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure rsyslog is installed"
    Test = {
        $test1 = dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' rsyslog
        if($test1 -match "rsyslog install ok installed installed"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Id = "4.2.2.3"
    Task = "Ensure journald is configured to send logs to rsyslog"
    Test = {
        $test1 = grep ^\s*ForwardToSyslog /etc/systemd/journald.conf
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
    Id = "4.2.2.4"
    Task = "Ensure rsyslog default file permissions configured"
    Test = {
        $test1 = grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf
        if($test1 -match "$FileCreateMode 0640"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "4.2.2.5"
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
    Id = "4.2.2.6"
    Task = "Ensure rsyslog is configured to send logs to a remote log host"
    Test = {
        $test1 = nix
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
    Id = "4.2.2.7"
    Task = "Ensure rsyslog is not configured to receive logs from a remote client"
    Test = {
        $test1 = grep -P -- '^\h*module\(load="imtcp"\)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
        $test2 = grep -P -- '^\h*input\(type="imtcp" port="514"\)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
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
    Id = "5.2.2"
    Task = "Ensure permissions on SSH private host key files are configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-5.2.2.sh"
        $result=bash $path
        if($result -match "** PASS **") {
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure permissions on SSH public host key files are configured"
    Test = {
        $res = bash -c "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;" | grep "Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)\s*"
        if($res.count -eq 3){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.2.4"
    Task = "Ensure SSH access is limited"
    Test = {
        try{
            $result = bash -c "sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep -Ei '^\s*(allow|deny)(users|groups)\s+\S+'"
            $result2 = bash -c "grep -rPi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$' /etc/ssh/sshd_config*"
            if(($result -match "allowusers" -or $result -match "allowgroups" -or $result -match "denyusers" -or $result -match "denygroups") -and ($result2 -match "allowusers" -or $result2 -match "allowgroups" -or $result2 -match "denyusers" -or $result2 -match "denygroups")){
                return @{
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
    Id = "5.2.5"
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
    Id = "5.2.6"
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
    Id = "5.2.7"
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
    Id = "5.2.8"
    Task = "Ensure SSH HostbasedAuthentication is disabled"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep hostbasedauthentication
            try{
                $test2 = grep -Ei '^\s*HostbasedAuthentication\s+yes' /etc/ssh/sshd_config
            }
            catch{
                return @{
                    Message = "Path not found!"
                    Status = "False"
                }
            }
            if($test1 -match "hostbasedauthentication no" -and $test2 -eq $null){
                return @{
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
    Id = "5.2.9"
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
    Id = "5.2.10"
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
    Id = "5.2.11"
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
    Id = "5.2.12"
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
    Id = "5.2.13"
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
    Id = "5.2.14"
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
    Id = "5.2.15"
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
    Id = "5.2.16"
    Task = "Ensure SSH AllowTcpForwarding is disabled"
    Test = {
        $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i allowtcpforwarding
        $test2 = grep -Ei '^\s*AllowTcpForwarding\s+yes' /etc/ssh/sshd_config
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
}
[AuditTest] @{
    Id = "5.2.17"
    Task = "Ensure SSH warning banner is configured"
    Test = {
        $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep banner
        if($test1 -match "banner /etc/issue.net"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.2.18"
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
    Id = "5.2.19"
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
    Id = "5.2.20"
    Task = "Ensure SSH MaxSessions is set to 10 or less"
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
    Id = "5.2.21"
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
    Id = "5.2.22"
    Task = "Ensure SSH Idle Timeout Interval is configured"
    Test = {
        try{
            $test1 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep clientaliveinterval | cut -d ' ' -f 2
            $test2 = sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname)/etc/hosts | awk '{print $1}')" | grep clientalivecountmax | cut -d ' ' -f 2
            if($test1 -ge 1 -and $test2 -ge 1) {
                return @{
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
    Id = "5.3.1"
    Task = "Ensure sudo is installed"
    Test = {
        $test1 = dpkg-query -W sudo sudo-ldap > /dev/null 2>&1 && dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' sudo sudo-ldap | awk '($4=="installed" && $NF=="installed") {print "\n""PASS:""\n""Package ""\""$1"\""" is installed""\n"}' || echo -e "\nFAIL:\nneither \"sudo\" or \"sudo-ldap\" package is installed\n"
        if($test1 -match "PASS:"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.3.2"
    Task = "Ensure sudo commands use pty"
    Test = {
        $test1 = grep -rPi '^\h*Defaults\h+([^#\n\r]+,)?use_pty(,\h*\h+\h*)*\h*(#.*)?$' /etc/sudoers*
        if($test1 -match "/etc/sudoers:Defaults\s*use_pty"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure sudo log file exists"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-5.3.3.sh"
        $result=bash $path
        if($result -match "/var/log/sudo.log"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure users must provide password for privilege escalation"
    Test = {
        $test1 = grep -r "^[^#].*NOPASSWD" /etc/sudoers*
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
    Id = "5.3.5"
    Task = "Ensure re-authentication for privilege escalation is not disabled globally"
    Test = {
        $test1 = grep -r "^[^#].*\!authenticate" /etc/sudoers*
        if($test1 -match "!authenticate"){
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
    Id = "5.3.6"
    Task = "Ensure sudo authentication timeout is configured correctly"
    Test = {
        $test1 = nix
        if($test1 -match "!authenticate"){
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
    Id = "5.3.7"
    Task = "Ensure access to the su command is restricted"
    Test = {
        $test1 = grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su
        if($test1 -match "pam_wheel.so use_uid group="){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
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
    Task = "Ensure password hashing algorithm is up to date with the latest standards"
    Test = {
        $test1 = grep -v ^ /etc/pam.d/common-password | grep -E "(yescrypt|md5|bigcrypt|sha256|sha512|blowfish)"
        $test2 = grep -i "^\s*ENCRYPT_METHOD\s*yescrypt\s*$" /etc/login.defs
        if($test1 -match $null -and $test2 -match "ENCRYPT_METHOD yescrypt"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.4.5"
    Task = "Ensure all current passwords uses the configured hashing algorithm"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-5.4.5.sh"
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
    Id = "5.5.4"
    Task = "Ensure default user umask is 027 or more restrictive"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-5.5.4.sh"
        $result=bash $path
        $test2 = grep -RPi '(^|^[^#]*)\s*umask\s+([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b|[0-7][01][0-7]\b|[0-7][0-7][0-6]\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}(,o=[rwx]{0,3})?\b)' /etc/login.defs /etc/profile* /etc/bash.bashrc*
        if($result -match "Default user umask is set" -and $test2 -eq $null){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "5.5.5"
    Task = "Ensure default user shell timeout is 900 seconds or less"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-5.5.5.sh"
        $result=bash $path
        if($result -match "PASSED"){
            return @{
                Message = "Compliant"
                Status = "True"
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

            if($res -le 365){
                return @{
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
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-5.5.1.5.sh"
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
    Id = "6.1.1"
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
    Id = "6.1.2"
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
    Id = "6.1.3"
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
    Id = "6.1.4"
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
    Id = "6.1.5"
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
    Id = "6.1.6"
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
    Id = "6.1.7"
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
    Id = "6.1.8"
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
    Id = "6.1.9"
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
    Id = "6.1.10"
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
    Id = "6.1.11"
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
    Id = "6.1.12"
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
    Task = "Ensure /etc/shadow password fields are not empty"
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
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-6.2.3.sh"
        $result=bash $path
        if($result -match $null){
            return @{
                Message = "Compliant"
                Status = "True"
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
[AuditTest] @{
    Id = "6.2.5"
    Task = "Ensure no duplicate UIDs exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-6.2.5.sh"
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
    Task = "Ensure no duplicate GIDs exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-6.2.6.sh"
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
    Task = "Ensure no duplicate user names exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-6.2.7.sh"
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
    Task = "Ensure no duplicate group names exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-6.2.8.sh"
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
    Id = "6.2.9"
    Task = "Ensure root PATH Integrity"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-6.2.9.sh"
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
    Id = "6.2.11"
    Task = "Ensure local interactive user home directories exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-6.2.11.sh"
        $result=bash $path
        if($result -eq "##TEST"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure local interactive users own their home directories"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-6.2.12.sh"
        $result=bash $path
        if($result -eq "##TEST"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure local interactive user home directories are mode 750 or more restrictive"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-6.2.13.sh"
        $result=bash $path
        if($result -eq "##TEST"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure no local interactive user has .netrc files"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-6.2.14.sh"
        $result=bash $path
        if($result -eq "##TEST"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure no local interactive user has .forward files"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-6.2.15.sh"
        $result=bash $path
        if($result -eq "##TEST"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure no local interactive user has .rhosts files"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-6.2.16.sh"
        $result=bash $path
        if($result -eq "##TEST"){
            return @{
                Message = "Compliant"
                Status = "True"
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
    Task = "Ensure local interactive user dot files are not group or world writable"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/CIS-Ubuntu22.04_LTS-6.2.17.sh"
        $result=bash $path
        if($result -eq "##TEST"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
