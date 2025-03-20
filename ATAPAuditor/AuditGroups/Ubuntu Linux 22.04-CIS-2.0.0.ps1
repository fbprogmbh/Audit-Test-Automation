$rcTrue = "True"
$rcCompliant = "Compliant"
$rcFalse = "False"
$rcNone = "None"
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
    Status = $rcNone
}

# Ubuntu Linux 22.04-CIS-2.0.0.ps1
# Generated from benchmarks_ubuntu.txt and Ubuntu Linux 22.04-CIS-1.0.0.ps1
# Rules use either existing PowerShell checks or new Bash scripts if available.

[AuditTest] @{
    Id = "1.1.1.1"
    Task = "Ensure cramfs kernel module is not available"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.1.1.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.2"
    Task = "Ensure freevxfs kernel module is not available"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.1.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.3"
    Task = "Ensure hfs kernel module is not available"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.1.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.4"
    Task = "Ensure hfsplus kernel module is not available"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.1.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.5"
    Task = "Ensure jffs2 kernel module is not available"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.1.5.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.6"
    Task = "Ensure squashfs kernel module is not available"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.1.6.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.7"
    Task = "Ensure udf kernel module is not available"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.1.7.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.8"
    Task = "Ensure usb-storage kernel module is not available"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.1.8.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.1.1"
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
    Id = "1.1.2.1.2"
    Task = "Ensure nodev option set on /tmp partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.1.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.1.3"
    Task = "Ensure nosuid option set on /tmp partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.1.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.1.4"
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

# MISSING RULE: 1.1.2.2.1 - Ensure /dev/shm is a separate partition
[AuditTest] @{
    Id = "1.1.2.2.2"
    Task = "Ensure nodev option set on /dev/shm partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.2.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.2.3"
    Task = "Ensure nosuid option set on /dev/shm partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.2.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.2.4"
    Task = "Ensure noexec option set on /dev/shm partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.2.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.3.1"
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
    Id = "1.1.2.3.2"
    Task = "Ensure nodev option set on /home partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.3.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.3.3"
    Task = "Ensure nosuid option set on /home partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.3.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.4.1"
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
    Id = "1.1.2.4.2"
    Task = "Ensure nodev option set on /var partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.4.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.4.3"
    Task = "Ensure nosuid option set on /var partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.4.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.5.1"
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
    Id = "1.1.2.5.2"
    Task = "Ensure nodev option set on /var/tmp partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.5.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.5.3"
    Task = "Ensure nosuid option set on /var/tmp partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.5.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.5.4"
    Task = "Ensure noexec option set on /var/tmp partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.5.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.6.1"
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
    Id = "1.1.2.6.2"
    Task = "Ensure nodev option set on /var/log partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.6.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.6.3"
    Task = "Ensure nosuid option set on /var/log partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.6.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.6.4"
    Task = "Ensure noexec option set on /var/log partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.6.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.7.1"
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
    Id = "1.1.2.7.2"
    Task = "Ensure nodev option set on /var/log/audit partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.7.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.7.3"
    Task = "Ensure nosuid option set on /var/log/audit partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.7.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.7.4"
    Task = "Ensure noexec option set on /var/log/audit partition"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.1.2.7.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.2.1.1"
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
    Id = "1.2.1.2"
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
[AuditTest] @{ # added: 1.9 Ensure updates, patches, and additional security software are installed
    Id = "1.2.2.1"
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
    Id = "1.3.1.1"
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
    Id = "1.3.1.2"
    Task = "Ensure AppArmor is enabled in the bootloader configuration"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.3.1.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.3.1.3"
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
    Id = "1.3.1.4"
    Task = "Ensure all AppArmor Profiles are enforcing"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.3.1.4.sh"
        $result = bash $script
        if ($?) {
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
    Task = "Ensure access to bootloader config is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.4.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.5.1"
    Task = "Ensure address space layout randomization is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.5.1.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.5.2"
    Task = "Ensure ptrace_scope is restricted"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.5.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.5.3"
    Task = "Ensure core dumps are restricted"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.5.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
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
    Id = "1.5.5"
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
    Id = "1.6.1"
    Task = "Ensure message of the day is configured properly"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.6.1.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.6.2"
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
    Id = "1.6.3"
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
    Id = "1.6.4"
    Task = "Ensure access to /etc/motd is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.6.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{ # added: 1.7.5 Ensure permissions on /etc/issue are configured
    Id = "1.6.5"
    Task = "Ensure access to /etc/issue is configured"
    Test = {
        $output = stat -L /etc/issue | grep "Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)"
        
        if($output -ne $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # added: 1.7.6 Ensure permissions on /etc/issue.net are configured
    Id = "1.6.6"
    Task = "Ensure access to /etc/issue.net is configured"
    Test = {
        $output = stat -L /etc/issue.net | grep "Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)"
        
        if($output -ne $null){
            return $retCompliant
        }
        return $retNonCompliant
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
    Id = "1.7.7"
    Task = "Ensure GDM disabling automatic mounting of removable media is not overridden"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.8.7.sh"
        $result=bash $path | grep " PASS "
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
    Id = "1.7.8"
    Task = "Ensure GDM autorun-never is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.8.8.sh"
        $result=bash $path
        if($result -match " PASS "){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}

[AuditTest] @{
    Id = "1.7.9"
    Task = "Ensure GDM autorun-never is not overridden"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.8.9.sh"
        $result=bash $path
        if($result -match " PASS "){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}

[AuditTest] @{
    Id = "1.7.10"
    Task = "Ensure XDCMP is not enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/1.7.10.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{ # added: 1.1.23 Disable Automounting
    Id = "2.1.1"
    Task = "Ensure autofs services are not in use"
    Test = {
        $result = dpkg -l | grep -o autofs
        if($result -eq $null){
            return $retCompliant
        }
        else{
            $result = systemctl is-enabled autofs
            if($result -match "No such file or directory"){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # added: 2.1.3 Ensure Avahi Server is not installed
    Id = "2.1.2"
    Task = "Ensure avahi daemon services are not in use"
    Test = {
        $status = dpkg -l | grep -o avahi-daemon
        if($status -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # added: 2.1.5 Ensure DHCP Server is not installed
    Id = "2.1.3"
    Task = "Ensure dhcp server services are not in use"
    Test = {
        $test1 = dpkg -l | grep -o isc-dhcp-server
        if($test1 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # added: 2.1.8 Ensure DNS Server is not installed
    Id = "2.1.4"
    Task = "Ensure dns server services are not in use"
    Test = {
        $test1 = dpkg -l | grep -o bind9
        if($test1 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
# MISSING RULE: 2.1.5 - Ensure dnsmasq services are not in use
[AuditTest] @{ # added: 2.1.9 Ensure FTP Server is not installed
    Id = "2.1.6"
    Task = "Ensure ftp server services are not in use"
    Test = {
        $test1 = dpkg -l | grep -o vsftpd
        if($test1 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # added: 2.1.6 Ensure LDAP server is not installed
    Id = "2.1.7"
    Task = "Ensure ldap server services are not in use"
    Test = {
        $test1 = dpkg -l | grep -o slapd
        if($test1 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # added: 2.1.11 Ensure IMAP and POP3 server are not installed
    Id = "2.1.8"
    Task = "Ensure message access server services are not in use"
    Test = {
        $test1 =  dpkg -l | grep -o dovecot-imapd
        $test2 = dpkg -l | grep -o dovecot-pop3d
        if($test1 -eq $null -and $test2 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # added: 2.1.7 Ensure NFS is not installed
    Id = "2.1.9"
    Task = "Ensure network file system services are not in use"
    Test = {
        $test1 = dpkg -l | grep -o nfs-kernel-server
        if($test1 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # added: 2.1.17 Ensure NIS Server is not installed
    Id = "2.1.10"
    Task = "Ensure nis server services are not in use"
    Test = {
        $test1 = dpkg -s nis
        $test1 = $?
        if($test1 -match "False"){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # added: 2.1.4 Ensure CUPS is not installed
    Id = "2.1.11"
    Task = "Ensure print server services are not in use"
    Test = {
        $test1 = dpkg -s cups
        $test1 = $?
        if($test1 -match "False"){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # added: 2.2.6 Ensure RPC is not installed
    Id = "2.1.12"
    Task = "Ensure rpcbind services are not in use"
    Test = {
        $test1 = dpkg -l | grep -o rpcbind
        if($test1 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # added: 2.1.16 Ensure rsync service is not installed
    Id = "2.1.13"
    Task = "Ensure rsync services are not in use"
    Test = {
        dpkg -s rsync | grep -E '(Status:|not installed)'
        $test1 = $?
        if($test1 -match "False"){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # added: 2.1.12 Ensure Samba is not installed
    Id = "2.1.14"
    Task = "Ensure samba file server services are not in use"
    Test = {
        dpkg -s samba | grep -E '(Status:|not installed)'
        $test1 = $?
        if($test1 -match "False"){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # added: 2.1.14 Ensure SNMP Server is not installed
    Id = "2.1.15"
    Task = "Ensure snmp services are not in use"
    Test = {
        $test1 = dpkg -l | grep -o snmpd
        if($test1 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
# MISSING RULE: 2.1.16 - Ensure tftp server services are not in use
[AuditTest] @{ # added: 2.1.13 Ensure HTTP Proxy Server is not installed
    Id = "2.1.17"
    Task = "Ensure web proxy server services are not in use"
    Test = {
        $test1 = dpkg -l | grep -o squid
        if($test1 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # added: 2.1.10 Ensure HTTP server is not installed
    Id = "2.1.18"
    Task = "Ensure web server services are not in use"
    Test = {
        $test1 = dpkg -l | grep -o apache2
        if($test1 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
# MISSING RULE: 2.1.19 - Ensure xinetd services are not in use
[AuditTest] @{ # added diff!: 2.1.2 Ensure X Window System is not installed
    Id = "2.1.20"
    Task = "Ensure X window server services are not in use"
    Test = {
        $test1 = dpkg -l | grep -o xserver-commen # previous: xorg*
        if($test1 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.21"
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

# MISSING RULE: 2.1.22 - Ensure only approved services are listening on a network interface
# ^ this one's manual; 2.4 Ensure nonessential services are removed or masked
# has no implementation?
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
    Id = "2.3.1.1"
    Task = "Ensure a single time synchronization daemon is in use"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/2.1.1.1.sh"
        $result=bash $path
        if($result -match "PASS:"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }

        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}

# MISSING RULE: 2.3.2.1 - Ensure systemd-timesyncd configured with authorized timeserver
# ^ this one's manual; 2.1.3.1 Ensure systemd-timesyncd configured with authorized timeserver

[AuditTest] @{ # added: 2.1.1.2 Ensure systemd-timesyncd is configured
    Id = "2.3.2.2"
    Task = "Ensure systemd-timesyncd is enabled and running"
    Test = {
        $test1 = systemctl is-enabled systemd-timesyncd.service
        $time = timedatectl status
        if($test1 -match "enabled" -and $time -ne $null){    
            return $retCompliant
        }
        return $retNonCompliant
    }
}
# MISSING RULE: 2.3.3.1 - Ensure chrony is configured with authorized timeserver
# ^ this one's manual; 2.1.2.1 Ensure chrony is configured with authorized timeserver

[AuditTest] @{
    Id = "2.3.3.2"
    Task = "Ensure chrony is running as user _chrony"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/2.3.3.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
# MISSING RULE: 2.3.3.3 - Ensure chrony is enabled and running

[AuditTest] @{ # added diff: 5.1.1 Ensure cron daemon is enabled and running
    Id = "2.4.1.1"
    Task = "Ensure cron daemon is enabled and active"
    Test = {
        $test1 = systemctl is-enabled cron
        $test2 = systemctl status cron | grep 'Active: active (running) '
        if($test1 -eq "enabled" -and $test2 -match "running"){
            return $retCompliant
        }
        return $retCompliant
    }
}
[AuditTest] @{
    Id = "2.4.1.2"
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
    Id = "2.4.1.3"
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
    Id = "2.4.1.4"
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
    Id = "2.4.1.5"
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
    Id = "2.4.1.6"
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
    Id = "2.4.1.7"
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
    Id = "2.4.1.8"
    Task = "Ensure crontab is restricted to authorized users"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/2.4.1.8.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "2.4.2.1"
    Task = "Ensure at is restricted to authorized users"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/2.4.2.1.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.1.1"
    Task = "Ensure system is checked to determine if IPv6 is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.1.1.sh"
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
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.1.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
# MISSING RULE: 3.1.3 - Ensure bluetooth services are not in use
[AuditTest] @{
    Id = "3.2.1"
    Task = "Ensure dccp kernel module is not available"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.2.1.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.2.2"
    Task = "Ensure tipc kernel module is not available"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.2.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.2.3"
    Task = "Ensure rds kernel module is not available"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.2.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.2.4"
    Task = "Ensure sctp kernel module is not available"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.2.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.1"
    Task = "Ensure ip forwarding is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.3.1.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.2"
    Task = "Ensure packet redirect sending is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.3.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.3"
    Task = "Ensure bogus icmp responses are ignored"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.3.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.4"
    Task = "Ensure broadcast icmp requests are ignored"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.3.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.5"
    Task = "Ensure icmp redirects are not accepted"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.3.5.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.6"
    Task = "Ensure secure icmp redirects are not accepted"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.3.6.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.7"
    Task = "Ensure reverse path filtering is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.3.7.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.8"
    Task = "Ensure source routed packets are not accepted"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.3.8.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.9"
    Task = "Ensure suspicious packets are logged"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.3.9.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.10"
    Task = "Ensure tcp syn cookies is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.3.10.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.11"
    Task = "Ensure ipv6 router advertisements are not accepted"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.3.11.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "4.1.1"
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
    Id = "4.1.2"
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
    Id = "4.1.3"
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
    Id = "4.1.4"
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
    Id = "4.1.5"
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
    Id = "4.1.6"
    Task = "Ensure ufw firewall rules exist for all open ports"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.5.1.6.sh"
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
    Id = "4.1.7"
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
    Id = "4.2.1"
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
    Id = "4.2.2"
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
        Id = "4.2.3"
        Task = "Ensure all logfiles have appropriate permissions and ownership"
        Test = {
            $parentPath = Split-Path -Parent -Path $PSScriptRoot
            $path = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/4.2.3.sh"
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
    Id = "4.2.4"
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
    Id = "4.2.5"
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
    Id = "4.2.6"
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
    Id = "4.2.7"
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
    Id = "4.2.8"
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
    Id = "4.2.9"
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
    Id = "4.2.10"
    Task = "Ensure nftables rules are permanent"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.5.2.10_1.sh"
        $path2 = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.5.2.10_2.sh"
        $path3 = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/3.5.2.10_3.sh"
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
    Id = "4.3.1.1"
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
    Id = "4.3.1.2"
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
    Id = "4.3.1.3"
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
    Id = "4.3.2.1"
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
    Id = "4.3.2.2"
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
    Id = "4.3.2.3"
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
# 3.5.3.2.4 ...

# MISSING RULE: 4.3.2.4 - Ensure iptables firewall rules exist for all open ports
[AuditTest] @{
    Id = "4.3.3.1"
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
# MISSING RULE: 4.3.3.2 - Ensure ip6tables loopback traffic is configured
# 3.5.3.3.2 ...
# MISSING RULE: 4.3.3.3 - Ensure ip6tables outbound and established connections are configured
# ^this one's manual; 3.5.3.3.3 "
# MISSING RULE: 4.3.3.4 - Ensure ip6tables firewall rules exist for all open ports
# 3.5.3.3.4 ...
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
    Task = "Ensure permissions on SSH public host key files are configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.4"
    Task = "Ensure permissions on /etc/cron.daily are configured"
    Test = {
        $test1 = bash -c "stat -c '%#a' /etc/cron.daily/ | grep -q 700"
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
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
    Task = "Ensure sshd Ciphers are configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.6.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.7"
    Task = "Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.7.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.8"
    Task = "Ensure sshd DisableForwarding is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.8.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.9"
    Task = "Ensure sshd GSSAPIAuthentication is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.9.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.10"
    Task = "Ensure sshd HostbasedAuthentication is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.10.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.11"
    Task = "Ensure sshd IgnoreRhosts is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.11.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.12"
    Task = "Ensure sshd KexAlgorithms is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.12.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.13"
    Task = "Ensure sshd LoginGraceTime is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.13.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.14"
    Task = "Ensure sshd LogLevel is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.14.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.15"
    Task = "Ensure sshd MACs are configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.15.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.16"
    Task = "Ensure sshd MaxAuthTries is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.16.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.17"
    Task = "Ensure sshd MaxSessions is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.17.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.18"
    Task = "Ensure sshd MaxStartups is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.18.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.19"
    Task = "Ensure sshd PermitEmptyPasswords is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.19.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.20"
    Task = "Ensure sshd PermitRootLogin is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.20.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.21"
    Task = "Ensure sshd PermitUserEnvironment is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.21.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.22"
    Task = "Ensure sshd UsePAM is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.1.22.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
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
    Task = "Ensure sudo commands use pty"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.2.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.2.3"
    Task = "Ensure sudo log file exists"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.2.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
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
    Task = "Ensure sudo authentication timeout is configured correctly"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.2.6.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
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

# MISSING RULE: 5.3.1.1 - Ensure latest version of pam is installed
# MISSING RULE: 5.3.1.2 - Ensure libpam-modules is installed
# MISSING RULE: 5.3.1.3 - Ensure libpam-pwquality is installed
[AuditTest] @{
    Id = "5.3.2.1"
    Task = "Ensure pam_unix module is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.2.1.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.2.2"
    Task = "Ensure pam_faillock module is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.2.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.2.3"
    Task = "Ensure pam_pwquality module is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.2.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.2.4"
    Task = "Ensure pam_pwhistory module is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.2.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.1.1"
    Task = "Ensure password failed attempts lockout is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.1.1.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.1.2"
    Task = "Ensure password unlock time is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.1.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.1.3"
    Task = "Ensure password failed attempts lockout includes root account"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.1.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.2.1"
    Task = "Ensure password number of changed characters is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.2.1.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.2.2"
    Task = "Ensure minimum password length is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.2.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
# MISSING RULE: 5.3.3.2.3 - Ensure password complexity is configured
# This ones's manual
[AuditTest] @{
    Id = "5.3.3.2.4"
    Task = "Ensure password same consecutive characters is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.2.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.2.5"
    Task = "Ensure password maximum sequential characters is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.2.5.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.2.6"
    Task = "Ensure password dictionary check is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.2.6.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.2.7"
    Task = "Ensure password quality checking is enforced"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.2.7.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.2.8"
    Task = "Ensure password quality is enforced for the root user"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.2.8.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.3.1"
    Task = "Ensure password history remember is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.3.1.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.3.2"
    Task = "Ensure password history is enforced for the root user"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.3.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.3.3"
    Task = "Ensure pam_pwhistory includes use_authtok"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.3.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.4.1"
    Task = "Ensure pam_unix does not include nullok"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.4.1.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.4.2"
    Task = "Ensure pam_unix does not include remember"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.4.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.4.3"
    Task = "Ensure pam_unix includes a strong password hashing algorithm"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.4.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.4.4"
    Task = "Ensure pam_unix includes use_authtok"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.3.3.4.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.1.1"
    Task = "Ensure password expiration is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.4.1.1.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.1.2"
    Task = "Ensure minimum password age is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.4.1.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.1.3"
    Task = "Ensure password expiration warning days is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.4.1.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.1.4"
    Task = "Ensure strong password hashing algorithm is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.4.1.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.1.5"
    Task = "Ensure inactive password lock is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.4.1.5.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.1.6"
    Task = "Ensure all users last password change date is in the past"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.5.1.5.sh"
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
    Id = "5.4.2.1"
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

# [AuditTest] @{
#     Id = "5.5.3"
#     Task = "Ensure default group for the root account is GID 0"
#     Test = {
#         $test1 = grep "^root:" /etc/passwd | cut -f4 -d ':'
#         if($test1 -eq 0){
#             return $retCompliant
#         }
#         return $retNonCompliant
#     }
# }
# ^This rule got split in the three below?
# MISSING RULE: 5.4.2.2 - Ensure root is the only GID 0 account
# MISSING RULE: 5.4.2.3 - Ensure group root is the only GID 0 group
# MISSING RULE: 5.4.2.4 - Ensure root password is set
[AuditTest] @{
    Id = "5.4.2.5"
    Task = "Ensure root PATH Integrity"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.2.9.sh"
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
    Id = "5.4.2.6"
    Task = "Ensure root user umask is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.4.2.6.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.2.7"
    Task = "Ensure system accounts do not have a valid login shell"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.4.2.7.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{ # added: 5.5.2 Ensure system accounts are secured
    Id = "5.4.2.8"
    Task = "Ensure accounts without a valid login shell are locked"
    Test = {
        $test1 = awk -F: '$1!~/(root|sync|shutdown|halt|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!~/((\/usr)?\/sbin\/nologin)/ && $7!~/(\/bin)?\/false/ {print}' /etc/passwd
        $test2 = awk -F: '($1!~/(root|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}'/etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!~/LK?/) {print $1}'
        if($test1 -eq $null -and $test2 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "5.4.3.1"
    Task = "Ensure nologin is not listed in /etc/shells"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.4.3.1.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.3.2"
    Task = "Ensure default user shell timeout is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.4.3.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.3.3"
    Task = "Ensure default user umask is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/5.4.3.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
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
    Task = "Ensure cryptographic mechanisms are used to protect the integrity of audit tools"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.1.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
# MISSING RULE: 6.2.1.1.1 - Ensure journald service is enabled and active
# 4.2.1.2 Ensure journald service is enabled
# MISSING RULE: 6.2.1.1.2 - Ensure journald log file access is configured
# ^this one's manual
# MISSING RULE: 6.2.1.1.3 - Ensure journald log file rotation is configured
# ^this one's manual
[AuditTest] @{
    Id = "6.2.1.1.4"
    Task = "Ensure journald ForwardToSyslog is disabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.2.1.1.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.2.1.1.5"
    Task = "Ensure journald Storage is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.2.1.1.5.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.2.1.1.6"
    Task = "Ensure journald Compress is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.2.1.1.6.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.2.1.2.1"
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

# MISSING RULE: 6.2.1.2.2 - Ensure systemd-journal-remote authentication is configured
# # ^this one's manual; 4.2.1.1.2 Ensure systemd-journal-remote is configured 
# MISSING RULE: 6.2.1.2.3 - Ensure systemd-journal-upload is enabled and active
# the rule was manual: 4.2.1.1.3 Ensure systemd-journal-remote is enabled
# but isn't anymore!
[AuditTest] @{
    Id = "6.2.1.2.4"
    Task = "Ensure systemd-journal-remote service is not in use"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.2.1.2.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{ # added: 4.2.3 Ensure permissions on all logfiles are configured
    Id = "6.2.2.1"
    Task = "Ensure access to all logfiles has been configured"
    Test = {
        $fileListAll = find /var/log -type f -ls
        $fileListFiltered = find /var/log -type f -ls | grep "\-....\-\-\-\-\-"
        if($fileListAll.Count -eq $fileListFiltered.Count){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # added: 4.1.1.1 Ensure auditd is installed
    Id = "6.3.1.1"
    Task = "Ensure auditd packages are installed"
    Test = {
        $test1 = dpkg -l | grep -o auditd
        $test2 = dpkg -l | grep -o audispd-plugins
        if($test1 -ne $null -and $test2 -ne $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # added: 4.1.1.2 Ensure auditd service is enabled
    Id = "6.3.1.2"
    Task = "Ensure auditd service is enabled and active"
    Test = {
        $test1 = systemctl is-enabled auditd
        if($test1 -match "enabled"){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "6.3.1.3"
    Task = "Ensure auditing for processes that start prior to auditd is enabled"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.1.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.1.4"
    Task = "Ensure audit_backlog_limit is sufficient"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.1.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.2.1"
    Task = "Ensure audit log storage size is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.2.1.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.2.2"
    Task = "Ensure audit logs are not automatically deleted"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.2.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
} 
[AuditTest] @{ # added: 4.1.2.3 Ensure system is disabled when audit logs are full
    Id = "6.3.2.3"
    Task = "Ensure system is disabled when audit logs are full"
    Test = {
        $test1 = grep space_left_action /etc/audit/auditd.conf
        $test2 = grep action_mail_acct /etc/audit/auditd.conf
        $test3 = grep admin_space_left_action /etc/audit/auditd.conf
        if($test1 -match "space_left_action = email" -and $test2 -match "action_mail_acct = root" -and $test3 -match "admin_space_left_action = halt"){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
# MISSING RULE: 6.3.2.4 - Ensure system warns when audit logs are low on space
[AuditTest] @{
    Id = "6.3.3.1"
    Task = "Ensure changes to system administration scope is collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.1.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.2"
    Task = "Ensure actions as another user are always logged"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.3"
    Task = "Ensure events that modify the sudo log file are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.4"
    Task = "Ensure events that modify date and time information are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.5"
    Task = "Ensure events that modify the system's network environment are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.5.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.6"
    Task = "Ensure use of privileged commands are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.6.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.7"
    Task = "Ensure unsuccessful file access attempts are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.7.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.8"
    Task = "Ensure events that modify user/group information are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.8.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.9"
    Task = "Ensure discretionary access control permission modification events are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.9.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.10"
    Task = "Ensure successful file system mounts are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.10.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.11"
    Task = "Ensure session initiation information is collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path1 = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/4.1.3.11_1.sh"
        $result11 = bash $path1 | grep "\-w /var/run/utmp -p wa -k session"
        $result12 = bash $path1 | grep "\-w /var/log/wtmp -p wa -k session"
        $result13 = bash $path1 | grep "\-w /var/log/btmp -p wa -k session"
        $path2 = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/4.1.3.11_2.sh"
        $result21 = bash $path2 | grep "\-w /var/run/utmp -p wa -k session"
        $result22 = bash $path2 | grep "\-w /var/log/wtmp -p wa -k session"
        $result23 = bash $path2 | grep "\-w /var/log/btmp -p wa -k session"
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
    Id = "6.3.3.12"
    Task = "Ensure login and logout events are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.12.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.13"
    Task = "Ensure file deletion events by users are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.13.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.14"
    Task = "Ensure events that modify the system's Mandatory Access Controls are collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.14.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.15"
    Task = "Ensure successful and unsuccessful attempts to use the chcon command are recorded"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.15.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.16"
    Task = "Ensure successful and unsuccessful attempts to use the setfacl command are recorded"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.16.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.17"
    Task = "Ensure successful and unsuccessful attempts to use the chacl command are recorded"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.17.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.18"
    Task = "Ensure successful and unsuccessful attempts to use the usermod command are recorded"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.18.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.19"
    Task = "Ensure kernel module loading unloading and modification is collected"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.3.19.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.20"
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
    Id = "6.3.3.21"
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
    Id = "6.3.4.1"
    Task = "Ensure audit log files mode is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.4.1.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.2"
    Task = "Ensure audit log files owner is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.4.2.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.3"
    Task = "Ensure audit log files group owner is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.4.3.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.4"
    Task = "Ensure the audit log file directory mode is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.4.4.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.5"
    Task = "Ensure audit configuration files mode is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.4.5.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.6"
    Task = "Ensure audit configuration files owner is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.4.6.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.7"
    Task = "Ensure audit configuration files group owner is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.4.7.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.8"
    Task = "Ensure audit tools mode is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.4.8.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.9"
    Task = "Ensure audit tools owner is configured"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $script = Join-Path -Path $parentPath -ChildPath "Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.3.4.9.sh"
        $result = bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
# MISSING RULE: 6.3.4.10 - Ensure audit tools group owner is configured
# this one is 4.1.4.8 Ensure audit tools are 755 or more restrictive
# got all 4.1.4.X ensured by 4.1.4 Ensure events that modify user/group information are collected?
[AuditTest] @{
    Id = "7.1.1"
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
    Id = "7.1.2"
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
    Id = "7.1.3"
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
    Id = "7.1.4"
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
    Id = "7.1.5"
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
    Id = "7.1.6"
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
    Id = "7.1.7"
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
    Id = "7.1.8"
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

# MISSING RULE: 7.1.9 - Ensure permissions on /etc/shells are configured
# MISSING RULE: 7.1.10 - Ensure permissions on /etc/security/opasswd are configured
[AuditTest] @{ # added diff: 6.1.10 Ensure no world writable files exist
    Id = "7.1.11"
    Task = "Ensure world writable files and directories are secured"
    Test = {
        #$partitions = mapfile -t partitions < (sudo fdisk -l | grep -o '/dev/[^ ]*')
        $test1 = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002
        if($test1 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{ # adde diff: 6.1.11 Ensure no unowned files or directories exist
    Id = "7.1.12"
    Task = "Ensure no files or directories without an owner and a group exist"
    Test = {
        try{
            $test1 = df --local -P | awk "{if (NR -ne 1) { print `$6 }}" | xargs -I '{}' find '{}' -xdev -nouser
            if($test1 -eq $null){
                return $retCompliant
            }
            return $retNonCompliant
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }  
        }
    }
} 
[AuditTest] @{ # added diff: 6.1.13 Audit SUID executables
    Id = "7.1.13"
    Task = "Ensure SUID and SGID files are reviewed"
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
    Id = "7.2.1"
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
    Id = "7.2.2"
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
    Id = "7.2.3"
    Task = "Ensure all groups in /etc/passwd exist in /etc/group"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.2.3.sh"
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
    Id = "7.2.4"
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
    Id = "7.2.5"
    Task = "Ensure no duplicate UIDs exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.2.5.sh"
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
    Id = "7.2.6"
    Task = "Ensure no duplicate GIDs exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.2.6.sh"
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
    Id = "7.2.7"
    Task = "Ensure no duplicate user names exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.2.7.sh"
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
    Id = "7.2.8"
    Task = "Ensure no duplicate group names exist"
    Test = {
        $parentPath = Split-Path -Parent -Path $PSScriptRoot
        $path = $parentPath+"/Helpers/ShellScripts/Ubuntu22.04-2.0.0/6.2.8.sh"
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

# MISSING RULE: 7.2.9 - Ensure local interactive user home directories are configured
# 6.2.11-13?
# MISSING RULE: 7.2.10 - Ensure local interactive user dot files access is configured
# could be 6.2.17 Ensure local interactive user dot files are not group or world writable
# but is not in 1.1.0?

