$parentPath = Split-Path -Parent -Path $PSScriptRoot
$rcTrue = "True"
$rcCompliant = "Compliant"
$retCompliant = @{
    Message = $rcCompliant
    Status = $rcTrue
}
$rcFalse = "False"
$rcNonCompliant = "Non-Compliant"
$retNonCompliant = @{
    Message = $rcNonCompliant
    Status = $rcFalse
}

[AuditTest] @{
    Id = "1.1.1.1"
    Task = "Ensure mounting of squashfs filesystems is disabled"
    Test = {
        $result1 = modprobe -n -v squashfs | grep -E '(suqashfs|install)'
        $result2 = lsmod | grep squashfs
        if ($result1 -match "install /bin/true" && $result2 -eq $null) {
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
        $result1 = modprobe -n -v udf | grep -E '(udf|install)'
        $result2 = lsmod | grep udf
        if ($result1 -match "install /bin/true" && $result2 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.1.3"
    Task = "Ensure mounting of FAT filesystems is disabled"
    Test = {
        $result1 = modprobe -n -v fat | grep -E '(fat|install)'
        $result2 = lsmod | grep udf
        $result3 = modprobe -n -v vfat | grep -E '(vfat|install)'
        $result4 = lsmod | grep udf
        $result5 = modprobe -n -v msdos | grep -E '(msdos|install)'
        $result6 = lsmod | grep udf
        if ($result1 -match "install /bin/true" && $result2 -eq $null && $result3 -match "install /bin/true" && $result4 -eq $null && $result5 -match "install /bin/true" && $result6 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.2"
    Task = "Ensure /tmp is configured"
    Test = {
        $result1 = mount | grep -E '\s/tmp\s'
        if ($result1 -match "/tmp") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.3"
    Task = "Ensure noexec option set on /tmp partition"
    Test = {
        $result1 = mount | grep -E '\s/tmp\s' | grep -v noexec
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.4"
    Task = "Ensure nodev option set on /tmp partition"
    Test = {
        $result1 = mount | grep -E '\s/tmp\s' | grep -v nodev
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.5"
    Task = "Ensure nosuid option set on /tmp partition"
    Test = {
        $result1 = mount | grep -E '\s/tmp\s' | grep -v nosuid
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.6"
    Task = "Ensure /dev/shm is configured"
    Test = {
        $result1 = mount | grep -E '\s/dev/shm\s'
        $result2 = grep -E '\s/dev/shm\s' /etc/fstab
        if ($result1 -ne $null && $result2 -ne $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.7"
    Task = "Ensure noexec option set on /dev/shm partition"
    Test = {
        $result1 = mount | grep -E '\s/dev/shm\s' | grep -v noexec
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.8"
    Task = "Ensure nodev option set on /dev/shm partition"
    Test = {
        $result1 = mount | grep -E '\s/dev/shm\s' | grep -v nodev
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.9"
    Task = "Ensure nosuid option set on /dev/shm partition"
    Test = {
        $result1 = mount | grep -E '\s/dev/shm\s' | grep -v nosuid
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.10"
    Task = "Ensure separate partition exists for /var"
    Test = {
        $result1 = mount | grep -E '\s/var\s'
        if ($result1 -ne $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.11"
    Task = "Ensure separate partition exists for /var/tmp"
    Test = {
        $result1 = mount | grep /var/tmp
        if ($result1 -ne $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.12"
    Task = "Ensure noexec option set on /var/tmp partition"
    Test = {
        $result1 = mount | grep -E '\s/var/tmp\s' | grep -v noexec
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.13"
    Task = "Ensure nodev option set on /var/tmp partition"
    Test = {
        $result1 = mount | grep -E '\s/var/tmp\s' | grep -v nodev
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.14"
    Task = "Ensure nosuid option set on /var/tmp partition"
    Test = {
        $result1 = mount | grep -E '\s/var/tmp\s' | grep -v nosuid
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.15"
    Task = "Ensure separate partition exists for /var/log"
    Test = {
        $result1 = mount | grep -E '\s/var/log\s'
        if ($result1 -ne $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.16"
    Task = "Ensure separate partition exists for /var/log/audit"
    Test = {
        $result1 = mount | grep /var/log/audit
        if ($result1 -ne $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.17"
    Task = "Ensure separate partition exists for /home"
    Test = {
        $result1 = mount | grep /home
        if ($result1 -ne $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.18"
    Task = "Ensure nodev option set on /home partition"
    Test = {
        $result1 = mount | grep -E '\s/home\s' | grep -v nodev
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.19"
    Task = "Ensure noexec option set on removable media partitions"
    Test = {
        $path = $parentPath+"/Helpers/ShellScripts/CIS-SUSE15-1.1.19_through_1.1.21.sh"
        $result = bash $path
        foreach($line in $result){
            if(!($line -match "noexec")){
                return $retNonCompliant
            }
        }
        return $retCompliant
    }
}

[AuditTest] @{
    Id = "1.1.20"
    Task = "Ensure nodev option set on removable media partitions"
    Test = {
        $path = $parentPath+"/Helpers/ShellScripts/CIS-SUSE15-1.1.19_through_1.1.21.sh"
        $result = bash $path
        foreach($line in $result){
            if(!($line -match "nodev")){
                return $retNonCompliant
            }
        }
        return $retCompliant
    }
}

[AuditTest] @{
    Id = "1.1.21"
    Task = "Ensure nosuid option set on removable media partitions"
    Test = {
        $path = $parentPath+"/Helpers/ShellScripts/CIS-SUSE15-1.1.19_through_1.1.21.sh"
        $result = bash $path
        foreach($line in $result){
            if(!($line -match "nosuid")){
                return $retNonCompliant
            }
        }
        return $retCompliant
    }
}

[AuditTest] @{
    Id = "1.1.22"
    Task = "Ensure sticky bit is set on all world-writable directories"
    Test = {
        $result = df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
        if ($result -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.23"
    Task = "Disable Automounting"
    Test = {
        $result = systemctl is-enabled autofs
        if ($result -match "enabled") {
            return $retNonCompliant
        } else {
            return $retCompliant
        }
    }
}

# 1.2.1 TODO - brauche suse15 zur implementierung
# 1.2.2 TODO - s.o.

[AuditTest] @{
    Id = "1.2.3"
    Task = "Ensure gpgcheck is globally activated"
    Test = {
        $result = grep ^\s*gpgcheck /etc/zypp/zypp.conf
        if ($result -match "gpgcheck=1") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.3.1"
    Task = "Ensure sudo is installed"
    Test = {
        $result = rpm -q sudo
        if ($result -match "sudo-") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.3.2"
    Task = "Ensure sudo is installed"
    Test = {
        $result = grep -Ei '^\s*Defaults\s+([^#]\S+,\s*)?use_pty\b' /etc/sudoers /etc/sudoers.d/*
        if ($result -match "Defaults user_pty") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.3.3"
    Task = "Ensure sudo log file exists"
    Test = {
        $result = grep -Ei '^\s*Defaults\s+([^#;]+,\s*)?logfile\s*=\s*(")?[^#;]+(")?' /etc/sudoers /etc/sudoers.d/*
        if ($result -match "Defaults logfile=") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.4.1"
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
    Id = "1.4.2"
    Task = "Ensure filesystem integrity is regularly checked"
    Test = {
        $result1 = crontab -u root -l | grep aide
        $result2 = grep -r aide /etc/cron.* /etc/crontab
        if ($result1 -ne $null || $result2 -ne $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.5.1"
    Task = "Ensure bootloader password is set"
    Test = {
        $result1 = grep "^\s*set superusers" /boot/grub2/grub.cfg
        $result2 = grep "^\s*password" /boot/grub2/grub.cfg
        if ($result1 -match "set superusers=" && $result2 -match "password_pbkdf2 ") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.5.2"
    Task = "Ensure permissions on bootloader config are configured"
    Test = {
        $result = stat /boot/grub2/grub.cfg | grep "Uid: "
        $result = $result | cut -d '(' -f 2
        $result = $result | cut -d '/' -f 1
        if($result -eq "0400" -or $result[1] -le 4){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.5.3"
    Task = "Ensure authentication required for single user mode"
    Test = {
        $result1 = grep /systemd-sulogin-shell /usr/lib/systemdm/system/rescue.service
        $result2 = grep /systemd-sulogin-shell /usr/lib/systemdm/system/rescue.service
        if($result1 -ne $null -and $result2 -ne $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.6.1"
    Task = "Ensure core dumps are restricted"
    Test = {
        $result1 = grep -E "^\s*\*\s+hard\s+core" /etc/security/limits.conf
        $result2 = sysctl fs.suid_dumpable
        $result3 = grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "hard core 0" -and $result2 -match "fs.suid_dumpable = 0" -and $result3 -match "fs.suid_dumpable = 0") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

# 1.6.2 implemented for journalctl only
[AuditTest] @{
    Id = "1.6.2"
    Task = "Ensure XD/NX support is enabled"
    Test = {
        $result1 = journalctl | grep 'protection: active'
        if($result1 -match "protection: active") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.6.3"
    Task = "Ensure address space layout randomization (ASLR) is enabled"
    Test = {
        $result1 = sysctl kernel.randomize_va_space
        $result2 = grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "kernel.randomize_va_space = 2" -and $result2 -match "kernel.randomize_va_space = 2") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.6.4"
    Task = "Ensure prelink is disabled"
    Test = {
        $result1 = rpm -q prelink
        if($result1 -match "package prelink is not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.7.1.1"
    Task = "Ensure AppArmor is installed"
    Test = {
        $result1 = rpm -q apparmor-docs apparmor-parser apparmor-profiles apparmor-utils libapparmor1
        if($result1 -ne $null -or $result2 -ne $null) {
            return $retNonCompliant
        } else {
            return $retCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.7.1.2"
    Task = "Ensure AppArmor is enabled in the bootloader configuration"
    Test = {
        $result1 = grep "^\s*linux" /boot/grub2/grub.cfg | grep -v "apparmor=1"
        $result2 = grep "^\s*linux" /boot/grub2/grub.cfg | grep -v "security=apparmor"
        if($result1 -match "apparmor-docs-" -and $result1 -match "apparmor-parser-" -and $result1 -match "apparmor-profiles-" -and $result1 -match "apparmor-utils-" -and $result1 -match "libapparmor1-") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.7.1.3"
    Task = "Ensure all AppArmor Profiles are in enforce or complain mode"
    Test = {
        $profileMode1 = apparmor_status | grep profiles | sed '1!d' | cut -d ' ' -f 1
        $profileMode2 = apparmor_status | grep profiles | sed '2!d' | cut -d ' ' -f 1
        $profileMode3 = apparmor_status | grep profiles | sed '3!d' | cut -d ' ' -f 1
        $result = expr $profileMode3 + $profileMode2
        $unconfinedProcesses = apparmor_status | grep processes | sed '4!d' | cut -d ' ' -f 1
        if ($result -eq $profileMode1 -and $unconfinedProcesses -eq 0) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.7.1.4"
    Task = "Ensure all AppArmor Profiles are enforcing"
    Test = {
        $profileMode1 = apparmor_status | grep profiles | sed '1!d' | cut -d ' ' -f 1
        $profileMode2 = apparmor_status | grep profiles | sed '2!d' | cut -d ' ' -f 1
        
        $unconfinedProcesses = apparmor_status | grep processes | sed '4!d' | cut -d ' ' -f 1

        if($profileMode1 -eq $profileMode2 -and $unconfinedProcesses -eq 0){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.1.1"
    Task = "Ensure message of the day is configured properly"
    Test = {
        $result = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/motd
        if($result -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.1.2"
    Task = "Ensure local login warning is configured peoperly"
    Test = {
        $result = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue
        if($result -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.1.3"
    Task = "Ensure remote login warning banner is configured properly"
    Test = {
        $result = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net
        if($result -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.1.4"
    Task = "Ensure permissions on /etc/motd are configured"
    Test = {
        $result = stat -L /etc/motd | grep "Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)"
        if($result -eq $null -or $result -match "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.1.5"
    Task = "Ensure permissions on /etc/issue are configured"
    Test = {
        $result = stat -L /etc/issue | grep "Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)"
        if($result -ne $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.1.6"
    Task = "Ensure permissions on /etc/issue.net are configured"
    Test = {
        $result = stat -L /etc/issue.net | grep "Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)"
        if($result -ne $null){
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
        $output = zypper list-updates
        $output = $?
        if($output -match "True"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.10"
    Task = "Ensure GDM is removed or login is configured"
    Test = {
        $result = rpm -q gdm
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}