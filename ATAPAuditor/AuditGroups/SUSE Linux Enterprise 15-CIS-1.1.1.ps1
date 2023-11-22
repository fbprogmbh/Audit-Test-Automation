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
        $result1 = modprobe -n -v squashfs | grep -E '(suqashfs|install)'
        $result2 = lsmod | grep squashfs
        if ($result1 -match "install /bin/true" -and $result2 -eq $null) {
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
        if ($result1 -match "install /bin/true" -and $result2 -eq $null) {
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
        if ($result1 -match "install /bin/true" -and $result2 -eq $null -and $result3 -match "install /bin/true" -and $result4 -eq $null -and $result5 -match "install /bin/true" -and $result6 -eq $null) {
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
        if ($result1 -ne $null -and $result2 -ne $null) {
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

[AuditTest] @{
    Id = "1.2.1"
    Task = "Ensure GPG keys are configured"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "1.2.2"
    Task = "Ensure package manager repositories are configured"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

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
    Task = "Ensure sudo commands use pty"
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
        if ($result1 -ne $null -or $result2 -ne $null) {
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
        if ($result1 -match "set superusers=" -and $result2 -match "password_pbkdf2 ") {
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

### Chapter 2 - Services

[AuditTest] @{
    Id = "2.1.1"
    Task = "Ensure xinetd is not installed"
    Test = {
        $result = rpm -q xinetd
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.1.1"
    Task = "Ensure time synchronization is in use"
    Test = {
        $result = rpm -q chrony
        if($result -match "chrony-"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.1.2"
    Task = "Ensure systemd-timesyncd is configured"
    Test = {
        $result = systemctl is-enabled systemd-timesyncd.service
        if($result -match "enabled"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.1.3"
    Task = "Ensure chrony is configured"
    Test = {
        $result1 = grep -E "^(server|pool)" /etc/chrony.conf
        $result2 = grep ^OPTIONS /etc/sysconfig/chronyd
        if($result1 -match "server " -and $result2 -match "-u chrony") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.2"
    Task = "Ensure X11 Server components are not installed"
    Test = {
        $result = rpm -qa xorg-x11-server*
        if($result -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.4"
    Task = "Ensure CUPS is not installed"
    Test = {
        $result = rpm -q cups
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.5"
    Task = "Ensure DHCP Server is not installed"
    Test = {
        $result = rpm -q dhcp
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.6"
    Task = "Ensure LDAP server is not installed"
    Test = {
        $result = rpm -q openldap2
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.7"
    Task = "Ensure nfs-utils is not installed or the nfs-server service is masked"
    Test = {
        $result1 = rpm -q nfs-utils
        $result2 = rpm -q nfs-kernel-server
        if($result1 -match "not installed" -and $result2 -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.8"
    Task = "Ensure rpcbind is not installed or the rpcbind services are masked"
    Test = {
        $result = rpm -q rpcbind
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.9"
    Task = "Ensure DNS Server is not installed"
    Test = {
        $result = rpm -q bind
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.10"
    Task = "Ensure FTP Server is not installed"
    Test = {
        $result = rpm -q vsftpd
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.11"
    Task = "Ensure HTTP Server is not installed"
    Test = {
        $result = rpm -q apache2
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.12"
    Task = "Ensure HTTP Server is not installed"
    Test = {
        $result = rpm -q dovecot
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.13"
    Task = "Ensure Samba is not installed"
    Test = {
        $result = rpm -q samba
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.14"
    Task = "Ensure HTTP Proxy Server is not installed"
    Test = {
        $result = rpm -q squid
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.15"
    Task = "Ensure net-snmp is not installed"
    Test = {
        $result = rpm -q net-snmp
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.16"
    Task = "Ensure mail transfer agent is configured for local-only mode"
    Test = {
        $result = ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|\[?::1\]?):25\s'
        if($result -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.17"
    Task = "Ensure rsync is not installed or the rsyncd service is masked"
    Test = {
        $result = rpm -q rsync
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.18"
    Task = "Ensure NIS server is not installed"
    Test = {
        $result = rpm -q ypserv
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.19"
    Task = "Ensure telnet-server is not installed"
    Test = {
        $result = rpm -q telnet-server
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.3.1"
    Task = "Ensure NIS Client is not installed"
    Test = {
        $result = rpm -q ypbind
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.3.2"
    Task = "Ensure rsh client is not installed"
    Test = {
        $result = rpm -q rsh
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.3.3"
    Task = "Ensure talk client is not installed"
    Test = {
        $result = rpm -q talk
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.3.4"
    Task = "Ensure telnet client is not installed"
    Test = {
        $result = rpm -q telnet
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.3.5"
    Task = "Ensure LDAP client is not installed"
    Test = {
        $result = rpm -q openldap2-clients
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.4"
    Task = "Ensure nonessential services are removed or masked"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

## Chapter 3 - Network Configuration

# sysctl wird ignoriert
[AuditTest] @{
    Id = "3.1.1"
    Task = "Disable IPv6"
    Test = {
        if ($IPv6Status -match "disable") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.1.2"
    Task = "Ensure wireless interfaces are disabled"
    Test = {
        $result = ip link show up
        if($result -eq $null){
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
        if ($IPv6Status -match "disable") {
            $result1 = sysctl net.ipv4.ip_forward
            $result2 = grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
            if($result1 -match "net.ipv4.ip_forward = 0" -and $result2 -eq $null){
                return $retCompliant
            } else {
                return $retNonCompliant
            }
        } else {
            $result1 = sysctl net.ipv4.ip_forward
            $result2 = grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
            $result3 = sysctl net.ipv6.conf.all.forwarding
            $result4 = grep -E -s "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
            if($result1 -match "net.ipv4.ip_forward = 0" -and $result2 -eq $null -and $result3 -match "net.ipv6.conf.all.forwarding = 0" -and $result4 -eq $null){
                return $retCompliant
            } else {
                return $retNonCompliant
            }
        }
        
    }
}

[AuditTest] @{
    Id = "3.2.2"
    Task = "Ensure packet redirect sending is disabled"
    Test = {
        $result1 = sysctl net.ipv4.conf.all.send_redirects
        $result2 = sysctl net.ipv4.conf.default.send_redirects
        $result3 = grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        $result4 = grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.conf.all.send_redirects = 0" -and $result2 -match "net.ipv4.conf.default.send_redirects = 0" -and $result3 -match "net.ipv4.conf.all.send_redirects = 0" -and $result4 -match "net.ipv4.conf.default.send_redirects= 0"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.3.1"
    Task = "Ensure source routed packets are not accepted"
    Test = {
        if ($IPv6Status -match "disable") {
            $result1 = sysctl net.ipv4.conf.all.accept_source_route
            $result2 = sysctl net.ipv4.conf.default.accept_source_route
            $result3 = grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
            $result4 = grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
            if($result1 -match "net.ipv4.conf.all.accept_source_route = 0" -and $result2 -match "net.ipv4.conf.default.accept_source_route = 0" -and $result3 -match "net.ipv4.conf.all.accept_source_route= 0" -and $result4 -match "net.ipv4.conf.default.accept_source_route= 0"){
                return $retCompliant
            } else {
                return $retNonCompliant
            }
        } else {
            $result1 = sysctl net.ipv4.conf.all.accept_source_route
            $result2 = sysctl net.ipv4.conf.default.accept_source_route
            $result3 = grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
            $result4 = grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
            $result5 = sysctl net.ipv6.conf.all.accept_source_route
            $result6 = sysctl net.ipv6.conf.default.accept_source_route
            $result7 = grep "net\.ipv6\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
            $result8 = grep "net\.ipv6\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
            if($result1 -match "net.ipv4.conf.all.accept_source_route = 0" -and $result2 -match "net.ipv4.conf.default.accept_source_route = 0" -and $result3 -match "net.ipv4.conf.all.accept_source_route= 0" -and $result4 -match "net.ipv4.conf.default.accept_source_route= 0" -and $result5 -match "net.ipv6.conf.all.accept_source_route = 0" -and $result6 -match "net.ipv6.conf.default.accept_source_route = 0" -and $result7 -match "net.ipv4.conf.all.accept_source_route= 0" -and $result8 -match "net.ipv6.conf.default.accept_source_route= 0"){
                return $retCompliant
            } else {
                return $retNonCompliant
            }
        }
    }
}

[AuditTest] @{
    Id = "3.3.2"
    Task = "Ensure ICMP redirects are not accepted"
    Test = {
        $result1 = sysctl net.ipv4.conf.all.accept_redirects
        $result2 = sysctl net.ipv4.conf.default.accept_redirects
        $result3 = grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        $result4 = grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.conf.all.accept_redirects = 0" -and $result2 -match "net.ipv4.conf.default.accept_redirects = 0" -and $result3 -match "net.ipv4.conf.all.accept_redirects= 0" -and $result4 -match "net.ipv4.conf.default.accept_redirects= 0"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.3.3"
    Task = "Ensure secure ICMP redirects are not accepted"
    Test = {
        $result1 = sysctl net.ipv4.conf.all.secure_redirects
        $result2 = sysctl net.ipv4.conf.default.accept_redirects
        $result3 = grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        $result4 = grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.conf.all.accept_redirects = 0" -and $result2 -match "net.ipv4.conf.default.accept_redirects = 0" -and $result3 -match "net.ipv4.conf.all.accept_redirects= 0" -and $result4 -match "net.ipv4.conf.default.accept_redirects= 0"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.3.4"
    Task = "Ensure suspicious packets are logged"
    Test = {
        $result1 = sysctl net.ipv4.conf.all.log_martians
        $result2 = sysctl net.ipv4.conf.default.log_martians
        $result3 = grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*
        $result4 = grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.conf.all.log_martians = 1" -and $result2 -match "net.ipv4.conf.default.log_martians = 1" -and $result3 -match "net.ipv4.conf.all.log_martians = 1" -and $result4 -match "net.ipv4.conf.default.log_martians = 1"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.3.5"
    Task = "Ensure broadcast ICMP requests are ignored"
    Test = {
        $result1 = sysctl net.ipv4.icmp_echo_ignore_broadcasts
        $result2 = grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.icmp_echo_ignore_broadcasts = 1" -and $result2 -match "net.ipv4.icmp_echo_ignore_broadcasts = 1"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.3.6"
    Task = "Ensure bogus ICMP responses are ignored"
    Test = {
        $result1 = sysctl net.ipv4.icmp_ignore_bogus_error_responses
        $result2 = grep "net.ipv4.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.icmp_ignore_bogus_error_responses = 1" -and $result2 -match "net.ipv4.icmp_ignore_bogus_error_responses = 1"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.3.7"
    Task = "Ensure Reverse Path Filtering is enabled"
    Test = {
        $result1 = sysctl net.ipv4.conf.all.rp_filter
        $result2 = sysctl net.ipv4.conf.default.rp_filter
        $result3 = grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*
        $result4 = grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.conf.all.rp_filter = 1" -and $result2 -match "net.ipv4.conf.default.rp_filter = 1" -and $result3 -match "net.ipv4.conf.all.rp_filter = 1" -and $result4 -match "net.ipv4.conf.default.rp_filter = 1"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.3.8"
    Task = "Ensure TCP SYN Cookies is enabled"
    Test = {
        $result1 = sysctl net.ipv4.tcp_syncookies
        $result2 = grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.tcp_syncookies = 1" -and $result2 -match "net.ipv4.tcp_syncookies = 1"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.3.9"
    Task = "Ensure IPv6 router advertisements are not accepted"
    Test = {
        $result1 = sysctl net.ipv6.conf.all.accept_ra
        $result2 = sysctl net.ipv6.conf.default.accept_ra
        $result3 = grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*
        $result4 = grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv6.conf.all.accept_ra = 0" -and $result2 -match "net.ipv6.conf.default.accept_ra = 0" -and $result3 -match "net.ipv6.conf.all.accept_ra = 0" -and $result4 -match "net.ipv6.conf.default.accept_ra = 0"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.4.1"
    Task = "Ensure TCP SYN Cookies is enabled"
    Test = {
        $result1 = modprobe -n -v dccp
        $result2 = lsmod | grep dccp
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.4.2"
    Task = "Ensure SCTP is disabled"
    Test = {
        $result1 = modprobe -n -v sctp
        $result2 = lsmod | grep sctp
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.1.1"
    Task = "Ensure FirewallD is installed"
    Test = {
        $result = rpm -q firewalld iptables
        if($result -match "firewalld-" -and $result -match "iptables-"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.1.2"
    Task = "Ensure nftables is not installed or stopped and masked"
    Test = {
        $result1 = rpm -q nftables
        $result21 = systemctl status nftables | grep "Active: " | grep -v "active (running) "
        $result22 = systemctl is-enabled nftables
        if($result1 -match "not installed" -or ($result21 -eq $null -and $result22 -match "masked")){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.1.3"
    Task = "Ensure firewalld service is enabled and running"
    Test = {
        $result1 = systemctl is-enabled firewalld
        $result2 = firewall-cmd --state
        if($result1 -match "enabled" -and $result2 -match "running"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.1.4"
    Task = "Ensure default zone is set"
    Test = {
        $result = firewall-cmd --get-default-zone
        if($result -ne $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.1.5"
    Task = "Ensure network interfaces are assigned to appropriate zone"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "3.5.1.6"
    Task = "Ensure unnecessary services and ports are not accepted"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "3.5.2.1"
    Task = "Ensure nftables is installed"
    Test = {
        $result = rpm -q nftables
        if($result -match "nftables-"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.2"
    Task = "Ensure firewalld is not installed or stopped and masked"
    Test = {
        $result1 = rpm -q firewalld
        $result21 = systemctl status firewalld | grep "Active: " | grep -v "active (running) "
        $result22 = systemctl is-enabled firewalld
        if($result1 -match "not installed" -or ($result21 -eq $null -and $result22 -match "masked")){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.3"
    Task = "Ensure iptables are flushed"
    Test = {
        $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "3.5.2.4"
    Task = "Ensure a table exists"
    Test = {
        $result = nft list tables
        if($result -match "table inet filter") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.5"
    Task = "Ensure base chain exist"
    Test = {
        $result1 = nft list ruleset | grep 'hook input'
        $result2 = nft list ruleset | grep 'hook forward'
        $result3 = nft list ruleset | grep 'hook output'
        if($result1 -match "type filter hook input priority 0;" -and $result2 -match "type filter hook forward priority 0;" -and $result3 -match "type filter hook output priority 0;") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.6"
    Task = "Ensure loopback traffic is configured"
    Test = {
        $result1 = nft list ruleset | awk '/hook input/,/}/' | grep 'iif "lo" accept'
        $result2 = nft list ruleset | awk '/hook input/,/}/' | grep 'ip saddr'
        if($result1 -match "iif ""lo"" accept" -and $result2 -match "ip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.7"
    Task = "Ensure outbound and established connections are configured"
    Test = {
        $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "3.5.2.8"
    Task = "Ensure default deny firewall policy"
    Test = {
        $result1 = nft list ruleset | grep 'hook input'
        $result2 = nft list ruleset | grep 'hook forward'
        $result3 = nft list ruleset | grep 'hook output'
        if($result1 -match "type filter hook input priority 0; policy drop;" -and $result2 -match "type filter hook forward priority 0; policy drop;" -and $result3 -match "type filter hook output priority 0; policy drop;") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.9"
    Task = "Ensure nftables service is enabled"
    Test = {
        $result = systemctl is-enabled nftables
        if($result -match "enabled") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.10"
    Task = "Ensure nftables rules are permanent"
    Test = {
        $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "3.5.3.1.1"
    Task = "Ensure iptables package is installed"
    Test = {
        $result = rpm -q iptables
        if($result -match "iptables-") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.3.1.2"
    Task = "Ensure nftables is not installed"
    Test = {
        $result = rpm -q nftables
        if($result -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.3.1.3"
    Task = "Ensure firewalld is not installed or stopped and masked"
    Test = {
        $result1 = rpm -q firewalld
        $result21 = systemctl status firewalld | grep "Active: " | grep -v "active (running) "
        $result22 = systemctl is-enabled firewalld
        if($result1 -match "not installed" -or ($result21 -eq $null -and $result22 -match "masked")){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.3.2.1"
    Task = "Ensure default deny firewall policy"
    Test = {
        $output = iptables -L
        $test11 = $output -match "DROP" | grep "Chain INPUT (policy DROP)"
        $result11 = $?
        $test12 = $output -match "REJECT" | grep "Chain INPUT (policy REJECT)"
        $result12 = $?
        $test21 = $output -match "DROP" | grep "Chain FORWARD (policy DROP)"
        $result21 = $?
        $test22 = $output -match "REJECT" | grep "Chain FORWARD (policy REJECT)"
        $result22 = $?
        $test31 = $output -match "DROP" | grep "Chain OUTPUT (policy DROP)"
        $result31 = $?
        $test32 = $output -match "REJECT" | grep "Chain OUTPUT (policy REJECT)"
        $result32 = $?
        if(($result11 -match "True" -or $result12 -match "True") -and ($result21 -match "True" -or $result22 -match "True") -and ($result31 -match "True" -or $result32 -match "True")){
            return $retCompliant
        } else {
            return $retNonCompliant
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
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id = "3.5.3.2.3"
    Task = "Ensure outbound and established connections are configured"
    Test = {
        $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "3.5.3.2.4"
    Task = "Ensure firewall rules exist for all open ports"
    Test = {
        $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "3.5.3.3.1"
    Task = "Ensure IPv6 default deny firewall policy"
    Test = {
        if ($IPv6Status -match "disabled") {
            return $retCompliantIPv6Disabled
        }
        $output = ip6tables -L
        $test11 = $output -match "DROP" | grep "Chain INPUT (policy DROP)"
        $result11 = $?
        $test12 = $output -match "REJECT" | grep "Chain INPUT (policy REJECT)"
        $result12 = $?
        $test21 = $output -match "DROP" | grep "Chain FORWARD (policy DROP)"
        $result21 = $?
        $test22 = $output -match "REJECT" | grep "Chain FORWARD (policy REJECT)"
        $result22 = $?
        $test31 = $output -match "DROP" | grep "Chain OUTPUT (policy DROP)"
        $result31 = $?
        $test32 = $output -match "REJECT" | grep "Chain OUTPUT (policy REJECT)"
        $result32 = $?
        if(($result11 -match "True" -or $result12 -match "True") -and ($result21 -match "True" -or $result22 -match "True") -and ($result31 -match "True" -or $result32 -match "True")){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.3.3.2"
    Task = "Ensure IPv6 loopback traffic is configured"
    Test = {
        if ($IPv6Status -match "disabled") {
            return $retCompliantIPv6Disabled
        }
        $output1 = ip6tables -L INPUT -v -n
        $test1 = $output1 | grep "ACCEPT\s*all\s*lo\s**\s*::/0\s*::/0"
        $test2 = $output1 | grep "DROP\s*all\s**\s**\s*::1\s*::/0"
        $output2 = ip6tables -L OUTPUT -v -n
        $test3 = $output2 | grep "ACCEPT\s*all\s*lo\s**\s*::/0\s*::/0"
        if($test1 -ne $null -and $test2 -ne $null -and $test3 -ne $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.3.3.3"
    Task = "Ensure IPv6 outbound and established connections are configured"
    Test = {
        if ($IPv6Status -match "disabled") {
            return $retCompliantIPv6Disabled
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "3.5.3.3.4"
    Task = "Ensure IPv6 firewall rules exist for all open ports"
    Test = {
        if ($IPv6Status -match "disabled") {
            return $retCompliantIPv6Disabled
        }
        return $retNonCompliantManualReviewRequired
    }
}

## Chapter 4 Logging and Auditing

[AuditTest] @{
    Id = "4.1.1.1"
    Task = "Ensure auditd is installed"
    Test = {
        $test = rpm -q audit
        if($test -match "audit-"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.1.2"
    Task = "Ensure auditd service is enabled and running"
    Test = {
        $test1 = systemctl is-enabled auditd
        $test2 = systemctl status auditd | grep 'Active: active (running) '
        if($test1 -match "enabled" -and $test2 -ne $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.1.3"
    Task = "Ensure auditing for processes that start prior to auditd is enabled"
    Test = {
        $test = grep "^\s*linux" /boot/grub2/grub.cfg | grep -v "audit=1"
        if($test -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.2.1"
    Task = "Ensure audit log storage size is configured"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "4.1.2.2"
    Task = "Ensure audit logs are not automatically deleted"
    Test = {
        $test = grep max_log_file_action /etc/audit/auditd.conf
        if($test -match "max_log_file_action = keep_logs"){
            return $retCompliant
        } else {
            return $retNonCompliant
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
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.2.4"
    Task = "Ensure system is disabled when audit logs are full"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "4.1.3"
    Task = "Ensure system is disabled when audit logs are full"
    Test = {
        $test1 = grep time-change /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | grep time-change
        if($test1 -match "/etc/audit/rules.d/time_change.rules:-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" -and
        $test1 -match "/etc/audit/rules.d/time_change.rules:-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" -and
        $test1 -match "/etc/audit/rules.d/time_change.rules:-a always,exit -F arch=b64 -S clock_settime -k time-change" -and
        $test1 -match "/etc/audit/rules.d/time_change.rules:-a always,exit -F arch=b32 -S clock_settime -k time-change" -and
        $test1 -match "/etc/audit/rules.d/time_change.rules:-w /etc/localtime -p wa -k time-change" -and
        $test2 -match "-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change" -and
        $test2 -match "-a always,exit -F arch=b32 -S stime,settimeofday,adjtimex -F key=time-change" -and
        $test2 -match "-a always,exit -F arch=b64 -S clock_settime -F key=time-change" -and
        $test2 -match "-a always,exit -F arch=b32 -S clock_settime -F key=time-change" -and
        $test2 -match "-w /etc/localtime -p wa -k time-change"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.4"
    Task = "Ensure events that modify user/group information are collected"
    Test = {
        $test1 = grep identity /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | grep identity
        if($test1 -match "/etc/audit/rules.d/identity.rules:-w /etc/group -p wa -k identity" -and
        $test1 -match "/etc/audit/rules.d/identity.rules:-w /etc/passwd -p wa -k identity" -and
        $test1 -match "/etc/audit/rules.d/identity.rules:-w /etc/shadow -p wa -k identity" -and
        $test1 -match "/etc/audit/rules.d/identity.rules:-w /etc/security/opasswd -p wa -k identity" -and
        $test2 -match "-w /etc/group -p wa -k identity" -and
        $test2 -match "-w /etc/passwd -p wa -k identity" -and
        $test2 -match "-w /etc/shadow -p wa -k identity" -and
        $test2 -match "-w /etc/security/opasswd -p wa -k identity"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.5"
    Task = "Ensure events that modify the system's network environment are collected"
    Test = {
        $test1 = grep system-locale /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | grep system-locale
        if($test1 -match "/etc/audit/rules.d/system-locale.rules:-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" -and
        $test1 -match "/etc/audit/rules.d/system-locale.rules:-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" -and
        $test1 -match "/etc/audit/rules.d/system-locale.rules:-w /etc/issue -p wa -k system-locale" -and
        $test1 -match "/etc/audit/rules.d/system-locale.rules:-w /etc/issue.net -p wa -k system-locale" -and
        $test1 -match "/etc/audit/rules.d/system-locale.rules:-w /etc/hosts -p wa -k system-locale" -and
        $test1 -match "/etc/audit/rules.d/system-locale.rules:-w /etc/sysconfig/network -p wa -k system-locale" -and
        $test2 -match "-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale" -and
        $test2 -match "-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale" -and
        $test2 -match "-w /etc/issue -p wa -k system-locale" -and
        $test2 -match "-w /etc/issue.net -p wa -k system-locale" -and
        $test2 -match "-w /etc/hosts -p wa -k system-locale" -and
        $test2 -match "-w /etc/sysconfig/network -p wa -k system-locale"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.6"
    Task = "Ensure events that modify the system's Mandatory Access Controls are collected"
    Test = {
        $test1 = grep MAC-policy /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | grep MAC-policy
        if($test1 -match "/etc/audit/rules.d/MAC_policy.rules:-w /etc/selinux/ -p wa -k MAC-policy" -and $test1 -match "/etc/audit/rules.d/MAC_policy.rules:-w /usr/share/selinux/ -p wa -k MAC-policy" -and $test2 -match "-w /etc/selinux/ -p wa -k MAC-policy" -and $test2 -match "-w /usr/share/selinux/ -p wa -k MAC-policy"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.7"
    Task = "Ensure login and logout events are collected"
    Test = {
        $test1 = grep logins /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | grep logins
        if($test1 -match "/etc/audit/rules.d/logins.rules:-w /var/log/faillog -p wa -k logins" -and
        $test1 -match "/etc/audit/rules.d/logins.rules:-w /var/log/lastlog -p wa -k logins" -and
        $test1 -match "/etc/audit/rules.d/logins.rules:-w /var/log/tallylog -p wa -k logins" -and
        $test2 -match "-w /var/log/faillog -p wa -k logins" -and
        $test2 -match "-w /var/log/lastlog -p wa -k logins" -and
        $test2 -match "-w /var/log/tallylog -p wa -k logins"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.8"
    Task = "Ensure session initiation information is collected"
    Test = {
        $test1 = grep -E '(session|logins)' /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | grep -E '(session|logins)'
        if($test1 -match "/etc/audit/rules.d/session.rules:-w /var/run/utmp -p wa -k session" -and
        $test1 -match "/etc/audit/rules.d/session.rules:-w /var/log/wtmp -p wa -k logins" -and
        $test1 -match "/etc/audit/rules.d/session.rules:-w /var/log/btmp -p wa -k logins" -and
        $test2 -match "-w /var/run/utmp -p wa -k session" -and
        $test2 -match "-w /var/log/wtmp -p wa -k logins" -and
        $test2 -match "-w /var/log/btmp -p wa -k logins"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.9"
    Task = "Ensure discretionary access control permission modification events are collected"
    Test = {
        $test1 = grep perm_mod /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | grep perm_mod
        if($test1 -match "/etc/audit/rules.d/perm_mod.rules:-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" -and
        $test1 -match "/etc/audit/rules.d/perm_mod.rules:-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" -and
        $test1 -match "/etc/audit/rules.d/perm_mod.rules:-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" -and
        $test1 -match "/etc/audit/rules.d/perm_mod.rules:-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" -and
        $test1 -match "/etc/audit/rules.d/perm_mod.rules:-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" -and
        $test1 -match "/etc/audit/rules.d/perm_mod.rules:-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" -and
        $test2 -match "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod" -and
        $test2 -match "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod" -and
        $test2 -match "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod" -and
        $test2 -match "-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod" -and
        $test2 -match "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod" -and
        $test2 -match "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.10"
    Task = "Ensure discretionary access control permission modification events are collected"
    Test = {
        $test1 = grep access /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | grep access
        if($test1 -match "/etc/audit/rules.d/access.rules:-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" -and
        $test1 -match "/etc/audit/rules.d/access.rules:-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" -and
        $test1 -match "/etc/audit/rules.d/access.rules:-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" -and
        $test1 -match "/etc/audit/rules.d/access.rules:-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" -and
        $test2 -match "/etc/audit/rules.d/access.rules:-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" -and
        $test2 -match "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access" -and
        $test2 -match "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access" -and
        $test2 -match "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.11"
    Task = "Ensure use of privileged commands is collected"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "4.1.12"
    Task = "Ensure successful file system mounts are collected"
    Test = {
        $test1 = grep mounts /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | grep mounts
        if($test1 -match "/etc/audit/rules.d/mounts.rules:-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" -and
        $test1 -match "/etc/audit/rules.d/mounts.rules:-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" -and
        $test2 -match "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts" -and
        $test2 -match "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.13"
    Task = "Ensure file deletion events by users are collected"
    Test = {
        $test1 = grep delete /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | grep delete
        if($test1 -match "/etc/audit/rules.d/deletion.rules:-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" -and
        $test1 -match "/etc/audit/rules.d/deletion.rules:-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" -and
        $test2 -match "-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete" -and
        $test2 -match "-a always,exit -F arch=b32 -S unlink,rename,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.14"
    Task = "Ensure changes to system administration scope (sudoers) is collected"
    Test = {
        $test1 = grep scope /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | grep scope
        if($test1 -match "/etc/audit/rules.d/scope.rules:-w /etc/sudoers -p wa -k scope" -and
        $test1 -match "/etc/audit/rules.d/scope.rules:-w /etc/sudoers.d/ -p wa -k scope" -and
        $test2 -match "-w /etc/sudoers -p wa -k scope" -and
        $test2 -match "-w /etc/sudoers.d -p wa -k scope"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.15"
    Task = "Ensure system administrator actions (sudolog) are collected"
    Test = {
        $test1 = grep -E "^\s*-w\s+$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//')\s+-p\s+wa\s+-k\s+actions" /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | grep actions
        $test3 = echo "-w $(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//') -p wa -k actions"
        if($test1 -match $test3 -and $test2 -match $test3){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.16"
    Task = "Ensure kernel module loading and unloading is collected"
    Test = {
        $test1 = grep modules /etc/audit/rules.d/*.rules
        $test2 = auditctl -l | grep modules
        if($test1 -match "/etc/audit/rules.d/modules.rules:-w /sbin/insmod -p x -k modules" -and
        $test1 -match "/etc/audit/rules.d/modules.rules:-w /sbin/rmmod -p x -k modules" -and
        $test1 -match "/etc/audit/rules.d/modules.rules:-w /sbin/modprobe -p x -k modules" -and
        $test1 -match "/etc/audit/rules.d/modules.rules:-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" -and
        $test2 -match "-w /sbin/insmod -p x -k modules" -and
        $test2 -match "-w /sbin/rmmod -p x -k modules" -and
        $test2 -match "-w /sbin/modprobe -p x -k modules" -and
        $test2 -match "-a always,exit -F arch=b64 -S init_module,delete_module -F key=modules"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.1.17"
    Task = "Ensure the audit configuration is immutable"
    Test = {
        $test = grep "^\s*[^#]" /etc/audit/rules.d/*.rules | tail -1
        if($test -match "-e 2"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.2.1.1"
    Task = "Ensure rsyslog is installed"
    Test = {
        $test = rpm -q rsyslog
        if($test -match "rsyslog-"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.2.1.2"
    Task = "Ensure rsyslog Service is enabled and running"
    Test = {
        $test1 = systemctl is-enabled rsyslog
        $test2 = systemctl status rsyslog | grep 'active (running) '
        if($test1 -match "enabled" -and $test2 -ne $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.2.1.3"
    Task = "Ensure rsyslog default file permissions configured"
    Test = {
        $test = grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf
        if($test -match "FileCreateMode"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.2.1.4"
    Task = "Ensure logging is configured"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "4.2.1.5"
    Task = "Ensure rsyslog is configured to send logs to a remote log host"
    Test = {
        $test = grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf
        if($test -ne $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.2.1.6"
    Task = "Ensure remote rsyslog messages are only accepted on designated log hosts"
    Test = {
        $test1 = grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
        $test2 = grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
        if($test1 -match "ModLoad imtcp" -and $test2 -match "InputTCPServerRun 514"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.2.2.1"
    Task = "Ensure journald is configured to send logs to rsyslog"
    Test = {
        $test = grep -E ^\s*ForwardToSyslog /etc/systemd/journald.conf
        if($test -match "ForwardToSyslog=yes"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.2.2.2"
    Task = "Ensure journald is configured to compress large log files"
    Test = {
        $test = grep -E ^\s*Compress /etc/systemd/journald.conf
        if($test -match "Compress=yes"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.2.2.3"
    Task = "Ensure journald is configured to write logfiles to persistent disk"
    Test = {
        $test = grep -E ^\s*Storage /etc/systemd/journald.conf
        if($test -match "Storage=persistent"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.2.3"
    Task = "Ensure permissions on all logfiles are configured"
    Test = {
        $test = find /var/log -type f -perm /g+wx,o+rwx -exec ls -l {} \;
        if($test -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.2.4"
    Task = "Ensure logrotate is configured"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "5.1.1"
    Task = "Ensure cron daemon is enabled and running"
    Test = {
        $test1 = systemctl is-enabled cron
        $test2 = systemctl status cron | grep 'Active: active (running) '
        if($test1 -eq $null -and $test2 -match "active (running)"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.1.2"
    Task = "Ensure permissions on /etc/crontab are configured"
    Test = {
        $test = stat /etc/crontab
        if($test -match "Access:\s+(0600/-rw-------)\s+Uid:\s+(\s+0/\s+root)\s+Gid: (\s+0/\s+root)"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.1.3"
    Task = "Ensure permissions on /etc/cron.hourly are configured"
    Test = {
        $test = stat /etc/cron.hourly/
        if($test -match "Access:\s+(0700/drwx------)\s+Uid:\s+(\s+0/\s+root)\s+Gid: (\s+0/\s+root)"){
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
        $test = stat /etc/cron.daily
        if($test -match "Access:\s+(0700/drwx------)\s+Uid:\s+(\s+0/\s+root)\s+Gid: (\s+0/\s+root)"){
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
        $test = stat /etc/cron.weekly
        if($test -match "Access:\s+(0700/drwx------)\s+Uid:\s+(\s+0/\s+root)\s+Gid: (\s+0/\s+root)"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.1.6"
    Task = "Ensure permissions on /etc/cron.monthly are configured"
    Test = {
        $test = stat /etc/cron.weekly
        if($test -match "Access:\s+(0700/drwx------)\s+Uid:\s+(\s+0/\s+root)\s+Gid: (\s+0/\s+root)"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.1.7"
    Task = "Ensure permissions on /etc/cron.d are configured"
    Test = {
        $test = stat /etc/cron.weekly
        if($test -match "Access:\s+(0700/drwx------)\s+Uid:\s+(\s+0/\s+root)\s+Gid: (\s+0/\s+root)"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.1.8"
    Task = "Ensure cron is restricted to authorized users"
    Test = {
        $test = stat /etc/cron.deny
        if($test -match "cannot stat"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.1.9"
    Task = "Ensure cron is restricted to authorized users"
    Test = {
        $test1 = stat /etc/at.deny
        $test2 = stat /etc/at.allow
        if($test1 -match "cannot stat" -and $test2 -match "Access:\s+(0600/-rw-------)\s+Uid:\s+(\s+0/\s+root)\s+Gid: (\s+0/\s+root)"){
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
        $test1 = stat /etc/ssh/sshd_config
        if($test1 -match "Access:\s+(0600/-rw-------)\s+Uid:\s+(\s+0/\s+root)\s+Gid: (\s+0/\s+root)"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

### TODO ...
[AuditTest] @{
    Id = "5.2.2"
    Task = "Ensure permissions on SSH private host key files are configured"
    Test = {
        return $retCompliant
    }
}

### TODO...
[AuditTest] @{
    Id = "5.2.3"
    Task = "Ensure permissions on SSH public host key files are configured"
    Test = {
        return $retCompliant
    }
}

[AuditTest] @{
    Id = "5.2.4"
    Task = "Ensure SSH access is limited"
    Test = {
        $test = sshd -T | grep -E '^\s*(allow|deny)(users|groups)\s+\S+'
        if($test -match "allowusers " -or $test -match "allowgroups " -or $test -match "denyusers " -or $test -match "denygroups "){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.5"
    Task = "Ensure SSH LogLevel is appropriate"
    Test = {
        $test = sshd -T | grep loglevel
        if($test -match "loglevel\s+VERBOSE" -or $test -match "loglevel\s+INFO"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.6"
    Task = "Ensure SSH X11 forwarding is disabled"
    Test = {
        $test = sshd -T | grep -i x11forwarding
        if($test -match "x11forwarding no"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

### TODO
[AuditTest] @{
    Id = "5.2.7"
    Task = "Ensure SSH MaxAuthTries is set to 4 or less"
    Test = {
        $test = sshd -T | grep maxauthtries | grep maxauthtries | cut -d ' ' -f 2
        if($test -le 4){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.8"
    Task = "Ensure SSH IgnoreRhosts is enabled"
    Test = {
        $test = sshd -T | grep ignorerhosts
        if($test -match "ignorehosts yes"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.9"
    Task = "Ensure SSH HostbasedAuthentication is disabled"
    Test = {
        $test = sshd -T | grep hostbasedauthentication
        if($test -match "hostbasedauthentication no"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.10"
    Task = "Ensure SSH root login is disabled"
    Test = {
        $test = sshd -T | grep permitrootlogin
        if($test -match "permitrootlogin no"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.11"
    Task = "Ensure SSH PermitEmptyPasswords is disabled"
    Test = {
        $test = sshd -T | grep permitemptypasswords
        if($test -match "permitemptypasswords no"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.12"
    Task = "Ensure SSH PermitUserEnvironment is disabled"
    Test = {
        $test = sshd -T | grep permituserenvironment
        if($test -match "permituserenvironment no"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.13"
    Task = "Ensure only strong Ciphers are used"
    Test = {
        $test = sshd -T | grep ciphers
        if($test -match "3des-cbc" -or $test -match "aes128-cbc" -or $test -match "aes192-cbc" -or $test -match "aes256-cbc"){
            return $retNonCompliant
        } else {
            return $retCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.14"
    Task = "Ensure only strong MAC algorithms are used"
    Test = {
        $test = sshd -T | grep -i "MACs"
        if($test -match "hmac-md5" -or
        $test -match "hmac-md5-96" -or
        $test -match "hmac-ripemd160" -or
        $test -match "hmac-sha1" -or
        $test -match "hmac-sha1-96" -or
        $test -match "umac-64@openssh.com" -or
        $test -match "umac-128@openssh.com" -or
        $test -match "hmac-md5-etm@openssh.com" -or
        $test -match "hmac-md5-96-etm@openssh.com" -or
        $test -match "hmac-ripemd160-etm@openssh.com" -or
        $test -match "hmac-sha1-etm@openssh.com" -or
        $test -match "hmac-sha1-96-etm@openssh.com" -or
        $test -match "umac-64-etm@openssh.com" -or
        $test -match "umac-128-etm@openssh.com"){
            return $retNonCompliant
        } else {
            return $retCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.15"
    Task = "Ensure only strong Key Exchange algorithms are used"
    Test = {
        $test = sshd -T | grep kexalgorithms
        if($test -match "diffie-hellman-group1-sha1" -or
        $test -match "diffie-hellman-group14-sha1" -or
        $test -match "diffie-hellman-group-exchange-sha1"){
            return $retNonCompliant
        } else {
            return $retCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.16"
    Task = "Ensure SSH Idle Timeout Interval is configured"
    Test = {
        $test1 = sshd -T | grep clientaliveinterval | cut -d ' ' -f 2
        $test2 = sshd -T | grep clientaliveinterval | cut -d ' ' -f 2
        if($test1 -ge 1 -and $test1 -le 300 -and $test2 -ge 1 -and $test2 -le 3){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.17"
    Task = "Ensure SSH LoginGraceTime is set to one minute or less"
    Test = {
        $test = sshd -T | grep logingracetime | cut -d ' ' -f 2
        if($test -ge 1 -and $test1 -le 60){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.18"
    Task = "Ensure SSH warning banner is configured"
    Test = {
        $test = sshd -T | grep banner
        if($test -match "banner /etc/issue.net"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.19"
    Task = "Ensure SSH PAM is enabled"
    Test = {
        $test = sshd -T | grep -i usepam
        if($test -match "usepam yes"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.20"
    Task = "Ensure SSH AllowTcpForwarding is disabled"
    Test = {
        $test = sshd -T | grep -i allowtcpforwarding
        if($test -match "allowtcpforwarding no"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.21"
    Task = "Ensure SSH MaxStartups is configured"
    Test = {
        $test = sshd -T | grep -i maxstartups
        if($test -match "maxstartups 10:30:60"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2.22"
    Task = "Ensure SSH MaxSessions is limited"
    Test = {
        $test = sshd -T | grep -i maxsessions | cut -d ' ' -f 2
        if($test -le 10){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

# TODO
[AuditTest] @{
    Id = "5.3.1"
    Task = "Ensure password creation requirements are configured"
    Test = {
        return $retCompliant
    }
}

# TODO
[AuditTest] @{
    Id = "5.3.2"
    Task = "Ensure lockout for failed password attempts is configured"
    Test = {
        return $retCompliant
    }
}

# TODO
[AuditTest] @{
    Id = "5.3.3"
    Task = "Ensure password reuse is limited"
    Test = {
        return $retCompliant
    }
}

[AuditTest] @{
    Id = "5.4.1.1"
    Task = "Ensure password hashing algorithm is SHA-512"
    Test = {
        $test = grep -Ei '^\s*^\s*ENCRYPT_METHOD\s+SHA512' /etc/login.defs
        if($test -match "SHA512"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

## TODO
[AuditTest] @{
    Id = "5.4.1.2"
    Task = "Ensure password expiration is 365 days or less"
    Test = {
        $test = grep -Ei '^\s*^\s*ENCRYPT_METHOD\s+SHA512' /etc/login.defs
        if($test -match "SHA512"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

## TODO
[AuditTest] @{
    Id = "5.4.1.3"
    Task = "Ensure minimum days between password changes is configured"
    Test = {
        $test = grep -Ei '^\s*^\s*ENCRYPT_METHOD\s+SHA512' /etc/login.defs
        if($test -match "SHA512"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

## TODO
[AuditTest] @{
    Id = "5.4.1.4"
    Task = "Ensure password expiration warning days is 7 or more"
    Test = {
        $test = grep -Ei '^\s*^\s*ENCRYPT_METHOD\s+SHA512' /etc/login.defs
        if($test -match "SHA512"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

## TODO
[AuditTest] @{
    Id = "5.4.1.5"
    Task = "Ensure inactive password lock is 30 days or less"
    Test = {
        $test = grep -Ei '^\s*^\s*ENCRYPT_METHOD\s+SHA512' /etc/login.defs
        if($test -match "SHA512"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

# TODO
[AuditTest] @{
    Id = "5.4.1.6"
    Task = "Ensure all users last password change date is in the past"
    Test = {
        $test = @'
        #!/bin/bash
        for usr in $(cut -d: -f1 /etc/shadow); do
        [[ $(chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo "$usr :$(chage --list $usr | grep '^Last password change' | cut -d: -f2)"; done
'@
        if($test -eq $null){
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
        $test1 = awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print}' /etc/passwd
        $test2 = awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!="L" && $2!="LK") {print $1}'
        if($test1 -eq $null -and $test2 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.4.3"
    Task = "Ensure default group for the root account is GID 0"
    Test = {
        $test = grep "^root:" /etc/passwd | cut -f4
        if($test -eq 0){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.4.4"
    Task = "Ensure default user shell timeout is configured"
    Test = {
        $test1 = @'
for f in /etc/profile.d/*.sh ; do grep -Eq '(^|^[^#]*;)\s*(readonly|export(\s+[^$#;]+\s*)*)?\s*TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\b' $f && grep -Eq '(^|^[^#]*;)\s*readonly\s+TMOUT\b' $f && grep -Eq '(^|^[^#]*;)\s*export\s+([^$#;]+\s+)*TMOUT\b' $f && echo "TMOUT correctly configured in file: $f"; done
'@
        $test2 = grep -PR '^\s*([^$#;]+\s+)*TMOUT=(9[0-9][1-9]|0+|[1-9]\d{3,})\b\s*(\S+\s*)*(\s+#.*)?$' /etc/profile* /etc/bashrc.bashrc*
        if($test1 -match "configured in file: /etc/profile.d/" -and $test2 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.4.5"
    Task = "Ensure default user umask is configured"
    Test = {
        $test1 = grep -RPi '(^|^[^#]*)\s*umask\s+([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b|[0-7][01][0-7]\b|[0-7][0-7][0-6]\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}(,o=[rwx]{0,3})?\b)' /etc/login.defs /etc/default/login /etc/profile* /etc/bash.bashrc*
        $test2 = grep -REi '^\s*UMASK\s+\s*(0[0-7][2-7]7|[0-7][2-7]7|u=(r?|w?|x?)(r?|w?|x?)(r?|w?|x?),g=(r?x?|x?r?),o=)\b' /etc/login.defs /etc/default/login /etc/profile* /etc/bash.bashrc*
        if(($test1 -eq $null -or $test1 -match "No such file or directory") -and $test2 -match "UMASK\s*027"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.5"
    Task = "Ensure root login is restricted to system console"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

#TODO
[AuditTest] @{
    Id = "5.6"
    Task = "Ensure access to the su command is restricted"
    Test = {
        $test1 = grep -RPi '(^|^[^#]*)\s*umask\s+([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b|[0-7][01][0-7]\b|[0-7][0-7][0-6]\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}(,o=[rwx]{0,3})?\b)' /etc/login.defs /etc/default/login /etc/profile* /etc/bash.bashrc*
        $test2 = grep -REi '^\s*UMASK\s+\s*(0[0-7][2-7]7|[0-7][2-7]7|u=(r?|w?|x?)(r?|w?|x?)(r?|w?|x?),g=(r?x?|x?r?),o=)\b' /etc/login.defs /etc/default/login /etc/profile* /etc/bash.bashrc*
        if(($test1 -eq $null -or $test1 -match "No such file or directory") -and $test2 -match "UMASK\s*027"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}


### Chapter 6 - System Maintenance

[AuditTest] @{
    Id = "6.1.1"
    Task = "Audit system file permissions"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "6.2.1"
    Task = "Ensure permissions on /etc/passwd are configured"
    Test = {
        $test1 = stat /etc/passwd
        if($test1 -match "Access:\s+(0644/-rw-------)\s+Uid:\s+(\s+0/\s+root)\s+Gid: (\s+0/\s+root)"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.1.3"
    Task = "Ensure permissions on /etc/shadow are configured"
    Test = {
        $test1 = stat /etc/shadow
        if($test1 -match "Access:\s+(0640/-rw-------)\s+Uid:\s+(\s+0/\s+root)\s+Gid: (\s+0/\s+root)"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.1.4"
    Task = "Ensure permissions on /etc/group are configured"
    Test = {
        $test1 = stat /etc/group
        if($test1 -match "Access:\s+(0644/-rw-------)\s+Uid:\s+(\s+0/\s+root)\s+Gid: (\s+0/\s+root)"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.1.5"
    Task = "Ensure permissions on /etc/passwd- are configured"
    Test = {
        $test1 = stat /etc/passwd-
        if($test1 -match "Access:\s+(0644/-rw-------)\s+Uid:\s+(\s+0/\s+root)\s+Gid: (\s+0/\s+root)"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.1.6"
    Task = "Ensure permissions on /etc/shadow- are configured"
    Test = {
        $test1 = stat /etc/shadow-
        if($test1 -match "Access:\s+(0640/-rw-------)\s+Uid:\s+(\s+0/\s+root)\s+Gid: (\s+0/\s+root)"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.1.7"
    Task = "Ensure permissions on /etc/group- are configured"
    Test = {
        $test1 = stat /etc/group-
        if($test1 -match "Access:\s+(0644/-rw-------)\s+Uid:\s+(\s+0/\s+root)\s+Gid: (\s+0/\s+root)"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.1.8"
    Task = "Ensure no world writable files exist"
    Test = {
        $test1 = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.1.9"
    Task = "Ensure no unowned files or directories exist"
    Test = {
        $test1 = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.1.10"
    Task = "Ensure no ungrouped files or directories exist"
    Test = {
        $test1 = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.1.11"
    Task = "Audit SUID executables"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "6.1.12"
    Task = "Audit SGID executables"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "6.2.1"
    Task = "Ensure accounts in /etc/passwd use shadowed passwords"
    Test = {
        $test1 = awk -F: '($2 != "x" ) { print $1 " is not set to shadowed passwords "}' /etc/passwd
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.2"
    Task = "Ensure /etc/shadow password fields are not empty"
    Test = {
        $test1 = awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.3"
    Task = "Ensure root is the only UID 0 accoun"
    Test = {
        $test1 = awk -F: '($3 == 0) { print $1 }' /etc/passwd
        if($test1 -match "root"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.4"
    Task = "Ensure root PATH Integrity"
    Test = {
        $test1 = @'
#!/bin/bash
if echo "$PATH" | grep -q "::" ; then
    echo "Empty Directory in PATH (::)"
fi
if echo "$PATH" | grep -q ":$" ; then
    echo "Trailing : in PATH"
fi
for x in $(echo "$PATH" | tr ":" " ") ; do
    if [ -d "$x" ] ; then
        ls -ldH "$x" | awk '
        $9 == "." {print "PATH contains current working directory (.)"}
        $3 != "root" {print $9, "is not owned by root"}
        substr($1,6,1) != "-" {print $9, "is group writable"}
        substr($1,9,1) != "-" {print $9, "is world writable"}'
    else
        echo "$x is not a directory"
    fi
done
'@
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.5"
    Task = "Ensure all users' home directories exist"
    Test = {
        $test1 = @'
#!/bin/bash
grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist." fi done
'@
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.6"
    Task = "Ensure users' home directories permissions are 750 or more restrictive"
    Test = {
        $test1 = @'
#!/bin/bash
grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist." else dirperm=$(ls -ld $dir | cut -f1 -d" ") if [ $(echo $dirperm | cut -c6) != "-" ]; then echo "Group Write permission set on the home directory ($dir) of user $user" fi if [ $(echo $dirperm | cut -c8) != "-" ]; then echo "Other Read permission set on the home directory ($dir) of user $user" fi if [ $(echo $dirperm | cut -c9) != "-" ]; then echo "Other Write permission set on the home directory ($dir) of user $user" fi if [ $(echo $dirperm | cut -c10) != "-" ]; then echo "Other Execute permission set on the home directory ($dir) of user $user" fi fi done
'@
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.7"
    Task = "Ensure users own their home directories"
    Test = {
        $test1 = @'
#!/bin/bash
grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist." else owner=$(stat -L -c "%U" "$dir") if [ "$owner" != "$user" ]; then echo "The home directory ($dir) of user $user is owned by $owner." fi fi done
'@
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.8"
    Task = "Ensure users' dot files are not group or world writable"
    Test = {
        $test1 = @'
#!/bin/bash
grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist." else for file in $dir/.[A-Za-z0-9]*; do if [ ! -h "$file" -a -f "$file" ]; then fileperm=$(ls -ld $file | cut -f1 -d" ") if [ $(echo $fileperm | cut -c6) != "-" ]; then echo "Group Write permission set on file $file" fi if [ $(echo $fileperm | cut -c9) != "-" ]; then echo "Other Write permission set on file $file" fi fi done fi done
'@
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.9"
    Task = "Ensure no users have .forward files"
    Test = {
        $test1 = @'
#!/bin/bash
awk -F: '($1 !~ /^(root|halt|sync|shutdown)$/ && $7 != "'"$(which nologin)"'" && $7 != "/bin/false" && $7 != "/usr/bin/false") { print $1 " " $6 }' /etc/passwd | while read user dir; do if [ ! -d "$dir" ] ; then echo "The home directory ($dir) of user $user does not exist." else if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ] ; then echo ".forward file $dir/.forward exists" fi fi done
'@
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.10"
    Task = "Ensure no users have .netrc files"
    Test = {
        $test1 = @'
#!/bin/bash
awk -F: '($1 !~ /^(root|halt|sync|shutdown)$/ && $7 != "'"$(which nologin)"'" && $7 != "/bin/false" && $7 != "/usr/bin/false") { print $1 " " $6 }' /etc/passwd | while read user dir; do if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist." else if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then echo ".netrc file $dir/.netrc exists" fi fi done
'@
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.11"
    Task = "Ensure users' .netrc Files are not group or world accessible"
    Test = {
        $test1 = @'
#!/bin/bash
awk -F: '($1 !~ /^(root|halt|sync|shutdown)$/ && $7 != "'"$(which nologin)"'" && $7 != "/bin/false" && $7 != "/usr/bin/false") { print $1 " " $6 }' /etc/passwd | while read user dir; do if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist." else for file in $dir/.netrc; do if [ ! -h "$file" -a -f "$file" ]; then fileperm=$(ls -ld $file | cut -f1 -d" ") if [ $(echo $fileperm | cut -c5) != "-" ]; then echo "Group Read set on $file" fi if [ $(echo $fileperm | cut -c6) != "-" ]; then echo "Group Write set on $file" fi if [ $(echo $fileperm | cut -c7) != "-" ]; then echo "Group Execute set on $file" fi if [ $(echo $fileperm | cut -c8) != "-" ]; then echo "Other Read set on $file" fi if [ $(echo $fileperm | cut -c9) != "-" ]; then echo "Other Write set on $file" fi if [ $(echo $fileperm | cut -c10) != "-" ]; then echo "Other Execute set on $file" fi fi done fi done
'@
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.12"
    Task = "Ensure no users have .rhosts files"
    Test = {
        $test1 = @'
#!/bin/bash
awk -F: '($1 !~ /^(root|halt|sync|shutdown)$/ && $7 != "'"$(which nologin)"'" && $7 != "/bin/false" && $7 != "/usr/bin/false") { print $1 " " $6 }' /etc/passwd | while read user dir; do if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist." else for file in $dir/.rhosts; do if [ ! -h "$file" -a -e "$file" ]; then echo ".rhosts file in $dir" fi done fi done
'@
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.13"
    Task = "Ensure all groups in /etc/passwd exist in /etc/group"
    Test = {
        $test1 = @'
#!/bin/bash
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do grep -q -P "^.*?:[^:]*:$i:" /etc/group if [ $? -ne 0 ]; then echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" fi done
'@
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.14"
    Task = "Ensure no duplicate UIDs exist"
    Test = {
        $test1 = @'
#!/bin/bash
cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read x ; do [ -z "$x" ] && break set - $x if [ $1 -gt 1 ]; then users=$(awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs) echo "Duplicate UID ($2): $users" fi done
'@
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.15"
    Task = "Ensure no duplicate GIDs exist"
    Test = {
        $test1 = @'
#!/bin/bash
cut -d: -f3 /etc/group | sort | uniq -d | while read x ; do echo "Duplicate GID ($x) in /etc/group" done
'@
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.16"
    Task = "Ensure no duplicate user names exist"
    Test = {
        $test1 = @'
#!/bin/bash
cut -d: -f1 /etc/passwd | sort | uniq -d | while read x do echo "Duplicate login name ${x} in /etc/passwd" done
'@
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.17"
    Task = "Ensure no duplicate group names exist"
    Test = {
        $test1 = @'
#!/bin/bash
cut -d: -f1 /etc/group | sort | uniq -d | while read x do echo "Duplicate group name ${x} in /etc/group" done
'@
        if($test1 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "6.2.18"
    Task = "Ensure shadow group is empty"
    Test = {
        $test1 = grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group
        $test2 = awk -F: '($4 == "<shadow-gid>") { print }' /etc/passwd
        if($test1 -eq $null -and $test2 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}